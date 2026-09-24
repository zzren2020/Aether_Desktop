//! TUN→SOCKS5 relay — the Windows twin of Android's hev-socks5-tunnel.
//!
//! # >>> AETHER-APP-FIX tun-relay-goes-live
//!
//! Until now the Wintun adapter was a shell: `tun.rs` created it, set its
//! address and DNS, and then deliberately captured no routes, because nothing
//! drained its ring buffer — "an adapter with no relay". The data path was the
//! system proxy (TCP only), and every browser QUIC attempt blackholed (the
//! 2026-09-23 psiphon log, entry 4-1).
//!
//! This module is the relay that file's header comment always promised:
//!
//! ```text
//!   Android: VpnService → TUN fd → hev-socks5-tunnel → engine SOCKS5
//!   Windows: Wintun adapter → smoltcp (userspace TCP/IP) → SOCKS5 → engine
//! ```
//!
//! # How a packet flows
//!
//! 1. `tun_relay::engage` installs 0.0.0.0/1 + 128.0.0.0/1 routes over the
//!    Wintun adapter (the two-half trick: same coverage as 0.0.0.0/0, but the
//!    real default route stays in the table so teardown can never strand the
//!    machine), and — before that — host routes for every network the ENGINE
//!    itself dials, so the engine's own packets never enter the adapter we
//!    are feeding (no feedback loop).
//! 2. A Wintun read thread drains `try_receive` (non-blocking, 1 ms idle
//!    retry) and pushes raw IP packets into a queue.
//! 3. A poll thread owns a smoltcp `Interface` (medium-ip, any-ip) plus the
//!    `SocketSet`. Before each poll it peeks the queued packets and — for a
//!    TCP SYN or the first datagram of a UDP source port — creates the
//!    matching socket, because smoltcp accepts nothing it has no socket for.
//! 4. Every accepted TCP connection is bridged, byte for byte, to a SOCKS5
//!    CONNECT towards the engine's exit SOCKS5 (127.0.0.1:1819 by default —
//!    the same exit the share bridge and the Psiphon stage already use). UDP
//!    source ports get a SOCKS5 UDP ASSOCIATE (the engine implements it).
//! 5. DNS responses coming back through port 53 have their AAAA records
//!    stripped, so applications resolve to IPv4 addresses and actually use
//!    the tunnel; a plain AAAA would send them straight out over (missing or
//!    unprotected) IPv6.
//!
//! # What happens on failure
//!
//! Nothing here can kill the connection: if the adapter, the routes or the
//! relay cannot come up, `engage` returns an error and the caller keeps the
//! system-proxy data path with an honest log line. The reverse is also true:
//! once the relay IS live, the system proxy is switched off — the adapter is
//! the data path now.
//!
//! # <<< AETHER-APP-FIX tun-relay-goes-live

use crate::log::DiagnosticsLog;
use anyhow::{anyhow, Context, Result};
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{Socket as TcpSocket, SocketBuffer as TcpSocketBuffer, State as TcpState};
use smoltcp::socket::udp::{
    PacketBuffer as UdpPacketBuffer, PacketMetadata as UdpPacketMetadata, Socket as UdpSocket,
    UdpMetadata,
};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{
    HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv4Address, Ipv4Packet, TcpPacket,
};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream, UdpSocket as StdUdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const TAG: &str = "tun_relay";

// Hide the console window of every route.exe/netsh child: a GUI process
// spawning console tools without this flag flashes a cmd window per call
// (17 route adds on connect, 17 deletes on disconnect — user report 2026-09-23).
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Addresses this process talks to ABOUT the tunnel are all inside these
/// networks: WireGuard endpoints (`wireguard::WG_PREFIXES_V4`) and MASQUE
/// edges (`prober::MASQUE_CIDRS_V4`, DoH included). Every one of them gets a
/// host/subnet route over the REAL gateway before the TUN routes go in, so
/// the engine's own dials (and its reconnects!) never enter the adapter we
/// are draining — that feedback loop would blackhole the tunnel itself.
const ENGINE_PREFIXES_V4: [&str; 15] = [
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.195.0/24",
    "162.159.196.0/24",
    "162.159.197.0/24",
    "162.159.198.0/24",
    "162.159.199.0/24",
    "162.159.204.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
    "172.65.251.0/24",
    "162.159.36.0/24",
    "162.159.46.0/24",
];

// ---------------------------------------------------------------------------
// Public surface
// ---------------------------------------------------------------------------

/// Live relay. `shutdown` removes the routes it added and lets the threads
/// die with the session (the caller drops the Wintun session right after).
pub struct RelayHandle {
    stop: Arc<AtomicBool>,
    routes_added: Vec<(String, String)>,
    _poll_thread: Option<std::thread::JoinHandle<()>>,
}

impl RelayHandle {
    /// Remove the TUN routes and stop the relay. Idempotent.
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Routes first: a torn-down adapter with live 0.0.0.0/1 routes is how
        // a machine loses its internet after a disconnect.
        for (dest, mask) in &self.routes_added {
            route_delete(dest, mask);
        }
        DiagnosticsLog::i(TAG, "TUN data path removed — default routes released.");
        // The poll thread checks `stop` every tick; the Wintun read thread
        // unblocks when the caller closes the session right after us.
        if let Some(h) = self._poll_thread.take() {
            let _ = h.join();
        }
    }
}

/// Bring the TUN data path up for an already-created Wintun session.
///
/// Order is security, not preference: engine-prefix routes go in FIRST (so a
/// packet can never take the TUN route to an address the engine itself is
/// dialling), then the two default halves. Any failure here is fatal for the
/// relay but harmless for the connection — the caller falls back to the
/// system-proxy path.
pub fn engage(session: Arc<wintun::Session>, mtu: u16, socks_port: u16) -> Result<RelayHandle> {
    let gateway = default_gateway().map_err(|e| anyhow!("no default gateway found: {e}"))?;

    let tun_gw = crate::tun::TUN_IPV4.to_string();
    let mut routes_added: Vec<(String, String)> = Vec::new();
    let install = |routes_added: &mut Vec<(String, String)>| -> Result<()> {
        for prefix in ENGINE_PREFIXES_V4 {
            let (dest, mask) = prefix.split_once('/').expect("static prefix");
            let mask = prefix_to_mask(mask.parse::<u8>().expect("static prefix len"));
            route_add_idempotent(dest, &mask, &gateway.to_string())?;
            routes_added.push((dest.to_string(), mask));
        }
        for dest in ["0.0.0.0", "128.0.0.0"] {
            route_add_idempotent(dest, "128.0.0.0", &tun_gw)?;
            routes_added.push((dest.to_string(), "128.0.0.0".to_string()));
        }
        Ok(())
    };
    if let Err(e) = install(&mut routes_added) {
        // Never leave a partial route set behind: a stale 0.0.0.0/1 pointing
        // at an adapter nobody drains is how a machine loses its internet
        // (and a stale engine route is what made the next connect's route add
        // fail with "object already exists" — log 6-2).
        for (dest, mask) in &routes_added {
            route_delete(dest, mask);
        }
        return Err(e);
    }
    DiagnosticsLog::i(
        TAG,
        &format!(
            "TUN routes installed: 0.0.0.0/1 + 128.0.0.0/1 over {tun_gw}; {} engine network(s) pinned to the real gateway {gateway}.",
            ENGINE_PREFIXES_V4.len()
        ),
    );

    let stop = Arc::new(AtomicBool::new(false));
    let (pkt_tx, pkt_rx) = std::sync::mpsc::channel::<Vec<u8>>();

    // Wintun read thread: blocking receive, vector-copy, hand over.
    {
        let session = session.clone();
        let stop = stop.clone();
        std::thread::Builder::new()
            .name("tun-read".into())
            .spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match session.try_receive() {
                        Ok(Some(packet)) => {
                            let bytes = packet.bytes().to_vec();
                            drop(packet);
                            // A full queue means the poll loop is stuck; drop
                            // newest rather than wedging the ring buffer.
                            let _ = pkt_tx.send(bytes);
                        }
                        Ok(None) => {
                            // Nothing right now: retry shortly so `stop` is
                            // honored promptly (try_receive is non-blocking;
                            // a blocking receive would wedge this thread until
                            // the session closes).
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break, // session closed by teardown
                    }
                }
            })
            .ok();
    }

    let poll_stop = stop.clone();
    let poll_thread = std::thread::Builder::new()
        .name("tun-poll".into())
        .spawn(move || poll_loop(pkt_rx, session, mtu, socks_port, poll_stop))
        .ok();

    DiagnosticsLog::i(
        TAG,
        &format!("TUN relay live: adapter packets are bridged to SOCKS5 127.0.0.1:{socks_port}."),
    );
    Ok(RelayHandle {
        stop,
        routes_added,
        _poll_thread: poll_thread,
    })
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

fn route_add(dest: &str, mask: &str, gateway: &str) -> Result<()> {
    let out = std::process::Command::new("route")
        .args(["add", dest, "mask", mask, gateway, "metric", "1"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .context("route add failed to execute")?;
    if !out.status.success() {
        return Err(anyhow!(
            "route add {dest} mask {mask} via {gateway} failed (administrator rights required?)"
        ));
    }
    Ok(())
}

/// Idempotent add: a route left over from an earlier session makes a plain
/// `route add` fail with "the object already exists" (log 6-2). Remove the
/// stale copy and try once more before giving up.
fn route_add_idempotent(dest: &str, mask: &str, gateway: &str) -> Result<()> {
    if route_add(dest, mask, gateway).is_ok() {
        return Ok(());
    }
    route_delete(dest, mask);
    route_add(dest, mask, gateway)
}

fn route_delete(dest: &str, mask: &str) {
    let _ = std::process::Command::new("route")
        .args(["delete", dest, "mask", mask])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

fn prefix_to_mask(bits: u8) -> String {
    let mask = if bits == 0 {
        0u32
    } else {
        u32::MAX << (32 - bits)
    };
    Ipv4Addr::from(mask).to_string()
}

/// The gateway the machine used BEFORE the TUN routes went in: parse the
/// active 0.0.0.0/0 row out of `route print 0.0.0.0`.
fn default_gateway() -> Result<Ipv4Addr> {
    let out = std::process::Command::new("route")
        .args(["print", "0.0.0.0"])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .context("route print failed to execute")?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // Active route row: NetworkDestination Netmask Gateway Interface Metric
        if cols.len() >= 5 && cols[0] == "0.0.0.0" && cols[1] == "0.0.0.0" {
            if let Ok(gw) = cols[2].parse::<Ipv4Addr>() {
                return Ok(gw);
            }
        }
    }
    Err(anyhow!("no active 0.0.0.0/0 row in route print"))
}

// ---------------------------------------------------------------------------
// smoltcp device plumbing
// ---------------------------------------------------------------------------

type SharedQueue = Arc<Mutex<VecDeque<Vec<u8>>>>;

struct RelayDevice {
    queue: SharedQueue,
    session: Arc<wintun::Session>,
    mtu: u16,
}

struct RelayRxToken {
    packet: Vec<u8>,
}

struct RelayTxToken {
    session: Arc<wintun::Session>,
}

impl Device for RelayDevice {
    type RxToken<'a> = RelayRxToken;
    type TxToken<'a> = RelayTxToken;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let packet = self.queue.lock().ok()?.pop_front()?;
        Some((
            RelayRxToken { packet },
            RelayTxToken {
                session: self.session.clone(),
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(RelayTxToken {
            session: self.session.clone(),
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu as usize;
        caps
    }
}

impl RxToken for RelayRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.packet)
    }
}

impl TxToken for RelayTxToken {
    // smoltcp 0.12 signature: consume(self, len, f) — no timestamp parameter.
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = match self.session.allocate_send_packet(len as u16) {
            Ok(p) => p,
            // Session is closing: build into a scratch buffer so `f` still
            // sees a buffer of the promised size, and drop the frame.
            Err(_) => {
                let mut scratch = vec![0u8; len];
                return f(&mut scratch);
            }
        };
        let out = f(packet.bytes_mut());
        self.session.send_packet(packet);
        out
    }
}

// ---------------------------------------------------------------------------
// Poll loop
// ---------------------------------------------------------------------------

struct TcpEntry {
    handle: smoltcp::iface::SocketHandle,
    dst: IpEndpoint,
    /// Poll thread → bridge writer: bytes the application sent into the
    /// tunnel. Dropping this sender is the EOF signal.
    app_to_socks: Option<Sender<Vec<u8>>>,
    /// Bridge reader → poll thread: bytes that came back from the tunnel.
    socks_to_app: Receiver<Vec<u8>>,
    /// Bytes received from the tunnel that smoltcp's send buffer had no room
    /// for yet. Front-of-queue on partial sends — never a dropped byte.
    pending: VecDeque<Vec<u8>>,
    /// Tunnel half-close seen: the bridge reader is gone (EOF from SOCKS5).
    socks_eof: bool,
    bridged: bool,
}

struct UdpEntry {
    handle: smoltcp::iface::SocketHandle,
    /// Poll thread → relay thread: datagrams the application sent (dst kept).
    to_relay: Sender<(Vec<u8>, IpEndpoint)>,
    /// Relay thread → poll thread: datagrams that came back (src kept).
    from_relay: Receiver<(Vec<u8>, IpEndpoint)>,
    last_seen: std::time::Instant,
}

fn poll_loop(
    pkt_rx: Receiver<Vec<u8>>,
    session: Arc<wintun::Session>,
    mtu: u16,
    socks_port: u16,
    stop: Arc<AtomicBool>,
) {
    let queue: SharedQueue = Arc::new(Mutex::new(VecDeque::new()));
    let mut device = RelayDevice {
        queue: queue.clone(),
        session,
        mtu,
    };

    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 0x61e7_4a11_9c3f_b0d2;
    let mut iface = Interface::new(config, &mut device, SmolInstant::from_millis(0));
    iface.set_any_ip(true);
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(
            IpAddress::v4(172, 19, 0, 2),
            24,
        ));
    });
    // The default-route gateway MUST be our own address, not a phantom
    // 172.19.0.1: smoltcp's AnyIP ingress filter drops any non-local packet
    // whose route resolves to a gateway that is not one of our own addresses
    // ("no matching routes" — iface/interface/ipv4.rs). With Medium::Ip there
    // is no link-layer gateway at all; the packet goes straight into the
    // adapter we are draining, so "we are the gateway" is the correct
    // semantics — and the only configuration the filter accepts. This one
    // line silently blackholed every TCP handshake (log 7-1/7-2/7-3: zero
    // "TCP through tunnel" while UDP sessions lived).
    let _ = iface
        .routes_mut()
        .add_default_ipv4_route(crate::tun::TUN_IPV4);

    let mut sockets = SocketSet::new(vec![]);
    let mut tcp_sessions: Vec<TcpEntry> = Vec::new();
    let mut udp_sessions: HashMap<u16, UdpEntry> = HashMap::new();
    let start = std::time::Instant::now();
    while !stop.load(Ordering::Relaxed) {
        // 1. Drain the Wintun read thread into the device queue.
        {
            let mut q = match queue.lock() {
                Ok(q) => q,
                Err(_) => break,
            };
            while let Ok(pkt) = pkt_rx.try_recv() {
                q.push_back(pkt);
            }
        }

        // 2. Peek the queue and create sockets for new flows BEFORE the poll:
        //    smoltcp drops a TCP SYN it has no listening socket for, and a
        //    UDP datagram with no bound port. Sniffing here is what makes the
        //    "connect to any address" model work.
        {
            let q = match queue.lock() {
                Ok(q) => q,
                Err(_) => break,
            };
            for pkt in q.iter() {
                sniff_and_seed(pkt, &mut sockets, &mut tcp_sessions, &mut udp_sessions);
            }
        }

        // 3. Let smoltcp drain the queue and drive every socket.
        let now = SmolInstant::from_millis(start.elapsed().as_millis() as i64);
        let _ = iface.poll(now, &mut device, &mut sockets);

        // 4. Pump the TCP bridges.
        pump_tcp(&mut iface, &mut sockets, &mut tcp_sessions, socks_port);

        // 5. Pump the UDP relays.
        pump_udp(&mut iface, &mut sockets, &mut udp_sessions);

        std::thread::sleep(Duration::from_millis(2));
    }

    // Teardown: abort every socket so FINs/RSTs go out while the session
    // is still alive (best effort).
    for t in &tcp_sessions {
        let sock = sockets.get_mut::<TcpSocket>(t.handle);
        if sock.is_open() {
            sock.abort();
        }
    }
    let _ = iface.poll(SmolInstant::from_millis(start.elapsed().as_millis() as i64), &mut device, &mut sockets);
    DiagnosticsLog::i(TAG, "TUN relay poll loop stopped.");
}

/// Inspect a raw IP packet and, for a flow we have not seen yet, create the
/// socket that will make smoltcp accept it:
///   * TCP SYN (not SYN+ACK): listen socket bound to the ORIGINAL DESTINATION
///     — any_ip makes smoltcp accept packets addressed to foreign hosts, and
///     the listen endpoint selects which socket owns the flow.
///   * UDP: bind a socket to the SOURCE port (0.0.0.0:src), so replies can be
///     routed back to the same application socket.
fn sniff_and_seed(
    pkt: &[u8],
    sockets: &mut SocketSet,
    tcp_sessions: &mut Vec<TcpEntry>,
    udp_sessions: &mut HashMap<u16, UdpEntry>,
) {
    let Some(ipv4) = Ipv4Packet::new_checked(pkt).ok() else {
        return; // IPv6 is not captured (routes are v4-only); fragments and non-IP are ignored.
    };
    // smoltcp 0.12: the IPv4 protocol field getter is `next_header()`.
    match ipv4.next_header() {
        smoltcp::wire::IpProtocol::Tcp => {
            let Ok(tcp) = TcpPacket::new_checked(ipv4.payload()) else {
                return;
            };
            // smoltcp 0.12: flag getters are `syn()` / `ack()`.
            let is_syn = tcp.syn() && !tcp.ack();
            if !is_syn {
                return;
            }
            let dst = IpEndpoint::new(
                IpAddress::Ipv4(ipv4.dst_addr()),
                tcp.dst_port(),
            );
            if tcp_sessions.iter().any(|t| t.dst == dst) {
                return;
            }
            let rx = TcpSocketBuffer::new(vec![0u8; 65535]);
            let tx = TcpSocketBuffer::new(vec![0u8; 65535]);
            let mut sock = TcpSocket::new(rx, tx);
            if sock.listen(dst).is_err() {
                return;
            }
            let handle = sockets.add(sock);
            // Evidence chain, level 1 of 2: the SYN reached the stack and a
            // listener now owns the flow. (Level 2 is "TCP through tunnel"
            // once the smoltcp handshake completes and the bridge spawns —
            // if this line appears without that one, the handshake itself
            // is failing inside smoltcp.)
            DiagnosticsLog::i(
                TAG,
                &format!("TCP SYN seen → accepting connection to {dst}"),
            );
            tcp_sessions.push(TcpEntry {
                handle,
                dst,
                app_to_socks: None,
                socks_to_app: never_recv(),
                pending: VecDeque::new(),
                socks_eof: false,
                bridged: false,
            });
        }
        smoltcp::wire::IpProtocol::Udp => {
            let Some(src_port) = udp_src_port(ipv4.payload()) else {
                return;
            };
            if udp_sessions.contains_key(&src_port) {
                return;
            }
            // NBNS (137), mDNS (5353), SSDP and friends are broadcast/multicast
            // by nature — they must never leave the machine, and seeding a
            // relay session for them only produces noise (log 6-3: dozens of
            // idle sessions expiring).
            let dst = ipv4.dst_addr();
            if dst.is_broadcast() || dst.is_multicast() || dst.is_unspecified() {
                return;
            }
            let rx = UdpPacketBuffer::new(
                vec![UdpPacketMetadata::EMPTY; 64],
                vec![0u8; 65535],
            );
            let tx = UdpPacketBuffer::new(
                vec![UdpPacketMetadata::EMPTY; 64],
                vec![0u8; 65535],
            );
            let mut sock = UdpSocket::new(rx, tx);
            // From<u16> for IpListenEndpoint = "this local port, any address"
            // — exactly the wildcard bind the source-port routing needs.
            if sock.bind(src_port).is_err() {
                return;
            }
            let handle = sockets.add(sock);
            let (to_relay_tx, to_relay_rx) = std::sync::mpsc::channel::<(Vec<u8>, IpEndpoint)>();
            let (from_relay_tx, from_relay_rx) = std::sync::mpsc::channel::<(Vec<u8>, IpEndpoint)>();
            udp_sessions.insert(
                src_port,
                UdpEntry {
                    handle,
                    to_relay: to_relay_tx,
                    from_relay: from_relay_rx,
                    last_seen: std::time::Instant::now(),
                },
            );
            spawn_udp_relay(src_port, to_relay_rx, from_relay_tx);
            DiagnosticsLog::i(
                TAG,
                &format!("UDP session opened on source port {src_port}"),
            );
        }
        _ => {}
    }
}

fn never_recv() -> Receiver<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    // Keep the sender alive for the session's lifetime; an empty channel is
    // exactly "nothing came back from the tunnel yet".
    std::mem::forget(tx);
    rx
}

fn udp_src_port(payload: &[u8]) -> Option<u16> {
    if payload.len() < 8 {
        return None;
    }
    Some(u16::from_be_bytes([payload[0], payload[1]]))
}

// ---------------------------------------------------------------------------
// TCP bridging
// ---------------------------------------------------------------------------

fn pump_tcp(
    _iface: &mut Interface,
    sockets: &mut SocketSet,
    sessions: &mut Vec<TcpEntry>,
    socks_port: u16,
) {
    sessions.retain_mut(|entry| {
        let sock = sockets.get_mut::<TcpSocket>(entry.handle);

        // Spawn the SOCKS5 bridge the moment smoltcp completed the handshake.
        if !entry.bridged && sock.state() == TcpState::Established {
            entry.bridged = true;
            let (to_socks_tx, to_socks_rx) = std::sync::mpsc::channel::<Vec<u8>>();
            let (from_socks_tx, from_socks_rx) = std::sync::mpsc::channel::<Vec<u8>>();
            entry.app_to_socks = Some(to_socks_tx);
            entry.socks_to_app = from_socks_rx;
            spawn_tcp_bridge(entry.dst, socks_port, to_socks_rx, from_socks_tx);
            DiagnosticsLog::i(
                TAG,
                &format!("TCP through tunnel: {} — bridged via SOCKS5", entry.dst),
            );
        }

        // Tunnel → application: bridge reader handed us bytes; feed them into
        // smoltcp's send buffer, keeping a partial remainder at the front of
        // `pending` so nothing is ever dropped.
        while sock.may_send() {
            if entry.pending.is_empty() {
                match entry.socks_to_app.try_recv() {
                    Ok(chunk) => entry.pending.push_back(chunk),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        entry.socks_eof = true;
                        break;
                    }
                }
            }
            let chunk = entry.pending.front_mut().expect("checked above");
            let n = sock.send_slice(chunk).unwrap_or(0);
            if n == chunk.len() {
                entry.pending.pop_front();
            } else {
                chunk.drain(..n);
                break; // send buffer full; finish next tick
            }
        }

        // Application → tunnel: drain smoltcp's receive buffer into the
        // bridge writer's channel (unbounded — no byte is ever lost here).
        while sock.can_recv() {
            let mut buf = [0u8; 16384];
            let n = match sock.recv_slice(&mut buf) {
                Ok(n) => n,
                Err(_) => break,
            };
            if n == 0 {
                break;
            }
            match entry.app_to_socks.as_ref() {
                Some(tx) => {
                    if tx.send(buf[..n].to_vec()).is_err() {
                        // The writer is gone (SOCKS5 dial failed or died):
                        // abort the flow rather than pretend it works.
                        sock.abort();
                        break;
                    }
                }
                None => break, // not bridged yet — cannot happen post-Established
            }
        }

        // Half-closes, in both directions:
        //  * app half done (may_recv false, buffer drained) → tell the writer.
        //  * socks EOF (reader gone, nothing pending, nothing buffered) → FIN.
        if !sock.may_recv() && !sock.can_recv() {
            entry.app_to_socks.take();
        }
        if entry.socks_eof && entry.pending.is_empty() && !sock.may_send() {
            if sock.is_open() {
                sock.close();
            }
        }
        if entry.app_to_socks.is_none() && sock.state() == TcpState::Closed {
            return false; // both sides done
        }
        let dead = entry.bridged && sock.state() == TcpState::Closed;
        !(dead)
    });
}

fn spawn_tcp_bridge(
    dst: IpEndpoint,
    socks_port: u16,
    to_socks: Receiver<Vec<u8>>,
    from_socks: Sender<Vec<u8>>,
) {
    // Reader: SOCKS5 → application.
    std::thread::Builder::new()
        .name("tun-tcp-r".into())
        .spawn(move || {
            let result = (|| -> std::io::Result<()> {
                let mut stream = socks5_connect(socks_port, dst)?;
                let mut buf = [0u8; 16384];
                loop {
                    let n = stream.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    if from_socks.send(buf[..n].to_vec()).is_err() {
                        break; // app side went away
                    }
                }
                Ok(())
            })();
            let _ = result;
            // Dropping `from_socks` tells the poll loop this half is over.
        })
        .ok();
    // Writer: application → SOCKS5.
    std::thread::Builder::new()
        .name("tun-tcp-w".into())
        .spawn(move || {
            let result = (|| -> std::io::Result<()> {
                let mut stream = socks5_connect(socks_port, dst)?;
                for chunk in to_socks {
                    if stream.write_all(&chunk).is_err() {
                        break;
                    }
                }
                Ok(())
            })();
            let _ = result;
        })
        .ok();
}

// ---------------------------------------------------------------------------
// UDP relaying
// ---------------------------------------------------------------------------

fn spawn_udp_relay(
    src_port: u16,
    from_poll: Receiver<(Vec<u8>, IpEndpoint)>,
    to_poll: Sender<(Vec<u8>, IpEndpoint)>,
) {
    std::thread::Builder::new()
        .name("tun-udp".into())
        .spawn(move || {
            // DNS never touches UDP ASSOCIATE: the psiphon exit refuses
            // CMD 0x03 outright ("command was 0x03, not 0x01" — log 6-1) and
            // the masque pipeline's UDP egress is unreliable (log 6-3), so
            // every :53 datagram is resolved over DNS-over-TCP on a plain
            // SOCKS5 CONNECT instead — the one path every pipeline supports.
            // Other UDP lazily establishes one ASSOCIATE per source port; if
            // the exit has no UDP egress those datagrams are dropped (QUIC
            // falls back to TCP) while DNS keeps working.
            let mut associate: Option<(TcpStream, StdUdpSocket)> = None;
            let mut refused_logged = false;
            // Once the exit refused ASSOCIATE, stop retrying: a QUIC flow
            // would otherwise dial SOCKS once per datagram.
            let mut associate_dead = false;
            let mut buf = [0u8; 65535];
            loop {
                // Application → tunnel.
                match from_poll.recv_timeout(Duration::from_millis(250)) {
                    Ok((data, dst)) => {
                        if dst.port == 53 {
                            // One short-lived thread per query; it only needs
                            // a clone of the return channel.
                            let to_poll = to_poll.clone();
                            std::thread::Builder::new()
                                .name("tun-dns".into())
                                .spawn(move || {
                                    if let Some(resp) = dns_over_tcp(&data, &dst) {
                                        let _ = to_poll.send((resp, dst));
                                    }
                                })
                                .ok();
                            continue;
                        }
                        if associate.is_none() {
                            if !associate_dead {
                                match establish_udp_associate(src_port) {
                                    Ok(pair) => associate = Some(pair),
                                    Err(_) => {
                                        associate_dead = true;
                                        if !refused_logged {
                                            refused_logged = true;
                                            DiagnosticsLog::w(
                                                TAG,
                                                "UDP ASSOCIATE refused by the exit SOCKS5 — this pipeline has no UDP egress; DNS still resolves over TCP and QUIC falls back to TCP.",
                                            );
                                        }
                                    }
                                }
                            }
                            if associate.is_none() {
                                continue; // drop the datagram
                            }
                        }
                        let sent = match associate.as_ref() {
                            Some((_, sock)) => {
                                let mut gram = Vec::with_capacity(data.len() + 10);
                                gram.extend_from_slice(&[0u8, 0, 0]); // RSV + FRAG
                                push_endpoint(&mut gram, &dst);
                                gram.extend_from_slice(&data);
                                sock.send(&gram).is_ok()
                            }
                            None => false,
                        };
                        if !sent {
                            associate = None; // relay socket died; re-establish lazily
                        }
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                    Err(_) => return, // poll loop dropped the session
                }
                // Tunnel → application (only meaningful with a live associate).
                // `take()` keeps the borrow checker unambiguous: the pair is
                // owned for the drain and restored only if still healthy.
                if let Some((control, sock)) = associate.take() {
                    let mut healthy = true;
                    loop {
                        match sock.recv(&mut buf) {
                            Ok(n) => {
                                let Some((src, payload)) = parse_socks_udp(&buf[..n]) else {
                                    continue;
                                };
                                let mut out = payload.to_vec();
                                if src.port == 53 {
                                    strip_aaaa(&mut out);
                                }
                                if to_poll.send((out, src)).is_err() {
                                    return;
                                }
                            }
                            Err(ref e)
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut =>
                            {
                                break
                            }
                            Err(_) => {
                                healthy = false;
                                break;
                            }
                        }
                    }
                    if healthy && control_alive(&control) {
                        associate = Some((control, sock));
                    }
                }
            }
        })
        .ok();
}

/// Establish (control stream + relay socket) for non-DNS UDP, with the relay
/// socket pre-connected and a short read timeout so the pump loop never wedges.
fn establish_udp_associate(src_port: u16) -> std::io::Result<(TcpStream, StdUdpSocket)> {
    let (control, relay) = socks5_udp_associate(socks_port_of(), src_port)?;
    let sock = StdUdpSocket::bind("127.0.0.1:0")?;
    sock.connect(relay)?;
    sock.set_read_timeout(Some(Duration::from_millis(250)))?;
    Ok((control, sock))
}

/// Resolve one DNS query over DNS-over-TCP (RFC 1035 §4.2.2: 2-byte length
/// prefix) through a SOCKS5 CONNECT to the resolver — the transport every
/// exit pipeline supports, unlike UDP ASSOCIATE.
fn dns_over_tcp(query: &[u8], dst: &IpEndpoint) -> Option<Vec<u8>> {
    if query.len() < 12 || query.len() > 4096 {
        return None;
    }
    let mut stream = socks5_connect(socks_port_of(), *dst).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(4))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(4))).ok();
    let mut msg = Vec::with_capacity(query.len() + 2);
    msg.extend_from_slice(&(query.len() as u16).to_be_bytes());
    msg.extend_from_slice(query);
    stream.write_all(&msg).ok()?;
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).ok()?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return None;
    }
    let mut resp = vec![0u8; len];
    stream.read_exact(&mut resp).ok()?;
    // The reply came back through the tunnel; strip AAAA here too so the
    // application never sees an IPv6 answer it cannot use.
    strip_aaaa(&mut resp);
    Some(resp)
}

fn socks_port_of() -> u16 {
    crate::engine::exit_socks_port()
}

/// Push a SOCKS5 address (ATYP + ADDR + PORT) for an endpoint.
fn push_endpoint(buf: &mut Vec<u8>, ep: &IpEndpoint) {
    // IPv4 only: the TUN routes are v4-only, so every destination is v4.
    match ep.addr {
        IpAddress::Ipv4(a) => {
            buf.push(1);
            buf.extend_from_slice(&a.octets());
        }
    }
    buf.extend_from_slice(&ep.port.to_be_bytes());
}

/// Parse the SOCKS5 UDP reply header, returning (source, payload).
fn parse_socks_udp(data: &[u8]) -> Option<(IpEndpoint, &[u8])> {
    if data.len() < 10 {
        return None;
    }
    let atyp = data[3];
    let (addr, rest) = match atyp {
        1 => {
            if data.len() < 10 {
                return None;
            }
            let a = Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            (IpAddress::Ipv4(a), &data[8..])
        }
        // ATYP 4 (IPv6) cannot occur: the tunnel carries IPv4 only, so every
        // destination we ever asked about was v4.
        4 => return None,
        _ => return None,
    };
    if rest.len() < 2 {
        return None;
    }
    let port = u16::from_be_bytes([rest[0], rest[1]]);
    Some((IpEndpoint::new(addr, port), &rest[2..]))
}

/// Drive every UDP session: datagrams that arrived on the adapter go to the
/// relay thread, datagrams that came back from the tunnel go onto the
/// adapter with the original source endpoint. Idle sessions expire.
fn pump_udp(
    _iface: &mut Interface,
    sockets: &mut SocketSet,
    sessions: &mut HashMap<u16, UdpEntry>,
) {
    // smoltcp 0.12: UdpSocket::recv_slice/send_slice take no Context — the
    // socket carries its own send metadata (UdpMetadata) per datagram.
    let now = std::time::Instant::now();
    let mut expired: Vec<u16> = Vec::new();
    for (src_port, entry) in sessions.iter_mut() {
        let sock = sockets.get_mut::<UdpSocket>(entry.handle);

        // Application → tunnel.
        loop {
            let mut buf = [0u8; 65535];
            match sock.recv_slice(&mut buf) {
                Ok((n, meta)) => {
                    entry.last_seen = now;
                    let dst = meta.endpoint; // the remote the app was sending to
                    if entry
                        .to_relay
                        .send((buf[..n].to_vec(), dst))
                        .is_err()
                    {
                        // relay died (SOCKS5 UDP refused) — nothing to serve
                        sock.close();
                        break;
                    }
                }
                Err(smoltcp::socket::udp::RecvError::Exhausted) => break,
                Err(_) => break,
            }
        }

        // Tunnel → application.
        loop {
            match entry.from_relay.try_recv() {
                Ok((data, src)) => {
                    entry.last_seen = now;
                    // Sending "to" the original remote endpoint is what
                    // delivers the datagram to the application's socket: from
                    // the app's point of view the reply came from there.
                    let meta: UdpMetadata = src.into();
                    let _ = sock.send_slice(&data, meta);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    sock.close();
                    break;
                }
            }
        }

        if now.duration_since(entry.last_seen) > Duration::from_secs(90) {
            expired.push(*src_port);
        }
    }
    for port in expired {
        if let Some(entry) = sessions.remove(&port) {
            let sock = sockets.get_mut::<UdpSocket>(entry.handle);
            sock.close();
        }
        DiagnosticsLog::i(TAG, &format!("UDP session on source port {port} expired (idle 90 s)."));
    }
}

/// Non-blocking liveness probe of the UDP-ASSOCIATE control connection: the
/// engine drops it when the session ends, and the relay must follow.
fn control_alive(control: &TcpStream) -> bool {
    let mut b = [0u8; 1];
    let _ = control.set_read_timeout(Some(Duration::from_millis(1)));
    match control.peek(&mut b) {
        Ok(_) => true, // server actually sent something — still alive
        Err(ref e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            true
        }
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// SOCKS5 client (sync; one short-lived control socket per flow)
// ---------------------------------------------------------------------------

fn socks_greet(stream: &mut TcpStream) -> std::io::Result<()> {
    stream.write_all(&[0x05, 0x01, 0x00])?; // VER, 1 method, NO AUTH
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply)?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "SOCKS5 server refused NO-AUTH",
        ));
    }
    Ok(())
}

fn socks_request(
    stream: &mut TcpStream,
    cmd: u8,
    ep: &IpEndpoint,
) -> std::io::Result<SocketAddr> {
    let mut req = vec![0x05, cmd, 0x00];
    push_endpoint(&mut req, ep);
    stream.write_all(&req)?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head)?;
    if head[1] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!("SOCKS5 request rejected (code {})", head[1]),
        ));
    }
    let addr = match head[3] {
        1 => {
            let mut o = [0u8; 4];
            stream.read_exact(&mut o)?;
            IpAddr::V4(Ipv4Addr::from(o))
        }
        4 => {
            let mut o = [0u8; 16];
            stream.read_exact(&mut o)?;
            IpAddr::V6(o.into())
        }
        3 => {
            // A domain in the reply is not expected from our engine; skip it.
            let mut l = [0u8; 1];
            stream.read_exact(&mut l)?;
            let mut d = vec![0u8; l[0] as usize];
            stream.read_exact(&mut d)?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "SOCKS5 reply carried a domain address",
            ));
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "SOCKS5 reply with unknown ATYP",
            ))
        }
    };
    let mut p = [0u8; 2];
    stream.read_exact(&mut p)?;
    Ok(SocketAddr::new(addr, u16::from_be_bytes(p)))
}

/// SOCKS5 CONNECT to `dst` through the engine exit; the returned stream is
/// the tunnel.
fn socks5_connect(socks_port: u16, dst: IpEndpoint) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port))?;
    stream.set_nodelay(true).ok();
    socks_greet(&mut stream)?;
    socks_request(&mut stream, 0x01, &dst)?;
    Ok(stream)
}

/// SOCKS5 UDP ASSOCIATE; returns the control connection and the relay
/// endpoint to send datagrams to.
fn socks5_udp_associate(socks_port: u16, _src_port: u16) -> std::io::Result<(TcpStream, SocketAddr)> {
    let mut stream = TcpStream::connect(("127.0.0.1", socks_port))?;
    stream.set_nodelay(true).ok();
    socks_greet(&mut stream)?;
    // BND.ADDR of 0.0.0.0:0 = "server, you choose"; the reply carries the
    // relay endpoint.
    let relay_ep = IpEndpoint::new(
        IpAddress::Ipv4(Ipv4Address::UNSPECIFIED),
        0,
    );
    let relay = socks_request(&mut stream, 0x03, &relay_ep)?;
    Ok((stream, relay))
}

// ---------------------------------------------------------------------------
// DNS AAAA stripping
// ---------------------------------------------------------------------------

/// Remove AAAA (type 28) records from a DNS response so applications resolve
/// to IPv4 and actually use the tunnel. Parser failures leave the packet
/// untouched (conservative).
fn strip_aaaa(data: &mut Vec<u8>) {
    if data.len() < 12 {
        return;
    }
    let qd = u16::from_be_bytes([data[4], data[5]]);
    let an = u16::from_be_bytes([data[6], data[7]]);
    if an == 0 {
        return;
    }
    let mut pos = 12usize;
    for _ in 0..qd {
        pos = match skip_name(data, pos) {
            Some(p) => p + 4, // QTYPE + QCLASS
            None => return,
        };
    }
    // Rewrite the answer section without AAAA records.
    let mut out: Vec<u8> = data[..pos].to_vec();
    let mut kept: u16 = 0;
    let mut p = pos;
    for _ in 0..an {
        let start = p;
        p = match skip_name(data, p) {
            Some(p) => p,
            None => return, // parse failed mid-record: keep the original
        };
        if p + 10 > data.len() {
            return;
        }
        let rtype = u16::from_be_bytes([data[p], data[p + 1]]);
        let rdlen = u16::from_be_bytes([data[p + 8], data[p + 9]]) as usize;
        let end = p + 10 + rdlen;
        if end > data.len() {
            return;
        }
        if rtype != 28 {
            out.extend_from_slice(&data[start..end]);
            kept += 1;
        }
        p = end;
    }
    out[6..8].copy_from_slice(&kept.to_be_bytes());
    *data = out;
}

/// Skip a (possibly compressed) DNS name starting at `pos`.
fn skip_name(data: &[u8], mut pos: usize) -> Option<usize> {
    for _ in 0..64 {
        let Some(&len) = data.get(pos) else {
            return None;
        };
        match len {
            0 => return Some(pos + 1),
            0xC0..=0xFF => return Some(pos + 2), // compression pointer
            _ => pos += 1 + len as usize,
        }
    }
    None
}
