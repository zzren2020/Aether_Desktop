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
use std::time::{Duration, Instant};

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
    /// The NRPT catch-all rule was put in place by this handle and must go
    /// when the data path goes.
    nrpt_installed: bool,
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
        if self.nrpt_installed {
            nrpt_remove();
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

    // >>> AETHER-APP-FIX route-verify
    // Log 12-3 (and 11-2 before it): a fully healthy tunnel — masque-in-masque
    // ready, watchdog passing, NRPT installed — yet ZERO packets reached the
    // relay for the whole session. One candidate shape is the catch-all
    // routes silently not in effect (route add racing adapter readiness, or
    // a teardown race with the previous connection). Verify they actually
    // exist and point at the TUN address; retry once, then say it loudly.
    if !verify_catchall_routes(&tun_gw) {
        DiagnosticsLog::w(
            TAG,
            "Catch-all routes missing right after install — retrying once.",
        );
        let _ = route_add_idempotent("0.0.0.0", "128.0.0.0", &tun_gw);
        let _ = route_add_idempotent("128.0.0.0", "128.0.0.0", &tun_gw);
        if verify_catchall_routes(&tun_gw) {
            DiagnosticsLog::i(TAG, "Catch-all routes verified after retry.");
        } else {
            DiagnosticsLog::w(
                TAG,
                "Catch-all routes STILL missing — traffic will bypass the tunnel entirely; send `route print 0.0.0.0` output.",
            );
        }
    } else {
        DiagnosticsLog::i(
            TAG,
            "Catch-all routes verified: 0.0.0.0/1 + 128.0.0.0/1 point at the TUN adapter.",
        );
    }
    // <<< AETHER-APP-FIX

    // DNS must ride the tunnel — name resolution is where the GFW bites
    // first. Windows resolves via ALL adapters' DNS servers in parallel and
    // uses the first answer ("Smart Multi-Homed Name Resolution"), so the
    // physical adapter's resolver — faster than the tunnel and, behind the
    // GFW, poisoned — would keep winning (log 10-1: not ONE DNS query
    // reached the relay; the TLS alerts to google IPs were the fingerprint
    // of poisoned answers). The NRPT catch-all policy forces EVERY name to
    // the tunnel resolver 1.1.1.1, which rides 0.0.0.0/1 into the adapter
    // and is answered by our DNS-over-TCP relay.
    let mut nrpt_installed = false;
    match nrpt_install() {
        Ok(true) => {
            nrpt_installed = true;
            DiagnosticsLog::i(
                TAG,
                "NRPT catch-all installed: every DNS name now resolves via 1.1.1.1 through the tunnel.",
            );
        }
        Ok(false) => {
            // A rule with our comment is already there (crashed previous
            // session): still ours to remove at shutdown.
            nrpt_installed = true;
            DiagnosticsLog::i(TAG, "NRPT catch-all already present — reusing it.");
        }
        Err(e) => DiagnosticsLog::w(
            TAG,
            &format!(
                "NRPT install failed: {e} — DNS will race the physical adapter's resolver and may come back poisoned."
            ),
        ),
    }
    // Poisoned answers cached before the connect would otherwise survive
    // until their (often long) TTL expires.
    flush_dns_cache();

    let stop = Arc::new(AtomicBool::new(false));
    let (pkt_tx, pkt_rx) = std::sync::mpsc::channel::<Vec<u8>>();

    // Wintun read thread: blocking receive, vector-copy, hand over.
    {
        let session = session.clone();
        let stop = stop.clone();
        std::thread::Builder::new()
            .name("tun-read".into())
            .spawn(move || {
                // >>> AETHER-APP-FIX zero-traffic-alarm
                // The read thread's health was invisible: if it ever died
                // early the relay looked "live" while the adapter delivered
                // nothing (the zero-traffic shape of logs 11-2/12-3). Count
                // what it hands over and report on exit.
                let mut seen: u64 = 0;
                // <<< AETHER-APP-FIX
                while !stop.load(Ordering::Relaxed) {
                    match session.try_receive() {
                        Ok(Some(packet)) => {
                            let bytes = packet.bytes().to_vec();
                            drop(packet);
                            // >>> AETHER-APP-FIX zero-traffic-alarm
                            seen += 1;
                            // <<< AETHER-APP-FIX
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
                // >>> AETHER-APP-FIX zero-traffic-alarm
                DiagnosticsLog::i(
                    TAG,
                    &format!(
                        "tun-read thread ended: {seen} packet(s) handed over, stop={}.",
                        stop.load(Ordering::Relaxed)
                    ),
                );
                // <<< AETHER-APP-FIX
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
        nrpt_installed,
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
// >>> AETHER-APP-FIX route-verify
// ---------------------------------------------------------------------------

/// True iff both halves of the catch-all route exist AND point at the TUN
/// address. Get-NetRoute prints the NextHop of every matching route; we need
/// at least two rows equal to the TUN address.
fn verify_catchall_routes(tun_gw: &str) -> bool {
    let script = "Get-NetRoute -DestinationPrefix '0.0.0.0/1','128.0.0.0/1' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NextHop";
    match run_powershell(script) {
        Ok(out) => out.lines().filter(|l| l.trim() == tun_gw).count() >= 2,
        Err(_) => false,
    }
}
// <<< AETHER-APP-FIX

// ---------------------------------------------------------------------------
// DNS policy (NRPT) and resolver hygiene
// ---------------------------------------------------------------------------

/// Comment tagging every NRPT rule this module created, so shutdown removes
/// only ours even if the user has rules from other VPN software.
const NRPT_COMMENT: &str = "AetherTunDns";

fn run_powershell(script: &str) -> Result<String> {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .context("powershell failed to execute")?;
    if !out.status.success() {
        return Err(anyhow!(
            "powershell exit {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Idempotent NRPT catch-all ("." = every name → the tunnel resolver).
/// Ok(true) = rule installed now; Ok(false) = a rule with our comment was
/// already present (crashed previous session — still ours to remove).
fn nrpt_install() -> Result<bool> {
    let script = format!(
        "$r = Get-DnsClientNrptRule | Where-Object Comment -eq '{comment}'; \
         if ($r) {{ Write-Output 'present' }} \
         else {{ Add-DnsClientNrptRule -Namespace '.' -NameServers '{dns}' -Comment '{comment}' -ErrorAction Stop | Out-Null; Write-Output 'installed' }}",
        comment = NRPT_COMMENT,
        dns = crate::tun::TUN_DNS_V4,
    );
    Ok(run_powershell(&script)?.contains("installed"))
}

fn nrpt_remove() {
    let script = format!(
        "Get-DnsClientNrptRule | Where-Object Comment -eq '{comment}' | Remove-DnsClientNrptRule -Force",
        comment = NRPT_COMMENT
    );
    if let Err(e) = run_powershell(&script) {
        DiagnosticsLog::w(
            TAG,
            &format!(
                "NRPT rule removal failed: {e} — remove the '{NRPT_COMMENT}' rule manually if it lingers."
            ),
        );
    }
}

/// Drop cached answers that were resolved through the physical adapter
/// before the connect — poisoned entries otherwise survive their TTL.
fn flush_dns_cache() {
    let _ = std::process::Command::new("ipconfig")
        .args(["/flushdns"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
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
    /// The application socket's own endpoint (its ephemeral source port).
    /// Flows are keyed on (src, dst), NOT dst alone: Chrome opens several
    /// parallel sockets to one origin, and a dst-only dedupe silently
    /// swallowed every socket after the first (log 9-1: 69 SYNs, many
    /// retried browser flows never got a listener).
    src: IpEndpoint,
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
    /// Data-plane observability (round 11): CONNECT OK, first-byte marks,
    /// byte counters, stall alarm and close summaries — the previous build
    /// could not distinguish "SOCKS5 accepted" from "SOCKS5 accepted and
    /// then went silent" (log 9-1/9-2: 68 bridges, zero data, zero errors).
    up: u64,
    down: u64,
    spawn: std::time::Instant,
    stall_warned: bool,
}

struct UdpEntry {
    /// The application's own endpoint (source of its datagrams). Replies are
    /// injected back TO this endpoint.
    src: IpEndpoint,
    /// Poll thread → relay thread: (payload, original destination).
    to_relay: Sender<(Vec<u8>, IpEndpoint)>,
    /// Relay thread → poll thread: (payload, source the reply claims).
    from_relay: Receiver<(Vec<u8>, IpEndpoint)>,
    last_seen: Instant,
}

fn poll_loop(
    pkt_rx: Receiver<Vec<u8>>,
    session: Arc<wintun::Session>,
    mtu: u16,
    socks_port: u16,
    stop: Arc<AtomicBool>,
) {
    let queue: SharedQueue = Arc::new(Mutex::new(VecDeque::new()));
    // Replies are written straight onto the adapter (raw UDP/IP injection);
    // keep a handle independent of the RelayDevice that smoltcp owns.
    let inject_session = session.clone();
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
    let start = Instant::now();
    // >>> AETHER-APP-FIX zero-traffic-alarm
    // Logs 11-2/12-3: the tunnel was fully healthy yet no packet EVER reached
    // the adapter, so "pages won't open" was indistinguishable from "the user
    // didn't browse". Count inbound packets and say it loudly when a connected
    // session stays at zero — with the exact evidence to capture next time.
    let mut adapter_pkts: u64 = 0;
    let mut last_zero_alarm: Option<Instant> = None;
    // <<< AETHER-APP-FIX
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

        // 2. Split the batch BEFORE smoltcp sees it:
        //    * TCP packets stay in the queue for smoltcp (with listeners
        //      seeded for new flows first — smoltcp drops a SYN that has no
        //      listening socket);
        //    * UDP datagrams are taken OUT and handled raw. smoltcp's UDP
        //      sockets match on the DESTINATION port (udp.rs accepts():
        //      `self.endpoint.port != repr.dst_port → reject`), so a socket
        //      bound to the application's source port can never receive the
        //      application's datagrams — every query that entered the tunnel
        //      was silently dropped (log 10-1: 69 UDP sessions opened, zero
        //      DNS queries relayed, zero DNS-over-TCP logs). Raw handling is
        //      what tun2socks does; smoltcp sockets are TCP-only here now.
        let incoming: Vec<Vec<u8>> = {
            let mut q = match queue.lock() {
                Ok(q) => q,
                Err(_) => break,
            };
            // The queue is a VecDeque; flatten this tick's batch to a Vec so
            // the UDP/TCP partition below can consume it.
            std::mem::take(&mut *q).into()
        };
        // >>> AETHER-APP-FIX zero-traffic-alarm
        adapter_pkts += incoming.len() as u64;
        if adapter_pkts == 0 && start.elapsed() > Duration::from_secs(60) {
            let fire = match last_zero_alarm {
                None => true,
                Some(t) => t.elapsed() > Duration::from_secs(120),
            };
            if fire {
                last_zero_alarm = Some(Instant::now());
                DiagnosticsLog::w(
                    TAG,
                    &format!(
                        "TUN relay: 0 packets received from the adapter in {:.0}s while connected — nothing can traverse the tunnel. If you tried to browse: run `route print 0.0.0.0` and `Get-DnsClientNrptRule` in PowerShell and send the output; also check the browser's proxy settings (a stale 127.0.0.1 proxy would bypass the TUN entirely).",
                        start.elapsed().as_secs_f32()
                    ),
                );
            }
        }
        // <<< AETHER-APP-FIX
        for pkt in &incoming {
            sniff_and_seed(pkt, &mut sockets, &mut tcp_sessions);
        }
        for pkt in incoming {
            if parse_udp_datagram(&pkt).is_some() {
                sniff_udp_datagram(&pkt, &mut udp_sessions);
            } else {
                // Non-UDP (TCP payload, ICMP, …) — smoltcp's business.
                let mut q = match queue.lock() {
                    Ok(q) => q,
                    Err(_) => break,
                };
                q.push_back(pkt);
            }
        }

        // 3. Let smoltcp drain the queue and drive every socket.
        let now = SmolInstant::from_millis(start.elapsed().as_millis() as i64);
        let _ = iface.poll(now, &mut device, &mut sockets);

        // 4. Pump the TCP bridges.
        pump_tcp(&mut iface, &mut sockets, &mut tcp_sessions, socks_port);

        // 5. Pump the UDP relays (reply injection straight to the adapter).
        pump_udp(&inject_session, mtu as usize, &mut udp_sessions);

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

/// Inspect a raw IP packet and, for a TCP flow we have not seen yet, create
/// the socket that will make smoltcp accept it:
/// a TCP SYN (not SYN+ACK) gets a listen socket bound to the ORIGINAL
/// DESTINATION — any_ip makes smoltcp accept packets addressed to foreign
/// hosts, and the listen endpoint selects which socket owns the flow.
/// UDP is NOT handled here: smoltcp's UDP sockets match on the destination
/// port and could never deliver the application's datagrams (see the
/// poll-loop comment); `sniff_udp_datagram` handles UDP raw.
fn sniff_and_seed(
    pkt: &[u8],
    sockets: &mut SocketSet,
    tcp_sessions: &mut Vec<TcpEntry>,
) {
    let Some(ipv4) = Ipv4Packet::new_checked(pkt).ok() else {
        return; // IPv6 is not captured (routes are v4-only); fragments and non-IP are ignored.
    };
    // smoltcp 0.12: the IPv4 protocol field getter is `next_header()`.
    if ipv4.next_header() != smoltcp::wire::IpProtocol::Tcp {
        return;
    }
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
    let src = IpEndpoint::new(
        IpAddress::Ipv4(ipv4.src_addr()),
        tcp.src_port(),
    );
    // Key on (src, dst): browsers open several parallel sockets to
    // the same origin, and every one of them needs its own listener.
    // smoltcp handles this correctly — listeners match on the local
    // endpoint, established sockets on the remote endpoint — but the
    // previous dst-only dedupe starved every flow after the first.
    if tcp_sessions
        .iter()
        .any(|t| t.src == src && t.dst == dst)
    {
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
        src,
        dst,
        app_to_socks: None,
        socks_to_app: never_recv(),
        pending: VecDeque::new(),
        socks_eof: false,
        bridged: false,
        up: 0,
        down: 0,
        spawn: std::time::Instant::now(),
        stall_warned: false,
    });
}

fn never_recv() -> Receiver<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
    // Keep the sender alive for the session's lifetime; an empty channel is
    // exactly "nothing came back from the tunnel yet".
    std::mem::forget(tx);
    rx
}

/// Parse a raw IPv4 UDP datagram: (source endpoint, destination endpoint,
/// payload). Used instead of smoltcp UDP sockets — see the poll-loop comment.
fn parse_udp_datagram(pkt: &[u8]) -> Option<(IpEndpoint, IpEndpoint, &[u8])> {
    let ipv4 = Ipv4Packet::new_checked(pkt).ok()?;
    if ipv4.next_header() != smoltcp::wire::IpProtocol::Udp {
        return None;
    }
    let udp = ipv4.payload();
    if udp.len() < 8 {
        return None;
    }
    let sport = u16::from_be_bytes([udp[0], udp[1]]);
    let dport = u16::from_be_bytes([udp[2], udp[3]]);
    let ulen = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    // NBNS (137), mDNS (5353), SSDP and friends are broadcast/multicast by
    // nature — they must never leave the machine (log 6-3).
    let dst_addr = ipv4.dst_addr();
    if dst_addr.is_broadcast()
        || dst_addr.is_multicast()
        || dst_addr.is_unspecified()
        // >>> AETHER-APP-FIX directed-broadcast-filter
        // Subnet-directed broadcast (172.19.0.255 — seen as a NetBIOS session
        // in log 11-2): the last octet 255 is never a real unicast host.
        || dst_addr.octets()[3] == 255
    // <<< AETHER-APP-FIX
    {
        return None;
    }
    if sport == 0 || dport == 0 {
        return None;
    }
    // Honour the UDP length field; fall back to the IP payload length if the
    // datagram was padded.
    let data_len = ulen.saturating_sub(8).min(udp.len() - 8);
    Some((
        IpEndpoint::new(IpAddress::Ipv4(ipv4.src_addr()), sport),
        IpEndpoint::new(IpAddress::Ipv4(dst_addr), dport),
        &udp[8..8 + data_len],
    ))
}

/// Route one raw application datagram into its UDP relay session. The poll
/// loop calls this for every unicast UDP packet the adapter produced.
fn sniff_udp_datagram(pkt: &[u8], sessions: &mut HashMap<u16, UdpEntry>) {
    let Some((src, dst, payload)) = parse_udp_datagram(pkt) else {
        return;
    };
    let entry = sessions.entry(src.port).or_insert_with(|| {
        let (to_relay_tx, to_relay_rx) = std::sync::mpsc::channel::<(Vec<u8>, IpEndpoint)>();
        let (from_relay_tx, from_relay_rx) = std::sync::mpsc::channel::<(Vec<u8>, IpEndpoint)>();
        spawn_udp_relay(src.port, to_relay_rx, from_relay_tx);
        DiagnosticsLog::i(
            TAG,
            &format!("UDP session opened: {src} → {dst}"),
        );
        UdpEntry {
            src,
            to_relay: to_relay_tx,
            from_relay: from_relay_rx,
            last_seen: Instant::now(),
        }
    });
    entry.last_seen = Instant::now();
    // The relay uses the PER-DATAGRAM destination, so one session can serve
    // several destinations; each reply is injected with the matching source.
    let _ = entry.to_relay.send((payload.to_vec(), dst));
}

/// Build a raw IPv4+UDP packet (`from` ⇐ payload, delivered to `to`) and
/// write it onto the adapter. This is how tunnel replies reach the
/// application: the datagram must look like it came from the endpoint the
/// application originally sent to (e.g. the resolver 1.1.1.1:53).
fn inject_udp_packet(
    session: &Arc<wintun::Session>,
    mtu: usize,
    from: &IpEndpoint,
    to: &IpEndpoint,
    payload: &[u8],
) {
    let (IpEndpoint { addr: from_addr, port: from_port }, IpEndpoint { addr: to_addr, port: to_port }) =
        (from.clone(), to.clone());
    // Single-variant match: the build enables proto-ipv4 only, so
    // smoltcp's IpAddress has no Ipv6 variant to worry about (same shape
    // as push_endpoint below).
    let (from_addr, to_addr) = match (from_addr, to_addr) {
        (IpAddress::Ipv4(a), IpAddress::Ipv4(b)) => (a, b),
    };
    let total = 20 + 8 + payload.len();
    if total > mtu {
        return; // cannot fit the adapter MTU; DNS replies always fit
    }
    let mut pkt = vec![0u8; total];
    // IPv4 header (no options).
    pkt[0] = 0x45; // version 4, IHL 5
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes()); // total length
    pkt[6..8].copy_from_slice(&0u16.to_be_bytes()); // no flags, no offset
    pkt[8] = 64; // TTL
    pkt[9] = 17; // protocol: UDP
    pkt[12..16].copy_from_slice(&from_addr.octets());
    pkt[16..20].copy_from_slice(&to_addr.octets());
    // Checksum over the header with its own field still zero — computed
    // into a local first: the slice writes below would otherwise borrow
    // `pkt` mutably and immutably at once.
    let header_checksum = internet_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&header_checksum.to_be_bytes());
    // UDP header. The checksum is optional under IPv4 (RFC 768) and zero is
    // universally accepted; computing it would need the pseudo-header only.
    let udp_len = (8 + payload.len()) as u16;
    pkt[20..22].copy_from_slice(&from_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&to_port.to_be_bytes());
    pkt[24..26].copy_from_slice(&udp_len.to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    if let Ok(mut p) = session.allocate_send_packet(total as u16) {
        p.bytes_mut().copy_from_slice(&pkt);
        session.send_packet(p);
    }
}

/// RFC 1071 internet checksum over a header with the checksum field zeroed.
fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in data.chunks(2) {
        let word = match pair.len() {
            2 => u16::from_be_bytes([pair[0], pair[1]]) as u32,
            _ => (pair[0] as u32) << 8, // odd byte, padded with zero
        };
        sum += word;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
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
            if n > 0 && entry.down == 0 {
                // Evidence chain, level 4a: the first byte ever returned by
                // the tunnel for this flow.
                DiagnosticsLog::i(
                    TAG,
                    &format!("TCP data ↓ {dst}: tunnel→app is flowing", dst = entry.dst),
                );
            }
            entry.down += n as u64;
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
            if entry.up == 0 {
                // Evidence chain, level 4b: the first byte the application
                // ever sent into the tunnel for this flow (TLS ClientHello
                // or HTTP request — without this, "did the payload even
                // leave the browser?" was unanswerable).
                DiagnosticsLog::i(
                    TAG,
                    &format!(
                        "TCP data ↑ {dst}: app→tunnel is flowing ({n} B first read)",
                        dst = entry.dst
                    ),
                );
            }
            entry.up += n as u64;
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

        // Stall alarm, level 5: a flow that CONNECTed but carried no return
        // data for 10 s. Distinguishes "browser never sent payload" (our
        // pump is broken) from "payload went in, nothing ever came back"
        // (the SOCKS5 accepted and went silent — log 9-1/9-2's shape).
        if entry.bridged
            && !entry.stall_warned
            && entry.spawn.elapsed() > Duration::from_secs(10)
            && entry.down == 0
            && sock.is_open()
        {
            entry.stall_warned = true;
            if entry.up == 0 {
                DiagnosticsLog::w(
                    TAG,
                    &format!(
                        "TCP bridge to {dst}: 10 s old, ZERO data both ways — CONNECT never completed or the SOCKS5 went silent before any payload",
                        dst = entry.dst
                    ),
                );
            } else {
                DiagnosticsLog::w(
                    TAG,
                    &format!(
                        "TCP bridge to {dst}: sent {up} B into the tunnel, ZERO bytes ever came back — the exit accepted CONNECT but swallowed the payload",
                        dst = entry.dst,
                        up = entry.up
                    ),
                );
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
        let state = sock.state();
        if entry.app_to_socks.is_none() && state == TcpState::Closed {
            // Close summary: the byte counters make every future round
            // diagnosis a table lookup instead of a guessing game.
            DiagnosticsLog::i(
                TAG,
                &format!(
                    "TCP bridge to {dst} closed after {secs:.1}s: ↑{up} B ↓{down} B, final state {state:?}",
                    dst = entry.dst,
                    secs = entry.spawn.elapsed().as_secs_f32(),
                    up = entry.up,
                    down = entry.down,
                ),
            );
            return false; // both sides done
        }
        let dead = entry.bridged && state == TcpState::Closed;
        if dead {
            DiagnosticsLog::i(
                TAG,
                &format!(
                    "TCP bridge to {dst} closed after {secs:.1}s: ↑{up} B ↓{down} B, final state {state:?}",
                    dst = entry.dst,
                    secs = entry.spawn.elapsed().as_secs_f32(),
                    up = entry.up,
                    down = entry.down,
                ),
            );
        }
        !(dead)
    });
}

fn spawn_tcp_bridge(
    dst: IpEndpoint,
    socks_port: u16,
    to_socks: Receiver<Vec<u8>>,
    from_socks: Sender<Vec<u8>>,
) {
    // ONE SOCKS5 CONNECT per flow. A TCP relay is a single bidirectional
    // connection; the previous code dialled twice (a reader thread and a
    // writer thread, each with its own CONNECT) and silently split every
    // browser flow into two unidirectional tunnels: the server's answers
    // arrived on the writer's connection, which nobody read, while the
    // reader's connection sat ClientHello-less until the exit killed it.
    // Symptom (log 8-1/8-2): 120+ "bridged via SOCKS5" handshakes, zero
    // pages loaded, psiphon "Relay failed … forcibly closed" churn.
    std::thread::Builder::new()
        .name("tun-tcp-io".into())
        .spawn(move || {
            let stream = match socks5_connect(socks_port, dst) {
                Ok(s) => s,
                Err(e) => {
                    // Evidence chain, level 3: the local smoltcp handshake
                    // succeeded but the engine-side CONNECT did not. Without
                    // this line a failed CONNECT was indistinguishable from a
                    // successful bridge ("bridged via SOCKS5" fired at spawn).
                    DiagnosticsLog::w(
                        TAG,
                        &format!("TCP bridge to {dst} failed: SOCKS5 CONNECT error: {e}"),
                    );
                    let _ = to_socks; // unblocks the poll loop's drain
                    return;
                }
            };
            // Evidence chain, level 3b: the exit answered 0x00. From here on
            // a silent flow means the DATA plane, not the dial, is broken.
            DiagnosticsLog::i(
                TAG,
                &format!("TCP bridge to {dst}: CONNECT OK via SOCKS5 :{socks_port}"),
            );
            let mut write_half = match stream.try_clone() {
                Ok(h) => h,
                Err(e) => {
                    DiagnosticsLog::w(
                        TAG,
                        &format!("TCP bridge to {dst}: socket clone failed: {e}"),
                    );
                    let _ = to_socks;
                    return;
                }
            };
            // Reader half of the SAME connection: tunnel → application.
            let reader = std::thread::Builder::new()
                .name("tun-tcp-r".into())
                .spawn(move || {
                    let mut stream = stream;
                    let mut buf = [0u8; 16384];
                    let mut total = 0u64;
                    let outcome = loop {
                        match stream.read(&mut buf) {
                            Ok(0) => break format!("EOF after {total} B"),
                            Ok(n) => {
                                total += n as u64;
                                if from_socks.send(buf[..n].to_vec()).is_err() {
                                    break format!("app side went away after {total} B");
                                }
                            }
                            Err(e) => break format!("read error after {total} B: {e}"),
                        }
                    };
                    DiagnosticsLog::i(
                        TAG,
                        &format!("TCP bridge to {dst}: tunnel→app reader ended — {outcome}"),
                    );
                    // Dropping `from_socks` tells the poll loop this half is
                    // over (EOF → FIN towards the application).
                });
            // Writer half of the SAME connection: application → tunnel.
            let mut written = 0u64;
            let mut writer_outcome = "app closed the flow".to_string();
            for chunk in to_socks {
                match write_half.write_all(&chunk) {
                    Ok(()) => written += chunk.len() as u64,
                    Err(e) => {
                        writer_outcome =
                            format!("write error after {written} B: {e}");
                        break;
                    }
                }
            }
            DiagnosticsLog::i(
                TAG,
                &format!(
                    "TCP bridge to {dst}: app→tunnel writer ended — {writer_outcome} (wrote {written} B)"
                ),
            );
            // Application half-closed: dropping the write half sends a FIN
            // toward the destination while the reader keeps draining.
            drop(write_half);
            if let Ok(handle) = reader {
                let _ = handle.join();
            }
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
///
/// >>> AETHER-APP-FIX dns-cache-retry
/// Log 11-3 showed 8 distinct names failing within the same 5 ms window — a
/// query storm outrunning the one-CONNECT-per-query resolver path — and log
/// 11-1's single i.ytimg.com failure came seconds after the same name had
/// resolved fine. Two defenses: a small TTL cache collapses repeats (a page
/// load asks for the same name over and over), and one retry absorbs
/// transient CONNECT/read timeouts under load.
const DNS_CACHE_TTL: Duration = Duration::from_secs(120);

fn dns_cache() -> &'static Mutex<HashMap<Vec<u8>, (Vec<u8>, Instant)>> {
    static CACHE: std::sync::OnceLock<Mutex<HashMap<Vec<u8>, (Vec<u8>, Instant)>>> =
        std::sync::OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Cache key = the question section (offset 12..): identical for every
/// retransmit of the same name/type, unlike the per-query transaction ID in
/// bytes 0-1 which changes every time.
fn dns_cache_get(query: &[u8]) -> Option<Vec<u8>> {
    let cache = dns_cache().lock().ok()?;
    let (resp, at) = cache.get(&query[12..].to_vec())?;
    if at.elapsed() > DNS_CACHE_TTL {
        return None;
    }
    // Rewrite the transaction ID so the reply matches THIS query — the OS
    // resolver silently drops responses whose ID differs from the outstanding
    // one, and a cached reply carries the ID of the query that filled it.
    let mut hit = resp.clone();
    hit[0] = query[0];
    hit[1] = query[1];
    Some(hit)
}

fn dns_cache_put(query: &[u8], resp: &[u8]) {
    let mut cache = dns_cache().lock().unwrap_or_else(|e| e.into_inner());
    if cache.len() > 1024 {
        cache.clear();
    }
    cache.insert(query[12..].to_vec(), (resp.to_vec(), Instant::now()));
}
// <<< AETHER-APP-FIX

fn dns_over_tcp(query: &[u8], dst: &IpEndpoint) -> Option<Vec<u8>> {
    if query.len() < 12 || query.len() > 4096 {
        return None;
    }
    let name = dns_qname(query);
    // >>> AETHER-APP-FIX dns-cache-retry
    if let Some(hit) = dns_cache_get(query) {
        DiagnosticsLog::i(
            TAG,
            &format!("DNS cache hit: {name} ({} B)", hit.len()),
        );
        return Some(hit);
    }
    // One retry: the failures in logs 11-1/11-3 are transient timeouts under
    // a query storm, not resolver policy — a second CONNECT succeeds.
    let result = dns_over_tcp_inner(query, dst).or_else(|| dns_over_tcp_inner(query, dst));
    // <<< AETHER-APP-FIX
    match &result {
        Some(resp) => {
            // ANCOUNT lives at bytes 6-8 of the message; strip_aaaa may have
            // rewritten the section, so report the ORIGINAL answer count.
            let ancount = u16::from_be_bytes([resp[6], resp[7]]);
            // >>> AETHER-APP-FIX dns-cache-retry
            dns_cache_put(query, resp);
            // <<< AETHER-APP-FIX
            DiagnosticsLog::i(
                TAG,
                &format!(
                    "DNS over TCP: {name} → {ancount} answer(s), {size} B",
                    size = resp.len()
                ),
            );
        }
        None => DiagnosticsLog::w(
            TAG,
            &format!("DNS over TCP: {name} FAILED — the resolver CONNECT or reply timed out; the application will stall on this name"),
        ),
    }
    result
}

/// The query's question name (labels at offset 12, no compression in the
/// question section); used only for log readability.
fn dns_qname(query: &[u8]) -> String {
    let mut pos = 12usize;
    let mut labels: Vec<&[u8]> = Vec::new();
    while pos < query.len() {
        let l = query[pos] as usize;
        if l == 0 {
            break;
        }
        if pos + 1 + l > query.len() || labels.len() > 8 {
            return "<malformed>".into();
        }
        labels.push(&query[pos + 1..pos + 1 + l]);
        pos += 1 + l;
    }
    let mut out = String::new();
    for lab in labels {
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(lab));
    }
    if out.is_empty() {
        "<empty>".into()
    } else {
        out
    }
}

fn dns_over_tcp_inner(query: &[u8], dst: &IpEndpoint) -> Option<Vec<u8>> {
    let mut stream = socks5_connect(socks_port_of(), *dst).ok()?;
    // >>> AETHER-APP-FIX dns-cache-retry: 4s → 6s — log 11-3's failure burst
    // hit queries racing ~10 concurrent CONNECTs; a wider window rides out
    // the storm (the caller retries once on top of this).
    stream.set_read_timeout(Some(Duration::from_secs(6))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(6))).ok();
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
    if resp.len() < 12 {
        return None;
    }
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

/// Drive every UDP session's RETURN path: the application's datagrams were
/// already handed to the relay threads at sniff time (`sniff_udp_datagram`),
/// so all that is left here is injecting tunnel replies onto the adapter and
/// expiring idle sessions. Idle sessions expire.
fn pump_udp(
    session: &Arc<wintun::Session>,
    mtu: usize,
    sessions: &mut HashMap<u16, UdpEntry>,
) {
    let now = Instant::now();
    let mut expired: Vec<u16> = Vec::new();
    for (src_port, entry) in sessions.iter_mut() {
        // Tunnel → application: inject the reply as a raw UDP/IP datagram
        // spoofing the endpoint the application originally talked to.
        loop {
            match entry.from_relay.try_recv() {
                Ok((data, from)) => {
                    entry.last_seen = now;
                    inject_udp_packet(session, mtu, &from, &entry.src, &data);
                }
                Err(TryRecvError::Empty) => break,
                // The relay thread is gone with the session teardown; the
                // entry itself is reaped by the idle expiry below.
                Err(TryRecvError::Disconnected) => break,
            }
        }

        if now.duration_since(entry.last_seen) > Duration::from_secs(90) {
            expired.push(*src_port);
        }
    }
    for port in expired {
        sessions.remove(&port);
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

/// >>> AETHER-APP-FIX socks-refused-retry
/// Connect to the engine's SOCKS5 listener, retrying while it refuses the
/// dial. Log 12-2: while the engine re-establishes its inner tunnel (warp×2,
/// ~12 s in the log), the listener on 1819 goes away and every bridge and
/// DNS query in that window died with os error 10061 ("connection refused")
/// — the browser's own retries are what the user feels as "pages take a
/// while to open". Each flow already runs in a dedicated thread with the
/// client's socket buffered in smoltcp, so holding the dial through the gap
/// costs nothing and converts the blackhole into a wait.
const SOCKS_REFUSED_RETRY_WINDOW: Duration = Duration::from_secs(20);
const SOCKS_REFUSED_RETRY_STEP: Duration = Duration::from_millis(500);

fn tcp_connect_socks(socks_port: u16) -> std::io::Result<TcpStream> {
    let begin = Instant::now();
    loop {
        match TcpStream::connect(("127.0.0.1", socks_port)) {
            Ok(s) => {
                let waited = begin.elapsed();
                if waited > Duration::from_millis(100) {
                    DiagnosticsLog::w(
                        TAG,
                        &format!(
                            "SOCKS5 port {socks_port} refused for {:.1}s, then accepted — the engine was re-establishing its tunnels; the flow was held instead of dropped.",
                            waited.as_secs_f32()
                        ),
                    );
                }
                return Ok(s);
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                if begin.elapsed() >= SOCKS_REFUSED_RETRY_WINDOW {
                    return Err(e);
                }
                std::thread::sleep(SOCKS_REFUSED_RETRY_STEP);
            }
            Err(e) => return Err(e),
        }
    }
}
// <<< AETHER-APP-FIX

/// SOCKS5 CONNECT to `dst` through the engine exit; the returned stream is
/// the tunnel.
fn socks5_connect(socks_port: u16, dst: IpEndpoint) -> std::io::Result<TcpStream> {
    // >>> AETHER-APP-FIX socks-refused-retry
    let mut stream = tcp_connect_socks(socks_port)?;
    // <<< AETHER-APP-FIX
    stream.set_nodelay(true).ok();
    // Greeting and CONNECT must not hang forever: a SOCKS5 that accepts the
    // TCP dial but never answers the handshake used to stall the whole
    // bridge invisibly — "bridged" fired, zero data, zero errors, forever
    // (the suspected shape behind log 9-1/9-2).
    stream.set_read_timeout(Some(Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(30))).ok();
    socks_greet(&mut stream)?;
    socks_request(&mut stream, 0x01, &dst)?;
    // Payload phase: clear the timeouts BEFORE the reader half is cloned —
    // socket timeouts are shared between the two halves, and an idle TLS
    // session must not be killed by the greeting window's 10 s read guard.
    stream.set_read_timeout(None).ok();
    stream.set_write_timeout(None).ok();
    Ok(stream)
}

/// SOCKS5 UDP ASSOCIATE; returns the control connection and the relay
/// endpoint to send datagrams to.
fn socks5_udp_associate(socks_port: u16, _src_port: u16) -> std::io::Result<(TcpStream, SocketAddr)> {
    // >>> AETHER-APP-FIX socks-refused-retry
    let mut stream = tcp_connect_socks(socks_port)?;
    // <<< AETHER-APP-FIX
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
