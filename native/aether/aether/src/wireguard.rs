use parking_lot::Mutex as StdMutex;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

use crate::aethernoize::{self, AetherNoizeConfig};
use crate::error::{AetherError, Result};
use rand::RngExt;

const TIMER_TICK: Duration = Duration::from_millis(250);
const MAX_PACKET: usize = 65536;

/// How many outbound IP packets are encapsulated under ONE acquisition of the
/// boringtun session lock.
///
/// ## 1.2.3-p1: the lock hand-off was the packets-per-second ceiling
///
/// The writer loop was, per packet:
///
/// ```text
///     outbound_rx.recv().await  ->  tunn_w.lock().await  ->  send
/// ```
///
/// `tunn` is the ONE boringtun session, and the socket reader takes the very same
/// lock for every datagram it decapsulates. So there was one acquisition per
/// packet, in both directions, contending with each other - and because it is a
/// fair async mutex, each hand-off is a full task park and wake through the tokio
/// scheduler.
///
/// A download is not the asymmetric flow it looks like: roughly one ACK leaves
/// for every two segments that arrive, so a fast download is a symmetric packet
/// stream, and the two tasks then trade the lock on essentially every packet.
/// The download can therefore never go faster than the scheduler can round-trip,
/// no matter what the line or the tunnel can do. That is a throughput ceiling
/// with no error, no counter and no log line attached to it.
///
/// Encapsulating a whole burst under one acquisition makes hand-offs scale with
/// bursts (>= 64x fewer) instead of with packets. No packet is ever delayed to
/// build a batch: the burst is whatever is ALREADY queued when the first packet
/// arrives.
const MAX_ENCAP_BATCH: usize = 64;

/// How often the writer reports what the uplink is actually doing.
///
/// The uplink queue is the one queue in the path that nothing in this process
/// could see before 1.2.3-p1, because it lived in the kernel's `SO_SNDBUF`. A
/// writer that never waits while the uplink is saturated means the OS ignored the
/// buffer request and the bound is not in effect.
const UPLINK_REPORT_INTERVAL: Duration = Duration::from_secs(15);

/// How long the socket reader will wait for room in the netstack's inbound queue
/// before it drops a datagram.
///
/// 1.2.3-p1. The reader used to `inbound_tx.send(..).await`, an unbounded wait. A
/// download fills that queue in milliseconds, so the only task draining the
/// WireGuard UDP socket parked - and while it was parked the kernel receive
/// buffer overflowed and discarded whatever arrived next. A datagram is worth
/// waiting a few milliseconds for; it is never worth going deaf for.
const INBOUND_HANDOFF_BUDGET: Duration = Duration::from_millis(20);
const VERIFY_RETRY_DELAYS: [Duration; 2] =
    [Duration::from_millis(750), Duration::from_millis(2_000)];

const WG_MSG_TYPE_MIN: u8 = 1;
const WG_MSG_TYPE_MAX: u8 = 4;

const MAX_TRANSIENT_RECV_ERRORS: u32 = 64;
const TRANSIENT_RECV_BACKOFF: Duration = Duration::from_millis(50);

pub fn is_transient_socket_error(error: &std::io::Error) -> bool {
    use std::io::ErrorKind;

    matches!(
        error.kind(),
        ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
            | ErrorKind::Interrupted
            | ErrorKind::WouldBlock
            | ErrorKind::TimedOut
    )
}

struct TaskGuard(Vec<tokio::task::AbortHandle>);

impl Drop for TaskGuard {
    fn drop(&mut self) {
        for handle in self.0.drain(..) {
            handle.abort();
        }
    }
}

/// Hands a decapsulated IP packet to the netstack without ever blocking the
/// socket reader indefinitely (see [`INBOUND_HANDOFF_BUDGET`]).
///
/// Returns `false` only when the netstack is gone for good, which is the one case
/// where the reader should stop.
async fn deliver_inbound(tx: &mpsc::Sender<Vec<u8>>, pkt: Vec<u8>) -> bool {
    match tx.try_send(pkt) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(pkt)) => {
            match tokio::time::timeout(INBOUND_HANDOFF_BUDGET, tx.send(pkt)).await {
                Ok(Ok(())) => true,
                // The netstack closed: nothing left to read for.
                Ok(Err(_)) => false,
                // Congested. Dropping here is deliberate and is exactly the loss
                // signal TCP congestion control is built to read; going deaf on
                // the socket is not.
                Err(_) => true,
            }
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

fn inject_client_id(pkt: &mut [u8], client_id: &[u8; 3]) {
    if pkt.len() < 4 {
        return;
    }
    if pkt[0] < WG_MSG_TYPE_MIN || pkt[0] > WG_MSG_TYPE_MAX {
        return;
    }
    pkt[1..4].copy_from_slice(client_id);
}

fn strip_client_id(pkt: &mut [u8]) {
    if pkt.len() < 4 {
        return;
    }
    if pkt[0] < WG_MSG_TYPE_MIN || pkt[0] > WG_MSG_TYPE_MAX {
        return;
    }
    pkt[1..4].copy_from_slice(&[0u8; 3]);
}

#[derive(Clone)]
pub struct WgConfig {
    pub local_private_key: [u8; 32],
    pub peer_public_key: [u8; 32],
    pub peer_endpoint: SocketAddr,
    pub local_ipv4: Ipv4Addr,
    pub local_ipv6: Ipv6Addr,
    pub client_id: [u8; 3],
    pub preshared_key: Option<[u8; 32]>,
    pub persistent_keepalive: Option<u16>,
    pub aethernoize: Arc<AetherNoizeConfig>,
}

pub struct WgTunnel {
    tunn: Arc<Mutex<Box<Tunn>>>,
    sock: Arc<UdpSocket>,
    detour: crate::upstream::DetourGuard,
    peer: SocketAddr,
    inbound_tx: mpsc::Sender<Vec<u8>>,
    pub obf_sent: Arc<Mutex<bool>>,
    pub aethernoize: Arc<AetherNoizeConfig>,
    pub client_id: [u8; 3],
    pub local_ipv4: Ipv4Addr,
    /// >>> AETHER-APP-FIX the-carrier-hop-is-not-the-data-path
    /// How long this tunnel may go without a decodable packet from its peer
    /// before the health watchdog calls it dead.
    ///
    /// This used to be a single process-wide value read from the environment,
    /// which is wrong for a nested pipeline: the *outer* hop of WARP-in-WARP or
    /// MASQUE-in-MASQUE is a carrier. It exists to move the inner hop's packets
    /// and nothing else, so while the inner tunnel is idle the outer is
    /// legitimately silent - and silence is not death. See
    /// [`carrier_stale_timeout`].
    stale_timeout: Duration,
}

pub struct EstablishedSession {
    tunn: Arc<Mutex<Box<Tunn>>>,
    sock: Arc<UdpSocket>,
    detour: crate::upstream::DetourGuard,
    peer: SocketAddr,
    client_id: [u8; 3],
}

impl WgTunnel {
    pub async fn new(cfg: WgConfig, inbound_tx: mpsc::Sender<Vec<u8>>) -> Result<Self> {
        let (sock, _, detour) = crate::upstream::bind_via_upstream(cfg.peer_endpoint).await?;

        let local_secret = StaticSecret::from(cfg.local_private_key);
        let peer_public = PublicKey::from(cfg.peer_public_key);
        let preshared = cfg.preshared_key;

        let tunn = Tunn::new(
            local_secret,
            peer_public,
            preshared,
            cfg.persistent_keepalive,
            0,
            None,
        );

        Ok(Self {
            tunn: Arc::new(Mutex::new(Box::new(tunn))),
            sock: Arc::new(sock),
            detour,
            peer: cfg.peer_endpoint,
            inbound_tx,
            obf_sent: Arc::new(Mutex::new(false)),
            aethernoize: cfg.aethernoize.clone(),
            client_id: cfg.client_id,
            local_ipv4: cfg.local_ipv4,
            // >>> AETHER-APP-FIX the-carrier-hop-is-not-the-data-path
            // This constructor has no callers today; the live tunnels are built
            // from an established session. It keeps the data-path budget so that
            // it can never become a way to bypass the carrier rule by accident.
            stale_timeout: wg_stale_timeout(),
            // <<< AETHER-APP-FIX the-carrier-hop-is-not-the-data-path
        })
    }

    pub fn from_established(
        session: EstablishedSession,
        aethernoize: Arc<AetherNoizeConfig>,
        inbound_tx: mpsc::Sender<Vec<u8>>,
        local_ipv4: Ipv4Addr,
    ) -> Self {
        Self::from_established_with_stale(
            session,
            aethernoize,
            inbound_tx,
            local_ipv4,
            wg_stale_timeout(),
        )
    }

    /// >>> AETHER-APP-FIX the-carrier-hop-is-not-the-data-path
    /// Same, but with an explicit silence budget. The outer hop of a nested
    /// pipeline passes [`carrier_stale_timeout`] here so that a carrier
    /// waiting on an idle inner tunnel is not mistaken for a dead one.
    pub fn from_established_with_stale(
        session: EstablishedSession,
        aethernoize: Arc<AetherNoizeConfig>,
        inbound_tx: mpsc::Sender<Vec<u8>>,
        local_ipv4: Ipv4Addr,
        stale_timeout: Duration,
    ) -> Self {
        Self {
            tunn: session.tunn,
            sock: session.sock,
            detour: session.detour,
            peer: session.peer,
            inbound_tx,
            obf_sent: Arc::new(Mutex::new(true)),
            aethernoize,
            client_id: session.client_id,
            local_ipv4,
            stale_timeout,
        }
    }
    // <<< AETHER-APP-FIX the-carrier-hop-is-not-the-data-path

    pub async fn run(self, mut outbound_rx: mpsc::Receiver<Vec<u8>>) -> Result<()> {
        let sock_r = self.sock.clone();
        let sock_w = self.sock.clone();
        let sock_t = self.sock.clone();
        let sock_h = self.sock.clone();
        let tunn_r = self.tunn.clone();
        let tunn_w = self.tunn.clone();
        let tunn_t = self.tunn.clone();
        let tunn_h = self.tunn.clone();
        let inbound_tx = self.inbound_tx.clone();
        let obf_sent = self.obf_sent.clone();
        let aethernoize = self.aethernoize.clone();
        let aethernoize_t = self.aethernoize.clone();
        let client_id = self.client_id;
        let client_id_h = self.client_id;
        let peer = self.peer;
        let local_ipv4 = self.local_ipv4;

        let last_valid_rx: Arc<StdMutex<Instant>> = Arc::new(StdMutex::new(Instant::now()));
        let last_valid_rx_r = last_valid_rx.clone();
        let last_valid_rx_h = last_valid_rx.clone();

        // >>> AETHER-APP-FIX the-carrier-hop-is-not-the-data-path
        // Silence is only evidence of death if we actually asked and got nothing
        // back. A tunnel that has just come up has not been asked anything yet,
        // so the health task counts the probes it really put on the wire and the
        // reader clears the count on every decodable packet. Death now needs
        // *both* a silent peer and [`WG_STALE_MIN_PROBES`] unanswered questions.
        let stale_timeout = self.stale_timeout;
        let probes_unanswered: Arc<StdMutex<u32>> = Arc::new(StdMutex::new(0));
        let probes_unanswered_r = probes_unanswered.clone();
        let probes_unanswered_h = probes_unanswered.clone();
        // <<< AETHER-APP-FIX the-carrier-hop-is-not-the-data-path

        let recv_task = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_PACKET];
            let mut tmp = vec![0u8; MAX_PACKET];
            let mut transient_errors = 0u32;
            // Reused across iterations so a busy tunnel does not allocate two
            // vectors per datagram.
            let mut to_network: Vec<Vec<u8>> = Vec::new();
            let mut to_tunnel: Vec<Vec<u8>> = Vec::new();
            loop {
                match sock_r.recv(&mut buf).await {
                    Ok(0) => {}
                    Ok(n) => {
                        transient_errors = 0;
                        strip_client_id(&mut buf[..n]);
                        to_network.clear();
                        to_tunnel.clear();
                        let mut progressed = false;

                        {
                            let mut tunn = tunn_r.lock().await;
                            // 1.2.3-p1: boringtun QUEUES packets internally - the
                            // ones that arrived while a handshake was in flight,
                            // and the handshake replies it owes the peer. One
                            // `decapsulate` call returns ONE of them. This used to
                            // take the first and throw the rest away, which is how
                            // a rekey under load could silently half-complete.
                            // Drain until it says Done.
                            let mut first = true;
                            loop {
                                let outcome = if first {
                                    tunn.decapsulate(None, &buf[..n], &mut tmp)
                                } else {
                                    tunn.decapsulate(None, &[], &mut tmp)
                                };
                                first = false;

                                match outcome {
                                    TunnResult::Done => {
                                        progressed = true;
                                        break;
                                    }
                                    TunnResult::Err(e) => {
                                        log::trace!("decapsulate error: {e:?}");
                                        break;
                                    }
                                    TunnResult::WriteToNetwork(pkt) => {
                                        progressed = true;
                                        let mut pkt_vec = pkt.to_vec();
                                        inject_client_id(&mut pkt_vec, &client_id);
                                        to_network.push(pkt_vec);
                                    }
                                    TunnResult::WriteToTunnelV4(pkt, _)
                                    | TunnResult::WriteToTunnelV6(pkt, _) => {
                                        progressed = true;
                                        to_tunnel.push(pkt.to_vec());
                                        break;
                                    }
                                }
                            }
                        }

                        if progressed {
                            *last_valid_rx_r.lock() = Instant::now();
                            // >>> AETHER-APP-FIX the-carrier-hop-is-not-the-data-path
                            // The peer answered: the outstanding questions are moot.
                            *probes_unanswered_r.lock() = 0;
                            // <<< AETHER-APP-FIX the-carrier-hop-is-not-the-data-path
                        }

                        for pkt in to_network.drain(..) {
                            let _ = sock_r.send(&pkt).await;
                        }
                        let mut netstack_gone = false;
                        for pkt in to_tunnel.drain(..) {
                            if !deliver_inbound(&inbound_tx, pkt).await {
                                netstack_gone = true;
                                break;
                            }
                        }
                        if netstack_gone {
                            log::warn!("[wg] the netstack is gone; stopping the socket reader");
                            break;
                        }
                    }
                    Err(e) => {
                        if is_transient_socket_error(&e) {
                            transient_errors += 1;
                            if transient_errors > MAX_TRANSIENT_RECV_ERRORS {
                                log::error!(
                                    "recv error: {e}; giving up after {transient_errors} consecutive transient failures"
                                );
                                break;
                            }
                            log::debug!(
                                "transient recv error: {e}; keeping the tunnel and retrying"
                            );
                            tokio::time::sleep(TRANSIENT_RECV_BACKOFF).await;
                            continue;
                        }
                        log::error!("recv error: {e}");
                        break;
                    }
                }
            }
        });

        // ------------------------------------------------------------------
        // 1.2.3-p1 THROUGHPUT FIX. See [MAX_ENCAP_BATCH] for the full reasoning.
        //
        // Two things were on this hot path once per PACKET: the single boringtun
        // session lock (contended with the socket reader on every datagram, and a
        // fair async mutex, so every hand-off is a scheduler park and wake) and
        // `obf_sent.lock().await`, a second async mutex taken forever to re-read a
        // flag that can only ever change once.
        //
        // A download is a symmetric packet stream (one ACK per ~two segments), so
        // both tasks wanted the lock constantly and the download could not go
        // faster than the scheduler could round-trip. Bursts are encapsulated
        // under one acquisition now, and the one-shot flag has left the hot path.
        // ------------------------------------------------------------------
        let send_task = tokio::spawn(async move {
            let mut out_buf = vec![0u8; MAX_PACKET];
            let mut post_hs_junk_sent = false;
            let mut batch: Vec<Vec<u8>> = Vec::with_capacity(MAX_ENCAP_BATCH);
            let mut wire: Vec<Vec<u8>> = Vec::with_capacity(MAX_ENCAP_BATCH);
            let mut obfuscation_settled = false;
            // Per-tunnel, not global: in WARP*2 mode there are two of these tasks
            // and their uplinks are nested, so one shared counter would be
            // unreadable. The peer address in the log line tells them apart.
            let mut up_pkts: u64 = 0;
            let mut up_bytes: u64 = 0;
            let mut up_waits: u64 = 0;
            let mut up_wait_micros: u64 = 0;
            let mut up_wait_worst_micros: u64 = 0;
            let mut last_uplink_report = Instant::now();
            let sndbuf_kb = crate::upstream::send_buffer_kb(&sock_w);
            let rcvbuf_kb = crate::upstream::recv_buffer_kb(&sock_w);

            loop {
                let first = match outbound_rx.recv().await {
                    Some(pkt) => pkt,
                    None => break,
                };

                batch.clear();
                batch.push(first);
                // Whatever is already waiting, nothing more: this never adds
                // latency in order to build a bigger burst.
                while batch.len() < MAX_ENCAP_BATCH {
                    match outbound_rx.try_recv() {
                        Ok(pkt) => batch.push(pkt),
                        Err(_) => break,
                    }
                }

                wire.clear();
                {
                    let mut tunn = tunn_w.lock().await;
                    for ip_packet in batch.drain(..) {
                        match tunn.encapsulate(&ip_packet, &mut out_buf) {
                            TunnResult::Done => {}
                            TunnResult::Err(e) => {
                                log::trace!("encapsulate error: {e:?}");
                            }
                            TunnResult::WriteToNetwork(pkt) => {
                                let mut pkt_vec = pkt.to_vec();
                                inject_client_id(&mut pkt_vec, &client_id);
                                wire.push(pkt_vec);
                            }
                            TunnResult::WriteToTunnelV4(_, _)
                            | TunnResult::WriteToTunnelV6(_, _) => {}
                        }
                    }
                }

                if wire.is_empty() {
                    continue;
                }

                // Once per session, not once per packet.
                if !obfuscation_settled {
                    obfuscation_settled = true;
                    let mut sent = obf_sent.lock().await;
                    if !*sent && aethernoize.is_enabled() {
                        *sent = true;
                        drop(sent);
                        aethernoize::apply_obfuscation(&sock_w, peer, &aethernoize).await;
                    }
                }

                // `try_send` + `writable()` rather than plain `send()` so a wait on
                // the uplink can be attributed and timed instead of being
                // invisible. With `SO_SNDBUF` now a latency budget rather than the
                // OS default (see upstream::tune_udp_buffers) this call really can
                // wait, and that wait is the only way backpressure from the NIC
                // reaches the congestion controller.
                for pkt in wire.drain(..) {
                    let began = Instant::now();
                    let mut waited = false;
                    loop {
                        match sock_w.try_send(&pkt) {
                            Ok(_) => break,
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                waited = true;
                                if sock_w.writable().await.is_err() {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    up_pkts = up_pkts.saturating_add(1);
                    up_bytes = up_bytes.saturating_add(pkt.len() as u64);
                    if waited {
                        let micros = began.elapsed().as_micros() as u64;
                        up_waits = up_waits.saturating_add(1);
                        up_wait_micros = up_wait_micros.saturating_add(micros);
                        if micros > up_wait_worst_micros {
                            up_wait_worst_micros = micros;
                        }
                    }
                }

                if last_uplink_report.elapsed() >= UPLINK_REPORT_INTERVAL {
                    let window = last_uplink_report.elapsed();
                    last_uplink_report = Instant::now();
                    let kbps = if window.as_millis() > 0 {
                        (up_bytes * 1000) / (window.as_millis() as u64) / 1024
                    } else {
                        0
                    };
                    log::info!(
                        "[uplink {peer}] {:?} window: {} pkts, {} KB ({} KB/s) | kernel sndbuf \
                         {} KB, rcvbuf {} KB | writer waited {} times, {} ms total, worst {} ms",
                        window,
                        up_pkts,
                        up_bytes / 1024,
                        kbps,
                        sndbuf_kb,
                        rcvbuf_kb,
                        up_waits,
                        up_wait_micros / 1000,
                        up_wait_worst_micros / 1000,
                    );
                    up_pkts = 0;
                    up_bytes = 0;
                    up_waits = 0;
                    up_wait_micros = 0;
                    up_wait_worst_micros = 0;
                }

                // Post-handshake junk once only, not on every data packet.
                if aethernoize.jc_after_hs > 0 && !post_hs_junk_sent {
                    post_hs_junk_sent = true;
                    aethernoize::send_post_handshake_junk(&sock_w, peer, &aethernoize).await;
                }
            }
        });

        let timer_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(TIMER_TICK);
            let mut tmp = vec![0u8; MAX_PACKET];
            loop {
                interval.tick().await;
                let mut tunn = tunn_t.lock().await;
                if let TunnResult::WriteToNetwork(pkt) = tunn.update_timers(&mut tmp) {
                    let mut pkt_vec = pkt.to_vec();
                    inject_client_id(&mut pkt_vec, &client_id);
                    drop(tunn);

                    if aethernoize_t.is_enabled() {
                        aethernoize::send_keepalive_junk(&sock_t, &aethernoize_t).await;
                    }
                    let _ = sock_t.send(&pkt_vec).await;
                }
            }
        });

        // >>> AETHER-APP-FIX the-carrier-hop-is-not-the-data-path
        // The budget is `self.stale_timeout` (bound at line 292), NOT a fresh
        // `wg_stale_timeout()`.
        //
        // This line used to re-read `wg_stale_timeout()` here, which shadowed
        // the correct value and made every hop — including the carrier hop,
        // which is given 45 s — die after 10 s of silence. The 2026-09-23
        // WARP-in-WARP log is that bug: `[wg] no valid data from peer
        // 162.159.195.244:946 in 10.6450912s`, i.e. the outer hop killed on the
        // inner hop's budget. The plumbing was right all the way from
        // `run_warp_in_warp` through `from_established_with_stale`; this one
        // line threw it away.
        //
        // `Duration` is `Copy`, so the `async move` below captures it directly.
        let stale_timeout = stale_timeout;
        // <<< AETHER-APP-FIX the-carrier-hop-is-not-the-data-path
        let health_task = tokio::spawn(async move {
            let mut out_buf = vec![0u8; MAX_PACKET];
            loop {
                tokio::time::sleep(health_check_pause()).await;

                let idle = last_valid_rx_h.lock().elapsed();
                let asked = *probes_unanswered_h.lock();
                // >>> AETHER-APP-FIX the-carrier-hop-is-not-the-data-path
                // Both conditions, not just the first: a silent peer is only dead
                // once we have asked it enough times to be sure it is not simply
                // idle. Without the second half, a carrier hop whose inner tunnel
                // had nothing to say was killed 10 s after coming up - the
                // WARP-in-WARP failure in the 2026-09-22 log.
                if idle >= stale_timeout && asked >= WG_STALE_MIN_PROBES {
                    log::warn!(
                        "[wg] no valid data from peer {} in {:?} despite {} unanswered data-plane \
                         probe(s); tunnel considered dead",
                        peer,
                        idle,
                        asked
                    );
                    return Err::<(), AetherError>(AetherError::Other(
                        "wireguard tunnel stale: no valid data from peer".into(),
                    ));
                }
                if idle >= stale_timeout {
                    log::debug!(
                        "[wg] peer {} has been silent for {:?} but only {} probe(s) are \
                         outstanding; waiting for the probe budget before judging",
                        peer,
                        idle,
                        asked
                    );
                }
                // <<< AETHER-APP-FIX the-carrier-hop-is-not-the-data-path

                let probe = build_dataplane_probe(local_ipv4);
                let mut tunn = tunn_h.lock().await;
                match send_dataplane_probe(&sock_h, &mut tunn, &client_id_h, &probe, &mut out_buf)
                    .await
                {
                    // >>> AETHER-APP-FIX the-carrier-hop-is-not-the-data-path
                    Ok(()) => {
                        let mut n = probes_unanswered_h.lock();
                        *n = n.saturating_add(1);
                    }
                    Err(e) => log::trace!("[wg] health probe send failed: {e}"),
                    // <<< AETHER-APP-FIX the-carrier-hop-is-not-the-data-path
                }
            }
        });

        let _guard = TaskGuard(vec![
            recv_task.abort_handle(),
            send_task.abort_handle(),
            timer_task.abort_handle(),
            health_task.abort_handle(),
        ]);

        let result = tokio::select! {
            _ = recv_task => {
                log::info!("wireguard recv task ended");
                Ok(())
            }
            _ = send_task => {
                log::info!("wireguard send task ended");
                Ok(())
            }
            _ = timer_task => {
                log::info!("wireguard timer task ended");
                Ok(())
            }
            r = health_task => {
                match r {
                    Ok(Err(e)) => Err(e),
                    Ok(Ok(())) => Ok(()),
                    Err(e) => Err(AetherError::Other(format!("health task panicked: {e}"))),
                }
            }
        };

        result
    }
}

const WG_HEALTHCHECK_INTERVAL: Duration = Duration::from_secs(3);
const WG_HEALTHCHECK_JITTER: Duration = Duration::from_millis(500);

fn health_check_pause() -> Duration {
    let jitter = WG_HEALTHCHECK_JITTER.as_millis() as u64;
    let offset = rand::rng().random_range(0..=jitter * 2);
    WG_HEALTHCHECK_INTERVAL - WG_HEALTHCHECK_JITTER + Duration::from_millis(offset)
}

/// The silence budget for a data-path hop: the one the user's traffic crosses.
///
/// Public so the nested pipelines in `lib.rs` can hand the carrier hop a
/// different, larger budget while keeping this one for the inner hop. See
/// [`carrier_stale_timeout`].
pub fn wg_stale_timeout() -> Duration {
    let secs = std::env::var("AETHER_WG_STALE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(10);
    Duration::from_secs(secs)
}

// >>> AETHER-APP-FIX the-carrier-hop-is-not-the-data-path
/// How many data-plane probes must go unanswered before silence is read as
/// death rather than as idleness.
///
/// The health task asks once every ~3 s, so three outstanding questions is
/// roughly the same wall-clock budget the old code had - but it is now a
/// statement about *answers*, not about *silence*.
const WG_STALE_MIN_PROBES: u32 = 3;

/// The silence budget for the **outer** hop of a nested pipeline.
///
/// ## Why the outer hop gets its own number
///
/// In WARP-in-WARP and MASQUE-in-MASQUE the outer hop is a carrier: it moves
/// the inner hop's packets and nothing else. Between the moment the inner
/// tunnel finishes validating and the moment an application actually pushes
/// traffic through SOCKS5, the carrier has nothing to carry - and on a
/// consumer WARP edge, a WireGuard keepalive is an empty data packet that the
/// peer does not answer. So "no decodable packet from the peer" is the normal
/// state of a healthy carrier, not a fault.
///
/// The 2026-09-22 WARP-in-WARP log shows exactly that:
///
/// ```text
///   05:47:28.974 [+] [outer] wireguard tunnel validated (end-to-end data confirmed)
///   05:47:30.842 [+] [inner] wireguard tunnel validated (end-to-end data confirmed)
///   05:47:41.456 [-] [wg] no valid data from peer 188.114.97.32:934 in 10.6141368s;
///                    tunnel considered dead
/// ```
///
/// Ten seconds of idleness killed a pipeline that had been proven working two
/// seconds earlier, and the launcher's remaining window was then spent on a
/// fresh scan it could not finish.
///
/// The carrier is still checked - it is not exempt from failure - but it is
/// judged on a budget sized for a link that is *allowed* to be quiet, and the
/// inner hop (the one the user's traffic actually crosses) remains the
/// authority that fails fast. A carrier that is genuinely dead takes the inner
/// hop down with it within the inner hop's own budget.
pub fn carrier_stale_timeout() -> Duration {
    let secs = std::env::var("AETHER_WG_CARRIER_STALE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(45);
    Duration::from_secs(secs)
}

/// Clamps a hop's keepalive so it can never be longer than half its own silence
/// budget.
///
/// ## The invariant
///
/// A keepalive is the only thing a quiet tunnel sends on its own, so a hop whose
/// keepalive is longer than the time it is given before being declared dead is
/// guaranteed to be declared dead while its keepalive is still pending. The
/// WARP-in-WARP path shipped exactly that: `run_warp_in_warp` handed the inner
/// hop `keepalive = 20 s` while the watchdog's budget was `10 s`, so the inner
/// hop could be pronounced stale before it had ever had the chance to speak.
///
/// Rather than trust every call site to remember, the clamp is applied where the
/// value is used, and [`keepalive_is_below_the_stale_budget`] pins it in a test.
pub fn clamp_keepalive_to_stale(keepalive: u16, stale: Duration) -> u16 {
    let ceiling = (stale.as_secs() / 2).max(1).min(u16::MAX as u64) as u16;
    keepalive.min(ceiling).max(1)
}

#[cfg(test)]
fn keepalive_is_below_the_stale_budget(keepalive: u16, stale: Duration) -> bool {
    u64::from(clamp_keepalive_to_stale(keepalive, stale)) < stale.as_secs().max(1)
}
// <<< AETHER-APP-FIX the-carrier-hop-is-not-the-data-path

fn build_dns_query() -> Vec<u8> {
    let id: u16 = rand::random();
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00]);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    for label in ["cloudflare", "com"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0x00);
    q.extend_from_slice(&[0x00, 0x01]);
    q.extend_from_slice(&[0x00, 0x01]);
    q
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < header.len() {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
        i += 2;
    }
    if i < header.len() {
        sum += (header[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_dataplane_probe(src: Ipv4Addr) -> Vec<u8> {
    let dns = build_dns_query();
    let udp_len = 8 + dns.len();
    let total_len = 20 + udp_len;
    let mut pkt = Vec::with_capacity(total_len);
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&(total_len as u16).to_be_bytes());
    let id: u16 = rand::random();
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.push(64);
    pkt.push(17);
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&Ipv4Addr::new(8, 8, 8, 8).octets());
    let csum = ipv4_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
    let sport: u16 = rand::rng().random_range(20000..60000);
    pkt.extend_from_slice(&sport.to_be_bytes());
    pkt.extend_from_slice(&53u16.to_be_bytes());
    pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x00]);
    pkt.extend_from_slice(&dns);
    pkt
}

async fn send_dataplane_probe(
    sock: &UdpSocket,
    tunn: &mut Tunn,
    client_id: &[u8; 3],
    probe: &[u8],
    out_buf: &mut [u8],
) -> Result<()> {
    match tunn.encapsulate(probe, out_buf) {
        TunnResult::WriteToNetwork(pkt) => {
            let mut v = pkt.to_vec();
            inject_client_id(&mut v, client_id);
            sock.send(&v).await?;
        }
        TunnResult::Err(e) => {
            return Err(AetherError::Other(format!("dataplane encap: {e:?}")));
        }
        _ => {}
    }
    Ok(())
}

const DATAPLANE_REQUIRED_SUCCESSES: u32 = 2;
const DATAPLANE_PROBE_GAP: Duration = Duration::from_millis(600);

async fn verify_dataplane(
    sock: &UdpSocket,
    tunn: &mut Tunn,
    client_id: &[u8; 3],
    local_ipv4: Ipv4Addr,
    start: Instant,
    deadline: Instant,
) -> Result<Duration> {
    let probe = build_dataplane_probe(local_ipv4);
    let mut out_buf = vec![0u8; MAX_PACKET];
    let mut recv_buf = vec![0u8; MAX_PACKET];
    let mut tmp_buf = vec![0u8; MAX_PACKET];

    let mut successes: u32 = 0;
    let mut last_probe_at = Instant::now();
    send_dataplane_probe(sock, tunn, client_id, &probe, &mut out_buf).await?;
    let mut resend_at = last_probe_at + Duration::from_millis(700);

    loop {
        let now = Instant::now();
        if now >= deadline {
            log::debug!(
                "[wg] dataplane verify timed out ({}/{} confirmations)",
                successes,
                DATAPLANE_REQUIRED_SUCCESSES
            );
            return Err(AetherError::Other("dataplane timeout".into()));
        }
        if now >= resend_at {
            let _ = send_dataplane_probe(sock, tunn, client_id, &probe, &mut out_buf).await;
            last_probe_at = now;
            resend_at = now + Duration::from_millis(700);
        }
        let wait = deadline
            .saturating_duration_since(now)
            .min(resend_at.saturating_duration_since(now));

        tokio::select! {
            r = sock.recv(&mut recv_buf) => {
                let n = r?;
                strip_client_id(&mut recv_buf[..n]);
                match tunn.decapsulate(None, &recv_buf[..n], &mut tmp_buf) {
                    TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                        successes += 1;
                        log::debug!(
                            "[wg] dataplane round-trip {}/{} confirmed in {:?}",
                            successes, DATAPLANE_REQUIRED_SUCCESSES, start.elapsed()
                        );
                        if successes >= DATAPLANE_REQUIRED_SUCCESSES {
                            let elapsed = start.elapsed();
                            log::debug!("[wg] dataplane ok in {:?}", elapsed);
                            return Ok(elapsed);
                        }
                        let next_at = Instant::now().max(last_probe_at + DATAPLANE_PROBE_GAP);
                        let _ = send_dataplane_probe(sock, tunn, client_id, &probe, &mut out_buf).await;
                        last_probe_at = next_at;
                        resend_at = next_at + Duration::from_millis(700);
                    }
                    TunnResult::WriteToNetwork(pkt) => {
                        let mut v = pkt.to_vec();
                        inject_client_id(&mut v, client_id);
                        let _ = sock.send(&v).await;
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(wait) => {}
        }
    }
}

pub async fn verify_endpoint(
    peer: SocketAddr,
    private_key: [u8; 32],
    peer_public: [u8; 32],
    client_id: [u8; 3],
    local_ipv4: Ipv4Addr,
    aethernoize: &AetherNoizeConfig,
    timeout: Duration,
    keepalive: Option<u16>,
) -> Result<Duration> {
    let (elapsed, _session) = verify_endpoint_keep_session(
        peer,
        private_key,
        peer_public,
        client_id,
        local_ipv4,
        aethernoize,
        timeout,
        keepalive,
    )
    .await?;
    Ok(elapsed)
}

pub async fn verify_endpoint_keep_session(
    peer: SocketAddr,
    private_key: [u8; 32],
    peer_public: [u8; 32],
    client_id: [u8; 3],
    local_ipv4: Ipv4Addr,
    aethernoize: &AetherNoizeConfig,
    timeout: Duration,
    keepalive: Option<u16>,
) -> Result<(Duration, EstablishedSession)> {
    let data_check = std::env::var("AETHER_WG_NO_DATA_CHECK").is_err();
    log::trace!(
        "[wg] verify {} obf={} data_check={}",
        peer,
        aethernoize.is_enabled(),
        data_check
    );

    let (sock, _, detour) = crate::upstream::bind_via_upstream(peer).await?;

    let start = Instant::now();
    let deadline = start + timeout;

    if aethernoize.is_enabled() {
        aethernoize::apply_obfuscation(&sock, peer, aethernoize).await;
    }

    let local_secret = StaticSecret::from(private_key);
    let peer_pk = PublicKey::from(peer_public);

    let mut tunn = Tunn::new(
        local_secret,
        peer_pk,
        None,
        Some(keepalive.unwrap_or(25)),
        0,
        None,
    );

    let mut out_buf = vec![0u8; MAX_PACKET];
    let mut recv_buf = vec![0u8; MAX_PACKET];
    let mut tmp_buf = vec![0u8; MAX_PACKET];

    let init_packet = match tunn.encapsulate(&[], &mut out_buf) {
        TunnResult::WriteToNetwork(pkt) => {
            let mut pkt_vec = pkt.to_vec();
            inject_client_id(&mut pkt_vec, &client_id);
            pkt_vec
        }
        other => {
            log::warn!("[wg] unexpected encap result: {:?}", other);
            return Err(AetherError::Other("handshake init failed".into()));
        }
    };

    log::trace!("[wg] sending init {} bytes to {}", init_packet.len(), peer);
    sock.send(&init_packet).await?;

    let mut retry_index = 0usize;
    let mut timer = tokio::time::interval(TIMER_TICK);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    timer.tick().await;

    let mut attempts = 0;
    loop {
        if Instant::now() >= deadline {
            log::trace!("[wg] timeout after {} recv attempts", attempts);
            return Err(AetherError::Other("verify timeout".into()));
        }

        let remaining = deadline.saturating_duration_since(Instant::now());

        tokio::select! {
            r = sock.recv(&mut recv_buf) => {
                attempts += 1;
                let n = r?;
                if n == 0 {
                    continue;
                }
                log::trace!("[wg] recv {} bytes (attempt {})", n, attempts);
                strip_client_id(&mut recv_buf[..n]);

                match tunn.decapsulate(None, &recv_buf[..n], &mut tmp_buf) {
                    TunnResult::Done => {
                        let elapsed = start.elapsed();
                        log::trace!("[wg] handshake done in {:?}", elapsed);
                        if data_check {
                            let dp_elapsed = verify_dataplane(&sock, &mut tunn, &client_id, local_ipv4, start, deadline).await?;
                            return Ok((dp_elapsed, EstablishedSession {
                                tunn: Arc::new(Mutex::new(Box::new(tunn))),
                                sock: Arc::new(sock),
                                detour,
                                peer,
                                client_id,
                            }));
                        }
                        return Ok((elapsed, EstablishedSession {
                            tunn: Arc::new(Mutex::new(Box::new(tunn))),
                            sock: Arc::new(sock),
                            detour,
                            peer,
                            client_id,
                        }));
                    }
                    TunnResult::WriteToNetwork(pkt) => {
                        let mut pkt_vec = pkt.to_vec();
                        inject_client_id(&mut pkt_vec, &client_id);
                        log::trace!("[wg] sending response {} bytes", pkt_vec.len());
                        sock.send(&pkt_vec).await?;
                        let elapsed = start.elapsed();
                        log::trace!("[wg] handshake success in {:?}", elapsed);
                        if data_check {
                            let dp_elapsed = verify_dataplane(&sock, &mut tunn, &client_id, local_ipv4, start, deadline).await?;
                            return Ok((dp_elapsed, EstablishedSession {
                                tunn: Arc::new(Mutex::new(Box::new(tunn))),
                                sock: Arc::new(sock),
                                detour,
                                peer,
                                client_id,
                            }));
                        }
                        return Ok((elapsed, EstablishedSession {
                            tunn: Arc::new(Mutex::new(Box::new(tunn))),
                            sock: Arc::new(sock),
                            detour,
                            peer,
                            client_id,
                        }));
                    }
                    TunnResult::Err(e) => {
                        log::trace!("[wg] decap error: {:?}", e);
                    }
                    other => {
                        log::trace!("[wg] unexpected decap: {:?}", other);
                    }
                }
            }
            _ = timer.tick() => {
                if let Some(delay) = VERIFY_RETRY_DELAYS.get(retry_index) {
                    if start.elapsed() >= *delay {
                        retry_index += 1;
                        log::trace!(
                            "[wg] retransmitting init to {} after {:?} ({}/{})",
                            peer,
                            delay,
                            retry_index,
                            VERIFY_RETRY_DELAYS.len()
                        );
                        sock.send(&init_packet).await?;
                    }
                }

                match tunn.update_timers(&mut out_buf) {
                    TunnResult::WriteToNetwork(pkt) => {
                        let mut pkt_vec = pkt.to_vec();
                        inject_client_id(&mut pkt_vec, &client_id);
                        log::trace!("[wg] timer generated {} byte handshake packet", pkt_vec.len());
                        sock.send(&pkt_vec).await?;
                    }
                    TunnResult::Err(e) => {
                        return Err(AetherError::Other(format!("wireguard timer failed: {e:?}")));
                    }
                    _ => {}
                }
            }
            _ = tokio::time::sleep(remaining) => {
                log::trace!("[wg] sleep timeout");
                return Err(AetherError::Other("verify timeout".into()));
            }
        }
    }
}

pub const WG_PREFIXES_V4: &[&str] = &[
    "162.159.192.0/24",
    "162.159.195.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
    "162.159.193.0/24",
];

pub const WG_PREFIXES_V6: &[&str] = &[
    "2606:4700:d0::/64",
    "2606:4700:d1::/64",
    "2606:4700:100::/48",
];

pub const WG_ZT_PREFIXES_V4: &[&str] = &["162.159.193.0/24"];

pub const WG_ZT_PREFIXES_V6: &[&str] = &["2606:4700:100::/48"];

pub const WG_PORTS: &[u16] = &[
    2408, 500, 1701, 4500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
    943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371,
    2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319,
    8742, 8854, 8886,
];

pub const WG_SEEDS_V4: &[&str] = &[
    "162.159.192.1",
    "162.159.195.1",
    "188.114.96.1",
    "188.114.97.1",
    "162.159.193.1",
];

pub const WG_SEEDS_V6: &[&str] = &[
    "2606:4700:d0::a29f:c001",
    "2606:4700:d1::a29f:c001",
    "2606:4700:d0::a29f:c301",
    "2606:4700:d0::bc72:6001",
];

pub fn wg_prefixes_v4() -> Vec<&'static str> {
    // >>> AETHER-APP-PATCH scan-cidrs — «بازهٔ آدرس» در تنظیمات برنامه
    if let Some(pinned) = crate::prober::pinned_cidrs_v4("AETHER_WG_CIDRS") {
        return pinned;
    }
    // <<< AETHER-APP-PATCH scan-cidrs
    crate::prober::prioritize(WG_PREFIXES_V4, WG_ZT_PREFIXES_V4)
}

pub fn wg_prefixes_v6() -> Vec<&'static str> {
    // >>> AETHER-APP-PATCH scan-cidrs
    if let Some(pinned) = crate::prober::pinned_cidrs_v6("AETHER_WG_CIDRS") {
        return pinned;
    }
    // <<< AETHER-APP-PATCH scan-cidrs
    crate::prober::prioritize(WG_PREFIXES_V6, WG_ZT_PREFIXES_V6)
}

pub fn wg_seeds_v4() -> Vec<&'static str> {
    // >>> AETHER-APP-PATCH scan-cidrs — دانهٔ بیرون از بازهٔ پین‌شده پروب نمی‌شود
    crate::prober::seeds_within(
        &crate::prober::prioritize(WG_SEEDS_V4, &["162.159.193.1"]),
        "AETHER_WG_CIDRS",
    )
    // <<< AETHER-APP-PATCH scan-cidrs
}

/// دانه‌های IPv6؛ مثل همتای v4 به بازهٔ پین‌شده محدود می‌شود.
/// (AETHER-APP-PATCH scan-cidrs)
pub fn wg_seeds_v6() -> Vec<&'static str> {
    crate::prober::seeds_within(WG_SEEDS_V6, "AETHER_WG_CIDRS")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn the_documented_zero_trust_wireguard_ingress_range_is_scanned() {
        assert!(WG_PREFIXES_V4.contains(&"162.159.193.0/24"));
        assert!(WG_PREFIXES_V6.contains(&"2606:4700:100::/48"));
    }

    #[test]
    fn the_documented_wireguard_ports_are_all_covered() {
        for port in [2408u16, 500, 1701, 4500] {
            assert!(WG_PORTS.contains(&port), "port {port} should be scanned");
        }
    }

    #[test]
    fn the_documented_default_wireguard_port_leads_the_sweep() {
        assert_eq!(
            WG_PORTS.first(),
            Some(&2408),
            "the primary sweep port is taken from the head of this list"
        );
    }

    #[test]
    fn the_documented_wireguard_fallback_ports_follow_the_default() {
        assert_eq!(&WG_PORTS[..4], &[2408, 500, 1701, 4500]);
    }

    #[test]
    fn the_consumer_range_leads_when_no_team_is_configured() {
        std::env::remove_var("AETHER_TEAM");
        assert_eq!(wg_prefixes_v4().first(), Some(&"162.159.192.0/24"));
        assert_eq!(wg_prefixes_v6().first(), Some(&"2606:4700:d0::/64"));
    }

    #[test]
    fn no_prefix_is_lost_when_the_zero_trust_range_is_promoted() {
        let promoted = crate::prober::prioritize(WG_PREFIXES_V4, WG_ZT_PREFIXES_V4);
        assert_eq!(promoted.len(), WG_PREFIXES_V4.len());
        for entry in WG_PREFIXES_V4 {
            assert!(promoted.contains(entry), "{entry} went missing");
        }
    }

    #[test]
    fn every_wireguard_prefix_parses() {
        for entry in WG_PREFIXES_V4 {
            let (addr, bits) = entry.split_once('/').expect("cidr");
            assert!(addr.parse::<std::net::Ipv4Addr>().is_ok(), "{entry}");
            assert!(bits.parse::<u8>().is_ok(), "{entry}");
        }
        for entry in WG_PREFIXES_V6 {
            let (addr, bits) = entry.split_once('/').expect("cidr");
            assert!(addr.parse::<std::net::Ipv6Addr>().is_ok(), "{entry}");
            assert!(bits.parse::<u8>().is_ok(), "{entry}");
        }
    }

    #[test]
    fn an_icmp_port_unreachable_is_treated_as_transient() {
        assert!(is_transient_socket_error(&Error::from(
            ErrorKind::ConnectionRefused
        )));
    }

    #[test]
    fn the_usual_transient_udp_errors_do_not_end_the_tunnel() {
        for kind in [
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::HostUnreachable,
            ErrorKind::NetworkUnreachable,
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
            ErrorKind::TimedOut,
        ] {
            assert!(
                is_transient_socket_error(&Error::from(kind)),
                "{kind:?} should be transient"
            );
        }
    }

    #[test]
    fn health_probes_are_jittered_around_the_interval() {
        for _ in 0..200 {
            let pause = health_check_pause();
            assert!(pause >= WG_HEALTHCHECK_INTERVAL - WG_HEALTHCHECK_JITTER);
            assert!(pause <= WG_HEALTHCHECK_INTERVAL + WG_HEALTHCHECK_JITTER);
        }
    }

    #[test]
    fn every_health_probe_is_a_fresh_packet() {
        let local = Ipv4Addr::new(172, 16, 0, 2);
        let distinct: std::collections::HashSet<Vec<u8>> =
            (0..16).map(|_| build_dataplane_probe(local)).collect();
        assert!(
            distinct.len() > 1,
            "the probe must not repeat byte for byte"
        );
    }

    // >>> AETHER-APP-FIX the-carrier-hop-is-not-the-data-path
    /// The invariant that the WARP-in-WARP path shipped broken: a hop's
    /// keepalive must never outlive the budget it is given before the watchdog
    /// calls it dead. `run_warp_in_warp` used to pass `20 s` against a `10 s`
    /// budget, so the inner hop could be pronounced stale before its keepalive
    /// was ever due.
    #[test]
    fn a_keepalive_can_never_outlive_the_stale_budget() {
        for stale_secs in [1u64, 2, 5, 10, 30, 45, 120, 3600] {
            let stale = Duration::from_secs(stale_secs);
            for keepalive in [1u16, 5, 20, 25, 60, u16::MAX] {
                assert!(
                    keepalive_is_below_the_stale_budget(keepalive, stale),
                    "keepalive {keepalive}s survived a {stale_secs}s stale budget"
                );
            }
        }
    }

    /// The concrete numbers from the 2026-09-22 WARP-in-WARP log: the inner hop
    /// asked for 20 s, the watchdog allowed 10 s.
    #[test]
    fn the_warp_in_warp_inner_keepalive_is_clamped_below_ten_seconds() {
        let stale = Duration::from_secs(10);
        assert_eq!(clamp_keepalive_to_stale(20, stale), 5);
        assert!(keepalive_is_below_the_stale_budget(20, stale));
    }

    /// A carrier is allowed to be quiet for longer than a data-path hop, and the
    /// default must stay comfortably above the inner hop's - otherwise the
    /// nested pipeline is killed by the hop that carries nothing.
    #[test]
    fn the_carrier_is_given_more_silence_than_the_data_path() {
        assert!(carrier_stale_timeout() > wg_stale_timeout());
        assert!(keepalive_is_below_the_stale_budget(5, carrier_stale_timeout()));
    }

    /// Silence alone is not death: the watchdog must also have asked and been
    /// ignored. Three probes at the ~3 s health interval is the same wall-clock
    /// window the old code had, but as a statement about answers.
    #[test]
    fn a_fresh_tunnel_is_not_dead_on_its_first_silent_check() {
        assert!(WG_STALE_MIN_PROBES >= 2);
        let probe_gap = WG_HEALTHCHECK_INTERVAL - WG_HEALTHCHECK_JITTER;
        let to_accumulate = probe_gap * WG_STALE_MIN_PROBES;
        assert!(
            to_accumulate <= Duration::from_secs(15),
            "accumulating the probe budget took {to_accumulate:?}, which would delay a real \
             failure past the launcher's window"
        );
    }
    // <<< AETHER-APP-FIX the-carrier-hop-is-not-the-data-path

    #[test]
    fn a_broken_socket_is_still_fatal() {
        for kind in [
            ErrorKind::NotConnected,
            ErrorKind::AddrNotAvailable,
            ErrorKind::PermissionDenied,
            ErrorKind::InvalidInput,
        ] {
            assert!(
                !is_transient_socket_error(&Error::from(kind)),
                "{kind:?} should be fatal"
            );
        }
    }

    #[tokio::test]
    async fn endpoint_verification_retransmits_a_lost_initial_handshake() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = server.local_addr().unwrap();
        let profile = aethernoize::from_profile("off");
        let verifier = tokio::spawn(async move {
            verify_endpoint(
                peer,
                [7u8; 32],
                [9u8; 32],
                [1u8, 2, 3],
                "172.16.0.2".parse().unwrap(),
                &profile,
                Duration::from_secs(4),
                None,
            )
            .await
        });

        let mut received = Vec::new();
        let mut buf = [0u8; 2048];
        for _ in 0..3 {
            let n = tokio::time::timeout(Duration::from_secs(3), server.recv(&mut buf))
                .await
                .expect("handshake packet deadline")
                .expect("handshake packet");
            received.push(buf[..n].to_vec());
        }

        verifier.abort();
        let _ = verifier.await;

        assert_eq!(received.len(), 3);
        assert_eq!(received[0], received[1]);
        assert_eq!(received[1], received[2]);
    }
}
