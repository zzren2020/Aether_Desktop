#![allow(dead_code)]
pub mod account;
pub mod aethernoize;
pub mod api;
pub mod apifront;
pub mod bridges;
pub mod cli;
pub mod config;
pub mod consts;
pub mod dns;
pub mod egress;
pub mod error;
pub mod ffi;
pub mod fragment;
pub mod lastconn;
pub mod masque;
pub mod masque_h2;
pub mod netstack;
pub mod noize;
pub mod prober;
pub mod quic;
pub mod routing;
pub mod sniff;
pub mod socks;
pub mod sysprofile;
pub mod tls;
pub mod tor;
pub mod tunnelping;
pub mod upstream;
pub mod wg_prober;
pub mod wireguard;
pub mod zerotrust;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use error::{AetherError, Result};

fn parse_local_v4(s: &str) -> Ipv4Addr {
    s.split('/')
        .next()
        .unwrap_or(s)
        .parse()
        .unwrap_or(Ipv4Addr::UNSPECIFIED)
}

const TUNNEL_MTU: usize = 1280;
const INNER_MTU: usize = 1200;

/// MASQUE over HTTP/2 carries its capsules on a TCP stream, where nothing has
/// to fit inside a single UDP datagram. The 1280 that keeps a QUIC datagram
/// whole only buys the netstack more segments to cut on that path, so it gets
/// an ordinary ethernet MTU instead.
const H2_TUNNEL_MTU: usize = 1500;

/// The inner MTU for the MASQUE tunnel. `AETHER_MASQUE_MTU` overrides it, for a
/// path where the edge turns out not to carry full-size packets.
fn masque_tunnel_mtu() -> usize {
    if let Some(mtu) = std::env::var("AETHER_MASQUE_MTU")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|mtu| (576..=1500).contains(mtu))
    {
        return mtu;
    }

    if masque_h2::enabled() {
        H2_TUNNEL_MTU
    } else {
        TUNNEL_MTU
    }
}
const DEFAULT_CONFIG: &str = "aether.toml";

pub async fn run() -> Result<()> {
    run_with(std::env::args().skip(1).collect()).await
}

pub async fn run_with(args: Vec<String>) -> Result<()> {
    if cli::parse_args(args)? == cli::Parsed::Done {
        return Ok(());
    }

    let level = std::env::var("AETHER_LOG_LEVEL")
        .ok()
        .map(|v| v.trim().to_lowercase())
        .filter(|v| matches!(v.as_str(), "error" | "warn" | "info" | "debug" | "trace"))
        .unwrap_or_else(|| "info".to_string());
    let default_filter = format!("info,aether={level}");
    let _ =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(default_filter))
            .format_timestamp_millis()
            .try_init();

    log::info!("Aether v{}", env!("CARGO_PKG_VERSION"));
    // >>> AETHER-APP-PATCH build-provenance
    // The line above is the UPSTREAM core version. It is identical in every
    // patch level of the core, so it identifies nothing: a stale engine and a
    // fresh one print the same banner. This line identifies the build.
    //
    // `AETHER-BUILD-STAMP:` is also embedded as a literal in the binary (see
    // build.rs), which is what `stage-payload.ps1` and CI grep for; printing it
    // here is what lets the Rust side cross-check the engine against the app and
    // what makes any future field log self-identifying in its second line.
    //
    // The capability list is DESKTOP-SPECIFIC and deliberately not copied from
    // the Android build, which claims `device backpressure=on` and
    // `uplink admission=rate-x-500ms`. Those three netstack patches are NOT in
    // this core (counted in netstack.rs: `MAX_DEVICE_TX` 0 hits, `admission` 0,
    // `liveness` 0). Copying that line would produce a log that lies about the
    // data plane, which is the exact failure this stamp exists to prevent.
    log::info!(
        "[*] {} (app patch level {}; netstack congestion control=cubic, \
         uplink sndbuf=bounded, wg writer waits=on; device backpressure=off, \
         flow liveness=off, uplink admission=off)",
        env!("AETHER_BUILD_STAMP"),
        env!("AETHER_APP_PATCHLEVEL"),
    );
    if env!("AETHER_APP_PATCHLEVEL") == "unstamped" {
        log::warn!(
            "[-] this engine carries no PATCHLEVEL stamp, so nothing can tell it \
             apart from any other build of core {}. Build it from the repository \
             root, or set APP_PATCHLEVEL, so the stamp is picked up.",
            env!("CARGO_PKG_VERSION"),
        );
    }
    // <<< AETHER-APP-PATCH build-provenance
    sysprofile::log_summary();
    sysprofile::raise_fd_limit();
    egress::init()?;

    install_netstack_panic_guard();

    let listen: SocketAddr = std::env::var("AETHER_SOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| "127.0.0.1:1819".parse().unwrap());

    drop(socks::bind_listener("socks5", listen).await?);
    drop(bind_http_proxy().await?);

    let base_config = std::env::var("AETHER_CONFIG").unwrap_or_else(|_| DEFAULT_CONFIG.to_string());

    if tor::mode() == tor::Mode::Only {
        return tor::run_only(listen, tor::state_dir(&base_config)).await;
    }

    // A malformed address is worth reporting before an account is provisioned.
    let pinned_wiw = wiw_endpoints_from_env()?;
    let pinned_mim = mim_endpoints_from_env()?;

    let protocol = match std::env::var("AETHER_PROTOCOL") {
        Ok(v) => Protocol::parse(&v),
        // Naming a warp-in-warp hop only makes sense for warp-in-warp.
        Err(_) if !pinned_wiw.is_empty() => Protocol::WarpInWarp,
        Err(_) if !pinned_mim.is_empty() => Protocol::MasqueInMasque,
        Err(_)
            if std::env::var("AETHER_PEER").is_ok() || std::env::var("AETHER_WG_PEER").is_ok() =>
        {
            Protocol::Masque
        }
        Err(_) => select_protocol(&base_config).await,
    };

    if tor::mode() == tor::Mode::Only {
        return tor::run_only(listen, tor::state_dir(&base_config)).await;
    }

    if protocol != Protocol::WarpInWarp && !pinned_wiw.is_empty() {
        log::warn!(
            "[-] the warp-in-warp endpoints you set are ignored on {}; they only apply to --gool",
            protocol.label()
        );
    }

    if protocol != Protocol::MasqueInMasque && !pinned_mim.is_empty() {
        log::warn!(
            "[-] the masque-in-masque endpoints you set are ignored on {}; they only apply to --mim",
            protocol.label()
        );
    }

    match tor::mode() {
        tor::Mode::Chain => {
            let through = listen;
            let state = tor::state_dir(&base_config);
            tokio::spawn(async move {
                if let Err(e) = tor::run_chain(through, state).await {
                    log::error!("[-] tor: {e}");
                }
            });
        }
        tor::Mode::Reverse => {
            if matches!(protocol, Protocol::WireGuard | Protocol::WarpInWarp) {
                return Err(AetherError::Other(format!(
                    "tor carries tcp only and warp's wireguard endpoints answer on udp alone, so \
                     {} can never be reached through tor; use --masque, which this mode runs over \
                     http/2, or put tor inside the tunnel instead with --tor",
                    protocol.label()
                )));
            }

            let socks = tor::start_reverse(tor::state_dir(&base_config)).await?;
            std::env::set_var("AETHER_UPSTREAM", format!("socks5://{socks}"));
            std::env::set_var("AETHER_MASQUE_HTTP2", "1");
            log::info!("[+] the tunnel is dialled through tor on the http/2 carrier");
        }
        tor::Mode::Only | tor::Mode::Off => {}
    }

    match protocol {
        Protocol::Masque => {
            select_masque_transport().await;
            let config_path = masque_config_path(&base_config);
            let identity = load_or_provision_masque(&config_path).await?;
            log::info!(
                "[+] identity ready: device={} ipv4={} ipv6={}",
                identity.device_id,
                identity.ipv4,
                identity.ipv6
            );
            // 1.2.3-p3: the HTTP/2 carrier does not use an ECHConfigList ANYWHERE.
            // `masque_h2::run` never receives one, `prober::MasqueProbe` is built
            // with `ech_config_list: None`, and so is the cached-gateway check -
            // the value is only ever handed to `quic::TunnelConfig`. So on an h2
            // session this lookup was a DNS round trip whose result was dropped on
            // the floor, and it sat on the critical path of every connect: the
            // field log measures it at 9.1 seconds. Nothing is lost by skipping it
            // and 9 seconds are returned to the user.
            let ech = if masque_h2::enabled() {
                log::info!(
                    "[+] ECH lookup skipped: the HTTP/2 carrier does not use an ECHConfigList (saves a DNS round trip on every connect)"
                );
                None
            } else {
                resolve_ech().await
            };
            let lastconn_path = lastconn_path(&config_path);
            run_masque(identity, ech, listen, lastconn_path).await
        }
        Protocol::WireGuard => {
            let config_path = warp_config_path(&base_config);
            let identity = load_or_provision_warp(&config_path).await?;
            log::info!(
                "[+] identity ready: device={} ipv4={} ipv6={}",
                identity.device_id,
                identity.ipv4,
                identity.ipv6
            );

            let lastconn_path = lastconn_path(&config_path);
            run_wireguard(identity, listen, lastconn_path).await
        }
        Protocol::WarpInWarp => {
            let primary_path = warp_config_path(&base_config);
            let secondary_path = derive_sibling_path(&primary_path, "secondary");
            let primary = load_or_provision_warp(&primary_path).await?;
            let secondary = load_or_provision_warp(&secondary_path).await?;
            log::info!(
                "[+] outer device={} ipv4={} | inner device={} ipv4={}",
                primary.device_id,
                primary.ipv4,
                secondary.device_id,
                secondary.ipv4
            );
            // >>> AETHER-APP-FIX a-nested-tunnel-remembers-its-edge
            // Its own cache file, not `lastconn_path`: see `gool_lastconn_path`.
            let lastconn_path = gool_lastconn_path(&primary_path);
            // <<< AETHER-APP-FIX a-nested-tunnel-remembers-its-edge
            run_gool(primary, secondary, listen, lastconn_path).await
        }
        Protocol::MasqueInMasque => {
            select_masque_transport().await;
            let primary_path = masque_config_path(&base_config);
            let secondary_path = derive_sibling_path(&primary_path, "secondary");
            let primary = load_or_provision_masque(&primary_path).await?;
            let secondary = load_or_provision_masque(&secondary_path).await?;
            log::info!(
                "[+] outer device={} ipv4={} | inner device={} ipv4={}",
                primary.device_id,
                primary.ipv4,
                secondary.device_id,
                secondary.ipv4
            );
            let ech = resolve_ech().await;
            // >>> AETHER-APP-FIX a-nested-tunnel-remembers-its-edge
            // Its own cache file, not `lastconn_path`: see `mim_lastconn_path`.
            let lastconn_path = mim_lastconn_path(&primary_path);
            // <<< AETHER-APP-FIX a-nested-tunnel-remembers-its-edge
            run_mim(primary, secondary, ech, listen, lastconn_path).await
        }
    }
}

/// The port Cloudflare's WireGuard edges usually answer on. It is only ever
/// shown as an example: an endpoint has to carry its own port, because which
/// port gets through is exactly what differs between one network and the next.
const WG_EXAMPLE_PORT: u16 = 2408;

/// The two hops of a warp-in-warp tunnel, as far as they were chosen by hand. A
/// hop left as `None` is one the scan still has to find.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct WiwEndpoints {
    outer: Option<SocketAddr>,
    inner: Option<SocketAddr>,
}

// >>> AETHER-APP-FIX one-edge-can-carry-both-hops
/// Whether one edge may carry both hops of a nested tunnel.
///
/// The answer differs by carrier, and the difference is not cosmetic:
///
/// * **WireGuard (warp-in-warp)** — two tunnels are told apart by their public
///   keys, so one edge carrying both is ordinary usage. Refusing it buys
///   nothing and costs a great deal: where only one edge is reachable, refusing
///   it throws away the tunnel that *could* have been built, and `run_gool`
///   answers by rescanning until the budget is gone.
/// * **MASQUE (masque-in-masque)** — the edge validates the client certificate,
///   so the same edge may not accept a second identity. A different edge stays
///   mandatory here.
///
/// The old rule was one sentence for both carriers: *"sending the inner tunnel
/// back out of the address it already arrived on gains nothing"*. That sentence
/// is true and the conclusion drawn from it was still wrong — *gains nothing*
/// is not *must be refused*. Where one edge is all the network offers, reusing
/// it is the only path that arrives, and that is a gain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SharedEdge {
    /// The hops must leave through different edges (MASQUE).
    Refused,
    /// One edge may carry both hops (WireGuard).
    Allowed,
}
// <<< AETHER-APP-FIX one-edge-can-carry-both-hops

impl WiwEndpoints {
    fn is_empty(&self) -> bool {
        self.outer.is_none() && self.inner.is_none()
    }

    // >>> AETHER-APP-FIX one-edge-can-carry-both-hops
    /// Rejects a shared edge only where the carrier cannot take one. See
    /// [`SharedEdge`] for why WireGuard and MASQUE answer this differently.
    fn checked(self, shared: SharedEdge) -> Result<Self> {
        match (self.outer, self.inner) {
            (Some(outer), Some(inner))
                if shared == SharedEdge::Refused && outer.ip() == inner.ip() =>
            {
                Err(AetherError::Other(format!(
                    "the two hops need separate edges, but both point at {}",
                    outer.ip()
                )))
            }
            _ => Ok(self),
        }
    }
    // <<< AETHER-APP-FIX one-edge-can-carry-both-hops
}

/// Reads one endpoint. The port has to be written out: which port answers is
/// the part that differs from network to network, so filling one in on
/// somebody's behalf would only send them at an address nobody offered.
fn parse_endpoint(raw: &str) -> Result<SocketAddr> {
    let text = raw.trim();

    if let Ok(peer) = text.parse::<SocketAddr>() {
        return Ok(peer);
    }

    // An address with the port left off is the likely slip, so name what is
    // missing rather than calling the whole thing unreadable.
    let portless = text.parse::<IpAddr>().ok().or_else(|| {
        text.strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
            .and_then(|inner| inner.parse::<IpAddr>().ok())
    });

    if let Some(address) = portless {
        return Err(AetherError::Other(format!(
            "{text} carries no port, and the port is required; write it out, as in {}",
            SocketAddr::new(address, WG_EXAMPLE_PORT)
        )));
    }

    Err(AetherError::Other(format!(
        "'{text}' is not an endpoint; write an address and a port together, \
         such as 162.159.192.1:{WG_EXAMPLE_PORT}"
    )))
}

/// Reads the one or two endpoints of a warp-in-warp pair, separated by commas,
/// semicolons or spaces.
fn parse_endpoint_list(raw: &str) -> Result<Vec<SocketAddr>> {
    let mut peers = Vec::new();

    for part in raw.split([',', ';', ' ']) {
        if part.trim().is_empty() {
            continue;
        }
        peers.push(parse_endpoint(part)?);
    }

    match peers.len() {
        0 => Err(AetherError::Other(
            "no endpoint was given; expected one or two addresses".to_string(),
        )),
        1 | 2 => Ok(peers),
        found => Err(AetherError::Other(format!(
            "warp-in-warp has two hops, but {found} addresses were given"
        ))),
    }
}

fn env_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// True when the endpoints were deliberately left to the scan, so there is
/// nothing left to ask about.
fn wiw_scan_requested(lookup: &dyn Fn(&str) -> Option<String>) -> bool {
    match lookup("AETHER_WIW_PEERS") {
        Some(value) => matches!(
            value.to_lowercase().as_str(),
            "auto" | "scan" | "none" | "off" | "0"
        ),
        None => false,
    }
}

fn scan_keyword(value: &str) -> bool {
    matches!(
        value.to_lowercase().as_str(),
        "auto" | "scan" | "none" | "off" | "0"
    )
}

// >>> AETHER-APP-FIX one-edge-can-carry-both-hops
/// Reads the endpoints a nested carrier was handed on the command line.
///
/// `shared` is the caller's answer to "may one edge carry both hops?" — it is
/// what keeps the WireGuard relaxation from leaking into MASQUE, which shares
/// this parser. See [`SharedEdge`].
fn nested_endpoints_of(
    lookup: &dyn Fn(&str) -> Option<String>,
    list_key: &str,
    outer_key: &str,
    inner_key: &str,
    shared: SharedEdge,
) -> Result<WiwEndpoints> {
    // <<< AETHER-APP-FIX one-edge-can-carry-both-hops
    let mut chosen = WiwEndpoints::default();

    if let Some(list) = lookup(list_key) {
        if !scan_keyword(&list) {
            let peers = parse_endpoint_list(&list)?;
            chosen.outer = peers.first().copied();
            chosen.inner = peers.get(1).copied();
        }
    }

    if let Some(value) = lookup(outer_key) {
        chosen.outer = Some(parse_endpoint(&value)?);
    }

    if let Some(value) = lookup(inner_key) {
        chosen.inner = Some(parse_endpoint(&value)?);
    }

    chosen.checked(shared)
}

fn wiw_endpoints_of(lookup: &dyn Fn(&str) -> Option<String>) -> Result<WiwEndpoints> {
    nested_endpoints_of(
        lookup,
        "AETHER_WIW_PEERS",
        "AETHER_WIW_OUTER_PEER",
        "AETHER_WIW_INNER_PEER",
        // WireGuard tells two tunnels apart by public key, so one edge may
        // carry both hops.
        SharedEdge::Allowed,
    )
}

fn wiw_endpoints_from_env() -> Result<WiwEndpoints> {
    wiw_endpoints_of(&env_value)
}

fn mim_endpoints_of(lookup: &dyn Fn(&str) -> Option<String>) -> Result<WiwEndpoints> {
    nested_endpoints_of(
        lookup,
        "AETHER_MIM_PEERS",
        "AETHER_MIM_OUTER_PEER",
        "AETHER_MIM_INNER_PEER",
        // A MASQUE edge validates the client certificate, so it may not accept
        // a second identity. The two hops stay separate here — this is the one
        // place where the old rule was right, and it is kept.
        SharedEdge::Refused,
    )
}

fn mim_endpoints_from_env() -> Result<WiwEndpoints> {
    mim_endpoints_of(&env_value)
}

/// `--peer` and `--wg-peer` are older than the warp-in-warp settings and the
/// guides already pair them with `--gool`, so they still name the outer hop.
fn wiw_endpoints_with_fallback(lookup: &dyn Fn(&str) -> Option<String>) -> Result<WiwEndpoints> {
    let mut chosen = wiw_endpoints_of(lookup)?;

    if chosen.outer.is_some() {
        return Ok(chosen);
    }

    let forced = lookup("AETHER_WG_PEER").or_else(|| lookup("AETHER_PEER"));
    let Some(forced) = forced else {
        return Ok(chosen);
    };

    let peers = parse_endpoint_list(&forced)?;
    chosen.outer = peers.first().copied();
    if chosen.inner.is_none() {
        chosen.inner = peers.get(1).copied();
    }

    // `--peer`/`--wg-peer` name a WireGuard hop, so a shared edge is allowed
    // here for the same reason it is in `wiw_endpoints_of`. Note the case this
    // covers: one address written once lands as both `outer` and `inner`, and
    // that used to be rejected as a mistake rather than accepted as the
    // single-edge tunnel it is.
    chosen.checked(SharedEdge::Allowed)
}

// >>> AETHER-APP-FIX a-nested-tunnel-remembers-its-edge
/// Read back the outer edge warp-in-warp used last time, and check it still
/// answers before handing it to [`run_warp_in_warp`].
///
/// ## Verified, not trusted
///
/// A cached address that has since been blocked would otherwise be handed
/// straight to `run_warp_in_warp`, which fails, comes back through the loop,
/// and only *then* scans — so the shortcut would have cost a delay instead of
/// saving one. The mobile core learned this the expensive way and writes it
/// down; the reuse check is what makes the shortcut a shortcut.
///
/// ## Why the profile is not negotiable
///
/// The check must run under the settings the connection will actually use. The
/// outer hop is raised by `establish_wg(.., obfuscate = true, ..)`, which
/// resolves [`primary_aethernoize_profile`] and never varies it. Verifying under
/// any other profile would prove something about a connection nobody is going
/// to make.
async fn load_cached_gool_peer(
    lastconn_path: &str,
    primary: &account::Identity,
) -> Option<SocketAddr> {
    let cached = lastconn::load(lastconn_path)?;
    let peer = cached.peer.parse::<SocketAddr>().ok()?;

    if !want_quick_reconnect(&cached).await {
        return None;
    }

    let private_key = primary.private_key_bytes().ok()?;
    let peer_public = primary.peer_public_key_bytes().ok()?;
    let ipv4: std::net::Ipv4Addr = primary.ipv4.parse().ok()?;

    log::info!("[*] verifying cached outer WARP endpoint {peer} before reuse");
    let profile = aethernoize::from_profile(&primary_aethernoize_profile());

    match wireguard::verify_endpoint(
        peer,
        private_key,
        peer_public,
        primary.client_id,
        ipv4,
        &profile,
        std::time::Duration::from_secs(6),
        None,
    )
    .await
    {
        Ok(rtt) => {
            log::info!(
                "[+] cached outer endpoint {peer} still works (rtt {rtt:?}); skipping scan"
            );
            Some(peer)
        }
        Err(e) => {
            log::warn!("[-] cached outer endpoint {peer} no longer works ({e}); scanning fresh");
            None
        }
    }
}

/// Read back the outer MASQUE edge masque-in-masque used last time, and check
/// it still answers.
///
/// Exactly what [`load_cached_gool_peer`] does for warp-in-warp, for the same
/// reason: an address that no longer answers must not be handed straight to
/// `run_masque_in_masque`. The check is a full MASQUE pre-flight, so what comes
/// back is an edge that has just accepted our identity — not merely an edge
/// that is reachable.
async fn load_cached_mim_peer(
    lastconn_path: &str,
    primary: &account::Identity,
) -> Option<SocketAddr> {
    let cached = lastconn::load(lastconn_path)?;
    let peer = cached.peer.parse::<SocketAddr>().ok()?;

    if !want_quick_reconnect(&cached).await {
        return None;
    }

    log::info!("[*] verifying cached outer MASQUE edge {peer} before reuse");

    if quick_verify_masque_peer(primary, peer).await {
        log::info!("[+] cached outer edge {peer} still works; skipping scan");
        Some(peer)
    } else {
        log::warn!("[-] cached outer edge {peer} no longer works; scanning fresh");
        None
    }
}
// <<< AETHER-APP-FIX a-nested-tunnel-remembers-its-edge

async fn run_gool(
    primary: account::Identity,
    secondary: account::Identity,
    listen: SocketAddr,
    lastconn_path: String,
) -> Result<()> {
    // Scanning is what happens unless somebody named an endpoint themselves.
    let pinned = wiw_endpoints_with_fallback(&env_value)?;

    match (pinned.outer, pinned.inner) {
        (Some(outer), Some(inner)) => log::info!(
            "[+] warp-in-warp endpoints given by hand: {outer} (outer) and {inner} (inner); the scan is skipped"
        ),
        (Some(outer), None) => log::info!(
            "[+] outer warp-in-warp endpoint given by hand: {outer}; scanning for the inner one"
        ),
        (None, Some(inner)) => log::info!(
            "[+] inner warp-in-warp endpoint given by hand: {inner}; scanning for the outer one"
        ),
        (None, None) => {}
    }

    let mut outer_peer = pinned.outer;
    let mut inner_peer = pinned.inner;
    let mut consecutive_fails: u32 = 0;
    const MAX_CONSECUTIVE_FAILS: u32 = 2;
    let mut scan_settings: Option<(String, prober::IpScan)> = None;

    // >>> AETHER-APP-FIX a-nested-tunnel-remembers-its-edge
    // The outer edge that worked the last time this identity connected, read
    // back from a previous run of the process and re-verified before use.
    //
    // `outer_peer` only remembers within one run, so without this every start
    // paid for a full scan — and the cost of that scan is our own scan budget,
    // not the network's, which is why it was the same number of seconds every
    // time. Skipped entirely when the user named an endpoint: a hand-picked hop
    // is not ours to replace.
    let mut cached_peer = if pinned.outer.is_none() {
        load_cached_gool_peer(&lastconn_path, &primary).await
    } else {
        None
    };
    // <<< AETHER-APP-FIX a-nested-tunnel-remembers-its-edge

    loop {
        if consecutive_fails >= MAX_CONSECUTIVE_FAILS {
            // A hop that was given by hand is kept: it was asked for on purpose,
            // and replacing it behind the user's back is not ours to do.
            let mut rescanning = false;

            if pinned.outer.is_none() {
                if let Some(peer) = outer_peer.take() {
                    log::warn!(
                        "[-] outer endpoint {peer} failed {consecutive_fails} times in a row; blacklisting and rescanning"
                    );
                    rescanning = true;
                }
            }

            if pinned.inner.is_none() {
                if let Some(peer) = inner_peer.take() {
                    log::warn!(
                        "[-] inner endpoint {peer} failed {consecutive_fails} times in a row; blacklisting and rescanning"
                    );
                    rescanning = true;
                }
            }

            if !rescanning {
                log::warn!(
                    "[-] the endpoints you chose failed {consecutive_fails} times in a row; still retrying them, drop --wiw-outer/--wiw-inner to let the scan pick instead"
                );
            }

            // >>> AETHER-APP-FIX a-nested-tunnel-remembers-its-edge
            // A blacklisted edge must not come back through the cache on the
            // next turn of this loop. Without this, blacklisting and caching
            // undo each other and the loop never actually replaces the edge.
            cached_peer = None;
            // <<< AETHER-APP-FIX a-nested-tunnel-remembers-its-edge

            consecutive_fails = 0;
        }

        let (peer, inner_peer_now) = match (outer_peer.or(cached_peer), inner_peer) {
            (Some(outer), Some(inner)) => (outer, inner),
            (known_outer, known_inner) => {
                let wanted =
                    usize::from(known_outer.is_none()) + usize::from(known_inner.is_none());
                let avoid: HashSet<IpAddr> = known_outer
                    .into_iter()
                    .chain(known_inner)
                    .map(|peer| peer.ip())
                    .collect();

                let (mode_str, ip) = match &scan_settings {
                    Some(settings) => settings.clone(),
                    None => {
                        let mode_str = select_scan_mode_str(WIW_MANUAL_TIP).await;
                        let ip = select_ip_version().await;
                        scan_settings.insert((mode_str, ip)).clone()
                    }
                };

                let found = match select_wg_peers(&primary, &mode_str, ip, wanted, &avoid).await {
                    Ok(found) => found,
                    Err(e) => {
                        log::warn!("[-] no usable WARP endpoint found: {e}; rescanning shortly");
                        tokio::time::sleep(wg_reconnect_delay()).await;
                        continue;
                    }
                };

                let mut found = found.into_iter();
                let outer = known_outer.or_else(|| found.next());
                let inner = known_inner.or_else(|| found.next());

                match (outer, inner) {
                    (Some(outer), Some(inner)) => (outer, inner),
                    // >>> AETHER-APP-FIX one-edge-can-carry-both-hops
                    // One edge is not half a tunnel. A network that offers
                    // exactly one reachable edge is the case this change exists
                    // for, so the single edge the scan found carries both hops
                    // instead of the loop rescanning until its budget is gone —
                    // which is what it used to do, and what the 2026-09-22 log
                    // shows it doing.
                    (Some(edge), None) | (None, Some(edge)) => {
                        log::warn!(
                            "[-] the scan turned up a single edge ({edge}); carrying both hops on it \
                             rather than rescanning"
                        );
                        (edge, edge)
                    }
                    // <<< AETHER-APP-FIX one-edge-can-carry-both-hops
                    (None, None) => {
                        log::warn!("[-] the scan turned up no edge at all; rescanning");
                        outer_peer = pinned.outer;
                        inner_peer = pinned.inner;
                        tokio::time::sleep(wg_reconnect_delay()).await;
                        continue;
                    }
                }
            }
        };

        // >>> AETHER-APP-FIX one-edge-can-carry-both-hops
        // Said out loud, because "one edge, both hops" is exactly the line a
        // field log needs to show when a session succeeds on a network that
        // offers nothing else.
        if peer.ip() == inner_peer_now.ip() {
            log::info!("[+] using cloudflare edge {peer} (outer and inner — the only edge this network offers)");
        } else {
            log::info!("[+] using cloudflare edge {peer} (outer) and {inner_peer_now} (inner)");
        }
        // <<< AETHER-APP-FIX one-edge-can-carry-both-hops
        outer_peer = Some(peer);
        inner_peer = Some(inner_peer_now);

        // >>> AETHER-APP-FIX a-nested-tunnel-remembers-its-edge
        // Saved *before* the tunnel is raised, not after. The outer edge has
        // already passed a handshake and a data-plane check by this point, and
        // `run_warp_in_warp` only returns when the whole session ends — waiting
        // for that would mean never recording an edge that worked for hours.
        if pinned.outer.is_none() {
            lastconn::save(
                &lastconn_path,
                &peer.to_string(),
                &primary_aethernoize_profile(),
            );
        }
        // <<< AETHER-APP-FIX a-nested-tunnel-remembers-its-edge

        match run_warp_in_warp(
            primary.clone(),
            secondary.clone(),
            peer,
            inner_peer_now,
            listen,
        )
        .await
        {
            Ok(()) => log::warn!("[-] gool tunnel closed; reconnecting"),
            Err(e) => log::warn!("[-] gool tunnel ended: {e}; reconnecting"),
        }
        consecutive_fails += 1;

        tokio::time::sleep(wg_reconnect_delay()).await;
    }
}

fn install_netstack_panic_guard() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let from_netstack = info
            .location()
            .map(|l| l.file().contains("smoltcp"))
            .unwrap_or(false);
        if from_netstack {
            log::debug!("[netstack] recovered from a malformed segment: {info}");
        } else {
            default_hook(info);
        }
    }));
}

fn noize_config() -> noize::NoizeConfig {
    let profile = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "firewall".to_string());
    log::info!("[+] obfuscation profile: {profile}");
    noize::from_profile(&profile)
}

// >>> AETHER-APP-FIX a-nested-tunnel-remembers-its-edge
/// The aethernoize profile name that non-varying WireGuard hops are raised
/// with.
///
/// One source of truth on purpose. [`aethernoize_config`] builds the config the
/// hops actually use, and the nested caches record *this name* next to the peer
/// they remember — so the reuse check can prove the cached peer was validated
/// under the very settings the connection is about to use. A second copy of the
/// default would be a second thing to keep in sync, and the failure mode of
/// drift here is a cache that "verifies" a peer under settings nobody uses.
fn primary_aethernoize_profile() -> String {
    std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "balanced".to_string())
}
// <<< AETHER-APP-FIX a-nested-tunnel-remembers-its-edge

fn aethernoize_config() -> aethernoize::AetherNoizeConfig {
    let profile = primary_aethernoize_profile();
    log::info!("[+] aethernoize profile: {profile}");
    aethernoize::from_profile(&profile)
}

fn team_scope() -> Option<String> {
    zerotrust::TeamSettings::from_env().map(|settings| settings.team)
}

fn enrolled_teams(base: &str) -> Vec<String> {
    let dir_end = base
        .rfind(|c| c == '/' || c == '\\')
        .map(|i| i + 1)
        .unwrap_or(0);
    let dir = if dir_end == 0 { "." } else { &base[..dir_end] };
    let stem = match base[dir_end..].rfind('.') {
        Some(rel) => &base[dir_end..dir_end + rel],
        None => &base[dir_end..],
    };
    let prefix = format!("{stem}-team-");

    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut teams: Vec<String> = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Some(rest) = name.strip_prefix(&prefix) else {
            continue;
        };
        let Some(team) = rest.strip_suffix(".toml") else {
            continue;
        };
        if team.is_empty() || team.ends_with("-secondary") || team.ends_with("-lastconn") {
            continue;
        }
        if !teams.iter().any(|known| known == team) {
            teams.push(team.to_string());
        }
    }
    teams.sort();
    teams
}

async fn enrol_zero_trust(base: &str) {
    let known = enrolled_teams(base);

    let prompt = match known.first() {
        Some(team) => format!(
            "\nZero Trust organization.\n  already enrolled: {}\nTeam name from \
             <team>.cloudflareaccess.com, or blank to reuse '{}': ",
            known.join(", "),
            team
        ),
        None => "\nZero Trust organization.\nTeam name from <team>.cloudflareaccess.com \
                 (blank to cancel): "
            .to_string(),
    };

    let answer = prompt_line(&prompt).await.unwrap_or_default();
    let answer = answer.trim().to_string();

    let team = if answer.is_empty() {
        match known.first() {
            Some(team) => team.clone(),
            None => {
                log::info!("[*] Zero Trust skipped; staying on personal WARP");
                return;
            }
        }
    } else {
        match zerotrust::normalize_team(&answer) {
            Some(team) => team,
            None => {
                log::warn!("[-] '{answer}' is not a usable team name");
                return;
            }
        }
    };

    std::env::set_var("AETHER_TEAM", &team);

    if known.iter().any(|enrolled| *enrolled == team) {
        log::info!("[+] reusing the saved enrolment for team {team}; no sign-in needed");
        return;
    }

    let needs_method = match zerotrust::TeamSettings::from_env() {
        Some(settings) => {
            !(settings.token.is_some() || settings.has_service_token() || settings.email.is_some())
        }
        None => {
            std::env::remove_var("AETHER_TEAM");
            return;
        }
    };

    if needs_method {
        let email = prompt_line("Email address for the one-time login code (blank to cancel): ")
            .await
            .unwrap_or_default();
        let email = email.trim().to_string();

        if email.is_empty() {
            log::warn!("[-] no email given; staying on personal WARP");
            std::env::remove_var("AETHER_TEAM");
            return;
        }

        std::env::set_var("AETHER_ACCESS_EMAIL", &email);
    }

    let settings = match zerotrust::TeamSettings::from_env() {
        Some(settings) => settings,
        None => {
            std::env::remove_var("AETHER_TEAM");
            return;
        }
    };

    match zerotrust::resolve_token(&settings).await {
        Ok(_) => log::info!("[+] signed in to team {team}; now pick the transport to use"),
        Err(error) => {
            log::error!("[-] Zero Trust sign-in failed: {error}");
            log::warn!("[-] staying on personal WARP");
            std::env::remove_var("AETHER_TEAM");
            std::env::remove_var("AETHER_ACCESS_EMAIL");
        }
    }
}

async fn provision_account() -> Result<account::Identity> {
    match zerotrust::TeamSettings::from_env() {
        Some(settings) => {
            log::info!(
                "[*] enrolling this device into the Zero Trust organization {} ({})",
                settings.team,
                settings.team_domain()
            );
            let identity =
                account::provision_team(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, &settings)
                    .await?;
            Ok(account::refresh_profile(identity).await)
        }
        None => account::provision_wg(consts::DEFAULT_MODEL, consts::DEFAULT_LOCALE, None).await,
    }
}

async fn adopt_team_profile(identity: account::Identity) -> account::Identity {
    if team_scope().is_none() {
        return identity;
    }

    let identity = account::refresh_profile(identity).await;

    if !identity.gateway_proxy.is_empty() {
        if std::env::var("AETHER_GATEWAY").is_ok() {
            socks::set_gateway_proxy(&identity.gateway_proxy);
        } else {
            log::debug!(
                "[zerotrust] the organization offers a gateway proxy at {}; pass --gateway to route http through it",
                identity.gateway_proxy
            );
        }
    }

    if !identity.assigned_endpoint.is_empty() && std::env::var("AETHER_PEER").is_err() {
        let port = if std::env::var("AETHER_PROTOCOL")
            .map(|value| value == "wg" || value == "gool")
            .unwrap_or(false)
        {
            2408
        } else {
            443
        };
        let peer = format!("{}:{port}", identity.assigned_endpoint);
        if peer.parse::<SocketAddr>().is_ok() {
            log::info!("[+] the organization assigned endpoint {peer}; trying it before scanning");
            std::env::set_var("AETHER_TEAM_ENDPOINT", &peer);
        }
    }

    identity
}

fn warp_config_path(base: &str) -> String {
    if let Ok(p) = std::env::var("AETHER_WG_CONFIG") {
        return p;
    }
    match team_scope() {
        Some(team) => derive_sibling_path(base, &format!("team-{team}")),
        None => base.to_string(),
    }
}

fn masque_config_path(base: &str) -> String {
    if let Ok(p) = std::env::var("AETHER_MASQUE_CONFIG") {
        return p;
    }
    match team_scope() {
        Some(team) => derive_sibling_path(base, &format!("team-{team}")),
        None => derive_sibling_path(base, "masque"),
    }
}

fn derive_sibling_path(base: &str, suffix: &str) -> String {
    let dir_end = base
        .rfind(|c| c == '/' || c == '\\')
        .map(|i| i + 1)
        .unwrap_or(0);
    match base[dir_end..].rfind('.') {
        Some(rel) => {
            let dot = dir_end + rel;
            format!("{}-{}{}", &base[..dot], suffix, &base[dot..])
        }
        None => format!("{base}-{suffix}"),
    }
}

fn keep_saved_identity() -> bool {
    !matches!(
        std::env::var("AETHER_REPROVISION").as_deref(),
        Ok("0") | Ok("off") | Ok("false")
    )
}

async fn load_or_provision_warp(config_path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] loaded existing warp identity from {config_path}");
        let identity = adopt_team_profile(identity).await;
        if !identity.refused {
            config::save(config_path, &identity)?;
            return Ok(identity);
        }
        if !keep_saved_identity() {
            return Ok(identity);
        }
        log::warn!("[*] registering a fresh wireguard account to replace the refused identity");
    }

    log::info!("[+] no warp identity found; provisioning dedicated wireguard account");
    let identity = provision_account().await?;
    let identity = adopt_team_profile(identity).await;
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new warp identity to {config_path}");
    Ok(identity)
}

async fn load_or_provision_masque(config_path: &str) -> Result<account::Identity> {
    if let Some(identity) = config::load(config_path)? {
        log::info!("[+] loaded existing masque identity from {config_path}");
        let refused = if identity.has_masque_credentials() {
            let identity = adopt_team_profile(identity).await;
            if !identity.refused {
                config::save(config_path, &identity)?;
                return Ok(identity);
            }
            identity
        } else {
            log::info!("[+] masque identity needs a certificate; enrolling masque key");
            match account::ensure_masque_enrolled(&identity).await {
                Ok(enrollment) => {
                    let identity = account::Identity {
                        cert_pem: enrollment.cert_pem,
                        key_pem: enrollment.key_pem,
                        cert_issued_at: enrollment.issued_at,
                        ..identity
                    };
                    config::save(config_path, &identity)?;
                    return Ok(identity);
                }
                Err(AetherError::IdentityRefused(reason)) => {
                    log::warn!("[-] the saved masque identity was refused: {reason}");
                    account::Identity {
                        refused: true,
                        ..identity
                    }
                }
                Err(error) => return Err(error),
            }
        };

        if !keep_saved_identity() {
            return Ok(refused);
        }
        log::warn!("[*] registering a fresh masque account to replace the refused identity");
    }

    log::info!("[+] no masque identity found; provisioning dedicated masque account");
    let identity = provision_account().await?;
    let enrollment = account::ensure_masque_enrolled(&identity).await?;
    let identity = account::Identity {
        cert_pem: enrollment.cert_pem,
        key_pem: enrollment.key_pem,
        cert_issued_at: enrollment.issued_at,
        ..identity
    };
    let identity = adopt_team_profile(identity).await;
    config::save(config_path, &identity)?;
    log::info!("[+] provisioned and saved new masque identity to {config_path}");
    Ok(identity)
}

async fn select_peer(identity: &account::Identity, protocol: Protocol) -> Result<SocketAddr> {
    let force_peer = match protocol {
        Protocol::Masque | Protocol::MasqueInMasque => std::env::var("AETHER_PEER").ok(),
        Protocol::WireGuard | Protocol::WarpInWarp => std::env::var("AETHER_WG_PEER")
            .ok()
            .or_else(|| std::env::var("AETHER_PEER").ok()),
    };

    if let Some(p) = force_peer {
        let peer: SocketAddr = p
            .parse()
            .map_err(|_| AetherError::Other(format!("bad peer address {p}")))?;
        log::info!("[+] using forced peer {peer} (probe skipped)");
        return Ok(peer);
    }

    log::info!("[+] selected protocol: {}", protocol.label());

    let mode_str = select_scan_mode_str("").await;
    let ip = select_ip_version().await;

    match protocol {
        Protocol::Masque | Protocol::MasqueInMasque => {
            log::info!("[*] hunting for a working MASQUE gateway (deep connect-ip verification)");
            let mode = prober::ScanMode::parse(&mode_str);
            let probe = prober::MasqueProbe {
                sni: consts::CONNECT_SNI.to_string(),
                authority: quic::default_authority().to_string(),
                path: quic::default_path().to_string(),
                cert_pem: std::sync::Arc::from(identity.cert_pem.clone()),
                key_pem: std::sync::Arc::from(identity.key_pem.clone()),
                ech_config_list: None,
                noize: noize_config(),
                ports: prober::MASQUE_PORTS.to_vec(),
                ip,
                local_ipv4: parse_local_v4(&identity.ipv4),
            };

            let best = prober::hunt_best_gateway(&probe, mode).await?;
            log::info!(
                "[+] selected MASQUE gateway {}:{} (rtt {:?})",
                best.ip,
                best.port,
                best.rtt
            );
            Ok(SocketAddr::new(best.ip, best.port))
        }
        Protocol::WireGuard | Protocol::WarpInWarp => {
            let peers = select_wg_peers(identity, &mode_str, ip, 1, &HashSet::new()).await?;
            Ok(peers[0])
        }
    }
}

/// Hunts for `want` endpoints, leaving out the addresses in `avoid`. Warp-in-warp
/// passes the hop it already has there, so the scan cannot hand back the same
/// edge for both ends of the tunnel.
async fn select_wg_peers(
    identity: &account::Identity,
    mode_str: &str,
    ip: prober::IpScan,
    want: usize,
    avoid: &HashSet<IpAddr>,
) -> Result<Vec<SocketAddr>> {
    log::info!(
        "[*] hunting for {want} working WireGuard endpoint(s) (handshake + data-plane verification)"
    );
    let mode = wg_prober::WgScanMode::parse(mode_str);

    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;

    let ports = wireguard::WG_PORTS.to_vec();
    let excluded: HashSet<SocketAddr> = avoid
        .iter()
        .flat_map(|address| {
            ports
                .iter()
                .map(move |port| SocketAddr::new(*address, *port))
        })
        .collect();

    if !avoid.is_empty() {
        log::info!(
            "[*] the scan leaves out {} address(es) already taken by the other hop",
            avoid.len()
        );
    }

    let probe = wg_prober::WgProbe {
        private_key: std::sync::Arc::new(private_key),
        peer_public_key: std::sync::Arc::new(peer_public),
        client_id: identity.client_id.clone(),
        local_ipv4: identity
            .ipv4
            .parse()
            .map_err(|_| AetherError::Other("invalid ipv4".into()))?,
        aethernoize: aethernoize_config(),
        ports,
        ip,
        excluded,
    };

    let found = wg_prober::hunt_wg_endpoints(&probe, mode, want).await?;

    // The exclusion above already keeps these out of the sweep; this is the
    // belt to its braces, since handing a hop its own address back is fatal.
    let picked: Vec<wg_prober::WgProbeResult> = found
        .into_iter()
        .filter(|pr| !avoid.contains(&pr.ip))
        .take(want)
        .collect();

    if picked.is_empty() {
        return Err(AetherError::NoCleanEndpoint);
    }

    for pr in &picked {
        log::info!(
            "[+] selected WireGuard endpoint {}:{} (rtt {:?})",
            pr.ip,
            pr.port,
            pr.rtt
        );
    }

    Ok(picked
        .into_iter()
        .map(|pr| SocketAddr::new(pr.ip, pr.port))
        .collect())
}

async fn resolve_ech() -> Option<Vec<u8>> {
    match std::env::var("AETHER_ECH") {
        Ok(v) if v.eq_ignore_ascii_case("auto") => match dns::fetch_ech_config().await {
            Ok(raw) => {
                log::info!(
                    "[+] fetched ECHConfigList automatically ({} bytes)",
                    raw.len()
                );
                Some(raw)
            }
            Err(e) => {
                log::warn!("[-] ECH auto-fetch failed ({e}); continuing without ECH");
                None
            }
        },
        Ok(b64) if !b64.is_empty() => match tls::decode_ech_config_list(&b64) {
            Ok(v) => {
                log::info!("[+] using ECHConfigList from AETHER_ECH");
                Some(v)
            }
            Err(e) => {
                log::warn!("[-] bad AETHER_ECH: {e}; continuing without ECH");
                None
            }
        },
        _ => {
            log::info!("[+] ECH disabled (warp masque endpoint does not accept ECH); SNI sent in cleartext");
            None
        }
    }
}

fn masque_reconnect_delay() -> std::time::Duration {
    let secs = std::env::var("AETHER_MASQUE_RECONNECT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(2);
    std::time::Duration::from_secs(secs)
}

fn masque_startup_timeout() -> std::time::Duration {
    let secs = std::env::var("AETHER_MASQUE_STARTUP_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(30);
    std::time::Duration::from_secs(secs)
}

async fn hunt_masque_peer(
    identity: &account::Identity,
    mode_str: &str,
    ip: prober::IpScan,
) -> Result<SocketAddr> {
    log::info!(
        "[*] hunting for a working MASQUE gateway (deep connect-ip + data-plane verification)"
    );
    let mode = prober::ScanMode::parse(mode_str);
    let probe = prober::MasqueProbe {
        sni: consts::CONNECT_SNI.to_string(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: std::sync::Arc::from(identity.cert_pem.clone()),
        key_pem: std::sync::Arc::from(identity.key_pem.clone()),
        ech_config_list: None,
        noize: noize_config(),
        ports: prober::MASQUE_PORTS.to_vec(),
        ip,
        local_ipv4: parse_local_v4(&identity.ipv4),
    };

    let best = prober::hunt_best_gateway(&probe, mode).await?;
    log::info!(
        "[+] selected MASQUE gateway {}:{} (rtt {:?})",
        best.ip,
        best.port,
        best.rtt
    );
    Ok(SocketAddr::new(best.ip, best.port))
}

/// How good a CACHED endpoint has to be before `--quick-reconnect` reuses it
/// instead of scanning.
///
/// ## 1.2.3-p1: quick reconnect reused any cached endpoint that still answered
///
/// However slow it had become. TCP throughput is inversely proportional to RTT,
/// so a session pinned to a cached edge three times slower than what is currently
/// available downloads roughly three times slower - for as long as the cache
/// survives, silently, with a healthy tunnel and no error anywhere. In chained
/// `Aether -> Psiphon` mode that penalty is paid on both hops, which is why the
/// chained mode felt worse than plain even though both were slow.
///
/// A cached endpoint is now only reused when it is not merely alive but still
/// FAST. Over budget, the cache is skipped and a normal scan runs: that costs a
/// few seconds once, and the better endpoint it finds is what gets re-cached.
/// Discarding the cache is also registered as a FLOOR
/// (`wg_prober::set_rtt_floor`), so a scan that fails to beat it hands the cached
/// endpoint back rather than committing the session to something worse - the bet
/// can only win or break even.
///
/// Budgets come from `AETHER_QUICK_RECONNECT_MAX_RTT_MS` for the WireGuard/WARP*2
/// data-plane probe and `AETHER_QUICK_RECONNECT_MAX_HANDSHAKE_MS` for the MASQUE
/// probe (a full QUIC/TLS handshake, therefore several times one RTT). Set either
/// to `0` to disable the check and restore the previous behaviour exactly.
fn env_budget_ms(name: &str, default_ms: u64) -> Option<std::time::Duration> {
    match std::env::var(name) {
        Ok(raw) => raw
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|ms| *ms > 0)
            .map(std::time::Duration::from_millis),
        Err(_) => Some(std::time::Duration::from_millis(default_ms)),
    }
}

fn within_budget(
    peer: SocketAddr,
    measured: std::time::Duration,
    budget: Option<std::time::Duration>,
    what: &str,
) -> bool {
    match budget {
        Some(limit) if measured > limit => {
            log::warn!(
                "[-] cached endpoint {peer} answered but is slow ({what} {:?} over the {:?} budget); ignoring the cache and scanning for a faster endpoint",
                measured,
                limit
            );
            false
        }
        _ => true,
    }
}

/// Data-plane RTT budget (WireGuard / WARP*2 cached endpoint).
fn cached_peer_fast_enough(peer: SocketAddr, rtt: std::time::Duration) -> bool {
    within_budget(
        peer,
        rtt,
        env_budget_ms(
            "AETHER_QUICK_RECONNECT_MAX_RTT_MS",
            wg_prober::DEFAULT_GOOD_RTT_MS,
        ),
        "rtt",
    )
}

// >>> AETHER-APP-PATCH keep-the-working-cached-endpoint
/// آیا یک endpointِ کارکن ولی کند باید دور انداخته شود و اسکن راه بیفتد؟
///
/// پیش‌فرض: نه — ثانیه‌هایی که کاربر پای دکمهٔ Connect می‌نشیند از چند صد
/// میلی‌ثانیه RTT گران‌ترند، و لاگ نشان داد که این اسکن معمولاً چیزی بهتر
/// پیدا نمی‌کند. برای عیب‌یابی می‌توان با env برگرداندش.
fn rescan_when_cache_is_slow() -> bool {
    std::env::var("AETHER_QUICK_RECONNECT_RESCAN_SLOW")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            v == "1" || v == "true" || v == "yes"
        })
        .unwrap_or(false)
}
// <<< AETHER-APP-PATCH keep-the-working-cached-endpoint

/// Handshake budget (MASQUE cached gateway; one QUIC/TLS setup, not one RTT).
fn cached_handshake_fast_enough(peer: SocketAddr, elapsed: std::time::Duration) -> bool {
    within_budget(
        peer,
        elapsed,
        env_budget_ms("AETHER_QUICK_RECONNECT_MAX_HANDSHAKE_MS", 1_500),
        "handshake",
    )
}

fn lastconn_path(config_path: &str) -> String {
    derive_sibling_path(config_path, "lastconn")
}

// >>> AETHER-APP-FIX a-nested-tunnel-remembers-its-edge
/// Where warp-in-warp remembers its outer edge.
///
/// Deliberately not `lastconn_path`, even though both hold a WireGuard endpoint
/// discovered with the same identity. Plain WireGuard stores the obfuscation
/// profile that worked and *varies* it across retries; the nested tunnels raise
/// their outer hop with one fixed profile and never vary it. Sharing a file
/// would mean each protocol reading back a peer that was validated under
/// settings the other never used — and then treating that as proof.
fn gool_lastconn_path(config_path: &str) -> String {
    derive_sibling_path(config_path, "gool-lastconn")
}

/// Where masque-in-masque remembers its outer edge.
///
/// Its own file for the same reason GOOL has one: the peer is a MASQUE edge,
/// validated by a MASQUE handshake, and a WireGuard cache has nothing useful to
/// say about it.
fn mim_lastconn_path(config_path: &str) -> String {
    derive_sibling_path(config_path, "mim-lastconn")
}
// <<< AETHER-APP-FIX a-nested-tunnel-remembers-its-edge

/// Fallback verification timeout for peers that are NOT subject to the quick
/// reconnect handshake budget (a forced peer, an organization-assigned endpoint,
/// or the last known-good gateway of a live session).
const PEER_VERIFY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// How long to wait when verifying the CACHED gateway.
///
/// ## 1.2.3-p3: waiting longer than the budget can only ever waste the wait
///
/// The cached gateway was verified with a flat 5 s timeout, and then
/// [`cached_handshake_fast_enough`] threw the result away if the handshake had
/// taken more than 1.5 s. So every second between 1.5 s and 5 s was spent
/// waiting for an answer that was already guaranteed to be rejected - three and a
/// half seconds of connect latency, per attempt, with no outcome that could
/// possibly benefit from it. On the ladder in the field log that ran twice before
/// the successful rung.
///
/// The wait is now the budget plus a little slack for scheduling. If the user
/// disables the budget entirely (`AETHER_QUICK_RECONNECT_MAX_HANDSHAKE_MS=0`)
/// there is no cut-off to align with, so the old 5 s is kept exactly.
fn cached_verify_timeout() -> std::time::Duration {
    match env_budget_ms("AETHER_QUICK_RECONNECT_MAX_HANDSHAKE_MS", 1_500) {
        Some(budget) => (budget + std::time::Duration::from_millis(500)).min(PEER_VERIFY_TIMEOUT),
        None => PEER_VERIFY_TIMEOUT,
    }
}

async fn quick_verify_masque_peer(identity: &account::Identity, peer: SocketAddr) -> bool {
    verify_masque_peer_within(identity, peer, PEER_VERIFY_TIMEOUT).await
}

async fn verify_masque_peer_within(
    identity: &account::Identity,
    peer: SocketAddr,
    timeout: std::time::Duration,
) -> bool {
    let vp = quic::VerifyParams {
        peer,
        sni: consts::CONNECT_SNI.to_string(),
        authority: quic::default_authority().to_string(),
        path: quic::default_path().to_string(),
        cert_pem: identity.cert_pem.clone(),
        key_pem: identity.key_pem.clone(),
        ech_config_list: None,
        noize: noize_config(),
        timeout,
        local_ipv4: parse_local_v4(&identity.ipv4),
    };

    if masque_h2::enabled() {
        let cfg = masque_h2::H2TunnelConfig {
            peer: masque_h2::h2_peer(peer),
            sni: consts::CONNECT_SNI.to_string(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            local_ipv4: parse_local_v4(&identity.ipv4),
            quiet: true,
            pin_endpoint: true,
            expected_pins: consts::MASQUE_PINS.iter().map(|p| p.to_vec()).collect(),
        };
        return masque_h2::verify_h2(&cfg, timeout).await.is_ok();
    }

    quic::verify_masque(&vp).await.is_ok()
}

async fn want_quick_reconnect(cached: &lastconn::LastConnection) -> bool {
    match std::env::var("AETHER_QUICK_RECONNECT").as_deref() {
        Ok("1") | Ok("true") | Ok("yes") | Ok("on") => return true,
        Ok("0") | Ok("false") | Ok("no") | Ok("off") => return false,
        _ => {}
    }

    let answer = prompt_line(&format!(
        "\nLast working gateway: {} (profile '{}')\nReconnect to it now without rescanning? [Y/n]: ",
        cached.peer, cached.profile
    ))
    .await;

    !matches!(answer.as_deref(), Some(a) if a.eq_ignore_ascii_case("n") || a.eq_ignore_ascii_case("no"))
}

async fn run_masque(
    identity: account::Identity,
    ech: Option<Vec<u8>>,
    listen: SocketAddr,
    lastconn_path: String,
) -> Result<()> {
    let forced = std::env::var("AETHER_PEER").ok();

    let mut quick_peer: Option<SocketAddr> = None;

    if forced.is_none() {
        if let Some(assigned) = std::env::var("AETHER_TEAM_ENDPOINT")
            .ok()
            .and_then(|value| value.parse::<SocketAddr>().ok())
        {
            log::info!("[*] verifying the endpoint the organization assigned: {assigned}");
            if quick_verify_masque_peer(&identity, assigned).await {
                log::info!("[+] the assigned endpoint {assigned} works; skipping the scan");
                quick_peer = Some(assigned);
            } else {
                log::warn!(
                    "[-] the assigned endpoint {assigned} did not answer; falling back to scanning"
                );
            }
        }
    }

    if forced.is_none() && quick_peer.is_none() {
        if let Some(cached) = lastconn::load(&lastconn_path) {
            if let Ok(peer) = cached.peer.parse::<SocketAddr>() {
                if want_quick_reconnect(&cached).await {
                    let verify_timeout = cached_verify_timeout();
                    log::info!(
                        "[*] verifying cached gateway {peer} before reuse (up to {:?}, matched to the handshake budget)",
                        verify_timeout
                    );
                    let quick_probe_started = std::time::Instant::now();
                    if verify_masque_peer_within(&identity, peer, verify_timeout).await {
                        log::info!("[+] cached gateway {peer} still works; skipping scan");
                        quick_peer = Some(peer);
                        if !cached_handshake_fast_enough(peer, quick_probe_started.elapsed()) {
                            quick_peer = None;
                        }
                    } else {
                        log::warn!("[-] cached gateway {peer} no longer works; scanning fresh");
                    }
                }
            }
        }
    }

    let (mode_str, ip) = if forced.is_some() || quick_peer.is_some() {
        scan_settings_from_env()
    } else {
        let mode_str = select_scan_mode_str("").await;
        let ip = select_ip_version().await;
        (mode_str, ip)
    };

    let mut last_good_peer: Option<SocketAddr> = None;

    loop {
        let peer = if let Some(p) = quick_peer.take() {
            p
        } else {
            let retried = match last_good_peer {
                Some(p) => {
                    log::info!("[*] retrying last known-good gateway {p} before rescanning");
                    if quick_verify_masque_peer(&identity, p).await {
                        Some(p)
                    } else {
                        log::warn!(
                            "[-] last known-good gateway {p} no longer responds; rescanning"
                        );
                        None
                    }
                }
                None => None,
            };

            match retried {
                Some(p) => p,
                None => match &forced {
                    Some(p) => match p.parse::<SocketAddr>() {
                        Ok(peer) => {
                            log::info!("[+] using forced peer {peer} (probe skipped)");
                            peer
                        }
                        Err(_) => return Err(AetherError::Other(format!("bad peer address {p}"))),
                    },
                    None => match hunt_masque_peer(&identity, &mode_str, ip).await {
                        Ok(peer) => peer,
                        Err(e) => {
                            log::warn!(
                                "[-] no usable MASQUE gateway found: {e}; rescanning shortly"
                            );
                            tokio::time::sleep(masque_reconnect_delay()).await;
                            continue;
                        }
                    },
                },
            }
        };

        log::info!("[+] using cloudflare edge {peer}");

        if forced.is_none() {
            let profile = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "firewall".to_string());
            lastconn::save(&lastconn_path, &peer.to_string(), &profile);
        }

        last_good_peer = Some(peer);

        match run_masque_tunnel(&identity, peer, ech.clone(), listen).await {
            Ok(()) => log::warn!("[-] MASQUE tunnel closed; reconnecting"),
            Err(e) => log::warn!("[-] MASQUE tunnel ended: {e}; reconnecting"),
        }

        tokio::time::sleep(masque_reconnect_delay()).await;
    }
}

struct MasqueHop {
    stack: netstack::StackHandle,
    exit: TunnelExit,
    _ctrl: tokio::sync::mpsc::Sender<quic::Control>,
    _guard: TaskGuard,
}

#[allow(clippy::too_many_arguments)]
async fn establish_masque(
    identity: &account::Identity,
    peer: SocketAddr,
    ech: Option<Vec<u8>>,
    h2: bool,
    mtu: usize,
    datagram: usize,
    version_bait: bool,
    startup: std::time::Duration,
    label: &str,
) -> Result<MasqueHop> {
    let (chans, internals) = quic::channels();
    let quic::Channels {
        outbound_tx,
        inbound_rx,
        ctrl_tx,
    } = chans;

    let stack = netstack::spawn(&identity.ipv4, &identity.ipv6, mtu, inbound_rx, outbound_tx)?;

    let mut guard = TaskGuard::new();

    let (addr_tx, mut addr_rx) = tokio::sync::mpsc::channel::<quic::AssignedAddr>(8);
    let bridge_stack = stack.clone();
    let bridge_task = tokio::spawn(async move {
        while let Some(a) = addr_rx.recv().await {
            let res = match a.ip {
                IpAddr::V4(v4) => bridge_stack.set_addrs(Some((v4, a.prefix)), None).await,
                IpAddr::V6(v6) => bridge_stack.set_addrs(None, Some((v6, a.prefix))).await,
            };
            if let Err(e) = res {
                log::warn!("[-] failed to sync edge address into netstack: {e}");
            }
        }
    });
    guard.push(bridge_task.abort_handle());

    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();

    let tunnel_task = if h2 {
        let h2cfg = masque_h2::H2TunnelConfig {
            peer,
            sni: consts::CONNECT_SNI.to_string(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            local_ipv4: parse_local_v4(&identity.ipv4),
            quiet: false,
            pin_endpoint: true,
            expected_pins: consts::MASQUE_PINS.iter().map(|p| p.to_vec()).collect(),
        };
        log::info!("[+] [{label}] MASQUE transport: HTTP/2 (TCP) to {peer} (inner mtu {mtu})");
        tokio::spawn(masque_h2::run(
            h2cfg,
            internals,
            Some(addr_tx),
            Some(ready_tx),
        ))
    } else {
        let cfg = quic::TunnelConfig {
            peer,
            sni: consts::CONNECT_SNI.to_string(),
            authority: quic::default_authority().to_string(),
            path: quic::default_path().to_string(),
            cert_pem: identity.cert_pem.clone(),
            key_pem: identity.key_pem.clone(),
            ech_config_list: ech,
            noize: noize_config(),
            local_ipv4: parse_local_v4(&identity.ipv4),
            quiet: false,
            max_datagram: datagram,
            version_bait,
        };
        log::info!(
            "[+] [{label}] MASQUE transport: HTTP/3 (QUIC) to {peer} (inner mtu {mtu}, datagram {})",
            cfg.datagram_budget()
        );
        tokio::spawn(quic::run(cfg, internals, Some(addr_tx), Some(ready_tx)))
    };
    guard.push(tunnel_task.abort_handle());

    let startup_timeout = startup;
    match tokio::time::timeout(startup_timeout, ready_rx).await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            let joined = tunnel_task.await;
            let msg = match joined {
                Ok(Ok(())) => format!("[{label}] tunnel exited before validation"),
                Ok(Err(e)) => format!("[{label}] tunnel failed before validation: {e}"),
                Err(e) => format!("[{label}] tunnel task join error: {e}"),
            };
            return Err(AetherError::Other(msg));
        }
        Err(_) => {
            tunnel_task.abort();
            let _ = tunnel_task.await;
            return Err(AetherError::Other(format!(
                "[{label}] tunnel startup timed out after {startup_timeout:?}"
            )));
        }
    }

    Ok(MasqueHop {
        stack,
        exit: tunnel_task,
        _ctrl: ctrl_tx,
        _guard: guard,
    })
}

async fn run_masque_tunnel(
    identity: &account::Identity,
    peer: SocketAddr,
    ech: Option<Vec<u8>>,
    listen: SocketAddr,
) -> Result<()> {
    let h2 = masque_h2::enabled();
    let dial = if h2 { masque_h2::h2_peer(peer) } else { peer };

    let mut hop = establish_masque(
        identity,
        dial,
        ech,
        h2,
        masque_tunnel_mtu(),
        quic::MAX_DATAGRAM_SIZE,
        true,
        masque_startup_timeout(),
        "masque",
    )
    .await?;

    let socks_listener = socks::bind_listener("socks5", listen).await?;
    let http_listener = bind_http_proxy().await?;

    let mut tasks = TaskGuard::new();

    let socks_stack = hop.stack.clone();
    let socks_task = tokio::spawn(async move { socks::serve(socks_listener, socks_stack).await });
    tasks.push(socks_task.abort_handle());

    let http_task = spawn_http_proxy(http_listener, &hop.stack);
    if let Some(task) = &http_task {
        tasks.push(task.abort_handle());
    }

    let tunnel_result = (&mut hop.exit).await;

    if let Some(task) = &http_task {
        task.abort();
    }
    socks_task.abort();

    match tunnel_result {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err(AetherError::Other(format!("tunnel exited: {e}"))),
        Err(e) => Err(AetherError::Other(format!("tunnel task join error: {e}"))),
    }
}

const MASQUE_DATAGRAM_OVERHEAD: usize = quic::MAX_DATAGRAM_SIZE - TUNNEL_MTU;

fn mim_inner_budget(outer_mtu: usize, inner_peer: SocketAddr, h2: bool) -> (usize, usize) {
    if h2 {
        let mtu = outer_mtu.saturating_sub(100).clamp(576, 1500);
        return (quic::MAX_DATAGRAM_SIZE, mtu);
    }

    let headers = if inner_peer.is_ipv4() { 28 } else { 48 };
    let datagram = outer_mtu
        .saturating_sub(headers)
        .clamp(quic::MIN_DATAGRAM_SIZE, quic::MAX_DATAGRAM_SIZE);
    let mtu = datagram
        .saturating_sub(MASQUE_DATAGRAM_OVERHEAD)
        .clamp(576, 1500);
    (datagram, mtu)
}

const MASQUE_INNER_PORT: u16 = 443;
const MIM_INNER_TRIES: usize = 6;

fn mim_inner_startup() -> std::time::Duration {
    masque_startup_timeout().min(std::time::Duration::from_secs(12))
}

/// Candidate edges for the inner hop of MASQUE-in-MASQUE.
///
/// ## The order matters, and it used to be random
///
/// The old body picked six hosts uniformly at random inside the outer hop's
/// `/24`, which is not a pool of MASQUE edges - it is just an address block. On
/// the 2026-09-22 log that produced four straight TLS `handshake_failure`
/// results (QUIC `0x128`, i.e. `CRYPTO_ERROR` carrying alert 40) against
/// `.153`, `.235`, `.216` and `.46`, none of which serve the MASQUE hostname,
/// while the outer hop was happily running against `.2` of the same block.
///
/// The pool is now, in order:
///
/// 1. **Edges this session has already proven** ([`prober::proven_gateways`]) -
///    each one completed a real MASQUE handshake moments ago.
/// 2. **The documented MASQUE seed pool** ([`prober::MASQUE_SEEDS`]) - the same
///    addresses the outer scan trusts, minus the outer hop itself.
///
/// And nothing else. The random `/24` tier that used to sit at the bottom is
/// gone, not merely demoted. *"Never a random guess"* is the rule the mobile
/// core arrived at after the same defect, and the reason it applies here is
/// that a tier only reached when the real pools run dry is reached precisely
/// when the network is at its most hostile - which is when guessing costs the
/// most.
///
/// A short pool is no longer a problem. When both tiers come up empty the list
/// is empty, and [`order_inner_candidates`] answers by appending the outer hop
/// itself: one address this network has *proven* it can reach, instead of six
/// it has not.
///
/// The outer hop is still excluded from these two tiers, because a nested
/// pipeline prefers a second edge. What changed is that "second edge" now means
/// *a known edge other than the first*, instead of *an arbitrary address*.
fn inner_masque_candidates(outer: SocketAddr, count: usize) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    let mut seen: HashSet<SocketAddr> = HashSet::new();
    let want_v6 = outer.is_ipv6();

    let mut push = |out: &mut Vec<SocketAddr>, seen: &mut HashSet<SocketAddr>, addr: SocketAddr| {
        if addr.ip() == outer.ip() || out.len() >= count {
            return;
        }
        if seen.insert(addr) {
            out.push(addr);
        }
    };

    // >>> AETHER-APP-FIX an-inner-hop-wants-a-proven-edge
    // 1) Proven this session.
    for addr in prober::proven_gateways() {
        if addr.is_ipv6() == want_v6 {
            push(&mut out, &mut seen, addr);
        }
    }

    // 2) The documented seed pool for this address family.
    let seeds: &[&str] = if want_v6 {
        prober::MASQUE_SEEDS_V6
    } else {
        prober::MASQUE_SEEDS
    };
    for seed in seeds {
        if let Ok(ip) = seed.parse::<IpAddr>() {
            if ip.is_ipv6() == want_v6 {
                push(&mut out, &mut seen, SocketAddr::new(ip, MASQUE_INNER_PORT));
            }
        }
    }
    // <<< AETHER-APP-FIX an-inner-hop-wants-a-proven-edge

    // >>> AETHER-APP-FIX never-a-random-guess
    // The random `/24` tier that stood here is gone rather than demoted.
    // `count` is now an upper bound, not a quota to fill: a short list is
    // correct, because every address in it has evidence behind it and the
    // outer-hop fallback in `order_inner_candidates` covers the shortfall.
    // <<< AETHER-APP-FIX never-a-random-guess

    out
}

/// Order the inner-hop candidates, keeping the outer hop as the *last* resort
/// instead of dropping it.
///
/// ## Why the outer hop is no longer excluded
///
/// [`inner_masque_candidates`] deliberately leaves the outer hop out of the pool,
/// on the reasoning that a nested pipeline wants a *second* edge. On the
/// 2026-09-22 log that reasoning cost the session. The outer hop was running
/// against `162.159.198.2` - the one address on that network *proven* to serve
/// the MASQUE hostname, with a live handshake in flight - while all six inner
/// candidates came from elsewhere and four of them answered TLS
/// `handshake_failure` (QUIC `0x128`, alert 40). The list ran out and the tunnel
/// that could have been built was thrown away.
///
/// So the rule is now: a *different* edge is still preferred and is tried first,
/// but the outer hop is kept as the final fallback. A MASQUE-in-MASQUE tunnel
/// whose two hops share an edge is still a real nested tunnel - the inner hop
/// runs inside the outer hop's netstack either way - and it is strictly better
/// than ending at "no inner masque edge answered through the outer tunnel".
///
/// The transform is deterministic and preserves input order:
///
/// * candidates whose IP differs from the outer hop keep their position;
/// * a candidate whose IP *is* the outer hop is moved to the end (there is at
///   most one, and it is the address we already know answers);
/// * if no candidate shares the outer hop's IP, the outer hop itself is appended
///   once, at the end;
/// * duplicates are removed.
///
/// Note that the outer hop is appended with its own port, not
/// [`MASQUE_INNER_PORT`]: when we fall back to it we fall back to the exact
/// endpoint that is already carrying the outer tunnel.
fn order_inner_candidates(outer: SocketAddr, candidates: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut preferred: Vec<SocketAddr> = Vec::with_capacity(candidates.len() + 1);
    let mut fallback: Option<SocketAddr> = None;

    for candidate in candidates {
        if candidate.ip() == outer.ip() {
            // Same host as the outer hop: it is the last resort, not the first
            // choice. Keep the first such entry we are handed.
            if fallback.is_none() {
                fallback = Some(*candidate);
            }
            continue;
        }
        if !preferred.contains(candidate) {
            preferred.push(*candidate);
        }
    }

    match fallback {
        Some(edge) => preferred.push(edge),
        None => preferred.push(outer),
    }

    preferred
}

async fn spawn_tcp_forwarder(
    outer: &netstack::StackHandle,
    remote: SocketAddr,
) -> Result<(SocketAddr, TaskGuard)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let local = listener.local_addr()?;
    let stack = outer.clone();

    let task = tokio::spawn(async move {
        let mut clients = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((sock, _)) = accepted else { break };
                    let stack = stack.clone();
                    clients.spawn(async move {
                        match stack.open_tcp(remote).await {
                            Ok(conn) => {
                                let (sender, from_stack) = conn.into_split();
                                socks::relay_tunneled(
                                    sock,
                                    sender,
                                    from_stack,
                                    socks::half_close_linger(),
                                )
                                .await;
                            }
                            Err(e) => log::warn!(
                                "[-] the inner hop could not reach {remote} through the outer tunnel: {e}"
                            ),
                        }
                    });
                }
                Some(_) = clients.join_next(), if !clients.is_empty() => {}
            }
        }
    });

    Ok((local, TaskGuard(vec![task.abort_handle()])))
}

// >>> AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure
/// Which hop of a masque-in-masque tunnel failed.
///
/// The distinction is the entire point of this type. Both failures used to
/// arrive as one `AetherError`, so the reconnect loop could not tell a dead
/// *outer* edge from an inner pool that simply ran out — and it answered the
/// second by blacklisting and rescanning a perfectly healthy outer. The mobile
/// core records what that costs: two inner refusals blacklisted a healthy
/// outer, the rescan storm that followed poisoned the carrier network, and
/// MASQUE never connected once that night.
///
/// The boundary is drawn where the mobile core draws it:
///
/// * raising the **outer** hop, or losing its userspace stack, is an
///   [`MimHopFailure::Outer`];
/// * every inner candidate refusing, or a mid-session death on the inner hop,
///   is an [`MimHopFailure::Inner`];
/// * one inner candidate that cannot be dialled *through the outer stack* is
///   neither. The outer stack being up is what makes it an inner-pool question
///   at all, so that candidate is skipped and the next one is tried.
#[derive(Debug)]
enum MimHopFailure {
    Outer(String),
    Inner(String),
}

impl std::fmt::Display for MimHopFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MimHopFailure::Outer(m) => write!(f, "outer hop: {m}"),
            MimHopFailure::Inner(m) => write!(f, "inner hop: {m}"),
        }
    }
}
// <<< AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure

async fn run_masque_in_masque(
    primary: &account::Identity,
    secondary: &account::Identity,
    peer: SocketAddr,
    inner_peers: &[SocketAddr],
    ech: Option<Vec<u8>>,
    listen: SocketAddr,
) -> std::result::Result<SocketAddr, MimHopFailure> {
    let h2 = masque_h2::enabled();
    let outer_mtu = masque_tunnel_mtu();

    log::info!("[*] establishing outer MASQUE tunnel to {peer}...");
    let mut outer = establish_masque(
        primary,
        peer,
        ech,
        h2,
        outer_mtu,
        quic::MAX_DATAGRAM_SIZE,
        true,
        masque_startup_timeout(),
        "outer",
    )
    .await
    .map_err(|e| MimHopFailure::Outer(e.to_string()))?;

    let mut chosen: Option<(SocketAddr, MasqueHop, TaskGuard)> = None;

    // >>> AETHER-APP-FIX an-inner-hop-wants-a-proven-edge
    let ordered = order_inner_candidates(peer, inner_peers);
    // <<< AETHER-APP-FIX an-inner-hop-wants-a-proven-edge

    for inner_peer in ordered {
        let (inner_datagram, inner_mtu) = mim_inner_budget(outer_mtu, inner_peer, h2);

        if !h2 && inner_datagram + 28 > outer_mtu {
            log::warn!(
                "[-] the outer link carries {outer_mtu} bytes, too little for an inner quic \
                 datagram; raise AETHER_MASQUE_MTU or use --h2 for both hops"
            );
        }

        // >>> AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure
        // A dial that cannot be bound through the outer stack is not a verdict
        // on the outer hop: the outer stack is up (we are standing on it) and
        // it is the thing this dial rides. So this candidate is skipped and the
        // next one is tried, instead of the whole attempt being thrown away.
        // This used to be a `?`, which turned one unreachable inner candidate
        // into a failed attempt — and, before the classification existed, into
        // a strike against the outer edge.
        let (forwarder, forwarder_guard) = if h2 {
            match spawn_tcp_forwarder(&outer.stack, inner_peer).await {
                Ok(ok) => ok,
                Err(e) => {
                    log::info!(
                        "[-] inner edge {inner_peer} could not be reached through the outer \
                         tunnel ({e}); trying the next known edge"
                    );
                    continue;
                }
            }
        } else {
            match spawn_udp_forwarder(&outer.stack, inner_peer).await {
                Ok(ok) => ok,
                Err(e) => {
                    log::info!(
                        "[-] inner edge {inner_peer} could not be reached through the outer \
                         tunnel ({e}); trying the next known edge"
                    );
                    continue;
                }
            }
        };
        // <<< AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure
        log::info!(
            "[*] trying inner MASQUE edge {inner_peer} through the outer tunnel via {forwarder}"
        );

        match establish_masque(
            secondary,
            forwarder,
            None,
            h2,
            inner_mtu,
            inner_datagram,
            false,
            mim_inner_startup(),
            "inner",
        )
        .await
        {
            Ok(hop) => {
                log::info!("[+] inner MASQUE tunnel established through {inner_peer}");
                chosen = Some((inner_peer, hop, forwarder_guard));
                break;
            }
            // >>> AETHER-APP-FIX an-inner-hop-wants-a-proven-edge
            // The old wording - "does not serve masque from inside the tunnel" -
            // asserted a conclusion the log did not support. When the edge
            // rejects the TLS handshake (QUIC `CRYPTO_ERROR`, 0x100-0x1ff, low
            // byte = the TLS alert) that is a statement about *this address*,
            // not about MASQUE-over-WARP being impossible. Naming the actual
            // failure is what makes the next log diagnosable.
            Err(e) => {
                let detail = e.to_string();
                if let Some(alert) = quic::tls_alert_in(&detail) {
                    log::info!(
                        "[-] inner edge {inner_peer} refused the TLS handshake (alert {alert}); \
                         trying the next known edge"
                    );
                } else {
                    log::info!(
                        "[-] inner edge {inner_peer} did not complete a MASQUE handshake: {detail}"
                    );
                }
            }
            // <<< AETHER-APP-FIX an-inner-hop-wants-a-proven-edge
        }
    }

    let Some((inner_peer, mut inner, _forwarder_guard)) = chosen else {
        // >>> AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure
        // Every candidate refused. The outer hop answered CONNECT-IP moments
        // ago, so this is an inner-pool failure and must be attributed as one —
        // otherwise the reconnect loop blacklists and rescans a healthy outer.
        return Err(MimHopFailure::Inner(
            "no inner masque edge answered through the outer tunnel".into(),
        ));
        // <<< AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure
    };

    // >>> AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure
    // Both hops are up at this point; what can still fail here is local
    // (a listener that cannot bind). Attributed to the inner hop on purpose:
    // it keeps the outer edge, which has just proven itself, out of the
    // blacklist for a fault that was never its own.
    let socks_listener = socks::bind_listener("socks5", listen)
        .await
        .map_err(|e| MimHopFailure::Inner(e.to_string()))?;
    let http_listener = bind_http_proxy()
        .await
        .map_err(|e| MimHopFailure::Inner(e.to_string()))?;
    // <<< AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure

    let mut tasks = TaskGuard::new();
    let http_task = spawn_http_proxy(http_listener, &inner.stack);
    if let Some(task) = &http_task {
        tasks.push(task.abort_handle());
    }

    let socks_stack = inner.stack.clone();
    let mut socks_task =
        tokio::spawn(async move { socks::serve(socks_listener, socks_stack).await });
    tasks.push(socks_task.abort_handle());

    log::info!("[+] masque-in-masque ready: {peer} (outer) and {inner_peer} (inner)");

    #[derive(PartialEq)]
    enum Winner {
        Outer,
        Inner,
        Socks,
    }

    let (outcome, winner) = tokio::select! {
        result = &mut outer.exit => (join_outcome("outer masque tunnel", result), Winner::Outer),
        result = &mut inner.exit => (join_outcome("inner masque tunnel", result), Winner::Inner),
        result = &mut socks_task => (join_outcome("socks5 server", result), Winner::Socks),
    };

    if winner != Winner::Outer {
        outer.exit.abort();
        let _ = (&mut outer.exit).await;
    }
    if winner != Winner::Inner {
        inner.exit.abort();
        let _ = (&mut inner.exit).await;
    }
    if winner != Winner::Socks {
        socks_task.abort();
        let _ = (&mut socks_task).await;
    }

    // >>> AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure
    // A session that ends was still a WORKING session: it carried traffic
    // through both hops. So the chosen inner edge is reported back on success —
    // the caller remembers it — and a mid-session death is attributed to the
    // hop that died, so the hop that was healthy is not rescanned because of it.
    //
    // `Socks` counts as inner for the same reason the mobile core counts its
    // local listener as inner: the failure is inside the tunnel we built, not a
    // statement about the edge that carries it.
    match outcome {
        Ok(()) => Ok(inner_peer),
        Err(e) => Err(match winner {
            Winner::Outer => MimHopFailure::Outer(e.to_string()),
            Winner::Inner | Winner::Socks => MimHopFailure::Inner(e.to_string()),
        }),
    }
    // <<< AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure
}

async fn run_mim(
    primary: account::Identity,
    secondary: account::Identity,
    ech: Option<Vec<u8>>,
    listen: SocketAddr,
    lastconn_path: String,
) -> Result<()> {
    let pinned = mim_endpoints_from_env()?;

    match (pinned.outer, pinned.inner) {
        (Some(outer), Some(inner)) => log::info!(
            "[+] masque-in-masque endpoints given by hand: {outer} (outer) and {inner} (inner); the scan is skipped"
        ),
        (Some(outer), None) => log::info!(
            "[+] outer masque-in-masque endpoint given by hand: {outer}; the inner one is chosen for you"
        ),
        (None, Some(inner)) => log::info!(
            "[+] inner masque-in-masque endpoint given by hand: {inner}; scanning for the outer one"
        ),
        (None, None) => {}
    }

    let mut outer_peer = pinned.outer;
    // No longer `mut`: the inner hop is not blacklisted by a counter any more,
    // so a hand-picked inner endpoint stays picked. Inner variation happens
    // through the candidate pool and `last_inner` instead.
    let inner_peer = pinned.inner;
    let mut consecutive_fails: u32 = 0;
    let mut scan_settings: Option<(String, prober::IpScan)> = None;
    const MAX_CONSECUTIVE_FAILS: u32 = 2;
    // >>> AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure
    // The inner edge that last carried a session through this outer. It is the
    // strongest evidence the pool can hold — it was chosen, and it worked — so
    // the next attempt tries it first. Dropped the moment an inner hop fails,
    // because then it may be the dead one. See [`MimHopFailure`].
    let mut last_inner: Option<SocketAddr> = None;
    // <<< AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure

    // >>> AETHER-APP-FIX a-nested-tunnel-remembers-its-edge
    // The outer MASQUE edge that worked last time, read back from a previous
    // run and re-verified before use — same shape as `run_gool`'s cache, and
    // skipped when the user named an endpoint.
    let mut cached_peer = if pinned.outer.is_none() {
        load_cached_mim_peer(&lastconn_path, &primary).await
    } else {
        None
    };
    // <<< AETHER-APP-FIX a-nested-tunnel-remembers-its-edge

    loop {
        if consecutive_fails >= MAX_CONSECUTIVE_FAILS {
            // >>> AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure
            // This counter now moves on *outer* failures only, so the edge it
            // blacklists is the edge that actually failed. The inner hop is not
            // blacklisted here any more: an inner refusal drops the remembered
            // inner edge and lets the pool vary, which is the change
            // [`MimHopFailure`] exists to make. Before it, this block also
            // discarded a hand-picked inner endpoint after two failures of any
            // kind — including two failures that were the outer hop's fault.
            if pinned.outer.is_none() {
                if let Some(peer) = outer_peer.take() {
                    log::warn!(
                        "[-] outer edge {peer} failed {consecutive_fails} times in a row; rescanning"
                    );
                }
            }
            // <<< AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure
            // >>> AETHER-APP-FIX a-nested-tunnel-remembers-its-edge
            // A blacklisted edge must not come back through the cache on the
            // next turn of this loop.
            cached_peer = None;
            // <<< AETHER-APP-FIX a-nested-tunnel-remembers-its-edge
            consecutive_fails = 0;
        }

        let outer = match outer_peer.or(cached_peer) {
            Some(peer) => peer,
            None => {
                let (mode_str, ip) = match &scan_settings {
                    Some(settings) => settings.clone(),
                    None => {
                        let mode_str = select_scan_mode_str(MIM_MANUAL_TIP).await;
                        let ip = select_ip_version().await;
                        scan_settings.insert((mode_str, ip)).clone()
                    }
                };

                match hunt_masque_peer(&primary, &mode_str, ip).await {
                    Ok(peer) => peer,
                    Err(e) => {
                        log::warn!("[-] no usable MASQUE gateway found: {e}; rescanning shortly");
                        tokio::time::sleep(masque_reconnect_delay()).await;
                        continue;
                    }
                }
            }
        };

        // >>> AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure
        let candidates = match inner_peer {
            Some(peer) => vec![peer],
            None => {
                let pool = inner_masque_candidates(outer, MIM_INNER_TRIES);
                // The inner edge that already carried a session through this
                // outer goes first — it is the strongest evidence the pool can
                // hold. Prepended only when it is absent, so the list stays
                // duplicate-free.
                match last_inner {
                    Some(preferred) if !pool.iter().any(|candidate| *candidate == preferred) => {
                        std::iter::once(preferred).chain(pool).collect()
                    }
                    _ => pool,
                }
            }
        };

        // An empty pool is no longer fatal. It used to `return Err`, which
        // ended the entire reconnect loop over a pool that
        // [`order_inner_candidates`] can still fill with the outer edge — the
        // one address on this network already known to answer.
        if candidates.is_empty() {
            log::warn!(
                "[-] no verified inner edge is known; falling back to the outer edge {outer}"
            );
        }
        // <<< AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure

        outer_peer = Some(outer);

        // >>> AETHER-APP-FIX a-nested-tunnel-remembers-its-edge
        // Saved before the tunnel is raised, for the same reason `run_gool`
        // does it here: the outer edge has already answered a MASQUE pre-flight
        // by this point, and `run_masque_in_masque` only returns when the whole
        // session ends.
        if pinned.outer.is_none() {
            lastconn::save(&lastconn_path, &outer.to_string(), &lastconn::MIM_OUTER_PROFILE);
        }
        // <<< AETHER-APP-FIX a-nested-tunnel-remembers-its-edge

        // >>> AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure
        match run_masque_in_masque(
            &primary,
            &secondary,
            outer,
            &candidates,
            ech.clone(),
            listen,
        )
        .await
        {
            Ok(inner_edge) => {
                log::warn!(
                    "[-] masque-in-masque session through {outer}/{inner_edge} ended; reconnecting"
                );
                // It carried traffic, so the inner edge it chose is worth
                // remembering even though the session ended.
                last_inner = Some(inner_edge);
                consecutive_fails = 0;
            }
            Err(MimHopFailure::Outer(e)) => {
                // Only a genuinely dead OUTER hop pays here. This is the
                // counter that used to move on a failure of any kind: two inner
                // refusals blacklisted a healthy outer and started the scan
                // storm that took the carrier network down with it.
                log::warn!("[-] outer hop {outer} failed — {e}; reconnecting");
                consecutive_fails += 1;
            }
            Err(MimHopFailure::Inner(e)) => {
                // Inner failure with a live outer: keep the outer, drop the
                // remembered inner (it may be the dead one), retry soon. The
                // counter deliberately does not move — the outer edge is not
                // what failed, and blacklisting it is the bug this fixes.
                log::warn!("[-] inner hop failed — {e}; keeping outer edge {outer}");
                if let Some(known) = last_inner.take() {
                    log::warn!("[-] dropping remembered inner edge {known}");
                }
            }
        }
        // <<< AETHER-APP-FIX an-inner-refusal-is-not-an-outer-failure

        tokio::time::sleep(masque_reconnect_delay()).await;
    }
}

fn wg_keepalive_secs() -> u16 {
    std::env::var("AETHER_WG_KEEPALIVE")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|&v| v > 0)
        .unwrap_or(5)
}

fn wg_profile_candidates() -> Vec<(String, aethernoize::AetherNoizeConfig)> {
    let primary = std::env::var("AETHER_NOIZE").unwrap_or_else(|_| "balanced".to_string());
    log::info!("[+] aethernoize primary profile: {primary}");

    let mut names = vec![primary.clone()];
    if std::env::var("AETHER_WG_NO_PROFILE_RETRY").is_err() {
        for fallback in ["balanced", "aggressive", "light", "off"] {
            if !names.iter().any(|n| n.eq_ignore_ascii_case(fallback)) {
                names.push(fallback.to_string());
            }
        }
    }

    names
        .into_iter()
        .map(|n| {
            let cfg = aethernoize::from_profile(&n);
            (n, cfg)
        })
        .collect()
}

async fn hunt_wg_peer_with_profile(
    identity: &account::Identity,
    mode_str: &str,
    ip: prober::IpScan,
    profile: aethernoize::AetherNoizeConfig,
    excluded: &HashSet<SocketAddr>,
) -> Result<SocketAddr> {
    let mode = wg_prober::WgScanMode::parse(mode_str);
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;

    let probe = wg_prober::WgProbe {
        private_key: std::sync::Arc::new(private_key),
        peer_public_key: std::sync::Arc::new(peer_public),
        client_id: identity.client_id,
        local_ipv4: identity
            .ipv4
            .parse()
            .map_err(|_| AetherError::Other("invalid ipv4".into()))?,
        aethernoize: profile,
        ports: wireguard::WG_PORTS.to_vec(),
        ip,
        excluded: excluded.clone(),
    };

    let best = wg_prober::hunt_best_wg_endpoint(&probe, mode).await?;
    Ok(SocketAddr::new(best.ip, best.port))
}

fn wg_reconnect_delay() -> std::time::Duration {
    let secs = std::env::var("AETHER_WG_RECONNECT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(2);
    std::time::Duration::from_secs(secs)
}

fn wg_endpoint_cooldown() -> std::time::Duration {
    let secs = std::env::var("AETHER_WG_ENDPOINT_COOLDOWN_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(300);
    std::time::Duration::from_secs(secs)
}

async fn hunt_wg_peer(
    identity: &account::Identity,
    candidates: &[(String, aethernoize::AetherNoizeConfig)],
    mode_str: &str,
    ip: prober::IpScan,
    excluded: &HashSet<SocketAddr>,
) -> Result<(SocketAddr, aethernoize::AetherNoizeConfig, String)> {
    let multi = candidates.len() > 1;
    for (name, profile) in candidates {
        log::info!(
            "[*] hunting for a working WireGuard endpoint (handshake + data-plane verification, aethernoize='{name}')"
        );
        match hunt_wg_peer_with_profile(identity, mode_str, ip, profile.clone(), excluded).await {
            Ok(peer) => {
                log::info!(
                    "[+] selected WireGuard endpoint {peer} using aethernoize profile '{name}'"
                );
                return Ok((peer, profile.clone(), name.clone()));
            }
            Err(e) => {
                if multi {
                    log::warn!("[-] profile '{name}' found no data-plane endpoint: {e}; trying next profile");
                } else {
                    log::warn!("[-] profile '{name}' found no data-plane endpoint: {e}");
                }
            }
        }
    }
    Err(AetherError::NoCleanEndpoint)
}

async fn run_wireguard(
    identity: account::Identity,
    listen: SocketAddr,
    lastconn_path: String,
) -> Result<()> {
    let candidates = wg_profile_candidates();

    let forced = std::env::var("AETHER_WG_PEER")
        .ok()
        .or_else(|| std::env::var("AETHER_PEER").ok());

    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;

    let mut quick: Option<(SocketAddr, aethernoize::AetherNoizeConfig, String)> = None;

    if forced.is_none() {
        if let Some(assigned) = std::env::var("AETHER_TEAM_ENDPOINT")
            .ok()
            .and_then(|value| value.parse::<SocketAddr>().ok())
        {
            log::info!("[*] verifying the endpoint the organization assigned: {assigned}");
            for (name, profile) in &candidates {
                match wireguard::verify_endpoint(
                    assigned,
                    private_key,
                    peer_public,
                    identity.client_id,
                    ipv4,
                    profile,
                    std::time::Duration::from_secs(8),
                    None,
                )
                .await
                {
                    Ok(rtt) => {
                        log::info!(
                            "[+] the assigned endpoint {assigned} works with profile '{name}' (rtt {rtt:?}); skipping the scan"
                        );
                        quick = Some((assigned, profile.clone(), name.clone()));
                        break;
                    }
                    Err(e) => {
                        log::debug!(
                            "[-] assigned endpoint {assigned} failed profile '{name}': {e}"
                        );
                    }
                }
            }
            if quick.is_none() {
                log::warn!(
                    "[-] the assigned endpoint {assigned} did not pass validation; falling back to scanning"
                );
            }
        }
    }

    // >>> AETHER-APP-PATCH scan-once-after-a-slow-cache
    // اگر این نشست یک کشِ کند را به‌هرحال پذیرفت، نشستِ بعدی باید بداند.
    let mut accepted_slow: Option<(SocketAddr, std::time::Duration)> = None;
    // <<< AETHER-APP-PATCH scan-once-after-a-slow-cache

    if forced.is_none() && quick.is_none() {
        if let Some(cached) = lastconn::load(&lastconn_path) {
            if let Ok(peer) = cached.peer.parse::<SocketAddr>() {
                // >>> AETHER-APP-PATCH scan-once-after-a-slow-cache
                // کشی که دفعهٔ پیش کند بود دوباره بی‌چون‌وچرا برداشته نمی‌شود:
                // یک اسکن می‌خریم و floor تضمین می‌کند اگر چیزی بهتر نبود، همین
                // برگردد. پس در بدترین حالت هزینه‌اش یک اسکن در میانِ دو نشست است،
                // نه در هر نشست — و همان وعده‌ای است که لاگ الان می‌دهد و عمل نمی‌کند.
                if cached.slow_rtt_ms > 0 {
                    let slow = std::time::Duration::from_millis(cached.slow_rtt_ms);
                    wg_prober::set_rtt_floor(peer, slow);
                    log::info!(
                        "[*] last session settled for {peer} at {:?}, over the budget; this session \
                         spends one scan trying to beat it. If nothing is faster, the recorded floor \
                         brings {peer} straight back.",
                        slow
                    );
                } else if want_quick_reconnect(&cached).await {
                    // <<< AETHER-APP-PATCH scan-once-after-a-slow-cache
                    let profile = aethernoize::from_profile(&cached.profile);
                    log::info!("[*] verifying cached WireGuard endpoint {peer} before reuse");
                    match wireguard::verify_endpoint(
                        peer,
                        private_key,
                        peer_public,
                        identity.client_id,
                        ipv4,
                        &profile,
                        std::time::Duration::from_secs(6),
                        None,
                    )
                    .await
                    {
                        Ok(rtt) => {
                            log::info!(
                                "[+] cached endpoint {peer} still works (rtt {:?}); skipping scan",
                                rtt
                            );
                            quick = Some((peer, profile, cached.profile.clone()));
                            // >>> AETHER-APP-PATCH keep-the-working-cached-endpoint
                            // پیش از این، یک endpointِ کارکن ولی کندتر از بودجه
                            // دور انداخته می‌شد و نشست به اسکن می‌رفت. لاگ
                            // ۲۰۲۶-۰۹-۱۶ نشان می‌دهد این شرط‌بندی چه چیزی خرید:
                            //
                            //     cached endpoint 162.159.192.1:4500 answered but
                            //     is slow (rtt 486ms over the 400ms budget);
                            //     ignoring the cache and scanning for a faster
                            //     endpoint
                            //     … 5s اسکن …
                            //     endpoint 188.114.98.224:1701 (rtt 3.6s)
                            //
                            // یعنی ۴۸۶ms را رد کرد تا ۳.۶ ثانیه پیدا کند. سازوکارِ
                            // rtt_floor آخرش کش را برمی‌گرداند، پس دستاورد نهایی
                            // صفر بود و هزینه‌اش ثانیه‌هایی که کاربر روی دکمهٔ
                            // Connect می‌نشیند — و همین تفاوتِ «موبایل سریع وصل
                            // می‌شود، ویندوز نه» است.
                            //
                            // تصمیم: endpointی که همین حالا جواب داده نگه داشته
                            // می‌شود. floor ثبت می‌شود تا اسکنِ نشستِ بعدی — که
                            // کاربر منتظرش نیست — بداند چه چیزی را باید بشکند.
                            // با AETHER_QUICK_RECONNECT_RESCAN_SLOW=1 رفتار قبلی
                            // برمی‌گردد.
                            if !cached_peer_fast_enough(peer, rtt) {
                                wg_prober::set_rtt_floor(peer, rtt);
                                if rescan_when_cache_is_slow() {
                                    quick = None;
                                } else {
                                    // همین سطر روی دیسک هم ثبت می‌شود، وگرنه «نشستِ بعدی»
                                    // هرگز نمی‌رسد: لاگِ ۱۷ سپتامبر دو نشست دارد که هر دو
                                    // همین endpointِ کند را بی‌اسکن برداشتند.
                                    accepted_slow = Some((peer, rtt));
                                    log::info!(
                                        "[*] using {peer} anyway: it answers, and a scan costs the \
                                         connect several seconds to beat {:?} — the next session \
                                         will look for something faster",
                                        rtt
                                    );
                                }
                            }
                            // <<< AETHER-APP-PATCH keep-the-working-cached-endpoint
                        }
                        Err(e) => {
                            log::warn!(
                                "[-] cached endpoint {peer} no longer works ({e}); scanning fresh"
                            );
                        }
                    }
                }
            }
        }
    }

    let (mode_str, ip) = if forced.is_some() || quick.is_some() {
        scan_settings_from_env()
    } else {
        let mode_str = select_scan_mode_str("").await;
        let ip = select_ip_version().await;
        (mode_str, ip)
    };

    let mut last_good: Option<(SocketAddr, aethernoize::AetherNoizeConfig, String)> = None;
    let mut consecutive_fails_on_peer: u32 = 0;
    let mut endpoint_cooldowns: HashMap<SocketAddr, Instant> = HashMap::new();
    const MAX_CONSECUTIVE_FAILS: u32 = 2;

    loop {
        let now = Instant::now();
        endpoint_cooldowns.retain(|_, until| *until > now);
        if consecutive_fails_on_peer >= MAX_CONSECUTIVE_FAILS {
            if let Some((peer, _, _)) = last_good.take() {
                let cooldown = wg_endpoint_cooldown();
                endpoint_cooldowns.insert(peer, now + cooldown);
                log::warn!(
                    "[-] endpoint {peer} failed {consecutive_fails_on_peer} times in a row; excluding it for {:?}",
                    cooldown
                );
            }
            consecutive_fails_on_peer = 0;
        }

        let (peer, profile, profile_name) = if let Some(q) = quick.take() {
            q
        } else {
            let retried = match &last_good {
                // >>> AETHER-APP-PATCH no-retry-on-a-peer-that-just-failed
                // شرطِ `consecutive_fails_on_peer == 0` تازه است. پیش از این،
                // این شاخه بی‌قیدوشرط اجرا می‌شد: تونل روی یک endpoint می‌مرد،
                // حلقه برمی‌گشت، و ۶ ثانیه صرفِ یک handshakeِ تازه با **همان**
                // endpoint می‌شد. handshake تقریباً همیشه جواب می‌دهد — چیزی که
                // خراب بود حملِ ترافیک بود، نه handshake — پس نتیجه‌اش وصل‌شدنِ
                // دوباره به همان endpointِ خراب بود و باز مردن. در لاگ
                // ۲۰۲۶-۰۹-۱۶ همین رفت‌وبرگشت دیده می‌شود.
                //
                // آزمونی که نتیجه‌اش را از قبل می‌دانیم، آزمون نیست؛ فقط تأخیر
                // است. پس وقتی تونلِ همین endpoint تازه افتاده، سراغ اسکن
                // می‌رویم و شمارندهٔ cooldown کارِ خودش را می‌کند.
                Some((p, profile, _)) if consecutive_fails_on_peer == 0 => {
                    // <<< AETHER-APP-PATCH no-retry-on-a-peer-that-just-failed
                    log::info!(
                        "[*] retrying last known-good WireGuard endpoint {p} before rescanning"
                    );
                    match wireguard::verify_endpoint(
                        *p,
                        private_key,
                        peer_public,
                        identity.client_id,
                        ipv4,
                        profile,
                        std::time::Duration::from_secs(6),
                        None,
                    )
                    .await
                    {
                        Ok(_) => Some(last_good.clone().unwrap()),
                        Err(e) => {
                            log::warn!("[-] last known-good endpoint {p} no longer responds ({e}); rescanning");
                            None
                        }
                    }
                }
                // >>> AETHER-APP-PATCH no-retry-on-a-peer-that-just-failed
                Some((p, _, _)) => {
                    log::info!(
                        "[*] not re-testing {p}: the tunnel through it just failed \
                         ({consecutive_fails_on_peer}x) and a fresh handshake would not show that; \
                         scanning for a different endpoint"
                    );
                    None
                }
                // <<< AETHER-APP-PATCH no-retry-on-a-peer-that-just-failed
                None => None,
            };

            match retried {
                Some(v) => v,
                None => {
                    if let Some(ref p) = forced {
                        let peer: SocketAddr = p
                            .parse()
                            .map_err(|_| AetherError::Other(format!("bad peer address {p}")))?;
                        log::info!("[+] using forced peer {peer} (probe skipped)");

                        let mut chosen = None;
                        for (name, profile) in &candidates {
                            log::info!(
                                "[*] testing forced peer {peer} with aethernoize profile '{name}'"
                            );
                            match wireguard::verify_endpoint(
                                peer,
                                private_key,
                                peer_public,
                                identity.client_id,
                                ipv4,
                                profile,
                                std::time::Duration::from_secs(10),
                                None,
                            )
                            .await
                            {
                                Ok(rtt) => {
                                    log::info!(
                                        "[+] profile '{}' passed handshake + data-plane (rtt {:?})",
                                        name,
                                        rtt
                                    );
                                    chosen = Some((peer, profile.clone(), name.clone()));
                                    break;
                                }
                                Err(e) => {
                                    log::warn!("[-] profile '{name}' failed on forced peer: {e}");
                                }
                            }
                        }
                        match chosen {
                            Some(v) => v,
                            None => {
                                log::warn!(
                                    "[-] forced peer {peer} failed with every aethernoize profile; retrying shortly"
                                );
                                tokio::time::sleep(wg_reconnect_delay()).await;
                                continue;
                            }
                        }
                    } else {
                        let excluded: HashSet<SocketAddr> =
                            endpoint_cooldowns.keys().copied().collect();
                        match hunt_wg_peer(&identity, &candidates, &mode_str, ip, &excluded).await {
                            Ok(v) => v,
                            Err(e) => {
                                log::warn!("[-] no usable WireGuard endpoint found: {e}; rescanning shortly");
                                tokio::time::sleep(wg_reconnect_delay()).await;
                                continue;
                            }
                        }
                    }
                }
            }
        };

        log::info!("[+] using cloudflare edge {peer}");

        if forced.is_none() {
            // >>> AETHER-APP-PATCH scan-once-after-a-slow-cache
            let slow = accepted_slow
                .filter(|(slow_peer, _)| *slow_peer == peer)
                .map(|(_, rtt)| rtt.as_millis().min(u128::from(u64::MAX)) as u64)
                .unwrap_or(0);
            lastconn::save_slow(&lastconn_path, &peer.to_string(), &profile_name, slow);
            // <<< AETHER-APP-PATCH scan-once-after-a-slow-cache
        }

        let is_same_peer_as_before = last_good.as_ref().map(|(p, _, _)| *p) == Some(peer);
        if !is_same_peer_as_before {
            consecutive_fails_on_peer = 0;
        }
        last_good = Some((peer, profile.clone(), profile_name));

        match run_wireguard_tunnel(identity.clone(), peer, profile, listen).await {
            Ok(()) => {
                log::warn!("[-] WireGuard tunnel closed; reconnecting");
                consecutive_fails_on_peer += 1;
            }
            Err(e) => {
                log::warn!("[-] WireGuard tunnel ended: {e}; reconnecting");
                consecutive_fails_on_peer += 1;
            }
        }

        tokio::time::sleep(wg_reconnect_delay()).await;
    }
}

fn wg_tunnel_validate_timeout() -> std::time::Duration {
    let secs = std::env::var("AETHER_WG_VALIDATE_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&v| v > 0)
        .map(|v| v.min(86_400))
        .unwrap_or(10);
    std::time::Duration::from_secs(secs)
}

async fn run_wireguard_tunnel(
    identity: account::Identity,
    peer: SocketAddr,
    aethernoize: aethernoize::AetherNoizeConfig,
    listen: SocketAddr,
) -> Result<()> {
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;
    let ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;

    log::info!("[*] validating WireGuard tunnel with {peer} (handshake + data-plane) before exposing socks5...");
    let (_, session) = wireguard::verify_endpoint_keep_session(
        peer,
        private_key,
        peer_public,
        identity.client_id,
        ipv4,
        &aethernoize,
        wg_tunnel_validate_timeout(),
        Some(wg_keepalive_secs()),
    )
    .await
    .map_err(|e| AetherError::Other(format!("tunnel failed validation: {e}")))?;
    log::info!("[+] wireguard tunnel validated (end-to-end data confirmed); exposing socks5");
    // The bet is settled; a later reconnect must be judged on its own numbers.
    wg_prober::clear_rtt_floor();

    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(packet_queue_capacity());
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(packet_queue_capacity());

    let tunnel = wireguard::WgTunnel::from_established(
        session,
        std::sync::Arc::new(aethernoize),
        inbound_tx,
        ipv4,
    );

    let stack = netstack::spawn(
        &identity.ipv4,
        &identity.ipv6,
        TUNNEL_MTU,
        inbound_rx,
        outbound_tx,
    )?;

    let mut tasks = TaskGuard::new();

    let socks_listener = socks::bind_listener("socks5", listen).await?;
    let http_listener = bind_http_proxy().await?;

    let socks_stack = stack.clone();
    let socks_task = tokio::spawn(async move { socks::serve(socks_listener, socks_stack).await });
    tasks.push(socks_task.abort_handle());

    let http_task = spawn_http_proxy(http_listener, &stack);
    if let Some(task) = &http_task {
        tasks.push(task.abort_handle());
    }

    let tunnel_result = tunnel.run(outbound_rx).await;

    if let Some(task) = &http_task {
        task.abort();
    }

    socks_task.abort();
    let _ = socks_task.await;

    drop(stack);

    match tunnel_result {
        Ok(()) => Ok(()),
        Err(e) => Err(AetherError::Other(format!("wireguard tunnel exited: {e}"))),
    }
}

type TunnelExit = tokio::task::JoinHandle<Result<()>>;

fn http_proxy_listen() -> Option<SocketAddr> {
    let raw = std::env::var("AETHER_HTTP_PROXY").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<SocketAddr>() {
        Ok(addr) => Some(addr),
        Err(_) => {
            log::warn!("[-] ignoring an unparsable http proxy address: {trimmed}");
            None
        }
    }
}

async fn bind_http_proxy() -> Result<Option<tokio::net::TcpListener>> {
    match http_proxy_listen() {
        Some(listen) => Ok(Some(socks::bind_listener("http proxy", listen).await?)),
        None => Ok(None),
    }
}

fn spawn_http_proxy(
    listener: Option<tokio::net::TcpListener>,
    stack: &netstack::StackHandle,
) -> Option<TunnelExit> {
    let listener = listener?;
    let stack = stack.clone();
    Some(tokio::spawn(async move {
        socks::serve_http(listener, stack).await
    }))
}

async fn establish_wg(
    identity: &account::Identity,
    peer: SocketAddr,
    mtu: usize,
    obfuscate: bool,
    keepalive: u16,
    stale: std::time::Duration,
    label: &'static str,
) -> Result<(netstack::StackHandle, TunnelExit)> {
    // >>> AETHER-APP-FIX the-carrier-hop-is-not-the-data-path
    // A hop whose keepalive is longer than the budget it is given before being
    // judged dead is guaranteed to be judged dead while its keepalive is still
    // pending. The clamp is applied here, at the one place every hop goes
    // through, instead of trusting each call site to do the arithmetic.
    let keepalive = wireguard::clamp_keepalive_to_stale(keepalive, stale);
    // <<< AETHER-APP-FIX the-carrier-hop-is-not-the-data-path
    let private_key = identity.private_key_bytes()?;
    let peer_public = identity.peer_public_key_bytes()?;

    let ipv4: std::net::Ipv4Addr = identity
        .ipv4
        .parse()
        .map_err(|_| AetherError::Other("invalid ipv4".into()))?;

    let profile = if obfuscate {
        aethernoize_config()
    } else {
        aethernoize::from_profile("off")
    };

    log::info!("[*] [{label}] validating WireGuard tunnel with {peer} (handshake + data-plane)...");
    let (_, session) = wireguard::verify_endpoint_keep_session(
        peer,
        private_key,
        peer_public,
        identity.client_id,
        ipv4,
        &profile,
        wg_tunnel_validate_timeout(),
        Some(keepalive),
    )
    .await
    .map_err(|e| AetherError::Other(format!("[{label}] tunnel failed validation: {e}")))?;
    log::info!("[+] [{label}] wireguard tunnel validated (end-to-end data confirmed)");

    let (outbound_tx, outbound_rx) = tokio::sync::mpsc::channel(packet_queue_capacity());
    let (inbound_tx, inbound_rx) = tokio::sync::mpsc::channel(packet_queue_capacity());

    let tunnel = wireguard::WgTunnel::from_established_with_stale(
        session,
        std::sync::Arc::new(profile),
        inbound_tx,
        ipv4,
        stale,
    );
    let stack = netstack::spawn(&identity.ipv4, &identity.ipv6, mtu, inbound_rx, outbound_tx)?;

    let exit = tokio::spawn(async move {
        match tunnel.run(outbound_rx).await {
            Ok(()) => {
                log::warn!("[-] [{label}] wireguard tunnel closed");
                Ok(())
            }
            Err(e) => {
                log::warn!("[-] [{label}] wireguard tunnel exited: {e}");
                Err(AetherError::Other(format!("[{label}] {e}")))
            }
        }
    });

    Ok((stack, exit))
}

struct TaskGuard(Vec<tokio::task::AbortHandle>);

impl TaskGuard {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn push(&mut self, handle: tokio::task::AbortHandle) {
        self.0.push(handle);
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        for handle in self.0.drain(..) {
            handle.abort();
        }
    }
}

/// Budget for handing one inner-tunnel datagram to the outer stack.
const GOOL_RELAY_HANDOFF_BUDGET: std::time::Duration = std::time::Duration::from_millis(20);

async fn spawn_udp_forwarder(
    outer: &netstack::StackHandle,
    remote: SocketAddr,
) -> Result<(SocketAddr, TaskGuard)> {
    let sock = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
    // A download's worth of 1200-byte datagrams overruns the default loopback
    // buffers long before this relay is slow enough to matter.
    upstream::tune_udp_buffers(&sock);
    let local = sock.local_addr()?;

    let udp = outer.open_udp().await?;
    let (udp_tx, mut udp_rx) = udp.into_split();

    // parking_lot, not tokio::sync: this lock is held for a couple of instructions
    // on the hot path of every single packet of a WARP*2 session, and an async
    // mutex there buys nothing but scheduler work - the same per-packet hand-off
    // that capped the WireGuard writer.
    let inner_peer: std::sync::Arc<parking_lot::Mutex<Option<SocketAddr>>> =
        std::sync::Arc::new(parking_lot::Mutex::new(None));

    let up_sock = sock.clone();
    let up_peer = inner_peer.clone();
    let up_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            match up_sock.recv_from(&mut buf).await {
                Ok((n, from)) => {
                    // 2.0.0: pin the relay to the first inner peer that answers
                    // and ignore anything else, so a stray datagram from a third
                    // party cannot be forwarded into the outer tunnel.
                    {
                        let mut known = up_peer.lock();
                        match *known {
                            Some(peer) if peer != from => continue,
                            Some(_) => {}
                            None => *known = Some(from),
                        }
                    }
                    // 1.2.3-p1: this relay carries EVERY byte of a WARP*2 session
                    // and it used to await the handoff with no bound at all, so
                    // whenever the outer stack was momentarily behind, the only
                    // reader of the inner tunnel's loopback socket parked - and
                    // the loopback receive buffer, which is small, threw away
                    // everything that arrived meanwhile, handshake traffic
                    // included. Waiting a few milliseconds is fine; going deaf is
                    // not.
                    match tokio::time::timeout(
                        GOOL_RELAY_HANDOFF_BUDGET,
                        udp_tx.send_to(remote, buf[..n].to_vec()),
                    )
                    .await
                    {
                        // Handed over, or dropped on purpose because the outer
                        // stack is congested - the loss signal the inner tunnel's
                        // congestion control is built to read.
                        Ok(Ok(())) | Err(_) => {}
                        Ok(Err(_)) => break,
                    }
                }
                Err(_) => break,
            }
        }
    });

    let down_sock = sock.clone();
    let down_peer = inner_peer.clone();
    let down_task = tokio::spawn(async move {
        while let Some((_src, data)) = udp_rx.recv().await {
            let dst = *down_peer.lock();
            if let Some(dst) = dst {
                let _ = down_sock.send_to(&data, dst).await;
            }
        }
    });

    let guard = TaskGuard(vec![up_task.abort_handle(), down_task.abort_handle()]);

    Ok((local, guard))
}

// >>> AETHER-APP-FIX let-the-carrier-settle-before-the-forwarder
/// How long the outer hop is left alone before the inner hop's forwarder is
/// started on top of it.
///
/// Not a timeout and not a retry budget: a settle window. The outer WireGuard
/// session has just completed its handshake and the forwarder is about to push
/// the inner hop's first packets through it. The mobile core does the same
/// thing between `establish_wg` and `spawn_udp_forwarder`, and a first inner
/// handshake that arrives before the outer session has settled is a handshake
/// that has to be retried.
///
/// `AETHER_WG_INNER_SETTLE_MS` overrides it, and `0` removes the wait — so a
/// field log can tell "the wait helped" from "the wait cost us 1.5 s".
fn wg_inner_settle() -> std::time::Duration {
    let ms = std::env::var("AETHER_WG_INNER_SETTLE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(|v| v.min(60_000))
        .unwrap_or(1500);
    std::time::Duration::from_millis(ms)
}
// <<< AETHER-APP-FIX let-the-carrier-settle-before-the-forwarder

async fn run_warp_in_warp(
    primary: account::Identity,
    secondary: account::Identity,
    peer: SocketAddr,
    inner_peer: SocketAddr,
    listen: SocketAddr,
) -> Result<()> {
    // >>> AETHER-APP-FIX one-edge-can-carry-both-hops
    // `inner_peer` is allowed to equal `peer` — see [`SharedEdge`]. There used
    // to be a hard error here ("warp-in-warp needs two separate edges"), and it
    // was the second of two gates that turned "this network offers one edge"
    // into an endless rescan. Two WireGuard tunnels are told apart by their
    // public keys, so one edge carrying both is not a mistake to refuse; it is
    // the single-edge tunnel this network can actually build, and it is
    // strictly better than ending at "no usable WARP endpoint found".
    if inner_peer.ip() == peer.ip() {
        log::info!(
            "[*] one edge carries both hops ({peer} outer, {inner_peer} inner); \
             the inner tunnel runs inside the outer one either way"
        );
    }
    // <<< AETHER-APP-FIX one-edge-can-carry-both-hops

    let mut tasks = TaskGuard::new();

    // >>> AETHER-APP-FIX the-carrier-hop-is-not-the-data-path
    // Two hops, two different jobs, two different silence budgets.
    //
    //   outer = carrier. It only moves the inner hop's packets, so between the
    //           inner tunnel validating and an application actually using SOCKS5
    //           it is legitimately silent. Judged on the carrier budget.
    //   inner = the data path. Everything the user sends crosses it, so it stays
    //           the hop that fails fast and keeps the short budget.
    //
    // The 2026-09-22 log had the outer hop killed after 10.6 s of silence, 2 s
    // after the inner hop had validated - and then spent the launcher's
    // remaining window on a fresh scan.
    let outer_stale = wireguard::carrier_stale_timeout();
    let inner_stale = wireguard::wg_stale_timeout();
    // <<< AETHER-APP-FIX the-carrier-hop-is-not-the-data-path

    log::info!("[*] establishing outer WARP tunnel to {peer}...");
    let (outer_stack, mut outer_exit) =
        establish_wg(&primary, peer, TUNNEL_MTU, true, 5, outer_stale, "outer").await?;
    tasks.push(outer_exit.abort_handle());

    // >>> AETHER-APP-FIX let-the-carrier-settle-before-the-forwarder
    // The forwarder starts moving the inner hop's packets the moment it exists,
    // and the outer session has just come up. Letting it settle before the
    // first inner handshake is cheaper than retrying that handshake against a
    // session that is still finding its feet. Same shape as the mobile core,
    // which sleeps between `establish_wg` and `spawn_udp_forwarder`.
    tokio::time::sleep(wg_inner_settle()).await;
    // <<< AETHER-APP-FIX let-the-carrier-settle-before-the-forwarder

    let (forwarder, _forwarder_guard) = spawn_udp_forwarder(&outer_stack, inner_peer).await?;
    log::info!("[+] inner endpoint {inner_peer} tunneled through outer warp via {forwarder}");

    log::info!("[*] establishing inner WARP tunnel (warp-in-warp)...");
    let (inner_stack, mut inner_exit) =
        establish_wg(&secondary, forwarder, INNER_MTU, false, 20, inner_stale, "inner").await?;
    tasks.push(inner_exit.abort_handle());

    let socks_listener = socks::bind_listener("socks5", listen).await?;
    let http_listener = bind_http_proxy().await?;

    let http_task = spawn_http_proxy(http_listener, &inner_stack);
    if let Some(task) = &http_task {
        tasks.push(task.abort_handle());
    }
    let mut socks_task =
        tokio::spawn(async move { socks::serve(socks_listener, inner_stack).await });
    tasks.push(socks_task.abort_handle());

    #[derive(PartialEq)]
    enum Winner {
        Outer,
        Inner,
        Socks,
    }

    let (outcome, winner) = tokio::select! {
        result = &mut outer_exit => (join_outcome("outer wireguard tunnel", result), Winner::Outer),
        result = &mut inner_exit => (join_outcome("inner wireguard tunnel", result), Winner::Inner),
        result = &mut socks_task => (join_outcome("socks5 server", result), Winner::Socks),
    };

    if let Some(task) = &http_task {
        task.abort();
    }

    // Whichever handle already resolved inside the select! above must not be
    // polled again: tokio panics with "JoinHandle polled after completion"
    // if you .await a JoinHandle that has already yielded Ready.
    if winner != Winner::Outer {
        outer_exit.abort();
        let _ = outer_exit.await;
    }
    if winner != Winner::Inner {
        inner_exit.abort();
        let _ = inner_exit.await;
    }
    if winner != Winner::Socks {
        socks_task.abort();
        let _ = socks_task.await;
    }

    drop(outer_stack);

    outcome
}

fn join_outcome(
    what: &str,
    result: std::result::Result<Result<()>, tokio::task::JoinError>,
) -> Result<()> {
    match result {
        Ok(Ok(())) => Err(AetherError::Other(format!("{what} stopped"))),
        Ok(Err(e)) => Err(e),
        Err(e) if e.is_cancelled() => Err(AetherError::Other(format!("{what} was cancelled"))),
        Err(e) => Err(AetherError::Other(format!("{what} panicked: {e}"))),
    }
}

async fn prompt_line(prompt: &str) -> Option<String> {
    use std::io::IsTerminal;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    if !std::io::stdin().is_terminal() {
        return None;
    }

    let mut stdout = tokio::io::stdout();
    let _ = stdout.write_all(prompt.as_bytes()).await;
    let _ = stdout.flush().await;

    let mut line = String::new();
    let mut reader = BufReader::new(tokio::io::stdin());
    match reader.read_line(&mut line).await {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

const SCAN_MODE_PROMPT: &str = "\nScan mode:\n  [1] turbo     (fast, first hit)\n  [2] balanced  (default)\n  [3] thorough  (deep, best ping)\n  [4] stealth   (quiet, patient)\n  [5] ironclad  (real tunnel + real HTTP check per candidate, guaranteed working)\nChoose [1-5] (default 2): ";

/// Shown above the scan mode question on warp-in-warp, where the addresses can
/// be handed over instead of hunted for.
const MIM_MANUAL_TIP: &str = "\n(tip: you can skip this scan and give the two masque hops yourself:\n        aether --mim --mim-outer <ip:port> --mim-inner <ip:port>\n      the port is required, and naming just the outer one lets aether pick\n      the inner edge for you)\n";

const WIW_MANUAL_TIP: &str = "\n(tip: you can skip this scan and give the two gool hops yourself:\n        aether --gool --wiw-outer <ip:port> --wiw-inner <ip:port>\n      the port is required, and naming just one of the two lets the scan\n      find the other)\n";

async fn select_scan_mode() -> prober::ScanMode {
    if let Ok(v) = std::env::var("AETHER_SCAN") {
        return prober::ScanMode::parse(&v);
    }

    let answer = prompt_line(SCAN_MODE_PROMPT).await;

    match answer.as_deref() {
        Some("1") => prober::ScanMode::Turbo,
        Some("3") => prober::ScanMode::Thorough,
        Some("4") => prober::ScanMode::Stealth,
        Some("5") => prober::ScanMode::Ironclad,
        _ => prober::ScanMode::Balanced,
    }
}

/// `tip` is printed above the question, for whatever the caller wants to point
/// out about scanning in the mode it is about to run.
async fn select_scan_mode_str(tip: &str) -> String {
    if let Ok(v) = std::env::var("AETHER_SCAN") {
        return v;
    }

    let answer = prompt_line(&format!("{tip}{SCAN_MODE_PROMPT}")).await;

    match answer.as_deref() {
        Some("1") => "turbo".to_string(),
        Some("3") => "thorough".to_string(),
        Some("4") => "stealth".to_string(),
        Some("5") => "ironclad".to_string(),
        _ => "balanced".to_string(),
    }
}

async fn select_protocol(base: &str) -> Protocol {
    if let Ok(v) = std::env::var("AETHER_PROTOCOL") {
        return Protocol::parse(&v);
    }

    loop {
        let (tor_entries, last) = if cfg!(feature = "tor") {
            (
                "  [5] Tor alone, with no warp under it\n  \
                 [6] Tor and warp chained, either way round\n"
                    .to_string(),
                7,
            )
        } else {
            (String::new(), 5)
        };

        let zero_trust_key = last.to_string();
        let zero_trust = match team_scope() {
            Some(team) => {
                format!("  [{last}] Zero Trust: signed in to {team}, pick another team\n")
            }
            None => {
                format!("  [{last}] Zero Trust: sign in to an organization (WARP for teams)\n")
            }
        };

        let answer = prompt_line(&format!(
            "\nProtocol:\n  [1] MASQUE (modern, QUIC/H3, default)\n  \
             [2] WireGuard (classic, faster)\n  [3] WARP-in-WARP / gool\n  \
             [4] MASQUE-in-MASQUE (two masque hops, for a different exit address)\n\
             {tor_entries}{zero_trust}Choose [1-{last}] (default 1): "
        ))
        .await;

        match answer.as_deref() {
            Some("2") => return Protocol::WireGuard,
            Some("3") => return Protocol::WarpInWarp,
            Some("4") => return Protocol::MasqueInMasque,
            Some(choice) if choice == zero_trust_key => {
                enrol_zero_trust(base).await;
                continue;
            }
            Some("5") if cfg!(feature = "tor") => {
                std::env::set_var("AETHER_TOR", "only");
                return Protocol::Masque;
            }
            Some("6") if cfg!(feature = "tor") => return select_tor_chain().await,
            _ => return Protocol::Masque,
        }
    }
}

async fn select_tor_chain() -> Protocol {
    let answer = prompt_line(
        "\nWhich way round?\n  \
         [1] tor inside warp: you, warp, tor, the internet. The exit is a tor exit, and a \
         network that blocks tor never sees it (default)\n  \
         [2] warp inside tor: you, tor, warp, the internet. The exit is a warp exit reached \
         from a tor exit, and your network never sees warp\n\
         Choose [1-2] (default 1): ",
    )
    .await;

    if matches!(answer.as_deref(), Some("2")) {
        std::env::set_var("AETHER_TOR", "reverse");
        log::info!("[*] the tunnel will be dialled through tor, on the http/2 carrier");
        return Protocol::Masque;
    }

    std::env::set_var("AETHER_TOR", "chain");
    log::info!("[*] tor will be carried inside the tunnel");
    select_chain_carrier().await
}

async fn select_chain_carrier() -> Protocol {
    let answer = prompt_line(
        "\nWhat carries tor?\n  \
         [1] MASQUE, over quic/h3 or http/2, asked next (default)\n  \
         [2] WireGuard, warp over udp\n  \
         [3] WARP-in-WARP / gool\n  \
         [4] MASQUE-in-MASQUE\n\
         Choose [1-4] (default 1): ",
    )
    .await;

    match answer.as_deref() {
        Some("2") => Protocol::WireGuard,
        Some("3") => Protocol::WarpInWarp,
        Some("4") => Protocol::MasqueInMasque,
        _ => Protocol::Masque,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Masque,
    WireGuard,
    WarpInWarp,
    MasqueInMasque,
}

impl Protocol {
    fn parse(s: &str) -> Protocol {
        match s.trim().to_lowercase().as_str() {
            "wg" | "wireguard" => Protocol::WireGuard,
            "gool" | "wiw" | "warp-in-warp" | "warpinwarp" => Protocol::WarpInWarp,
            "mim" | "m2" | "masque-in-masque" | "masqueinmasque" => Protocol::MasqueInMasque,
            _ => Protocol::Masque,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            Protocol::Masque => "MASQUE",
            Protocol::WireGuard => "WireGuard",
            Protocol::WarpInWarp => "WARP-in-WARP (gool)",
            Protocol::MasqueInMasque => "MASQUE-in-MASQUE",
        }
    }
}

async fn select_masque_transport() {
    if std::env::var("AETHER_MASQUE_HTTP2").is_ok() || std::env::var("AETHER_PEER").is_ok() {
        return;
    }

    let answer = prompt_line(
        "\nMASQUE transport:\n  [1] HTTP/3 (QUIC)  (default; fastest handshake, best on healthy UDP networks)\n  [2] HTTP/2 (TCP)   (looks like ordinary HTTPS; use if UDP/QUIC is blocked or throttled)\nChoose [1-2] (default 1): ",
    )
    .await;

    if matches!(answer.as_deref(), Some("2")) {
        std::env::set_var("AETHER_MASQUE_HTTP2", "1");
    }
}

fn scan_settings_from_env() -> (String, prober::IpScan) {
    let mode = std::env::var("AETHER_SCAN").unwrap_or_default();
    let ip = std::env::var("AETHER_IP")
        .map(|value| prober::IpScan::parse(&value))
        .unwrap_or(prober::IpScan::V4);
    (mode, ip)
}

async fn select_ip_version() -> prober::IpScan {
    if let Ok(v) = std::env::var("AETHER_IP") {
        return prober::IpScan::parse(&v);
    }

    let answer = prompt_line(
        "\nIP version to scan:\n  [1] IPv4 (default)\n  [2] IPv6\n  [3] Both\nChoose [1-3] (default 1): ",
    )
    .await;

    match answer.as_deref() {
        Some("2") => prober::IpScan::V6,
        Some("3") => prober::IpScan::Both,
        _ => prober::IpScan::V4,
    }
}

// >>> AETHER-APP-PATCH packet-queue-depth
/// Depth of the two PACKET handoff queues (netstack <-> WireGuard), in packets.
///
/// 1.2.3-p1 BUFFERBLOAT FIX. These two were sized from
/// `sysprofile::channel_capacity()`, which is an *application* queue depth and is
/// 1024 on a normal PC. 1024 packets at a 1280-byte MTU is ~1.3 MB of standing
/// queue in EACH direction, on top of the netstack's own retained burst.
///
/// That queue is pure latency, and latency is the other half of the download
/// speed problem: throughput per flow is window / RTT, so a megabyte of local
/// queue in front of every ACK lowers the ceiling exactly as effectively as a
/// small window does. In chained mode the whole machine rides one Psiphon
/// connection, so the queue is shared by every flow at once.
///
/// These queues are a device transmit/receive ring, not a congestion window.
/// Throughput is governed by smoltcp's own socket buffers
/// (`sysprofile::netstack_tcp_rx_buf_bytes`), so keeping the ring short costs no
/// bandwidth and buys back the whole queueing delay. 256 packets (~320 KB) is
/// still an order of magnitude more than any scheduling hiccup needs.
fn packet_queue_capacity() -> usize {
    const PACKET_QUEUE_MAX: usize = 256;
    sysprofile::channel_capacity().min(PACKET_QUEUE_MAX).max(64)
}
// <<< AETHER-APP-PATCH packet-queue-depth

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let values: BTreeMap<String, String> = pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        move |key: &str| values.get(key).cloned()
    }

    #[test]
    fn masque_in_masque_is_selected_by_name() {
        for written in ["mim", "m2", "masque-in-masque", "MIM", "MasqueInMasque"] {
            assert_eq!(
                Protocol::parse(written),
                Protocol::MasqueInMasque,
                "{written}"
            );
        }
    }

    #[test]
    fn the_masque_hops_can_be_named_by_hand() {
        let chosen = mim_endpoints_of(&env(&[
            ("AETHER_MIM_OUTER_PEER", "162.159.192.1:443"),
            ("AETHER_MIM_INNER_PEER", "188.114.96.1:443"),
        ]))
        .expect("both hops");

        assert_eq!(chosen.outer, Some("162.159.192.1:443".parse().unwrap()));
        assert_eq!(chosen.inner, Some("188.114.96.1:443".parse().unwrap()));
    }

    #[test]
    fn the_same_masque_edge_cannot_serve_as_both_hops() {
        assert!(mim_endpoints_of(&env(&[(
            "AETHER_MIM_PEERS",
            "162.159.192.1:443,162.159.192.1:8443"
        )]))
        .is_err());
    }

    #[test]
    fn an_inner_quic_datagram_fits_inside_the_outer_link() {
        let inner: SocketAddr = "162.159.192.1:443".parse().unwrap();
        let (datagram, mtu) = mim_inner_budget(TUNNEL_MTU, inner, false);

        assert!(
            datagram + 28 <= TUNNEL_MTU,
            "a {datagram} byte datagram plus headers must fit {TUNNEL_MTU}"
        );
        assert!(
            datagram >= quic::MIN_DATAGRAM_SIZE,
            "quic needs at least 1200"
        );
        assert!(
            mtu < datagram,
            "the inner link has to leave room for quic itself"
        );
    }

    #[test]
    fn an_ipv6_inner_hop_leaves_room_for_the_bigger_header() {
        let v4: SocketAddr = "162.159.192.1:443".parse().unwrap();
        let v6: SocketAddr = "[2606:4700:d0::a29f:c001]:443".parse().unwrap();

        let (over_v4, _) = mim_inner_budget(TUNNEL_MTU, v4, false);
        let (over_v6, _) = mim_inner_budget(TUNNEL_MTU, v6, false);
        assert!(
            over_v6 < over_v4,
            "{over_v6} should leave more room than {over_v4}"
        );
        assert!(over_v6 + 48 <= TUNNEL_MTU);
    }

    #[test]
    fn an_http2_pair_keeps_the_full_datagram_budget() {
        let inner: SocketAddr = "162.159.192.1:443".parse().unwrap();
        let (datagram, mtu) = mim_inner_budget(H2_TUNNEL_MTU, inner, true);

        assert_eq!(datagram, quic::MAX_DATAGRAM_SIZE);
        assert!(
            mtu < H2_TUNNEL_MTU,
            "the inner link stays under the outer one"
        );
    }

    /// The inner hop must aim at addresses that are *known MASQUE edges*, not at
    /// arbitrary hosts in the outer hop's `/24`.
    ///
    /// The previous version of this test asserted the opposite - that every
    /// candidate shared the outer edge's first three octets. That is exactly the
    /// assumption the 2026-09-22 log falsified: four candidates drawn from
    /// `162.159.198.0/24` all answered with TLS `handshake_failure`, because
    /// sharing a /24 with a working edge says nothing about serving the MASQUE
    /// hostname.
    #[test]
    fn the_inner_edges_are_known_masque_edges_not_random_neighbours() {
        let outer: SocketAddr = "162.159.198.104:8443".parse().unwrap();
        let candidates = inner_masque_candidates(outer, MIM_INNER_TRIES);

        assert_eq!(candidates.len(), MIM_INNER_TRIES);
        for candidate in &candidates {
            assert_ne!(
                candidate.ip(),
                outer.ip(),
                "the inner hop needs its own edge"
            );
            assert_eq!(candidate.port(), MASQUE_INNER_PORT);
        }

        let all: HashSet<SocketAddr> = candidates.iter().copied().collect();
        assert_eq!(all.len(), candidates.len(), "candidates must be distinct");

        // The documented seed pool is what a fresh process has to work from, and
        // it is large enough to fill the list on its own. There is no longer a
        // tier below it to fall through to - the random-neighbour last resort
        // was deleted, not demoted - so this now guards the property directly:
        // every candidate came from evidence, and none from a guess.
        let seeds: HashSet<SocketAddr> = prober::MASQUE_SEEDS
            .iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .map(|ip| SocketAddr::new(ip, MASQUE_INNER_PORT))
            .collect();
        let from_seeds = candidates
            .iter()
            .filter(|c| seeds.contains(c))
            .count();
        assert!(
            from_seeds > 0,
            "the inner hop should be handed real MASQUE edges first, got {candidates:?}"
        );
        assert_eq!(
            candidates.len(),
            MIM_INNER_TRIES,
            "the seed pool alone should be able to fill the list"
        );
    }

    /// A gateway the scan just proved is offered to the inner hop ahead of the
    /// static seed pool.
    #[test]
    fn a_proven_edge_outranks_the_static_seed_pool() {
        let outer: SocketAddr = "162.159.198.2:443".parse().unwrap();
        let proven: SocketAddr = "162.159.197.77:443".parse().unwrap();
        prober::remember_gateway(proven);

        let candidates = inner_masque_candidates(outer, MIM_INNER_TRIES);
        assert_eq!(
            candidates.first().copied(),
            Some(proven),
            "a gateway that just completed a MASQUE handshake is the best lead there is"
        );
        assert!(
            !candidates.contains(&outer),
            "the outer hop is still not a candidate for itself"
        );
    }

    /// The outer edge here is itself one of the IPv6 seeds, so the pool comes
    /// back one short of `count`.
    ///
    /// That is the correct answer now that no random tier fills the gap: `count`
    /// is an upper bound, and a list of known edges is better short than padded
    /// with guesses. `order_inner_candidates` is what covers a short list.
    #[test]
    fn an_ipv6_outer_edge_yields_ipv6_inner_candidates() {
        let outer: SocketAddr = "[2606:4700:d0::a29f:c601]:443".parse().unwrap();
        let candidates = inner_masque_candidates(outer, 4);

        let expected: Vec<SocketAddr> = prober::MASQUE_SEEDS_V6
            .iter()
            .filter_map(|seed| seed.parse::<IpAddr>().ok())
            .filter(|ip| *ip != outer.ip())
            .take(4)
            .map(|ip| SocketAddr::new(ip, MASQUE_INNER_PORT))
            .collect();

        assert_eq!(candidates, expected);
        assert!(candidates.len() < 4, "the outer hop is one of the seeds");
        assert!(candidates.iter().all(|candidate| candidate.is_ipv6()));
        assert!(candidates
            .iter()
            .all(|candidate| candidate.ip() != outer.ip()));
    }

    /// The outer hop is the last thing the inner hop tries, not something it
    /// never tries. On the 2026-09-22 log the outer hop was the only *proven*
    /// MASQUE edge on the network, and excluding it is what emptied the list.
    #[test]
    fn the_outer_hop_is_kept_as_the_last_resort_for_the_inner_hop() {
        let outer: SocketAddr = "162.159.198.2:8443".parse().unwrap();
        let others: Vec<SocketAddr> = ["162.159.198.153:443", "162.159.198.235:443"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();

        let ordered = order_inner_candidates(outer, &others);

        assert_eq!(
            ordered,
            vec![
                "162.159.198.153:443".parse().unwrap(),
                "162.159.198.235:443".parse().unwrap(),
                outer,
            ],
            "a different edge is still preferred, but the outer hop is not thrown away"
        );
    }

    /// A different edge keeps the order it was handed in, so the proven-first /
    /// seeds-second ranking done by `inner_masque_candidates` survives.
    #[test]
    fn a_different_edge_keeps_its_place_ahead_of_the_outer_hop() {
        let outer: SocketAddr = "162.159.198.2:8443".parse().unwrap();
        let proven: SocketAddr = "162.159.197.77:443".parse().unwrap();
        let candidate: SocketAddr = "162.159.192.1:443".parse().unwrap();

        let ordered = order_inner_candidates(outer, &[proven, candidate]);

        assert_eq!(ordered.first().copied(), Some(proven));
        assert_eq!(ordered.last().copied(), Some(outer));
        assert_eq!(ordered.len(), 3);
    }

    /// A list that already names the outer hop's host does not get a second copy
    /// of it - the host is the fallback, and it appears exactly once.
    #[test]
    fn the_outer_host_is_offered_once_when_the_list_already_names_it() {
        let outer: SocketAddr = "162.159.198.2:8443".parse().unwrap();
        let same_host_other_port: SocketAddr = "162.159.198.2:443".parse().unwrap();
        let candidate: SocketAddr = "162.159.192.1:443".parse().unwrap();

        let ordered = order_inner_candidates(outer, &[same_host_other_port, candidate]);

        assert_eq!(ordered, vec![candidate, same_host_other_port]);
        assert_eq!(
            ordered
                .iter()
                .filter(|addr| addr.ip() == outer.ip())
                .count(),
            1,
            "the outer hop's host should be listed once, at the end"
        );
    }

    /// A list of only the outer hop still yields one attempt rather than an empty
    /// loop, and duplicates are collapsed.
    #[test]
    fn duplicates_collapse_and_a_lone_outer_hop_still_yields_one_attempt() {
        let outer: SocketAddr = "162.159.198.2:8443".parse().unwrap();
        let candidate: SocketAddr = "162.159.192.1:443".parse().unwrap();

        assert_eq!(order_inner_candidates(outer, &[outer]), vec![outer]);
        assert_eq!(
            order_inner_candidates(outer, &[candidate, candidate]),
            vec![candidate, outer]
        );
    }

    #[test]
    fn an_address_and_a_port_are_read_together() {
        let peer = parse_endpoint("162.159.192.1:894").expect("address and port");
        assert_eq!(peer, "162.159.192.1:894".parse().unwrap());
    }

    #[test]
    fn an_address_without_a_port_is_refused_rather_than_guessed_at() {
        let message = parse_endpoint("162.159.192.1")
            .expect_err("the port carries too much meaning to be assumed")
            .to_string();
        assert!(
            message.contains("162.159.192.1:2408"),
            "the error should spell out the shape wanted, got: {message}"
        );
    }

    #[test]
    fn an_ipv6_address_without_a_port_is_refused_the_same_way() {
        for written in ["2606:4700:d0::a29f:c001", "[2606:4700:d0::a29f:c001]"] {
            let message = parse_endpoint(written).expect_err(written).to_string();
            assert!(
                message.contains("[2606:4700:d0::a29f:c001]:2408"),
                "the error should bracket the address it suggests, got: {message}"
            );
        }
    }

    #[test]
    fn surrounding_whitespace_is_forgiven() {
        let peer = parse_endpoint("  162.159.192.1:2408  ").expect("padded");
        assert_eq!(peer, "162.159.192.1:2408".parse().unwrap());
    }

    #[test]
    fn ipv6_is_read_when_it_is_bracketed_and_carries_its_port() {
        let peer = parse_endpoint("[2606:4700:d0::a29f:c001]:2408").expect("ipv6 endpoint");
        assert_eq!(peer, "[2606:4700:d0::a29f:c001]:2408".parse().unwrap());
    }

    #[test]
    fn nonsense_is_reported_with_an_example_to_copy() {
        let message = parse_endpoint("not-an-address")
            .expect_err("a hostname is not an address")
            .to_string();
        assert!(
            message.contains("162.159.192.1:2408"),
            "the error should show the shape expected, got: {message}"
        );
    }

    #[test]
    fn an_impossible_port_is_rejected_rather_than_wrapped() {
        assert!(parse_endpoint("162.159.192.1:70000").is_err());
    }

    #[test]
    fn a_pair_may_be_written_with_a_comma_or_a_space() {
        for written in [
            "162.159.192.1:2408,162.159.195.1:500",
            "162.159.192.1:2408, 162.159.195.1:500",
            "162.159.192.1:2408 162.159.195.1:500",
        ] {
            let peers = parse_endpoint_list(written).expect(written);
            assert_eq!(peers.len(), 2, "{written} names two hops");
            assert_eq!(peers[0], "162.159.192.1:2408".parse().unwrap());
            assert_eq!(peers[1], "162.159.195.1:500".parse().unwrap());
        }
    }

    #[test]
    fn a_third_address_is_refused_because_there_are_only_two_hops() {
        let outcome = parse_endpoint_list("1.1.1.1:2408,2.2.2.2:2408,3.3.3.3:2408");
        assert!(outcome.is_err());
    }

    #[test]
    fn the_pair_setting_fills_the_outer_hop_first() {
        let chosen = wiw_endpoints_of(&env(&[(
            "AETHER_WIW_PEERS",
            "162.159.192.1:2408,162.159.195.1:500",
        )]))
        .expect("a usable pair");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, Some("162.159.195.1:500".parse().unwrap()));
    }

    #[test]
    fn one_address_pins_the_outer_hop_and_leaves_the_inner_one_to_the_scan() {
        let chosen = wiw_endpoints_of(&env(&[("AETHER_WIW_PEERS", "162.159.192.1:894")]))
            .expect("a single hop");
        assert_eq!(chosen.outer, Some("162.159.192.1:894".parse().unwrap()));
        assert_eq!(chosen.inner, None);
    }

    #[test]
    fn a_hop_named_on_its_own_wins_over_the_pair() {
        let chosen = wiw_endpoints_of(&env(&[
            ("AETHER_WIW_PEERS", "162.159.192.1:2408,162.159.195.1:500"),
            ("AETHER_WIW_INNER_PEER", "188.114.96.1:1701"),
        ]))
        .expect("the inner override");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, Some("188.114.96.1:1701".parse().unwrap()));
    }

    #[test]
    fn only_the_inner_hop_may_be_pinned() {
        let chosen = wiw_endpoints_of(&env(&[("AETHER_WIW_INNER_PEER", "188.114.96.1:2408")]))
            .expect("the inner hop");
        assert_eq!(chosen.outer, None);
        assert_eq!(chosen.inner, Some("188.114.96.1:2408".parse().unwrap()));
    }

    /// WireGuard tells two tunnels apart by public key, so one edge may carry
    /// both hops.
    ///
    /// This used to be an error, and that error was one of the two gates that
    /// turned "this network offers one edge" into an endless rescan. The two
    /// ports differ here on purpose: the point is that the *host* is shared, not
    /// that the endpoints are identical.
    #[test]
    fn one_address_may_serve_as_both_wireguard_hops() {
        let chosen = wiw_endpoints_of(&env(&[
            ("AETHER_WIW_OUTER_PEER", "162.159.192.1:2408"),
            ("AETHER_WIW_INNER_PEER", "162.159.192.1:894"),
        ]))
        .expect("one edge is a legal warp-in-warp");

        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, Some("162.159.192.1:894".parse().unwrap()));
    }

    /// The relaxation above belongs to WireGuard alone.
    ///
    /// A MASQUE edge validates the client certificate and may not accept a
    /// second identity, so MASQUE keeps the refusal. Both carriers share
    /// `nested_endpoints_of`, and this test is what stops the shared parser
    /// from loosening both at once.
    #[test]
    fn one_address_cannot_serve_as_both_masque_hops() {
        let outcome = mim_endpoints_of(&env(&[
            ("AETHER_MIM_OUTER_PEER", "162.159.192.1:443"),
            ("AETHER_MIM_INNER_PEER", "162.159.192.1:8443"),
        ]));

        let message = outcome
            .expect_err("the same MASQUE edge twice is not masque-in-masque")
            .to_string();
        assert!(
            message.contains("162.159.192.1"),
            "the error should name the address, got: {message}"
        );
    }

    #[test]
    fn asking_for_a_scan_leaves_both_hops_open() {
        for written in ["auto", "scan", "off", "none", "0"] {
            let lookup = env(&[("AETHER_WIW_PEERS", written)]);
            assert!(wiw_scan_requested(&lookup), "{written} means scan");
            assert!(
                wiw_endpoints_of(&lookup).expect(written).is_empty(),
                "{written} should pin nothing"
            );
        }
    }

    #[test]
    fn nothing_set_pins_nothing() {
        assert!(wiw_endpoints_of(&env(&[])).expect("empty").is_empty());
    }

    #[test]
    fn a_malformed_address_is_an_error_rather_than_a_silent_scan() {
        assert!(wiw_endpoints_of(&env(&[("AETHER_WIW_OUTER_PEER", "162.159.192")])).is_err());
    }

    #[test]
    fn a_hop_set_without_a_port_is_an_error_rather_than_a_silent_scan() {
        assert!(wiw_endpoints_of(&env(&[("AETHER_WIW_OUTER_PEER", "162.159.192.1")])).is_err());
    }

    #[test]
    fn the_older_wg_peer_setting_still_names_the_outer_hop() {
        let chosen = wiw_endpoints_with_fallback(&env(&[("AETHER_WG_PEER", "162.159.192.1:2408")]))
            .expect("the documented --gool --wg-peer pairing");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, None);
    }

    #[test]
    fn the_generic_peer_setting_is_the_last_fallback() {
        let chosen = wiw_endpoints_with_fallback(&env(&[("AETHER_PEER", "162.159.192.1:2408")]))
            .expect("--peer names the outer hop too");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
    }

    #[test]
    fn a_hop_chosen_for_warp_in_warp_beats_the_older_setting() {
        let chosen = wiw_endpoints_with_fallback(&env(&[
            ("AETHER_WG_PEER", "162.159.192.1:2408"),
            ("AETHER_WIW_OUTER_PEER", "188.114.96.1:2408"),
        ]))
        .expect("the warp-in-warp setting is the specific one");
        assert_eq!(chosen.outer, Some("188.114.96.1:2408".parse().unwrap()));
    }

    #[test]
    fn the_older_setting_may_carry_both_hops_at_once() {
        let chosen = wiw_endpoints_with_fallback(&env(&[(
            "AETHER_WG_PEER",
            "162.159.192.1:2408,188.114.96.1:2408",
        )]))
        .expect("a pair");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, Some("188.114.96.1:2408".parse().unwrap()));
    }

    #[test]
    fn the_older_setting_does_not_overwrite_a_pinned_inner_hop() {
        let chosen = wiw_endpoints_with_fallback(&env(&[
            ("AETHER_WG_PEER", "162.159.192.1:2408,188.114.96.1:2408"),
            ("AETHER_WIW_INNER_PEER", "162.159.195.1:2408"),
        ]))
        .expect("the inner hop stays where it was put");
        assert_eq!(chosen.outer, Some("162.159.192.1:2408".parse().unwrap()));
        assert_eq!(chosen.inner, Some("162.159.195.1:2408".parse().unwrap()));
    }
}
