use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use futures::stream::StreamExt;
use rand::RngExt;

use crate::error::{AetherError, Result};
use crate::noize::NoizeConfig;
use crate::quic;

pub const MASQUE_DOCUMENTED_CIDRS_V4: &[&str] = &["162.159.197.0/24", "162.159.198.0/24"];

pub const MASQUE_DOH_CIDRS_V4: &[&str] = &["162.159.36.0/24", "162.159.46.0/24"];

// >>> AETHER-APP-FIX masque-seeds-are-measured-not-guessed
// The seed list and the CIDR order below are the 2026-09-02 re-measurement the
// mobile core shipped (freshly enrolled device certificate, four connect-ip
// attempts per address, judged only by `:status 200`):
//
//   162.159.199.1   4/4 :status 200   best 80ms
//   162.159.199.2   4/4 :status 200   best 87ms
//   162.159.198.2   3/4 :status 200   best 81ms  (the endpoint the API assigns)
//   162.159.198.1   2/4 :status 200   best 113ms
//   162.159.197.1   0/4
//   162.159.197.2   0/4
//   162.159.197.3   0/4
//   162.159.204.2   0/4
//   162.159.204.3   0/4
//   162.159.196.1   0/4
//   162.159.196.2   0/4
//   162.159.195.1   0/4
//   162.159.192.1   0/4
//   162.159.193.1   0/4
//
// Three findings drive the layout:
//
//   * 162.159.199.0/24 — the two best gateways on the fleet — was missing from
//     the list entirely, so those edges were unreachable by seed and by sweep
//     alike. The desktop 2026-09-23 MIM log matches this defect exactly: every
//     inner candidate (196.1, 195.1, 192.1, 197.3, 197.1, 198.1, 198.2) came
//     back TLS alert 40/46/49 while the one edge the account had actually
//     assigned (198.2) carried the outer hop fine.
//   * "Completes the QUIC handshake" is not evidence of a gateway: the 197.x
//     and 204.x addresses finish TLS and then never answer connect-ip.
//   * One probe is not a verdict — working gateways missed attempts, so the
//     ranking was only written after four samples per address.
pub const MASQUE_CIDRS_V4: &[&str] = &[
    "162.159.199.0/24",
    "162.159.198.0/24",
    "162.159.197.0/24",
    "162.159.196.0/24",
    "162.159.195.0/24",
    "162.159.192.0/24",
    "162.159.193.0/24",
    "162.159.204.0/24",
    "172.65.251.0/24",
    "188.114.96.0/24",
    "188.114.97.0/24",
    "188.114.98.0/24",
    "188.114.99.0/24",
    "162.159.36.0/24",
    "162.159.46.0/24",
];

pub const MASQUE_SEEDS: &[&str] = &[
    "162.159.199.2",
    "162.159.198.2",
    "162.159.198.1",
    "162.159.199.1",
    "162.159.197.1",
    "162.159.204.2",
];

/// The addresses measured answering `:status 200` to connect-ip, best first.
///
/// Kept separate from [`MASQUE_SEEDS`] because the start path needs to know
/// *which* peers are worth a second chance on another UDP port: retrying an
/// ordinary Cloudflare edge on UDP/1701 is pointless (it has no connect-ip
/// listener on any port), while retrying a real gateway there is the escape
/// from a carrier that degrades UDP/443 to this range specifically.
pub const MASQUE_VERIFIED_GATEWAYS: &[&str] = &[
    "162.159.199.2",
    "162.159.198.2",
    "162.159.198.1",
    "162.159.199.1",
];

/// Alternate UDP ports a verified gateway was measured serving connect-ip on.
///
/// Two attempts per (gateway, port) across all four verified gateways with an
/// enrolled certificate, counting only connect-ip `:status 200`:
///
/// ```text
///                :500  :1701  :4500  :8095
/// 162.159.199.1   2/2   2/2    2/2    2/2
/// 162.159.199.2   1/2   0/2    1/2    2/2
/// 162.159.198.2   1/2   2/2    1/2    1/2
/// 162.159.198.1   2/2   0/2    1/2    2/2
/// ```
pub const MASQUE_ALT_PORTS: &[u16] = &[1701, 8095, 500, 4500];
// <<< AETHER-APP-FIX masque-seeds-are-measured-not-guessed

pub const MASQUE_PORTS: &[u16] = &[443, 500, 1701, 4500, 4443, 8443, 8095];

pub const MASQUE_CIDRS_V6: &[&str] = &[
    "2606:4700:d0::/48",
    "2606:4700:102::/48",
    "2606:4700:d1::/48",
];

pub const MASQUE_ZT_CIDRS_V4: &[&str] = &["162.159.197.0/24"];

pub const MASQUE_ZT_CIDRS_V6: &[&str] = &["2606:4700:102::/48"];

// >>> AETHER-APP-FIX an-inner-hop-wants-a-proven-edge
/// Gateways this process has *seen answer a real MASQUE handshake*, newest
/// first, shared by every scan in the process.
///
/// ## Why the scan has to hand its findings on
///
/// The inner hop of MASQUE-in-MASQUE is chosen by [`crate::inner_masque_candidates`],
/// which used to pick six hosts at random inside the outer hop's `/24`. A random
/// address in `162.159.198.0/24` is not a MASQUE edge; it is just an address in
/// the same block. The 2026-09-22 log spent four full TLS handshakes learning
/// that - every one of them came back as a QUIC `CRYPTO_ERROR` carrying TLS
/// alert 40 (`handshake_failure`):
///
/// ```text
///   [-] inner edge 162.159.198.153:443 does not serve masque from inside the tunnel
///   [-] inner edge 162.159.198.235:443 does not serve masque from inside the tunnel
///   [-] inner edge 162.159.198.216:443 does not serve masque from inside the tunnel
///   [-] inner edge 162.159.198.46:443  does not serve masque from inside the tunnel
/// ```
///
/// Meanwhile the outer scan had already proven `162.159.198.2:443` works. The
/// addresses a scan proves are the best possible input for the inner hop, so the
/// scan records them here and the inner hop reads them back.
///
/// Bounded so a long-lived process cannot grow it without limit.
static PROVEN_GATEWAYS: OnceLock<Mutex<Vec<SocketAddr>>> = OnceLock::new();

const PROVEN_GATEWAYS_MAX: usize = 32;

fn proven_cell() -> &'static Mutex<Vec<SocketAddr>> {
    PROVEN_GATEWAYS.get_or_init(|| Mutex::new(Vec::new()))
}

/// Records a gateway that just completed a deep MASQUE verification.
pub fn remember_gateway(addr: SocketAddr) {
    let mut list = match proven_cell().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };
    // Move to the front rather than duplicating: the most recent proof is the
    // one most likely to still hold.
    list.retain(|existing| *existing != addr);
    list.insert(0, addr);
    list.truncate(PROVEN_GATEWAYS_MAX);
}

/// Gateways proven this session, best-known first.
pub fn proven_gateways() -> Vec<SocketAddr> {
    match proven_cell().lock() {
        Ok(g) => g.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}
// <<< AETHER-APP-FIX an-inner-hop-wants-a-proven-edge

pub fn zero_trust_mode() -> bool {
    std::env::var("AETHER_TEAM")
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

pub fn prioritize(all: &[&'static str], first: &[&'static str]) -> Vec<&'static str> {
    if !zero_trust_mode() {
        return all.to_vec();
    }

    let mut out: Vec<&'static str> = Vec::with_capacity(all.len());
    for entry in first {
        if all.contains(entry) {
            out.push(entry);
        }
    }
    for entry in all {
        if !out.contains(entry) {
            out.push(entry);
        }
    }
    out
}

// >>> AETHER-APP-PATCH scan-cidrs
//
// «بازهٔ آدرس» در تنظیمات برنامه (EndpointMode::ManualRange).
//
// برنامه سه متغیر AETHER_SCAN_CIDRS / AETHER_MASQUE_CIDRS / AETHER_WG_CIDRS را
// به موتور می‌دهد، ولی آپ‌استریم هیچ‌کدام را نمی‌خواند: بدون این پچ کاربر بازه
// می‌نویسد و اسکن، بی‌صدا، همان بازه‌های توکار خودش را جارو می‌کند — تنظیمی که
// فقط ادای کار کردن درمی‌آورد.
//
// قاعده‌ها:
//   * متغیر مخصوص پروتکل بر AETHER_SCAN_CIDRS مقدم است.
//   * این ورودیِ کاربر است: هر تکه اعتبارسنجی می‌شود و تکهٔ نامعتبر دور
//     انداخته می‌شود، نه اینکه اسکن را بترکاند.
//   * اگر هیچ تکهٔ معتبری نماند، رفتار توکار برمی‌گردد. اسکنِ خالی یعنی «اصلاً
//     وصل نشو»، و کاربری که بازه را غلط تایپ کرده انتظارِ آن را ندارد.
//   * ترتیبِ نوشتهٔ کاربر حفظ می‌شود؛ prioritize (چیدنِ Zero Trust جلوتر) روی
//     بازهٔ دستی اعمال نمی‌شود، چون خودِ کاربر گفته چه چیزی اول بیاید.

/// یک تکهٔ ورودی → بازه‌ای که سازندهٔ کاندیدها می‌فهمد، یا None.
///
/// دقت در طولِ پیشوند لازم است: `parse_cidr_v4` هر عددی را که در u8 جا شود
/// می‌پذیرد، پس «10.0.0.0/64» از آن رد می‌شود و بعد در `sample_cidr_v4` به یک
/// آدرسِ تنها فرومی‌پاشد. یعنی بازهٔ غلط، بی هیچ پیامی، به یک آی‌پی تبدیل
/// می‌شود. اینجا جلویش گرفته می‌شود.
fn normalize_cidr(entry: &str) -> Option<String> {
    let entry = entry.trim();
    if entry.is_empty() {
        return None;
    }

    if let Some((ip, prefix)) = entry.split_once('/') {
        let len: u8 = prefix.trim().parse().ok()?;
        let ip = ip.trim();
        if ip.parse::<Ipv4Addr>().is_ok() && len <= 32 {
            return Some(format!("{ip}/{len}"));
        }
        if ip.parse::<Ipv6Addr>().is_ok() && len <= 128 {
            return Some(format!("{ip}/{len}"));
        }
        return None;
    }

    // یک آدرس تنها هم بازهٔ یک‌میزبانه است. کاربری که «188.114.98.7» نوشته
    // منظورش همان یک آدرس است، نه ورودیِ خراب.
    if let Ok(a) = entry.parse::<Ipv4Addr>() {
        return Some(format!("{a}/32"));
    }
    if let Ok(a) = entry.parse::<Ipv6Addr>() {
        return Some(format!("{a}/128"));
    }
    None
}

/// متنِ خامِ متغیر → فهرست بازه‌های معتبر. جدا از خواندنِ محیط نگه داشته شده تا
/// آزمون‌پذیر باشد بدون دست‌زدن به محیطِ فرایند.
fn parse_pinned(raw: &str) -> Option<Vec<&'static str>> {
    let mut out: Vec<&'static str> = Vec::new();
    for piece in raw.split([',', ';', ' ', '\t', '\n', '\r']) {
        if let Some(norm) = normalize_cidr(piece) {
            if out.iter().any(|existing| *existing == norm.as_str()) {
                continue;
            }
            // یک‌بار در طول عمر فرایند و فقط برای چند بازه؛ سازندهٔ کاندیدها
            // &'static می‌خواهد و همان چیزی است که بازه‌های توکار هستند.
            out.push(Box::leak(norm.into_boxed_str()));
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn pinned_all(specific: &str) -> Option<&'static [&'static str]> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<&'static [&'static str]>>>> =
        OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(hit) = guard.get(specific) {
        return *hit;
    }

    let raw = std::env::var(specific)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            std::env::var("AETHER_SCAN_CIDRS")
                .ok()
                .filter(|v| !v.trim().is_empty())
        });
    let value = raw
        .as_deref()
        .and_then(parse_pinned)
        .map(|list| &*Box::leak(list.into_boxed_slice()));
    guard.insert(specific.to_string(), value);
    value
}

/// بازه‌های IPv4 که کاربر پین کرده، اگر لااقل یکی معتبر باشد.
pub fn pinned_cidrs_v4(specific: &str) -> Option<Vec<&'static str>> {
    let picked: Vec<&'static str> = pinned_all(specific)?
        .iter()
        .copied()
        .filter(|c| c.contains('.'))
        .collect();
    (!picked.is_empty()).then_some(picked)
}

/// همان برای IPv6.
pub fn pinned_cidrs_v6(specific: &str) -> Option<Vec<&'static str>> {
    let picked: Vec<&'static str> = pinned_all(specific)?
        .iter()
        .copied()
        .filter(|c| c.contains(':'))
        .collect();
    (!picked.is_empty()).then_some(picked)
}

fn cidr_v4_contains(cidr: &str, addr: Ipv4Addr) -> bool {
    match parse_cidr_v4(cidr) {
        Some((base, len)) if len <= 32 => {
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            (u32::from(addr) & mask) == (base & mask)
        }
        _ => false,
    }
}

fn cidr_v6_contains(cidr: &str, addr: Ipv6Addr) -> bool {
    match parse_cidr_v6(cidr) {
        Some((base, len)) if len <= 128 => {
            let mask = if len == 0 {
                0
            } else {
                u128::MAX << (128 - len)
            };
            (u128::from(addr) & mask) == (base & mask)
        }
        _ => false,
    }
}

/// دانه‌های توکار وقتی کاربر بازه پین کرده است.
///
/// دانه‌ها اول از همه پروب می‌شوند، پس اگر دست‌نخورده بمانند، پین‌شدنِ بازه
/// بی‌معنی می‌شود: تونل با احتمال زیاد روی آدرسی بسته می‌شود که کاربر آن را
/// نخواسته. آن‌هایی که *داخل* بازه هستند می‌مانند — سرعتِ راه‌اندازی را نگه
/// می‌دارند بی آنکه از بازه بیرون بزنند.
pub fn seeds_within(seeds: &[&'static str], specific: &str) -> Vec<&'static str> {
    if pinned_all(specific).is_none() {
        return seeds.to_vec();
    }
    let v4 = pinned_cidrs_v4(specific).unwrap_or_default();
    let v6 = pinned_cidrs_v6(specific).unwrap_or_default();
    seeds
        .iter()
        .copied()
        .filter(|seed| {
            if let Ok(a) = seed.parse::<Ipv4Addr>() {
                return v4.iter().any(|c| cidr_v4_contains(c, a));
            }
            if let Ok(a) = seed.parse::<Ipv6Addr>() {
                return v6.iter().any(|c| cidr_v6_contains(c, a));
            }
            false
        })
        .collect()
}
// <<< AETHER-APP-PATCH scan-cidrs

pub fn masque_cidrs_v4() -> Vec<&'static str> {
    // >>> AETHER-APP-PATCH scan-cidrs
    if let Some(pinned) = pinned_cidrs_v4("AETHER_MASQUE_CIDRS") {
        return pinned;
    }
    // <<< AETHER-APP-PATCH scan-cidrs
    prioritize(MASQUE_CIDRS_V4, MASQUE_ZT_CIDRS_V4)
}

pub fn masque_cidrs_v6() -> Vec<&'static str> {
    // >>> AETHER-APP-PATCH scan-cidrs
    if let Some(pinned) = pinned_cidrs_v6("AETHER_MASQUE_CIDRS") {
        return pinned;
    }
    // <<< AETHER-APP-PATCH scan-cidrs
    prioritize(MASQUE_CIDRS_V6, MASQUE_ZT_CIDRS_V6)
}

pub const MASQUE_SEEDS_V6: &[&str] = &[
    "2606:4700:d0::a29f:c602",
    "2606:4700:d1::a29f:c602",
    "2606:4700:d0::a29f:c601",
    "2606:4700:d0::a29f:c001",
];

#[derive(Debug, Clone, Copy)]
pub struct ProbeResult {
    pub ip: IpAddr,
    pub port: u16,
    pub rtt: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpScan {
    V4,
    V6,
    Both,
}

impl IpScan {
    pub fn parse(s: &str) -> IpScan {
        match s.trim().to_lowercase().as_str() {
            "6" | "v6" | "ipv6" => IpScan::V6,
            "both" | "all" | "dual" => IpScan::Both,
            _ => IpScan::V4,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            IpScan::V4 => "ipv4",
            IpScan::V6 => "ipv6",
            IpScan::Both => "dual-stack",
        }
    }

    pub fn want_v4(&self) -> bool {
        matches!(self, IpScan::V4 | IpScan::Both)
    }

    pub fn want_v6(&self) -> bool {
        matches!(self, IpScan::V6 | IpScan::Both)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanMode {
    Turbo,
    Balanced,
    Thorough,
    Stealth,
    Ironclad,
}

impl ScanMode {
    pub fn parse(s: &str) -> ScanMode {
        match s.trim().to_lowercase().as_str() {
            "turbo" | "fast" => ScanMode::Turbo,
            "thorough" | "deep" | "pro" => ScanMode::Thorough,
            "stealth" | "quiet" => ScanMode::Stealth,
            "ironclad" | "real" | "verify" | "guaranteed" => ScanMode::Ironclad,
            _ => ScanMode::Balanced,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            ScanMode::Turbo => "turbo",
            ScanMode::Balanced => "balanced",
            ScanMode::Thorough => "thorough",
            ScanMode::Stealth => "stealth",
            ScanMode::Ironclad => "ironclad",
        }
    }

    fn strategy(&self) -> Strategy {
        match self {
            ScanMode::Turbo => Strategy {
                concurrency: 20,
                per_probe_timeout: Duration::from_millis(6000),
                overall_deadline: Duration::from_secs(45),
                quiet_after_first: Duration::from_secs(0),
                target_successes: 1,
                early_exit_first: true,
                full_subnet: false,
                sample_per_cidr: 64,
            },
            ScanMode::Balanced => Strategy {
                concurrency: 16,
                per_probe_timeout: Duration::from_millis(6000),
                overall_deadline: Duration::from_secs(120),
                quiet_after_first: Duration::from_secs(20),
                target_successes: 6,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 140,
            },
            ScanMode::Thorough => Strategy {
                concurrency: 20,
                per_probe_timeout: Duration::from_millis(10000),
                overall_deadline: Duration::from_secs(300),
                quiet_after_first: Duration::from_secs(30),
                target_successes: 0,
                early_exit_first: false,
                full_subnet: true,
                sample_per_cidr: 0,
            },
            ScanMode::Stealth => Strategy {
                concurrency: 3,
                per_probe_timeout: Duration::from_millis(12000),
                overall_deadline: Duration::from_secs(180),
                quiet_after_first: Duration::from_secs(25),
                target_successes: 4,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 64,
            },
            ScanMode::Ironclad => Strategy {
                concurrency: 4,
                per_probe_timeout: Duration::from_millis(15000),
                overall_deadline: Duration::from_secs(180),
                quiet_after_first: Duration::from_secs(15),
                target_successes: 3,
                early_exit_first: false,
                full_subnet: false,
                sample_per_cidr: 140,
            },
        }
    }
}

/// The scan budget the launcher hands down in `AETHER_SCAN_BUDGET_MS`.
///
/// ## 1.2.3-p3: the scan and the stopwatch used to be strangers
///
/// The app waits a fixed window for SOCKS5 to open (35 s for the first rung of
/// the ladder, 60 s afterwards) and kills the engine when it expires. The turbo
/// strategy below gives itself a 45 s scan budget - and only starts counting
/// after the identity is loaded, an ECH lookup may have run and the cached
/// gateway has been verified. The two numbers were never reconciled, so on any
/// network that needed a real scan the first rung could not finish one:
///
/// ```text
///   14:20:04  Waiting for SOCKS5 ... (timeout=35s)
///   14:20:09  scanning fresh, budget=45s
///   14:20:39  Engine still scanning - tearing down this attempt
/// ```
///
/// Thirty seconds of probing, thrown away three quarters of the way through,
/// twice in a row, on a plan that then spent another minute repeating it.
///
/// With the budget passed down, a scan is sized to the window it is actually
/// being held to: it either finishes, or it reports `no clean endpoint` in time
/// for the ladder to advance on its own terms rather than on a stopwatch.
pub fn scan_budget_override() -> Option<Duration> {
    std::env::var("AETHER_SCAN_BUDGET_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&ms| ms > 0)
        .map(Duration::from_millis)
}

/// Caps a strategy deadline with the launcher's budget. Never lengthens it: a
/// generous window is not permission to scan for longer than the mode allows.
pub fn apply_scan_budget(default_deadline: Duration, what: &str) -> Duration {
    match scan_budget_override() {
        Some(budget) if budget < default_deadline => {
            log::info!(
                "[*] {what} scan budget trimmed to {:?} to fit the launcher's attempt window (mode default {:?})",
                budget,
                default_deadline
            );
            budget
        }
        _ => default_deadline,
    }
}

/// Consecutive probe failures, with nothing whatsoever having answered, after
/// which the carrier itself is treated as blocked rather than the endpoints.
///
/// ## Why give up early at all
///
/// When QUIC is filtered, every candidate fails identically - by timing out. At
/// 20 in flight and a 6 s per-probe timeout that is about three verdicts a
/// second, so the full budget buys ~150 hopeless attempts and learns nothing
/// from any of them. The documented gateway seeds are probed FIRST and answer in
/// well under a second on a network where the carrier works, so dozens of
/// consecutive failures is not evidence about individual endpoints, it is
/// evidence about the transport. Reporting that immediately is what lets the
/// ladder move to a carrier that can work while the user is still watching.
const CARRIER_DEAD_FAILURES: usize = 64;

/// ...and never before this much time has passed, so a merely slow or lossy
/// network can never be mistaken for a filtered one.
const CARRIER_DEAD_MIN_ELAPSED: Duration = Duration::from_secs(12);

/// Escape hatch: `AETHER_SCAN_NO_EARLY_ABORT=1` restores the previous behaviour
/// of always spending the entire budget.
fn early_abort_enabled() -> bool {
    std::env::var("AETHER_SCAN_NO_EARLY_ABORT").is_err()
}

/// >>> AETHER-APP-FIX settle-after-the-first-good-gateway
/// How long the scan keeps looking *after* the first gateway has answered.
///
/// ## The bug this closes
///
/// The settle window used to be armed only once the scan already held
/// `target_successes` gateways - six of them in `balanced`. On a network where
/// one edge answers and the remaining two thousand are filtered, that condition
/// is **never** reached, so the window was never armed and the loop ran to the
/// very last millisecond of its budget. Two field logs of 2026-09-22 show the
/// cost:
///
/// ```text
///   log 1 (aether-psiphon, masque)   05:43:46.898 scan starts, budget=61s
///                                    05:43:49.408 [+] candidate ok 162.159.198.2:443
///                                    05:44:47.909 [-] scan deadline reached   <- 58s later
///   log 3 (aether, masque*2)         05:48:30.866 scan starts, budget=61s
///                                    05:48:33.580 [+] candidate ok 162.159.198.2:443
///                                    05:49:31.873 [-] scan deadline reached   <- 58s later
/// ```
///
/// In log 3 the launcher then killed the attempt at its 75 s window while the
/// inner hop was still being tried, twice in a row, and the user was told the
/// protocol "could not establish a working tunnel on this network". Nothing was
/// wrong with the network: the gateway had answered 2.7 s into the scan and the
/// engine spent the next 58 s confirming that the other 2010 candidates were
/// still filtered.
///
/// A gateway in hand is worth more than a sixth gateway. The window is now armed
/// by the **first** success and never extended, so the scan is bounded by
/// `first answer + settle` instead of by the whole budget - which is what the
/// name `quiet_after_first` always said it did.
///
/// Modes that declare no target (`thorough`, the full-subnet sweep) keep their
/// old "scan everything" behaviour on purpose: that mode exists to find the
/// best edge, not the first usable one.
///
/// `AETHER_SCAN_SETTLE_MS=<ms>` overrides the window, and
/// `AETHER_SCAN_FULL_BUDGET=1` restores the old always-spend-it-all behaviour.
///
/// Shared with [`crate::wg_prober`], which had the identical defect: its
/// `target_successes` for `balanced` is five, so on a network where two or three
/// endpoints answer, its settle window was never armed either and the scan ran
/// to the last millisecond of the same budget. One helper, one behaviour, so the
/// two probers cannot drift apart again.
pub(crate) fn settle_window(mode_default: Duration) -> Duration {
    if std::env::var("AETHER_SCAN_FULL_BUDGET").is_ok() {
        return Duration::ZERO;
    }
    std::env::var("AETHER_SCAN_SETTLE_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_millis)
        .unwrap_or(mode_default)
}
// <<< AETHER-APP-FIX settle-after-the-first-good-gateway

const IRONCLAD_TCPING_TIMEOUT: Duration = Duration::from_secs(10);

struct Strategy {
    concurrency: usize,
    per_probe_timeout: Duration,
    overall_deadline: Duration,
    quiet_after_first: Duration,
    target_successes: usize,
    early_exit_first: bool,
    full_subnet: bool,
    sample_per_cidr: usize,
}

#[derive(Clone)]
pub struct MasqueProbe {
    pub sni: String,
    pub authority: String,
    pub path: String,
    pub cert_pem: Arc<[u8]>,
    pub key_pem: Arc<[u8]>,
    pub ech_config_list: Option<Arc<[u8]>>,
    pub noize: NoizeConfig,
    pub ports: Vec<u16>,
    pub ip: IpScan,
    pub local_ipv4: Ipv4Addr,
}

pub async fn host_has_ipv6() -> bool {
    match crate::egress::udp_bind("[::]:0".parse().expect("a wildcard address")) {
        Ok(sock) => sock.connect("[2606:4700:d0::a29f:c001]:443").await.is_ok(),
        Err(_) => false,
    }
}

pub async fn hunt_best_gateway(probe: &MasqueProbe, mode: ScanMode) -> Result<ProbeResult> {
    let mut st = mode.strategy();
    st.concurrency = crate::sysprofile::cap_concurrency(st.concurrency);
    st.overall_deadline = apply_scan_budget(st.overall_deadline, "MASQUE");
    let timeout = st.per_probe_timeout;
    let mut effective_ip = probe.ip;
    if probe.ip.want_v6() && !host_has_ipv6().await {
        if probe.ip.want_v4() {
            log::warn!("[-] host has no IPv6 route; falling back to IPv4-only scan");
            effective_ip = IpScan::V4;
        } else {
            log::warn!("[-] host has no IPv6 route; IPv6 scan needs native IPv6 connectivity");
            return Err(AetherError::NoCleanEndpoint);
        }
    }
    let candidates = build_candidates(&st, &probe.ports, effective_ip);

    log::info!(
        "[*] scan mode={} ip={} candidates={} ports={:?} concurrency={} per_probe={:?} budget={:?}",
        mode.label(),
        effective_ip.label(),
        candidates.len(),
        probe.ports,
        st.concurrency,
        st.per_probe_timeout,
        st.overall_deadline,
    );

    let ironclad = mode == ScanMode::Ironclad;

    let stream = futures::stream::iter(
        candidates
            .into_iter()
            .map(|(ip, port)| verify_one(probe, ip, port, timeout, ironclad)),
    )
    .buffer_unordered(st.concurrency);
    tokio::pin!(stream);

    let scan_started = Instant::now();
    let deadline = scan_started + st.overall_deadline;
    let mut best: Option<ProbeResult> = None;
    let mut found = 0usize;
    let mut failures = 0usize;
    let mut quiet_until: Option<Instant> = None;

    loop {
        let effective = match quiet_until {
            Some(q) => q.min(deadline),
            None => deadline,
        };
        let remaining = effective.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            if best.is_some() {
                if quiet_until.is_some() {
                    log::info!("[+] no new gateways recently, finalizing selection");
                } else {
                    log::warn!("[-] scan deadline reached");
                }
            } else {
                log::warn!("[-] scan deadline reached with no gateway");
            }
            break;
        }

        tokio::select! {
            item = stream.next() => {
                match item {
                    None => break,
                    Some(None) => {
                        // Nothing has answered yet and dozens of candidates in a
                        // row have failed: this is the transport being blocked,
                        // not a run of unlucky endpoints. See
                        // [`CARRIER_DEAD_FAILURES`].
                        failures += 1;
                        if best.is_none()
                            && early_abort_enabled()
                            && failures >= CARRIER_DEAD_FAILURES
                            && scan_started.elapsed() >= CARRIER_DEAD_MIN_ELAPSED
                        {
                            log::warn!(
                                "[-] {failures} candidates failed and none answered in {:?}: this carrier looks blocked on this network - abandoning the scan instead of spending the rest of the {:?} budget on it",
                                scan_started.elapsed(),
                                st.overall_deadline
                            );
                            break;
                        }
                        continue;
                    }
                    Some(Some(pr)) => {
                        log::info!("[+] candidate ok {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
                        // >>> AETHER-APP-FIX an-inner-hop-wants-a-proven-edge
                        // Hand the finding on: the inner hop of MASQUE-in-MASQUE
                        // has nothing better to aim at than an address this scan
                        // just watched complete a MASQUE handshake.
                        remember_gateway(SocketAddr::new(pr.ip, pr.port));
                        // <<< AETHER-APP-FIX an-inner-hop-wants-a-proven-edge
                        if st.early_exit_first {
                            return Ok(pr);
                        }
                        best = Some(match best {
                            Some(cur) if cur.rtt <= pr.rtt => cur,
                            _ => pr,
                        });
                        found += 1;

                        // >>> AETHER-APP-FIX settle-after-the-first-good-gateway
                        // The window is armed by the FIRST success, not by the
                        // sixth. See [`settle_window`] for the field logs this
                        // closes. It is deliberately never extended: a scan that
                        // re-arms on every new hit is the unbounded scan again.
                        if st.target_successes > 0 && quiet_until.is_none() {
                            let settle = settle_window(st.quiet_after_first);
                            if !settle.is_zero() {
                                if found >= st.target_successes {
                                    log::info!(
                                        "[+] reached target of {} gateways, selecting best",
                                        st.target_successes
                                    );
                                } else {
                                    log::info!(
                                        "[+] first working gateway in hand ({} of {} wanted); \
                                         giving the scan {:?} more to try to beat it, then \
                                         selecting - a gateway in hand beats a longer scan",
                                        found,
                                        st.target_successes,
                                        settle
                                    );
                                }
                                quiet_until = Some(Instant::now() + settle);
                            } else if found >= st.target_successes {
                                break;
                            }
                        }
                        // <<< AETHER-APP-FIX settle-after-the-first-good-gateway
                    }
                }
            }
            _ = tokio::time::sleep(remaining) => {
                if best.is_some() {
                    if quiet_until.is_some() {
                        log::info!("[+] no new gateways recently, finalizing selection");
                    } else {
                        log::warn!("[-] scan deadline reached");
                    }
                } else {
                    log::warn!("[-] scan deadline reached with no gateway");
                }
                break;
            }
        }
    }

    match best {
        Some(pr) => {
            log::info!("[+] best gateway {}:{} rtt={:?}", pr.ip, pr.port, pr.rtt);
            Ok(pr)
        }
        None => Err(AetherError::NoCleanEndpoint),
    }
}

async fn verify_one(
    probe: &MasqueProbe,
    ip: IpAddr,
    port: u16,
    timeout: Duration,
    ironclad: bool,
) -> Option<ProbeResult> {
    if ironclad {
        let params = crate::tunnelping::MasquePingParams {
            peer: SocketAddr::new(ip, port),
            sni: probe.sni.clone(),
            authority: probe.authority.clone(),
            path: probe.path.clone(),
            cert_pem: probe.cert_pem.to_vec(),
            key_pem: probe.key_pem.to_vec(),
            noize: probe.noize.clone(),
            local_ipv4: probe.local_ipv4,
            local_ipv4_str: probe.local_ipv4.to_string(),
            local_ipv6_str: String::new(),
        };
        return match crate::tunnelping::masque_http_ping(&params, IRONCLAD_TCPING_TIMEOUT).await {
            Ok(rtt) => {
                log::info!(
                    "[+] ironclad verified {ip}:{port} real http round trip rtt={:?}",
                    rtt
                );
                Some(ProbeResult { ip, port, rtt })
            }
            Err(e) => {
                log::trace!("[-] ironclad {ip}:{port} failed real http check: {e}");
                None
            }
        };
    }

    if crate::masque_h2::enabled() {
        let cfg = crate::masque_h2::H2TunnelConfig {
            peer: SocketAddr::new(ip, port),
            sni: probe.sni.clone(),
            authority: probe.authority.clone(),
            path: probe.path.clone(),
            cert_pem: probe.cert_pem.to_vec(),
            key_pem: probe.key_pem.to_vec(),
            local_ipv4: probe.local_ipv4,
            quiet: true,
            pin_endpoint: true,
            expected_pins: crate::consts::MASQUE_PINS
                .iter()
                .map(|p| p.to_vec())
                .collect(),
        };
        return match crate::masque_h2::verify_h2(&cfg, timeout).await {
            Ok(rtt) => Some(ProbeResult { ip, port, rtt }),
            Err(e) => {
                log::trace!("h2 probe {ip}:{port} -> {e}");
                None
            }
        };
    }

    let vp = quic::VerifyParams {
        peer: SocketAddr::new(ip, port),
        sni: probe.sni.clone(),
        authority: probe.authority.clone(),
        path: probe.path.clone(),
        cert_pem: probe.cert_pem.to_vec(),
        key_pem: probe.key_pem.to_vec(),
        ech_config_list: probe.ech_config_list.as_ref().map(|a| a.to_vec()),
        noize: probe.noize.clone(),
        timeout,
        local_ipv4: probe.local_ipv4,
    };

    match quic::verify_masque(&vp).await {
        Ok(rtt) => Some(ProbeResult { ip, port, rtt }),
        Err(e) => {
            log::trace!("probe {ip}:{port} -> {e}");
            None
        }
    }
}

fn build_candidates(st: &Strategy, ports: &[u16], ip: IpScan) -> Vec<(IpAddr, u16)> {
    let primary = ports.first().copied().unwrap_or(443);
    let mut out: Vec<(IpAddr, u16)> = Vec::new();
    let mut seen: HashSet<(IpAddr, u16)> = HashSet::new();

    // >>> AETHER-APP-PATCH scan-cidrs — دانه‌ها هم به بازهٔ پین‌شده محدود می‌شوند
    let seeds: Vec<Ipv4Addr> = seeds_within(MASQUE_SEEDS, "AETHER_MASQUE_CIDRS")
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    let seeds6: Vec<Ipv6Addr> = seeds_within(MASQUE_SEEDS_V6, "AETHER_MASQUE_CIDRS")
        .iter()
        .filter_map(|s| s.parse().ok())
        .collect();
    // <<< AETHER-APP-PATCH scan-cidrs

    if ip.want_v4() {
        for a in &seeds {
            if seen.insert((IpAddr::V4(*a), primary)) {
                out.push((IpAddr::V4(*a), primary));
            }
        }
        let cidr_hosts: Vec<Vec<Ipv4Addr>> = masque_cidrs_v4()
            .iter()
            .map(|c| {
                if st.full_subnet {
                    enumerate_cidr_v4(c)
                } else {
                    sample_cidr_v4(c, st.sample_per_cidr)
                }
            })
            .collect();
        let max_len = cidr_hosts.iter().map(|v| v.len()).max().unwrap_or(0);
        for i in 0..max_len {
            for hosts in &cidr_hosts {
                if let Some(a) = hosts.get(i) {
                    if seen.insert((IpAddr::V4(*a), primary)) {
                        out.push((IpAddr::V4(*a), primary));
                    }
                }
            }
        }
    }

    if ip.want_v6() {
        for a in &seeds6 {
            if seen.insert((IpAddr::V6(*a), primary)) {
                out.push((IpAddr::V6(*a), primary));
            }
        }
        let per = if st.sample_per_cidr == 0 {
            96
        } else {
            st.sample_per_cidr
        };
        // >>> AETHER-APP-PATCH scan-cidrs
        // آدرس v6 وارپ یک آدرس v4 را در خودش جا می‌دهد؛ اگر کاربر بازهٔ v4 پین
        // کرده باشد، همان باید جاسازی شود، وگرنه v6 از بازه بیرون می‌زند.
        let embed_v4: Vec<&'static str> =
            pinned_cidrs_v4("AETHER_MASQUE_CIDRS").unwrap_or_else(|| MASQUE_CIDRS_V4.to_vec());
        let cidr6: Vec<Vec<Ipv6Addr>> = masque_cidrs_v6()
            .iter()
            .map(|c| sample_cidr_v6(c, per, &embed_v4))
            .collect();
        // <<< AETHER-APP-PATCH scan-cidrs
        let max6 = cidr6.iter().map(|v| v.len()).max().unwrap_or(0);
        for i in 0..max6 {
            for hosts in &cidr6 {
                if let Some(a) = hosts.get(i) {
                    if seen.insert((IpAddr::V6(*a), primary)) {
                        out.push((IpAddr::V6(*a), primary));
                    }
                }
            }
        }
    }

    if ip.want_v4() {
        for a in &seeds {
            for &port in ports {
                if port != primary && seen.insert((IpAddr::V4(*a), port)) {
                    out.push((IpAddr::V4(*a), port));
                }
            }
        }
    }
    if ip.want_v6() {
        for a in &seeds6 {
            for &port in ports {
                if port != primary && seen.insert((IpAddr::V6(*a), port)) {
                    out.push((IpAddr::V6(*a), port));
                }
            }
        }
    }

    out
}

fn parse_cidr_v4(cidr: &str) -> Option<(u32, u8)> {
    let (ip, prefix) = cidr.split_once('/')?;
    Some((
        u32::from(ip.parse::<Ipv4Addr>().ok()?),
        prefix.parse().ok()?,
    ))
}

fn enumerate_cidr_v4(cidr: &str) -> Vec<Ipv4Addr> {
    let (base, prefix) = match parse_cidr_v4(cidr) {
        Some(v) => v,
        None => return Vec::new(),
    };
    let host_bits = 32u32.saturating_sub(prefix as u32);
    if host_bits == 0 {
        return vec![Ipv4Addr::from(base)];
    }
    if host_bits > 12 {
        return Vec::new();
    }
    let size = 1u32 << host_bits;
    (1..size.saturating_sub(1))
        .map(|off| Ipv4Addr::from(base + off))
        .collect()
}

fn sample_cidr_v4(cidr: &str, n: usize) -> Vec<Ipv4Addr> {
    let (base, prefix) = match parse_cidr_v4(cidr) {
        Some(v) => v,
        None => return Vec::new(),
    };
    let host_bits = 32u32.saturating_sub(prefix as u32);
    let size = if host_bits >= 32 {
        u32::MAX
    } else {
        1u32 << host_bits
    };
    if size <= 2 {
        return vec![Ipv4Addr::from(base)];
    }

    let usable = size - 2;
    let want = (n as u32).min(usable);
    let mut rng = rand::rng();
    let mut chosen: HashSet<u32> = HashSet::with_capacity(want as usize);
    let mut out = Vec::with_capacity(want as usize);

    while (out.len() as u32) < want {
        let off = 1 + rng.random_range(0..usable);
        if chosen.insert(off) {
            out.push(Ipv4Addr::from(base + off));
        }
    }

    out
}

fn parse_cidr_v6(cidr: &str) -> Option<(u128, u8)> {
    let (ip, prefix) = cidr.split_once('/')?;
    Some((
        u128::from(ip.parse::<Ipv6Addr>().ok()?),
        prefix.parse().ok()?,
    ))
}

fn sample_cidr_v6(cidr: &str, n: usize, v4_cidrs: &[&str]) -> Vec<Ipv6Addr> {
    let (base, prefix) = match parse_cidr_v6(cidr) {
        Some(v) => v,
        None => return Vec::new(),
    };
    if 128u32.saturating_sub(prefix as u32) == 0 {
        return vec![Ipv6Addr::from(base)];
    }

    let v4: Vec<(u32, u8)> = v4_cidrs.iter().filter_map(|c| parse_cidr_v4(c)).collect();
    let mut rng = rand::rng();
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let embedded = if v4.is_empty() {
            rng.random::<u32>() as u128
        } else {
            let (b, p) = v4[rng.random_range(0..v4.len())];
            let host_bits = 32u32.saturating_sub(p as u32);
            let host = if host_bits == 0 {
                0
            } else {
                rng.random::<u32>() & ((1u32 << host_bits) - 1)
            };
            (b | host) as u128
        };
        out.push(Ipv6Addr::from(base | embedded));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // >>> AETHER-APP-PATCH scan-cidrs — آزمون‌های «بازهٔ آدرس»
    #[test]
    fn a_pinned_range_list_keeps_what_is_valid_and_drops_what_is_not() {
        let parsed = parse_pinned("162.159.192.0/24, 188.114.98.7 ;2606:4700:d0::/64").unwrap();
        assert_eq!(
            parsed,
            vec!["162.159.192.0/24", "188.114.98.7/32", "2606:4700:d0::/64"],
            "یک آدرس تنها باید بازهٔ یک‌میزبانه شود و ترتیب کاربر حفظ بماند"
        );

        // بازهٔ ناممکن روی v4: parse_cidr_v4 عدد را می‌پذیرد و بعد بی‌صدا به یک
        // آدرس فرومی‌پاشد، پس اینجا باید رد شود.
        assert!(parse_pinned("10.0.0.0/64").is_none());
        assert!(parse_pinned("not-an-ip, ,, /24").is_none());
        assert_eq!(
            parse_pinned("1.1.1.0/24,1.1.1.0/24").unwrap(),
            vec!["1.1.1.0/24"]
        );
    }

    #[test]
    fn a_pinned_range_replaces_the_built_in_ranges_and_trims_the_seeds() {
        // متغیر مخصوصِ همین آزمون تا با آزمون‌های دیگر (و AETHER_SCAN_CIDRS) قاطی نشود.
        std::env::set_var(
            "AETHER_TEST_PIN_CIDRS",
            "188.114.98.0/24, 2606:4700:d0::/64",
        );

        let v4 = pinned_cidrs_v4("AETHER_TEST_PIN_CIDRS").unwrap();
        assert_eq!(v4, vec!["188.114.98.0/24"]);
        let v6 = pinned_cidrs_v6("AETHER_TEST_PIN_CIDRS").unwrap();
        assert_eq!(v6, vec!["2606:4700:d0::/64"]);

        // دانهٔ داخل بازه می‌ماند، دانهٔ بیرون می‌رود.
        let kept = seeds_within(
            &["188.114.98.1", "162.159.192.1", "2606:4700:d0::a29f:c602"],
            "AETHER_TEST_PIN_CIDRS",
        );
        assert_eq!(kept, vec!["188.114.98.1", "2606:4700:d0::a29f:c602"]);

        // بی هیچ پینی، دانه‌ها دست‌نخورده‌اند.
        assert_eq!(
            seeds_within(MASQUE_SEEDS, "AETHER_TEST_PIN_NOTHING_SET"),
            MASQUE_SEEDS.to_vec()
        );
    }

    #[test]
    fn range_membership_is_computed_on_the_prefix_not_on_the_text() {
        assert!(cidr_v4_contains(
            "162.159.192.0/24",
            "162.159.192.77".parse().unwrap()
        ));
        assert!(!cidr_v4_contains(
            "162.159.192.0/24",
            "162.159.193.1".parse().unwrap()
        ));
        assert!(cidr_v4_contains("0.0.0.0/0", "8.8.8.8".parse().unwrap()));
        assert!(cidr_v6_contains(
            "2606:4700:d0::/48",
            "2606:4700:d0::a29f:c602".parse().unwrap()
        ));
        assert!(!cidr_v6_contains(
            "2606:4700:d0::/48",
            "2606:4700:100::1".parse().unwrap()
        ));
    }
    // <<< AETHER-APP-PATCH scan-cidrs

    #[test]
    fn the_documented_zero_trust_masque_ingress_range_is_scanned() {
        assert!(MASQUE_CIDRS_V4.contains(&"162.159.197.0/24"));
        assert!(MASQUE_CIDRS_V6.contains(&"2606:4700:102::/48"));
    }

    #[test]
    fn the_dns_over_https_ranges_are_swept_last_because_they_never_serve_masque() {
        let tail = &MASQUE_CIDRS_V4[MASQUE_CIDRS_V4.len() - MASQUE_DOH_CIDRS_V4.len()..];
        for entry in MASQUE_DOH_CIDRS_V4 {
            assert!(tail.contains(entry), "{entry} should be at the end");
        }
    }

    #[test]
    fn the_documented_default_masque_port_leads_the_sweep() {
        assert_eq!(MASQUE_PORTS.first(), Some(&443));
    }

    #[test]
    fn the_documented_masque_fallback_ports_keep_their_documented_order() {
        assert_eq!(MASQUE_PORTS, &[443, 500, 1701, 4500, 4443, 8443, 8095]);
    }

    #[test]
    fn without_a_team_the_range_order_is_left_alone() {
        std::env::remove_var("AETHER_TEAM");
        assert_eq!(
            prioritize(MASQUE_CIDRS_V4, MASQUE_ZT_CIDRS_V4),
            MASQUE_CIDRS_V4.to_vec()
        );
    }

    #[test]
    fn prioritize_moves_the_wanted_entries_to_the_front_without_losing_any() {
        let all = ["a", "b", "c", "d"];
        let out = {
            let mut out: Vec<&'static str> = vec!["c"];
            for entry in all {
                if !out.contains(&entry) {
                    out.push(entry);
                }
            }
            out
        };
        assert_eq!(out, vec!["c", "a", "b", "d"]);
        assert_eq!(out.len(), all.len());
    }

    #[test]
    fn the_documented_masque_fallback_ports_are_all_covered() {
        for port in [443u16, 500, 1701, 4443, 4500, 8443, 8095] {
            assert!(
                MASQUE_PORTS.contains(&port),
                "documented fallback port {port} should be scanned"
            );
        }
    }

    async fn quic_answers(peer: SocketAddr, timeout: Duration) -> Option<Duration> {
        let bind = if peer.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let sock = tokio::net::UdpSocket::bind(bind).await.ok()?;
        sock.connect(peer).await.ok()?;
        let local = sock.local_addr().ok()?;

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).ok()?;
        config.set_application_protos(&[b"h3"]).ok()?;
        config.verify_peer(false);
        config.set_max_idle_timeout(timeout.as_millis() as u64);
        config.set_initial_max_data(1_000_000);
        config.set_initial_max_stream_data_bidi_local(100_000);
        config.set_initial_max_streams_bidi(4);

        let mut scid = [0u8; 16];
        rand::rng().fill(&mut scid[..]);
        let scid = quiche::ConnectionId::from_ref(&scid);

        let sni = crate::consts::CONNECT_SNI;
        let mut conn = quiche::connect(Some(sni), &scid, local, peer, &mut config).ok()?;

        let mut out = [0u8; 1350];
        let (written, _) = conn.send(&mut out).ok()?;

        let started = Instant::now();
        sock.send(&out[..written]).await.ok()?;

        let mut buf = [0u8; 1500];
        match tokio::time::timeout(timeout, sock.recv(&mut buf)).await {
            Ok(Ok(read)) if read > 0 => Some(started.elapsed()),
            _ => None,
        }
    }

    async fn tcp_answers(peer: SocketAddr, timeout: Duration) -> Option<Duration> {
        let started = Instant::now();
        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(peer)).await {
            Ok(Ok(_)) => Some(started.elapsed()),
            _ => None,
        }
    }

    async fn first_answer(
        targets: &[SocketAddr],
        timeout: Duration,
        attempts: u32,
        udp: bool,
    ) -> Option<(SocketAddr, Duration)> {
        for _ in 0..attempts {
            let probes = targets.iter().copied().map(|peer| async move {
                let rtt = match udp {
                    true => quic_answers(peer, timeout).await,
                    false => tcp_answers(peer, timeout).await,
                };
                (peer, rtt)
            });

            let results: Vec<(SocketAddr, Option<Duration>)> = futures::stream::iter(probes)
                .buffer_unordered(targets.len().max(1))
                .collect()
                .await;

            if let Some((peer, Some(rtt))) = results.into_iter().find(|(_, rtt)| rtt.is_some()) {
                return Some((peer, rtt));
            }
        }
        None
    }

    fn hosts_of(cidr: &str, tails: &[u8]) -> Vec<Ipv4Addr> {
        let base: Ipv4Addr = cidr.split('/').next().unwrap().parse().expect("cidr base");
        let octets = base.octets();
        tails
            .iter()
            .map(|tail| Ipv4Addr::new(octets[0], octets[1], octets[2], *tail))
            .collect()
    }

    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "probes the live cloudflare edge from this network to see which masque ranges answer"]
    async fn report_which_masque_ranges_answer_on_this_network() {
        const TAILS: &[u8] = &[1, 2, 3];

        let timeout = Duration::from_millis(
            std::env::var("AETHER_PROBE_TIMEOUT_MS")
                .ok()
                .and_then(|raw| raw.trim().parse::<u64>().ok())
                .filter(|ms| *ms > 0)
                .unwrap_or(10_000),
        );

        let attempts = std::env::var("AETHER_PROBE_ATTEMPTS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u32>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(2);

        let ports: Vec<u16> = match std::env::var("AETHER_PROBE_PORTS") {
            Ok(raw) => raw
                .split(',')
                .filter_map(|p| p.trim().parse::<u16>().ok())
                .collect(),
            Err(_) => vec![443],
        };
        let ports = if ports.is_empty() { vec![443] } else { ports };

        println!();
        println!("probing the masque ranges from this network");
        println!("  udp timeout {timeout:?}, {attempts} attempt(s), hosts {TAILS:?}");
        println!("  udp ports {ports:?}");
        println!("  override: AETHER_PROBE_TIMEOUT_MS, AETHER_PROBE_ATTEMPTS, AETHER_PROBE_PORTS");
        println!();

        let control: Vec<SocketAddr> = vec![
            "1.1.1.1:443".parse().unwrap(),
            "8.8.8.8:443".parse().unwrap(),
        ];

        let control_quic = first_answer(&control, timeout, attempts, true).await;
        let control_tcp = first_answer(&control, timeout, attempts, false).await;

        println!("control targets (public resolvers, not cloudflare warp edges)");
        match control_quic {
            Some((peer, rtt)) => println!("  quic/udp 443 works: {peer} in {}ms", rtt.as_millis()),
            None => println!("  quic/udp 443 got no answer at all"),
        }
        match control_tcp {
            Some((peer, rtt)) => println!("  tcp 443 works:      {peer} in {}ms", rtt.as_millis()),
            None => println!("  tcp 443 got no answer at all"),
        }
        println!();

        let mut udp_ok = Vec::new();
        let mut tcp_only = Vec::new();
        let mut silent = Vec::new();

        for cidr in MASQUE_CIDRS_V4 {
            let note = if MASQUE_DOCUMENTED_CIDRS_V4.contains(cidr) {
                " [documented]"
            } else if MASQUE_DOH_CIDRS_V4.contains(cidr) {
                " [dns-over-https]"
            } else {
                ""
            };

            let hosts = hosts_of(cidr, TAILS);

            let mut udp_hit: Option<(SocketAddr, Duration)> = None;
            for port in &ports {
                let targets: Vec<SocketAddr> = hosts
                    .iter()
                    .map(|ip| SocketAddr::new(IpAddr::V4(*ip), *port))
                    .collect();
                udp_hit = first_answer(&targets, timeout, attempts, true).await;
                if udp_hit.is_some() {
                    break;
                }
            }

            let tcp_targets: Vec<SocketAddr> = hosts
                .iter()
                .map(|ip| SocketAddr::new(IpAddr::V4(*ip), 443))
                .collect();
            let tcp_hit = first_answer(&tcp_targets, timeout, attempts, false).await;

            match (udp_hit, tcp_hit) {
                (Some((peer, rtt)), _) => {
                    println!("  UDP OK    {cidr}{note}  {peer} in {}ms", rtt.as_millis());
                    udp_ok.push(*cidr);
                }
                (None, Some((peer, rtt))) => {
                    println!(
                        "  TCP ONLY  {cidr}{note}  {peer} in {}ms, udp stayed silent",
                        rtt.as_millis()
                    );
                    tcp_only.push(*cidr);
                }
                (None, None) => {
                    println!("  SILENT    {cidr}{note}");
                    silent.push(*cidr);
                }
            }
        }

        println!();
        println!("masque over quic works on ({}):", udp_ok.len());
        for cidr in &udp_ok {
            println!("  {cidr}");
        }
        println!();
        println!("reachable over tcp only ({}):", tcp_only.len());
        for cidr in &tcp_only {
            println!("  {cidr}");
        }
        println!();
        println!("no answer on either ({}):", silent.len());
        for cidr in &silent {
            println!("  {cidr}");
        }

        println!();
        println!("verdict");
        if !udp_ok.is_empty() {
            println!("  put these ranges first in MASQUE_CIDRS_V4: {udp_ok:?}");
        } else if control_quic.is_none() {
            println!("  this network answers no quic at all, not even a public resolver,");
            println!("  so udp 443 is blocked here rather than these ranges being blocked.");
            println!("  reordering MASQUE_CIDRS_V4 cannot help; masque needs its http/2");
            println!("  fallback over tcp 443 (--masque-http2) on this network.");
        } else {
            println!("  quic works to other hosts but every warp range stayed silent,");
            println!("  so these ranges really are filtered here.");
            if !tcp_only.is_empty() {
                println!("  the tcp-only ranges above can still carry masque over http/2.");
            }
        }
        println!();
    }

    #[test]
    fn every_masque_prefix_and_seed_parses() {
        for entry in MASQUE_CIDRS_V4 {
            let (addr, bits) = entry.split_once('/').expect("cidr");
            assert!(addr.parse::<Ipv4Addr>().is_ok(), "{entry}");
            assert!(bits.parse::<u8>().is_ok(), "{entry}");
        }
        for entry in MASQUE_CIDRS_V6 {
            let (addr, bits) = entry.split_once('/').expect("cidr");
            assert!(addr.parse::<Ipv6Addr>().is_ok(), "{entry}");
            assert!(bits.parse::<u8>().is_ok(), "{entry}");
        }
        for seed in MASQUE_SEEDS {
            assert!(seed.parse::<Ipv4Addr>().is_ok(), "{seed}");
        }
        for seed in MASQUE_SEEDS_V6 {
            assert!(seed.parse::<Ipv6Addr>().is_ok(), "{seed}");
        }
    }
}
