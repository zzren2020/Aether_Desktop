//! پورت از `core/AetherController.kt` + `vpn/AetherVpnService.kt` + `model/ConnectionState.kt`.
//!
//! ریشهٔ باگ «هیچ پروتکلی کانکت نمی‌شود» در نسخهٔ قبلی دسکتاپ:
//! `connect()` بلافاصله بعد از اجرای موتور، `Tunnel::establish` را صدا می‌زد؛
//! ساخت آداپتور Wintun بدون دسترسی Administrator شکست می‌خورد، خطا از
//! `connect()` بیرون می‌رفت و ماشین حالت برای همیشه روی StartingEngine گیر
//! می‌کرد — در حالی که موتور واقعاً وصل می‌شد (لاگ کاربر: «socks5 server
//! listening on 127.0.0.1:1819» بدون هیچ «I/state: Connecting» بعد از آن).
//!
//! حالا دقیقاً ترتیب اندروید (`connectAttempt`) اجرا می‌شود:
//!   ۱. StartingEngine → آزادشدن پورت → اجرای موتور → Connecting
//!   ۲. انتظار برای بازشدن پورت SOCKS5 (ground truth — همان PortProbe)
//!   ۳. فقط بعد از آن، مسیر داده برپا می‌شود (معادل VpnService.establish):
//!      پل HTTP/SOCKS محلی + پروکسی سیستمی ویندوز؛ Wintun هم اگر ممکن بود
//!      (شکست Wintun دیگر کل اتصال را نمی‌کُشد — فقط یک هشدار لاگ می‌شود).
//!   ۴. Verifying: خودآزمای ۴ مرحله‌ای (Diagnostics.kt) در ترد پس‌زمینه
//!   ۵. فقط بعد از قبولی همهٔ بررسی‌ها، Connected اعلام می‌شود
//!   ۶. شکست هر پله ← پلهٔ بعدی نردبان (معادل runLadder)، نه گیرکردن ابدی.

use crate::diagnostics;
use crate::engine::{self, AetherProcess};
use crate::geoip;
use crate::leakguard::{self, LeakGuard};
use crate::log::DiagnosticsLog;
use crate::ping;
use crate::probe;
use crate::profile::{ConnectionProfile, Protocol};
use crate::psiphon::PsiphonTransport;
use crate::psiphon_health;
use crate::share::ShareBridge;
use crate::smart_auto::{self, Candidate};
use crate::store::{PrefsStore, ProfileStore};
use crate::sysproxy;
use crate::tor_bootstrap;
use crate::tun::Tunnel;
use anyhow::Result;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

const TAG: &str = "state";

/// همان مقادیر اندروید: MAX_RETRIES=3، BACKOFF = 2s/5s/10s.
const DEFAULT_MAX_RETRIES: u32 = 3;
const BACKOFF_MS: [u64; 3] = [2_000, 5_000, 10_000];
/// پنجرهٔ گریس خودآزما — همان `OUTBOUND_GRACE_MS` (شروع سرد warp-in-warp).
const OUTBOUND_GRACE_MS: u64 = 90_000;
/// معادل `PORT_RELEASE_WAIT_MS` اندروید.
const PORT_RELEASE_WAIT_MS: u64 = 3_000;
const WATCHDOG_INTERVAL_SECS: u64 = 30;
/// How often the live latency badge is refreshed.
///
/// It used to be 15s because each measurement dialled a brand new connection
/// through both hops. A measurement is now one keep-alive round trip on a warm
/// session (see [`crate::ping`]), so it costs a single packet each way and the
/// badge can afford to feel live.
const LATENCY_INTERVAL_SECS: u64 = 10;
// >>> AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
/// پنجرهٔ انتخابِ مدار پس از اتصال — رجوع به
/// [`AetherController::consider_new_circuit`].
const CIRCUIT_HUNT_WINDOW: Duration = Duration::from_secs(20);
// <<< AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
/// بودجهٔ کل استیج ۲ (دروازهٔ استیج ۱ + دو پاسِ برقراری Psiphon).
///
/// سخاوتمند است چون پاس دوم عمداً از صفر شروع می‌کند: datastore پاک می‌شود و
/// فیلتر کشور برداشته می‌شود. مهلتِ پلهٔ نردبان در این فاز کنار گذاشته می‌شود،
/// وگرنه یک نشست زنجیره‌ای که فقط کُند است پیش از آنکه شانسی داشته باشد رد
/// می‌شود — همان اشتباهی که مستند موبایل «بدترین نتیجهٔ ممکن» می‌خواندش.
const CHAIN_BUDGET_MS: u64 = 430_000;
const WATCHDOG_FAILURE_THRESHOLD: u8 = 3;

// >>> AETHER-APP-FIX a-self-test-is-a-sample-not-a-verdict
/// The window the self-test gets, granted the moment the local port opens.
///
/// The attempt deadline exists to bound *establishing* the tunnel, and it is
/// usually spent by the time the port opens - the 2026-09-22 logs have the
/// engine taking 65 s of a 75 s window. Handing the self-test whatever is left
/// of that window means verifying a brand-new pipeline with zero runway: any
/// single failed sample then refuses a connection that was seconds from working.
///
/// Once the port is open the tunnel *is* established, so the self-test gets a
/// window of its own, sized so that one bad sample can be re-taken.
const VERIFY_WINDOW_MS: u64 = 45_000;
/// A chained pipeline warms up two hops, so it gets more room.
const VERIFY_WINDOW_CHAINED_MS: u64 = 75_000;
/// Ceiling on a single self-test sample.
///
/// The sample's own floor is 20 s, so this is what makes a second sample fit
/// inside the window instead of one long sample consuming all of it.
const VERIFY_SAMPLE_GRACE_MAX_MS: u64 = 20_000;
/// How much window must remain before another sample is worth taking.
const VERIFY_RETRY_MIN_REMAINING_MS: u64 = 20_000;
// <<< AETHER-APP-FIX a-self-test-is-a-sample-not-a-verdict

/// معادل دقیق `ConnectionState.kt` — همان هشت حالت، همان ترتیب.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConnectionState {
    Disconnected,
    StartingEngine,
    Connecting,
    Verifying,
    Connected,
    Reconnecting,
    Disconnecting,
    Failed,
}

impl ConnectionState {
    pub fn is_busy(self) -> bool {
        matches!(
            self,
            Self::StartingEngine
                | Self::Connecting
                | Self::Verifying
                | Self::Reconnecting
                | Self::Disconnecting
        )
    }
    pub fn is_active(self) -> bool {
        self.is_busy() || self == Self::Connected
    }
}

/// معادل `IpInfo` در UI اندروید — خوراک نشان «IP + پرچم».
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IpEndpoint {
    pub ip: String,
    pub country_code: Option<String>,
    /// true = IP خروجی سرور (از دل تونل)، false = IP واقعی کاربر.
    pub via_tunnel: bool,
}

/// حالت مشترک جست‌وجوی IP — معادل `ipInfo`/`ipLoading` در MainActivity.
struct IpSlot {
    info: Option<IpEndpoint>,
    loading: bool,
    /// شمارندهٔ نسل — نتیجهٔ جست‌وجوهای قدیمی دور ریخته می‌شود.
    session: u64,
}

/// معادل مجموع StateFlow‌هایی که HomeScreen.kt جمع می‌کرد.
/// `PartialEq` is load-bearing, not decoration: `main.rs` only pushes a snapshot
/// to the UI when it differs from the last one it sent. An idle app used to
/// re-serialise and repaint the entire home screen five times a second forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Snapshot {
    pub state: ConnectionState,
    pub detail: String,
    pub error: Option<String>,
    pub endpoint: Option<String>,
    pub protocol: Option<String>,
    pub latency_ms: Option<u64>,
    pub uptime_secs: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub share_socks: Option<String>,
    pub share_http: Option<String>,
    pub ip_info: Option<IpEndpoint>,
    pub ip_loading: bool,
    /// v1.2.0 — نتیجهٔ آخرین سنجش نشتی WebRTC. `None` = هنوز سنجیده نشده.
    pub webrtc_leak: Option<bool>,
    /// v1.2.0 — گارد نشتی همین حالا فعال است؟
    pub leak_guard: bool,
    /// ۱.۲.۵ — درصدِ bootstrapِ تور، یا `None` وقتی تور در کار نیست/چیزی
    /// نگفته است.
    ///
    /// عدد جداگانه فرستاده می‌شود و نه فقط داخلِ `detail`، چون جملهٔ نهایی را
    /// باید لایهٔ رابط بسازد: `detail` انگلیسی است و ترجمه‌نشده به کاربر
    /// نشان داده می‌شود، پس کاربر فارسی پنج دقیقه به یک جملهٔ انگلیسی نگاه
    /// می‌کرد — همان‌جایی که برنامه بیشترین وقت را از او می‌گیرد.
    pub tor_percent: Option<u8>,
}

/// What the user asked for with the last tap on the big button.
///
/// # Why the tap no longer does the work itself
///
/// `toggle_connection` used to run the whole of `connect()` / `disconnect()`
/// while holding the controller mutex. Both are full of slow Windows calls —
/// a network fingerprint (up to 2.4s), waiting for the SOCKS port to be released
/// (up to 3s), `netsh` firewall rules, registry proxy writes, process teardown.
/// The 200ms snapshot tick wants the same mutex, so for several seconds after a
/// tap nothing repainted: the button did not change, the spinner did not start,
/// and the app read as frozen exactly when the user was watching hardest.
///
/// Now a tap records an intent, flips the visible state, and returns instantly.
/// The tick thread performs the work on the next beat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Intent {
    Connect,
    Disconnect,
}

/// Which stage the off-lock preparation thread is preparing for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Prep {
    /// A fresh session: fingerprint the network, then build the whole ladder.
    Plan,
    /// The next rung of an existing ladder: no fingerprinting needed.
    Candidate,
}

/// Result of the off-lock preparation thread.
struct PrepOutcome {
    /// What the pre-connect probes learned. Only meaningful for [`Prep::Plan`].
    fingerprint: smart_auto::NetFingerprint,
}

pub struct AetherController {
    data_dir: PathBuf,
    store: ProfileStore,
    // >>> AETHER-APP-FIX the-rung-that-worked-goes-first
    /// The device-local memory of which ladder rung last carried traffic. See
    /// [`Self::remember_the_rung_that_worked`].
    prefs: PrefsStore,
    // <<< AETHER-APP-FIX the-rung-that-worked-goes-first
    profile: ConnectionProfile,
    state: ConnectionState,
    detail: String,
    error: Option<String>,
    endpoint: Option<String>,
    effective_protocol: Option<Protocol>,
    latency_ms: Option<u64>,
    connected_at: Option<Instant>,
    engine: AetherProcess,
    // >>> AETHER-APP-PATCH tor-native-carrier
    /// تورِ رسمی، وقتی این تلاش «تور تنها» است. `None` یعنی این تلاش از موتور
    /// می‌گذرد.
    native_tor: Option<crate::tor_native::TorNative>,
    // >>> AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
    /// کدام نیمهٔ یک نشستِ توری هنوز اجرا نشده است.
    tor_stage: TorStage,
    // <<< AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
    // <<< AETHER-APP-PATCH tor-native-carrier
    /// استیج ۲. `Arc` چون ترد راه‌اندازی و ترد چرخش هم به آن نیاز دارند و
    /// `Drop` باید فقط با آزادشدن آخرین ارجاع فرآیند را بکشد.
    psiphon: Arc<PsiphonTransport>,
    /// نتیجهٔ راه‌اندازی زنجیره در ترد پس‌زمینه — حلقهٔ tick مسدود نمی‌شود.
    chain_slot: Option<Arc<Mutex<Option<Result<u16, String>>>>>,
    tunnel: Option<Tunnel>,
    share: ShareBridge,
    sysproxy_on: bool,
    /// v1.2.0 — گارد نشتی WebRTC/UDP این نشست (Drop خودش آزادش می‌کند).
    guard: Option<LeakGuard>,
    /// v1.2.0 — آخرین نتیجهٔ سنجش نشتی، برای نشانِ صفحهٔ اصلی.
    webrtc_leak: Option<bool>,
    /// نردبان تلاش‌ها — معادل `runLadder` در AetherVpnService.kt.
    plan: Vec<Candidate>,
    plan_index: usize,
    /// تلاش‌های اتصال مجدد پشت‌سرهم — معادل `reconnectAttempts`.
    attempts: u32,
    deadline: Option<Instant>,
    reconnect_at: Option<Instant>,
    /// نتیجهٔ خودآزمای در حال اجرا (ترد پس‌زمینه — UI فریز نمی‌شود).
    verify_slot: Option<Arc<Mutex<Option<diagnostics::SelfTestOutcome>>>>,
    // >>> AETHER-APP-FIX a-self-test-is-a-sample-not-a-verdict
    /// How many times this attempt has re-run the self-test after a failure
    /// that was *not* a leak verdict. See [`Self::VERIFY_RETRY_LIMIT`].
    verify_retries: u8,
    /// Set once a leak verdict has cost this attempt one rung.
    ///
    /// A leak verdict is a statement about the *protection layer*, and the
    /// ladder does not vary the protection layer - it varies noize,
    /// fragmentation and ECH. So one advance is a fair second look (a firewall
    /// rule or a policy value may still have been settling when the sample was
    /// taken) and a second verdict is final. Without the cap, a machine with no
    /// browser-scoped protection at all would spend a full verify window on
    /// every rung before saying so. Reset in [`Self::launch_plan`], i.e. once
    /// per attempt.
    leak_refused: bool,
    // <<< AETHER-APP-FIX a-self-test-is-a-sample-not-a-verdict
    ip_slot: Arc<Mutex<IpSlot>>,
    /// پینگ زنده: نتیجهٔ آخرین اندازه‌گیری دوره‌ای در ترد پس‌زمینه.
    latency_slot: Arc<Mutex<Option<u64>>>,
    /// زمان اندازه‌گیری بعدی پینگ.
    latency_probe_at: Option<Instant>,
    // >>> AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
    /// تا کی اجازه داریم مدارِ تور را عوض کنیم؛ `None` یعنی نه.
    circuit_hunt_until: Option<Instant>,
    /// چند مدار در این نشست عوض شده.
    circuit_tries: u8,
    // <<< AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
    /// نتیجهٔ آخرین پروب واچداگ، خارج از حلقهٔ اصلی محاسبه می‌شود.
    watchdog_slot: Arc<Mutex<Option<bool>>>,
    watchdog_probe_at: Option<Instant>,
    watchdog_failures: u8,
    /// Firewall/registry work is deferred out of the IPC command path.
    security_refresh_pending: bool,
    /// The last tap, waiting for the next tick. See [`Intent`].
    pending_intent: Option<Intent>,
    /// Slow pre-launch work running off the controller lock. See [`Prep`].
    prep_slot: Option<Arc<Mutex<Option<PrepOutcome>>>>,
    prep_kind: Prep,
    /// Stage 2's listener once the chain is actually carrying traffic.
    ///
    /// This is what makes the PROTOCOL tile honest: it says `Aether → Psiphon`
    /// only once the Psiphon hop really is the exit, not merely because the
    /// chained backend is selected in Advanced.
    chain_exit_port: Option<u16>,
}

/// جوابِ دروازهٔ تور — [`AetherController::tor_gate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TorGate {
    /// تور به شبکه رسیده (یا این نشست تور ندارد): مسیر داده می‌تواند بالا بیاید.
    Ready,
    /// هنوز در حال bootstrap و **در حرکت**. صبر کردن درست‌ترین کار است.
    Waiting,
    /// درصد از حرکت ایستاده. این شکلِ واقعیِ شبکه‌ای است که تور را فیلتر
    /// می‌کند، و تنها حالتی که تلاش را زودتر از بودجه می‌کشد.
    Stalled,
}

// >>> AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
/// نیمهٔ اجرانشدهٔ یک نشستِ توریِ زنجیره‌ای.
///
/// # چرا اصلاً دو نیمه
///
/// تا امروز در `Tor → Aether` و `Aether → Tor` هر دو نیمه یک فرآیند بودند:
/// موتور با `--tor-reverse`/`--tor` تورِ داخلیِ خودش (arti) را بالا می‌آورد.
/// لاگِ ۱۷ سپتامبر روی همان شبکه هر دو مسیر را کنارِ هم نشان می‌دهد:
///
/// ```text
/// 13:45:58  [tor] Bootstrapped 100% (done)              ← tor.exe، ۲۲ ثانیه
/// 10:17:27  [engine] tor could not get through … 75s    ← arti، همان دقیقه
/// 10:23:02  [engine] Stuck at 15%: Can't bootstrap a Tor directory
/// 10:26:12  Engine still scanning — the SOCKS5 port never opened in time
/// ```
///
/// یعنی حاملِ تور همیشه باید `tor.exe` باشد و نیمهٔ دیگر مشتریِ آن. آن‌وقت
/// ترتیب اهمیت پیدا می‌کند و همین enum است که می‌گوید نوبتِ کیست.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TorStage {
    /// هیچ نیمه‌ای معلق نیست — نشستِ عادی، «تور تنها»، یا هر دو نیمه بالا.
    None,
    /// `Tor → Aether`: تور بالا است و موتور پس از آمادگیِ آن اجرا می‌شود.
    TorThenEngine,
    /// `Aether → Tor`: موتور بالا است و تور از دلِ تونلش اجرا می‌شود.
    EngineThenTor,
}
// <<< AETHER-APP-PATCH the-tor-in-front-is-the-real-tor

impl AetherController {
    pub fn new(data_dir: &Path) -> Self {
        let store = ProfileStore::new(data_dir);
        let mut profile = store.load();
        profile.normalize();
        let install_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| data_dir.to_path_buf());

        let ip_slot = Arc::new(Mutex::new(IpSlot {
            info: None,
            loading: false,
            session: 0,
        }));

        let me = Self {
            data_dir: data_dir.to_path_buf(),
            store,
            // >>> AETHER-APP-FIX the-rung-that-worked-goes-first
            prefs: PrefsStore::new(data_dir),
            // <<< AETHER-APP-FIX the-rung-that-worked-goes-first
            profile,
            state: ConnectionState::Disconnected,
            detail: String::new(),
            error: None,
            endpoint: None,
            effective_protocol: None,
            latency_ms: None,
            connected_at: None,
            engine: AetherProcess::new(&install_dir, data_dir),
            // >>> AETHER-APP-PATCH tor-native-carrier
            native_tor: None,
            tor_stage: TorStage::None,
            // <<< AETHER-APP-PATCH tor-native-carrier
            psiphon: Arc::new(PsiphonTransport::new(&install_dir, data_dir)),
            chain_slot: None,
            tunnel: None,
            share: ShareBridge::new(),
            sysproxy_on: false,
            guard: None,
            webrtc_leak: None,
            plan: Vec::new(),
            plan_index: 0,
            attempts: 0,
            deadline: None,
            reconnect_at: None,
            verify_slot: None,
            verify_retries: 0,
            leak_refused: false,
            ip_slot,
            latency_slot: Arc::new(Mutex::new(None)),
            latency_probe_at: None,
            circuit_hunt_until: None,
            circuit_tries: 0,
            watchdog_slot: Arc::new(Mutex::new(None)),
            watchdog_probe_at: None,
            watchdog_failures: 0,
            security_refresh_pending: false,
            pending_intent: None,
            prep_slot: None,
            prep_kind: Prep::Plan,
            chain_exit_port: None,
        };

        // >>> AETHER-APP-PATCH the-flag-is-already-on-disk
        // پرچمِ خروجی از فایلِ کشورِ خودِ Tor خوانده می‌شود، نه از شبکه. اینجا
        // گفته می‌شود آن فایل کجاست — یک بار، پیش از هر جست‌وجوی IP.
        if let Some((_, support)) = me.engine.native_tor() {
            geoip::use_dir(&support);
        }
        // <<< AETHER-APP-PATCH the-flag-is-already-on-disk

        // Tell the health scorer which destinations are OURS before anything can
        // dial them, so a refused self-probe can never be read as evidence that
        // the exit filters (mobile parity: registerSelfProbes).
        for (host, port) in ping::probe_targets() {
            psiphon_health::register_self_probe(host, port);
        }
        for (host, port) in probe::watchdog_targets() {
            psiphon_health::register_self_probe(host, port);
        }

        // Stale state from a previous crash is cleared on a worker thread.
        //
        // Both calls shell out: `recover_stale` writes the WinINET registry keys
        // and broadcasts a settings change, `purge_stale` runs several
        // `netsh advfirewall` deletions. Together they cost the better part of a
        // second, and they used to run inside the Tauri `setup` hook — which is
        // to say, before the window was allowed to appear. Nothing about them
        // needs to finish before the UI is on screen; they only have to happen
        // before a connection is brought up, and a connection needs a tap.
        std::thread::Builder::new()
            .name("aether-recover".into())
            .spawn(|| {
                sysproxy::recover_stale();
                leakguard::purge_stale();
            })
            .ok();
        // Do not install network-blocking rules during ordinary app startup.
        // The old behavior blocked Windows before a tunnel/bridge existed,
        // which is why reopening the app could kill internet access. The
        // guard is installed only after the SOCKS bridge is ready.
        // معادل LaunchedEffect فاز idle در MainActivity: نمایش IP واقعی کاربر از لحظهٔ اجرا.
        spawn_ip_lookup(me.ip_slot.clone(), false);
        me
    }

    pub fn profile(&self) -> ConnectionProfile {
        self.profile.clone()
    }

    pub fn set_profile(&mut self, profile: ConnectionProfile) -> Result<()> {
        let mut profile = profile;
        profile.normalize();
        // v10: فیلدهای محرمانه «write-only» هستند: get_profile هرگز آن‌ها را
        // برنمی‌گرداند، پس UI معمولاً رشتهٔ خالی می‌فرستد. خالی = «دست نزن»
        // تا رازِ در-حافظهٔ این نشست با هر تغییر تنظیم دیگر پاک نشود.
        if profile.access_secret.is_empty() {
            profile.access_secret = self.profile.access_secret.clone();
        }
        if profile.access_token.is_empty() {
            profile.access_token = self.profile.access_token.clone();
        }
        self.apply_profile(profile)
    }

    /// v10: «بازنشانی به تنظیمات پیش‌فرض» باید اسرارِ در-حافظه را هم واقعاً
    /// پاک کند. `set_profile` رشتهٔ خالی را «دست نزن» تفسیر می‌کند (چون UI
    /// اسرار را پس نمی‌گیرد)، پس Reset مسیر جداگانهٔ خودش را دارد؛ وگرنه
    /// توکن سازمانی پس از Reset بی‌صدا در حافظه زنده می‌ماند.
    pub fn reset_profile(&mut self) -> Result<ConnectionProfile> {
        let fresh = ConnectionProfile::default();
        self.apply_profile(fresh.clone())?;
        DiagnosticsLog::i(
            TAG,
            "Profile reset to factory defaults (in-memory Zero Trust secrets cleared).",
        );
        Ok(fresh)
    }

    /// مسیر مشترک ذخیره‌سازی — هرچه از set_profile/reset_profile بیاید.
    fn apply_profile(&mut self, profile: ConnectionProfile) -> Result<()> {
        self.store.save(&profile)?;
        let lan_toggled = profile.lan_share != self.profile.lan_share;
        let guard_toggled = profile.leak_guard != self.profile.leak_guard;
        let kill_toggled = profile.kill_switch != self.profile.kill_switch;
        let ipv6_toggled = profile.ipv6_protection != self.profile.ipv6_protection;
        self.profile = profile;
        // v1.2.0: خاموش/روشن‌کردن گارد نشتی وسط یک اتصالِ فعال باید فوراً
        // اثر کند — نه در اتصال بعدی. کاربری که سوییچ را می‌زند انتظار دارد
        // همان لحظه محافظت شود (یا آزاد شود).
        let safety_changed = guard_toggled || kill_toggled || ipv6_toggled;
        if safety_changed && self.state.is_active() {
            // Do not run reg.exe/netsh.exe while the UI IPC command is waiting.
            // The 200ms controller tick applies it outside the settings click,
            // preventing the white titlebar/freeze seen on safety toggles.
            self.security_refresh_pending = true;
            self.webrtc_leak = None;
        }
        // Root fix for "Share over LAN shows no IP:port": flipping the switch
        // while a connection is active must rebind the bridge immediately
        // (mobile restarts its ShareBridge the same way), so the UI gets the
        // fresh endpoints in the very next snapshot instead of never.
        if lan_toggled && self.state.is_active() {
            if let Err(e) = self.share.start(
                engine::SHARE_SOCKS_PORT,
                engine::SHARE_HTTP_PORT,
                self.profile.lan_share,
            ) {
                DiagnosticsLog::e(TAG, &format!("Bridge restart after LAN toggle failed: {e}"));
            }
        }
        Ok(())
    }

    pub fn snapshot(&self) -> Snapshot {
        let (tun_rx, tun_tx) = self.tunnel.as_ref().map(Tunnel::counters).unwrap_or((0, 0));
        let (br_rx, br_tx) = self.share.traffic();
        let (ip_info, ip_loading) = {
            let g = self.ip_slot.lock();
            (g.info.clone(), g.loading)
        };
        Snapshot {
            state: self.state,
            detail: self.detail.clone(),
            error: self.error.clone(),
            endpoint: self.endpoint.clone(),
            protocol: self.display_protocol(),
            latency_ms: self.latency_ms,
            uptime_secs: self
                .connected_at
                .map(|t| t.elapsed().as_secs())
                .unwrap_or(0),
            rx_bytes: tun_rx + br_rx,
            tx_bytes: tun_tx + br_tx,
            share_socks: self.share.socks_endpoint(),
            share_http: self.share.http_endpoint(),
            ip_info,
            ip_loading,
            webrtc_leak: self.webrtc_leak,
            leak_guard: leakguard::status().engaged,
            tor_percent: if self.tor_fronted() {
                tor_bootstrap::snapshot().percent
            } else {
                None
            },
        }
    }

    /// The label the PROTOCOL tile shows.
    ///
    /// ۱.۲.۵ — هر خط‌لوله‌ای که نامی دارد همان نام را نشان می‌دهد: در تصویرِ
    /// کاربر از «تور تنها» این خانه `SMART` می‌گفت؛ `SMART` روشِ پیداکردنِ
    /// تونل است و در این حالت هیچ تونلی وجود ندارد که با آن پیدا شود.
    ///
    /// شرطِ زنجیره سرجایش می‌ماند: در حالت‌های زنجیره‌ای نامِ خط‌لوله فقط
    /// وقتی گفته می‌شود که استیج ۲ واقعاً خروجی را در دست گرفته باشد؛
    /// نوشتنِ `Aether → Psiphon` پیش از آن، ادعای دروغ است.
    fn display_protocol(&self) -> Option<String> {
        if let Some(label) = self.profile.backend.protocol_label() {
            if !self.profile.is_chained() || self.chain_exit_port.is_some() {
                return Some(label.to_string());
            }
        }
        self.effective_protocol
            .map(|p| format!("{p:?}").to_uppercase())
    }

    /// معادل `onToggleConnection` — خطای اتصال دیگر به بیرون پرتاب نمی‌شود؛
    /// همیشه به حالت Failed ترجمه می‌شود تا UI هرگز در StartingEngine گیر نکند.
    ///
    /// Records the intent and repaints; the work happens on the next tick. See
    /// [`Intent`] for why this must not block.
    pub fn request_toggle(&mut self) {
        if self.state.is_active() {
            self.pending_intent = Some(Intent::Disconnect);
            self.set_state(ConnectionState::Disconnecting, "Disconnecting…");
        } else {
            self.error = None;
            self.pending_intent = Some(Intent::Connect);
            self.set_state(ConnectionState::StartingEngine, "Starting engine…");
        }
    }

    /// معادل `connect()` سرویس اندروید — فقط برنامه‌ریزی و اجرای پلهٔ اول؛
    /// بقیهٔ مراحل در tick() دنبال می‌شوند.
    fn connect(&mut self) -> Result<()> {
        self.error = None;
        self.attempts = 0;
        self.chain_slot = None;
        self.chain_exit_port = None;
        // هر نشست از موتور شروع می‌شود. اگر این جا بیفتد، یک نشست عادی به پورت
        // استیج ۲ که دیگر وجود ندارد وصل می‌ماند: «متصل ولی هیچ سایتی باز
        // نمی‌شود».
        engine::reset_exit_socks_port();
        // معادل DiagnosticsLog.clear + resetChecks در شروع اتصال اندروید.
        diagnostics::reset_checks();
        // The warm latency session belongs to the pipeline that is going away.
        ping::reset();
        // The visible state is already StartingEngine — request_toggle set it the
        // moment the user tapped, so the button never waits on this method.
        // ۱.۲.۵ — پیش از هر چیزِ دیگر: این بیلد کدام است؟ اگر موتورِ کهنه
        // اجرا شود، هر نتیجه‌گیری از این نشست دربارهٔ مسیرِ داده غلط است.
        crate::provenance::log_app_identity(&self.engine.core_version());
        DiagnosticsLog::i(
            TAG,
            &format!(
                "Connect requested — protocol={:?} scan={:?} ip={:?}",
                self.profile.protocol, self.profile.scan_mode, self.profile.ip_version
            ),
        );
        // SmartAuto.kt parity: fingerprint the network before planning. On a
        // filtered network the ladder leads with the hardened anti-DPI
        // candidate, so the plain first pass can no longer waste 35-75s
        // (slow connects) or win with a tunnel that cannot carry real
        // browser traffic afterwards.
        if self.profile.is_chained() && !self.psiphon.is_available() {
            return Err(anyhow::anyhow!(
                "The Psiphon stage is missing from this installation ({}). Reinstall Aether, or set the transport back to Aether.",
                self.psiphon.missing_parts()
            ));
        }
        DiagnosticsLog::i(
            TAG,
            &format!("Pipeline: {}", self.profile.backend.pipeline_label()),
        );
        // >>> AETHER-APP-FIX pt-egress-not-blocked
        // A Tor pipeline reaches the network through `lyrebird.exe`, a separate
        // process. Leak-guard rules left behind by a session that was killed
        // rather than closed are still in the firewall at this point, and they
        // make that process fail with WSAEACCES instead of connecting — which
        // is what the 2026-09-16 log shows as `broker failure dial tcp …
        // forbidden by its access permissions`, with Tor frozen at 0-15%.
        // Nothing owns those rules here (`self.guard` is None until the data
        // path comes up), so anything still installed is a leftover.
        if self.profile.backend.uses_tor() && self.guard.is_none() {
            leakguard::purge_stale();
        }
        // <<< AETHER-APP-FIX pt-egress-not-blocked
        // Fingerprinting and waiting for the port to be released are the two slow
        // steps, and neither may run on the controller lock. They go to a worker
        // thread and the ladder is built when the tick sees the result.
        self.begin_prep(Prep::Plan);
        Ok(())
    }

    /// Runs the slow pre-launch steps off the controller lock.
    ///
    /// Both used to sit directly in the connect path: `network_looks_filtered`
    /// dials two IP literals with a 1.2s timeout each, and `wait_for_port_release`
    /// polls for up to 3s. Nearly six seconds of a held mutex, on every rung of
    /// the ladder — that is the stall the user felt when tapping Connect.
    fn begin_prep(&mut self, kind: Prep) {
        let slot: Arc<Mutex<Option<PrepOutcome>>> = Arc::new(Mutex::new(None));
        self.prep_slot = Some(slot.clone());
        self.prep_kind = kind;
        // «تور تنها» از اثرانگشت هیچ تصمیمی نمی‌سازد — خودِ برنامه‌ریز
        // می‌گوید «no tunnel to scan» — ولی تا امروز ~۲.۴ ثانیه صرفش می‌شد،
        // پیش از هر تلاش. انتظارِ آزادشدنِ پورت می‌ماند، چون tor.exe همان
        // ۱۸۱۹ را می‌خواهد.
        let tor_only = self.profile.backend.tor_mode() == Some(crate::profile::TorMode::Only);
        let fingerprint = kind == Prep::Plan && !tor_only;
        if tor_only && kind == Prep::Plan {
            DiagnosticsLog::i(
                TAG,
                "Tor alone: skipping the network fingerprint — it decides nothing here.",
            );
        }
        std::thread::Builder::new()
            .name("aether-prep".into())
            .spawn(move || {
                // معادل PortProbe.awaitClosed — ریشهٔ باگ «تعویض پروتکل گیر می‌کند».
                if !engine::wait_for_port_release(
                    engine::LOCAL_SOCKS_PORT,
                    Duration::from_millis(PORT_RELEASE_WAIT_MS),
                ) {
                    DiagnosticsLog::w(
                        TAG,
                        &format!(
                            "Local port {} is still busy after {}s — starting anyway.",
                            engine::LOCAL_SOCKS_PORT,
                            PORT_RELEASE_WAIT_MS / 1000
                        ),
                    );
                }
                // SmartAuto.kt parity: fingerprint the network before planning.
                // 1.2.3-p2 adds the UDP leg. Without it the planner could not
                // tell HTTP/3 from HTTP/2 and defaulted to the slow carrier.
                // Keep the two questions separate. WireGuard needs any usable
                // UDP path; MASQUE's HTTP/3 carrier needs QUIC on UDP:443. The
                // field log proves they can differ: UDP worked for WireGuard,
                // while Cloudflare QUIC was filtered. Conflating them made Smart
                // Auto classify the network as UDP-blocked and always lead with
                // MASQUE.
                let fp = if fingerprint {
                    smart_auto::NetFingerprint {
                        filtered: probe::network_looks_filtered(),
                        udp_ok: probe::udp_egress_ok(),
                        quic_ok: probe::quic_carrier_ok(),
                    }
                } else {
                    smart_auto::NetFingerprint::default()
                };
                *slot.lock() = Some(PrepOutcome { fingerprint: fp });
            })
            .ok();
    }

    /// Builds the ladder once the fingerprint is in, then launches its first rung.
    fn launch_plan(&mut self, fingerprint: smart_auto::NetFingerprint) -> Result<()> {
        // استیج ۱ نردبانِ Smart Auto و سخت‌سازی ضد‌DPI را دست‌نخورده نگه می‌دارد،
        // پس یک نشست زنجیره‌ای همان اثر‌انگشت‌زنی و همان تلاش‌های مجدد نشست عادی
        // را می‌گیرد — ولی بدون مسیر داده و بدون پل.
        let planning_profile = if self.profile.is_chained() {
            self.profile.chained_stage()
        } else {
            self.profile.clone()
        };
        let plan = smart_auto::build_plan(&planning_profile, fingerprint);
        // >>> AETHER-APP-FIX the-rung-that-worked-goes-first
        // The rung that worked last time leads. The rotation wraps, so every
        // other rung keeps its place and still gets its turn; see
        // [`smart_auto::the_rung_that_worked_goes_first`].
        self.plan = smart_auto::the_rung_that_worked_goes_first(plan, self.remembered_rung());
        // <<< AETHER-APP-FIX the-rung-that-worked-goes-first
        self.plan_index = 0;
        // >>> AETHER-APP-FIX a-self-test-is-a-sample-not-a-verdict
        // A fresh attempt gets a fresh leak-verdict allowance; see
        // [`Self::leak_refused`].
        self.leak_refused = false;
        // <<< AETHER-APP-FIX a-self-test-is-a-sample-not-a-verdict
        self.launch_candidate()
    }

    // >>> AETHER-APP-FIX the-rung-that-worked-goes-first
    /// The rung that last carried traffic on this device, if any is remembered.
    ///
    /// Read from disk rather than held in memory on purpose: the desktop process
    /// lives longer than the phone's core, so an in-memory memory would cover
    /// reconnects within one run — but the case that costs the most is the one
    /// where the user closed the app and opened it again, and only a written
    /// preference survives that.
    fn remembered_rung(&self) -> Option<Protocol> {
        self.prefs
            .get_string(smart_auto::WORKING_RUNG_KEY)
            .and_then(|name| smart_auto::rung_from_name(&name))
    }

    /// Records the rung that just carried traffic.
    ///
    /// Called on a *verified* session, never on a raised one. A tunnel that comes
    /// up and carries nothing is exactly the case this memory must not learn
    /// from — otherwise the next connect starts on the rung that never worked,
    /// and the memory has made things worse rather than better.
    fn remember_the_rung_that_worked(&mut self) {
        let Some(protocol) = self.effective_protocol else {
            return;
        };
        // `Smart` names the ladder, not a rung of it. There is nothing to
        // remember, and writing it would only put noise on disk.
        if matches!(protocol, Protocol::Smart) {
            return;
        }
        let Some(name) = smart_auto::rung_name(protocol) else {
            return;
        };
        if self.prefs.get_string(smart_auto::WORKING_RUNG_KEY).as_deref() == Some(name.as_str()) {
            return;
        }

        match self.prefs.set_string(smart_auto::WORKING_RUNG_KEY, &name) {
            Ok(()) => DiagnosticsLog::i(
                TAG,
                &format!(
                    "Rung memory: {name} carried traffic — the next connect starts the ladder there."
                ),
            ),
            // Never fatal. A preference that cannot be written costs one
            // slower start, and refusing to connect over it would be absurd.
            Err(e) => DiagnosticsLog::w(
                TAG,
                &format!("Could not remember the working rung ({e}); the ladder keeps its fixed order."),
            ),
        }
    }
    // <<< AETHER-APP-FIX the-rung-that-worked-goes-first

    /// اجرای یک پله از نردبان — معادل یک دور `runLadder`.
    ///
    /// Assumes [`begin_prep`] has already waited for the local port, so all this
    /// does is spawn the engine: fast enough to stay on the lock.
    fn launch_candidate(&mut self) -> Result<()> {
        let cand = self.plan[self.plan_index].clone();
        DiagnosticsLog::i(
            TAG,
            &format!(
                "Attempt {}/{} → {}",
                self.plan_index + 1,
                self.plan.len(),
                cand.label
            ),
        );

        self.effective_protocol = Some(cand.profile.protocol);
        // >>> AETHER-APP-PATCH tor-native-carrier
        // «تور تنها» از tor.exe رسمی می‌گذرد. اگر این نصب باینری را نداشته
        // باشد، همان مسیرِ قبلی (arti داخلِ موتور) اجرا می‌شود: بیلدی که تور
        // را حمل نکند منتشر نمی‌شود، ولی نصبِ قدیمیِ روی دیسک ممکن است.
        if self.start_native_tor(&cand)? {
            return Ok(());
        }
        // <<< AETHER-APP-PATCH tor-native-carrier
        // >>> AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
        // `Aether → Tor`: ترتیب برعکس است — اول موتور، بعد tor.exe از دلِ همین
        // تونل. پس موتور باید پروفایلی بگیرد که `--tor` در آن نیست؛ وگرنه دو
        // تور روی یک زنجیر بالا می‌آمد و آن یکی همان arti بود که در لاگِ
        // ۱۷ سپتامبر روی ۱۵٪ ماند.
        let engine_profile = if self.tor_mode_of_attempt() == Some(crate::profile::TorMode::Chain)
            && self.engine.native_tor().is_some()
        {
            self.tor_stage = TorStage::EngineThenTor;
            let mut stage = cand.profile.clone();
            stage.backend = crate::profile::TransportBackend::Aether;
            stage
        } else {
            cand.profile.clone()
        };
        // <<< AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
        // The engine is told how long this rung is allowed to take, so its own
        // endpoint scan is sized to fit inside that window instead of being
        // killed 78% of the way through it. See `engine::AetherProcess::start`.
        self.engine.start(&engine_profile, Some(cand.timeout_ms))?;
        // ۱.۲.۵ — مهلتِ دیوارِ ساعت برای نشست تور جداست، و **بودجهٔ اسکن نیست**.
        // آن یکی بالا به موتور رفت تا اسکن لبه را اندازه کند؛ این یکی می‌گوید
        // برنامه چقدر صبر می‌کند. تور اسکن نمی‌کند، bootstrap می‌کند — و روی
        // شبکه‌ای که فقط کند است همان یک مرحله ده‌ها ثانیه طول می‌کشد. بستنِ
        // این پنجره به مهلتِ اسکن، دقیقاً همان بریدنی بود که کاربر آن را
        // «وصل نمی‌شود» گزارش کرد. آنچه این بودجهٔ بلند را به سکوتِ بلند تبدیل
        // **نمی‌کند**، تشخیصِ گیرکردن در `tor_gate` است.
        let budget_ms = self.tor_budget_ms().unwrap_or(cand.timeout_ms);
        self.deadline = Some(Instant::now() + Duration::from_millis(budget_ms));
        self.set_state(ConnectionState::Connecting, "Connecting…");
        DiagnosticsLog::i(
            TAG,
            &format!(
                "Waiting for SOCKS5 on 127.0.0.1:{}… (timeout={}s)",
                engine::LOCAL_SOCKS_PORT,
                budget_ms / 1000
            ),
        );
        Ok(())
    }

    // >>> AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
    /// تورِ زنجیره‌ای را **پشتِ** موتور بالا می‌آورد — حالتِ `Aether → Tor`.
    ///
    /// # چرا پل نمی‌گیرد
    ///
    /// پل برای رسیدن به توری است که خودش بسته است؛ اینجا تونلِ اِتِر همان چیزی
    /// است که ما را بیرون برده، پس آن پرسش قبلاً پاسخ گرفته. WhiteAesther هم
    /// همین را می‌کند و دلیلش را نوشته: تور `Socks5Proxy` و
    /// `ClientTransportPlugin` را با هم می‌پذیرد، ولی هرگز دیده نشده که
    /// lyrebird پلش را *از راهِ آن پراکسی* بگیرد — و ترابری که آن را نادیده
    /// بگیرد، نشانیِ پل را روی شبکهٔ سانسورشده لخت می‌گیرد.
    fn start_tor_behind_engine(&mut self) -> Result<()> {
        let upstream: std::net::SocketAddr = ([127, 0, 0, 1], engine::LOCAL_SOCKS_PORT).into();
        let socks = self.tor_listener_port();
        let budget_ms = self
            .tor_budget_ms()
            .unwrap_or(diagnostics::TOR_BOOTSTRAP_BUDGET_MS);
        self.spawn_native_tor(
            socks,
            Some(upstream),
            crate::tor_native::BridgeMode::None,
            String::new(),
            budget_ms,
            format!(
                "Aether → Tor: the tunnel is up; running the bundled tor.exe on 127.0.0.1:{socks} \
                 through it (no bridges — the tunnel already got us out)"
            ),
        )
    }

    /// موتور را **پشتِ** تورِ آماده اجرا می‌کند — حالتِ `Tor → Aether`.
    fn start_engine_behind_tor(&mut self) -> Result<()> {
        let cand = self.plan[self.plan_index].clone();
        let tor_port = self.tor_listener_port();
        // بدونِ این، موتور `--tor-reverse` می‌گرفت و تورِ داخلیِ خودش (arti) را
        // بالا می‌آورد — همان چیزی که در لاگِ ۱۷ سپتامبر ده دقیقه روی ۱۵٪ ماند
        // درحالی‌که tor.exe با همان پل‌ها ۲۲ ثانیه‌ای رسیده بود.
        let mut stage = cand.profile.clone();
        stage.backend = crate::profile::TransportBackend::Aether;
        // تور TCP حمل می‌کند و بس؛ MASQUE باید روی HTTP/2 برود. پرچمِ پروتکل و
        // متغیرِ `AETHER_MASQUE_HTTP2` هر دو گفته می‌شوند: نردبان از قبل همین را
        // انتخاب می‌کند، ولی صریح‌بودن اینجا ارزانتر از یک نشستِ ناممکن است.
        stage.protocol = crate::profile::Protocol::Masque;
        self.engine.set_upstream_socks(Some(tor_port));
        self.engine.start(&stage, Some(cand.timeout_ms))?;
        self.tor_stage = TorStage::None;
        // بودجهٔ تازه: bootstrapِ تور تمام شده و از این‌جا کارِ موتور است. اگر
        // مهلتِ مرحلهٔ اول را نگه می‌داشتیم، توری که ۹ دقیقه bootstrap کرده
        // موتور را با یک ثانیه بودجه تحویل می‌داد.
        self.deadline = Some(Instant::now() + Duration::from_millis(cand.timeout_ms));
        self.set_state(
            ConnectionState::Connecting,
            "Starting the tunnel through Tor…",
        );
        DiagnosticsLog::i(
            TAG,
            &format!(
                "Tor → Aether: tor is ready on 127.0.0.1:{tor_port}; the engine dials out through \
                 it (AETHER_UPSTREAM=socks5://127.0.0.1:{tor_port}, http/2 carrier)."
            ),
        );
        Ok(())
    }
    // <<< AETHER-APP-PATCH the-tor-in-front-is-the-real-tor

    // >>> AETHER-APP-PATCH tor-native-carrier
    /// تورِ رسمی را برای این تلاش بالا می‌آورد. `false` یعنی این تلاش جای
    /// دیگری دارد و مسیرِ موتور باید ادامه یابد.
    ///
    /// bootstrap تا سه دقیقه طول می‌کشد، پس روی یک ترد می‌نشیند و ماشینِ حالت
    /// مثل همیشه با `probe::socks_ready` و `tor_gate` پیش می‌رود. خطوطِ
    /// پیشرفت به همان لاگی می‌روند که `tor_bootstrap` می‌خواند، با همان قالبِ
    /// `tor reaching the network: N%` — پس درصد در UI و تشخیصِ گیرکردن
    /// بی‌هیچ تغییری کار می‌کنند.
    fn start_native_tor(&mut self, cand: &Candidate) -> Result<bool> {
        use crate::profile::{TorBridges, TorMode};

        // >>> AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
        // پیش‌تر تنها `Only` از این مسیر می‌گذشت و دو حالتِ دیگر به تورِ داخلیِ
        // موتور می‌رسیدند. `Reverse` هم از امروز اینجاست: تور جلوی موتور
        // می‌ایستد و موتور مشتریِ آن می‌شود. `Chain` اینجا نیست چون ترتیبش
        // برعکس است — اول موتور، بعد تور — و در `tick` انجام می‌شود.
        let socks = match self.tor_mode_of_attempt() {
            Some(TorMode::Only) => {
                // قراردادِ برنامه: مرورگر و پراکسیِ سیستم و TUN همین عدد را
                // می‌شناسند.
                engine::LOCAL_SOCKS_PORT
            }
            Some(TorMode::Reverse) => self.tor_listener_port(),
            _ => return Ok(false),
        };
        // <<< AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
        if self.engine.native_tor().is_none() {
            DiagnosticsLog::w(
                TAG,
                "This installation carries no tor binary; falling back to the engine's own tor.",
            );
            return Ok(false);
        }

        // پل: `Off` یعنی هیچ، و `Auto`/`Always` یعنی فهرستِ داخلیِ خودِ Tor.
        // «تلاشِ مستقیم و بعد پل» را همین‌جا نمی‌سازیم: نردبانِ برنامه از قبل
        // پله‌های جدا دارد و دوباره‌سازی‌اش یعنی دو منطقِ موازی.
        let bridges = match cand.profile.tor_bridges {
            TorBridges::Off => crate::tor_native::BridgeMode::None,
            TorBridges::Auto | TorBridges::Always => {
                if cand.profile.has_custom_bridges() {
                    crate::tor_native::BridgeMode::Custom
                } else {
                    crate::tor_native::BridgeMode::BuiltIn
                }
            }
        };
        let budget_ms = self.tor_budget_ms().unwrap_or(cand.timeout_ms);
        let headline = if socks == engine::LOCAL_SOCKS_PORT {
            format!(
                "Tor alone: running the bundled tor.exe on 127.0.0.1:{socks}, bridges={bridges:?} \
                 (timeout={}s)",
                budget_ms / 1000
            )
        } else {
            // مرحلهٔ دوم (موتور) در `tick` و پس از آمادگیِ تور اجرا می‌شود.
            self.tor_stage = TorStage::TorThenEngine;
            format!(
                "Tor → Aether: running the bundled tor.exe on 127.0.0.1:{socks} in front of the \
                 engine, bridges={bridges:?} (timeout={}s)",
                budget_ms / 1000
            )
        };
        self.spawn_native_tor(
            socks,
            None,
            bridges,
            cand.profile.sanitized_bridges().join("\n"),
            budget_ms,
            headline,
        )?;
        Ok(true)
    }

    /// یک tor.exe را روی یک ترد بالا می‌آورد — تنها جایی که این کار انجام
    /// می‌شود، چه تور جلوی موتور باشد، چه پشتش، چه تنها.
    #[allow(clippy::too_many_arguments)]
    fn spawn_native_tor(
        &mut self,
        socks: u16,
        upstream: Option<std::net::SocketAddr>,
        bridges: crate::tor_native::BridgeMode,
        custom_bridges: String,
        budget_ms: u64,
        headline: String,
    ) -> Result<()> {
        let Some((binary, support)) = self.engine.native_tor() else {
            return Err(anyhow::anyhow!("this installation carries no tor binary"));
        };
        let launch = crate::tor_native::TorLaunch {
            binary,
            support,
            home: self.engine.native_tor_home(),
            bridges,
            transport: String::new(),
            custom_bridges,
            upstream,
            socks: Some(socks),
            budget: Some(Duration::from_millis(budget_ms)),
        };

        // درصدِ نشستِ قبلی نباید این یکی را «در حرکت» نشان دهد.
        crate::tor_bootstrap::reset();

        let tor = crate::tor_native::TorNative::new(std::sync::Arc::new(|line: &str| {
            DiagnosticsLog::i("tor", line);
            crate::tor_bootstrap::ingest(line);
            // در حالت‌های توری اندپوینتِ واقعی پلِ اول است؛ همین سینک می‌رساندش.
            crate::firsthop::ingest(line);
        }));
        // پیش از هر چیز: از این لحظه حامل «در حالِ راه‌اندازی» است. اگر این
        // سطر نباشد، تیکِ بعدی (۲۰۰ms بعد) حاملی می‌بیند که هنوز فرزندی
        // ندارد و تلاش را جمع می‌کند — همان شکستِ تلاشِ اولِ لاگِ ۲۰:۰۴.
        tor.mark_starting();
        self.native_tor = Some(tor.clone());

        self.deadline = Some(Instant::now() + Duration::from_millis(budget_ms));
        self.set_state(ConnectionState::Connecting, "Connecting…");
        DiagnosticsLog::i(TAG, &headline);

        std::thread::Builder::new()
            .name("tor-native".to_string())
            .spawn(move || match tor.start(&launch) {
                Ok(address) => DiagnosticsLog::i("tor", &format!("tor is ready on {address}")),
                Err(e) => {
                    // تنها جایی که شکستِ راه‌اندازی اعلام می‌شود: هر مسیرِ
                    // خطای `start` از این‌جا می‌گذرد.
                    tor.mark_dead();
                    DiagnosticsLog::e("tor", &format!("tor did not come up: {e}"));
                }
            })
            .map_err(|e| anyhow::anyhow!("could not start the tor thread: {e}"))?;
        Ok(())
    }

    /// آیا حاملِ این تلاش زنده است؟
    ///
    /// در «تور تنها» هیچ موتوری اجرا نشده، پس پرسیدنِ `engine.is_alive()`
    /// همیشه «مرده» جواب می‌دهد و تلاش را در همان تیکِ اول می‌کُشد. و در
    /// حالت‌های زنجیره‌ای هر دو نیمه باید زنده باشند — ولی فقط آن نیمه‌ای که
    /// واقعاً اجرا شده پرسیده می‌شود.
    fn carrier_alive(&mut self) -> bool {
        let tor = self.native_tor.as_ref().map(|tor| tor.is_alive());
        let engine = if self.engine.was_started() {
            Some(self.engine.is_alive())
        } else {
            None
        };
        match (tor, engine) {
            (Some(tor), Some(engine)) => tor && engine,
            (Some(alive), None) | (None, Some(alive)) => alive,
            // هیچ‌کدام اجرا نشده: در فازِ Connecting این وضع یعنی چیزی مرده است.
            (None, None) => false,
        }
    }
    // <<< AETHER-APP-PATCH tor-native-carrier

    /// آیا این نشست واقعاً تور را اجرا می‌کند؟ (با احتساب گیتِ نسخهٔ هسته)
    ///
    /// پروفایلِ **پله** پرسیده می‌شود، نه پروفایلِ کاربر: در نشست زنجیره‌ای
    /// استیج ۱ چیزی است که `chained_stage` ساخته، و همان است که اجرا می‌شود.
    fn tor_fronted(&self) -> bool {
        if !self.engine.caps().tor {
            return false;
        }
        self.plan
            .get(self.plan_index)
            .map(|c| c.profile.backend)
            .unwrap_or(self.profile.backend)
            .uses_tor()
    }

    /// حالتِ توری که **این تلاش** اجرا می‌کند، با گیتِ نسخهٔ هسته.
    fn tor_mode_of_attempt(&self) -> Option<crate::profile::TorMode> {
        if !self.engine.caps().tor {
            return None;
        }
        self.plan
            .get(self.plan_index)
            .map(|c| c.profile.backend)
            .unwrap_or(self.profile.backend)
            .tor_mode()
    }

    /// آیا پل در این تلاش واقعاً می‌تواند کاری کند؟
    ///
    /// # چرا این سؤال با «آیا کاربر پل را خاموش نکرده» یکی نیست
    ///
    /// سه شرط، و هر سه از لاگ میدانیِ ۱۵٪ درآمده‌اند:
    ///
    /// * **حالت.** در `Aether → Tor` تور از داخل تونل dial می‌شود.
    ///   `profile.rs` در این حالت هیچ فلگ پلی به موتور نمی‌فرستد و موتور هم
    ///   بی `forced` هرگز به پل برنمی‌گردد (`tor.rs::establish`:
    ///   `(_, Some(_)) => forced`). پس صبرِ ۴۲۰ ثانیه‌ای انتظار برای چیزی است
    ///   که اتفاق نمی‌افتد — و دقیقاً همان ۸۳ ثانیهٔ بی‌پیامِ لاگ.
    /// * **پروفایلِ همین تلاش،** نه پروفایل کاربر: در نردبان، پلهٔ در حال اجرا
    ///   می‌تواند بک‌اند دیگری داشته باشد — همان دلیلی که `tor_fronted` هم
    ///   پروفایلِ پله را می‌پرسد.
    /// * **ترابر.** بی ترابر هیچ obfs4ای در کار نیست که ۷ دقیقه ارزش انتظار
    ///   داشته باشد؛ فقط پلِ ساده می‌ماند، که مثل هر رله جواب می‌دهد یا بسته
    ///   است. سطرهای دستیِ کاربر هم اینجا کمکی نمی‌کنند:
    ///   `profile::is_bridge_line` فقط سطری را می‌پذیرد که با نام یک ترابر
    ///   شروع شود.
    fn tor_bridges_can_help(&self) -> bool {
        if self.tor_mode_of_attempt() == Some(crate::profile::TorMode::Chain) {
            return false;
        }
        if self.profile.tor_bridges == crate::profile::TorBridges::Off {
            return false;
        }
        self.engine.transport_installed()
    }

    /// شکلِ توری که این تلاش دارد — برای پیام شکست.
    fn tor_shape(&self) -> Option<diagnostics::TorShape> {
        match self.tor_mode_of_attempt()? {
            crate::profile::TorMode::Chain => Some(diagnostics::TorShape::ThroughTunnel),
            _ => Some(diagnostics::TorShape::FacingNetwork {
                bridges_allowed: self.profile.tor_bridges != crate::profile::TorBridges::Off,
                transport_installed: self.engine.transport_installed(),
            }),
        }
    }

    /// بودجهٔ دیوارِ ساعت برای یک تلاش تور، یا `None` وقتی تور در کار نیست.
    fn tor_budget_ms(&self) -> Option<u64> {
        if !self.tor_fronted() {
            return None;
        }
        Some(if self.tor_bridges_can_help() {
            diagnostics::TOR_BRIDGE_BUDGET_MS
        } else {
            diagnostics::TOR_BOOTSTRAP_BUDGET_MS
        })
    }

    /// چند وقت بی‌حرکتیِ درصد یعنی این تلاش مرده است.
    fn tor_stall_ms(&self) -> u64 {
        if self.tor_bridges_can_help() {
            diagnostics::TOR_STALL_BRIDGED_MS
        } else {
            diagnostics::TOR_STALL_DIRECT_MS
        }
    }

    /// پورتی که مسیر داده باید به آن بچسبد — خروجیِ **واقعیِ** خط لوله.
    ///
    /// در `Aether → Tor` موتور دو لیسنر دارد: پورت همیشگی که خروجی WARP است و
    /// یک لیسنر دوم برای تور. مسیر داده باید به دومی برود، وگرنه کاربری که
    /// «Aether → Tor» را انتخاب کرده، از خروجی WARP بیرون می‌رفت و هرگز هم
    /// نمی‌فهمید: تونل بالا می‌آمد، خودآزما سبز می‌شد، و تور فقط بی‌مصرف
    /// می‌چرخید.
    ///
    /// گیت `tor_fronted` اینجا هم لازم است: روی هستهٔ قدیمی‌تر فلگ‌های تور
    /// اصلاً فرستاده نشده‌اند، پس لیسنر دومی وجود ندارد و اشاره به آن، مسیر
    /// داده را به پورتی می‌بست که کسی در آن گوش نمی‌دهد.
    fn data_path_exit_port(&self) -> u16 {
        if !self.tor_fronted() {
            return engine::LOCAL_SOCKS_PORT;
        }
        self.profile.backend.exposed_socks_port()
    }

    /// پورتی که **حمل‌کننده** خودش باز می‌کند — تنها چیزی که دروازهٔ تور حق دارد منتطرش بماند.
    ///
    /// # چرا این همانِ `data_path_exit_port` نیست
    ///
    /// در زنجیره (`Tor → Psiphon`) خروجیِ خط لوله پورتِ استیج ۲ است و را فقط
    /// Psiphon باز می‌کند — و Psiphon فقط پس از عبور از این دروازه شروع
    /// می‌شود. لاگِ `loge4` دقیقاً همین قفلِ دوطرفه است: تور ۱۰۰٪ می‌شود، پیام
    /// «Tor is ready — opening its local proxy…» می‌آید، و بعد پنج دقیقه سکوت تا
    /// کاربر دستی قطع کند؛ در کلِ فایل یک سطر «Starting Psiphon» وجود ندارد.
    fn tor_listener_port(&self) -> u16 {
        self.profile
            .backend
            .tor_socks_port()
            .unwrap_or(engine::LOCAL_SOCKS_PORT)
    }

    /// دروازهٔ تور: آیا می‌توان مسیر داده را بالا آورد؟
    ///
    /// # چرا پورتِ باز اثبات چیزی نیست
    ///
    /// موتور لیسنر SOCKS5 را همان لحظهٔ اجرا bind می‌کند، **پیش از** آنکه تور
    /// به شبکه رسیده باشد. تا ۱.۲.۴ همین حلقه پورتِ باز را آمادگیِ استیج ۱
    /// می‌گرفت و بی‌درنگ مسیر داده را بالا می‌آورد و خودآزما را می‌زد؛ روی
    /// حالت‌های تور آن خودآزما به توری می‌خورد که هنوز ۳۰٪ بود، شکست می‌خورد،
    /// و برنامه «تونل بالا آمد ولی خودآزما شکست خورد» می‌گفت — برای توری که
    /// هیچ ایرادی نداشت جز تمام‌نشدن.
    ///
    /// حالا سه جواب دارد: آماده، منتظر (با درصدی که روی صفحه می‌رود)، و
    /// گیرکرده — که تنها حالتی است که تلاش را می‌کشد، و پیامش علت واقعی را
    /// نام می‌برد.
    fn tor_gate(&mut self) -> TorGate {
        if !self.tor_fronted() {
            return TorGate::Ready;
        }
        if tor_bootstrap::done() {
            // bootstrap تمام است، ولی در حالت‌های زنجیره‌ای/برعکس لیسنرِ دومِ
            // تور یک لحظه بعد از آن باز می‌شود. معادلِ `awaitOpen(torPort)`
            // اندروید: چسباندنِ مسیر داده به پورتی که هنوز نیامده، همان
            // «وصل شد ولی هیچ چیز باز نمی‌شود» است.
            let exit = self.tor_listener_port();
            if exit != engine::LOCAL_SOCKS_PORT && !probe::socks_ready(exit) {
                self.set_state(
                    ConnectionState::Connecting,
                    "Tor is ready — opening its local proxy…",
                );
                return TorGate::Waiting;
            }
            return TorGate::Ready;
        }
        if tor_bootstrap::stalled(self.tor_stall_ms()) {
            return TorGate::Stalled;
        }
        let snap = tor_bootstrap::snapshot();
        // درصدِ گیرکرده روی شبکه‌ای که تور را می‌اندازد، خودش محرکِ
        // برگشت‌به‌پلِ موتور است. کاربر باید همین را بخواند، نه یک درصدِ
        // بی‌حرکت که شبیه هنگ است.
        let stuck = tor_bootstrap::stalled(diagnostics::TOR_STALL_DIRECT_MS);
        let chained = self.tor_mode_of_attempt() == Some(crate::profile::TorMode::Chain);
        let msg = if stuck && self.tor_bridges_can_help() {
            "Tor is not getting through directly — trying bridges…".to_string()
        } else if stuck && chained {
            // در این حالت تونل ثابت‌شده بالاست و تور از داخلش جلو نمی‌رود.
            // نگفتنش یعنی گذاشتنِ کاربر روبروی یک درصدِ یخ‌زده.
            "Tor is not moving inside the tunnel — trying the next strategy…".to_string()
        } else {
            match snap.percent {
                Some(p) => format!("Reaching the Tor network… {p}%"),
                None => "Reaching the Tor network…".to_string(),
            }
        };
        self.set_state(ConnectionState::Connecting, &msg);
        TorGate::Waiting
    }

    /// معادل بخش establish در connectAttempt — فقط بعد از بازشدن پورت SOCKS5.
    fn bring_up_data_path(&mut self) {
        let profile = self
            .plan
            .get(self.plan_index)
            .map(|c| c.profile.clone())
            .unwrap_or_else(|| self.profile.clone());

        // ۰) گارد نشتی — *قبل* از هر چیز دیگری. ترتیب امنیتی است، نه سلیقه‌ای:
        // تا وقتی مسیر UDP مستقیم باز است نباید مرورگر را به تونل وصل کنیم،
        // وگرنه بین «پروکسی روشن شد» و «گارد نصب شد» یک پنجرهٔ نشتی می‌ماند.
        if self.profile.leak_guard || self.profile.kill_switch || self.profile.ipv6_protection {
            if let Some(mut old_guard) = self.guard.take() {
                old_guard.disarm_without_cleanup();
            }
            self.guard = Some(LeakGuard::engage(&profile));
        } else {
            DiagnosticsLog::w(
                TAG,
                "Leak guard is disabled in the profile — WebRTC may expose your real IP over direct UDP.",
            );
        }

        // ۱) پل محلی HTTP/SOCKS — معادل hev-socks5-tunnel/ShareBridge (مسیر دادهٔ واقعی).
        if let Err(e) = self.share.start(
            engine::SHARE_SOCKS_PORT,
            engine::SHARE_HTTP_PORT,
            profile.lan_share,
        ) {
            DiagnosticsLog::e(TAG, &format!("Bridge failed to start: {e}"));
        }

        // ۲) پروکسی سیستمی ویندوز — معادل کارکرد VpnService (کل سیستم از تونل می‌رود).
        self.sysproxy_on = sysproxy::enable(engine::SHARE_HTTP_PORT, engine::SHARE_SOCKS_PORT);

        // ۳) Wintun — اختیاری. شکست آن دیگر اتصال را نمی‌کُشد (رفع ریشه‌ای گیر StartingEngine).
        if self.tunnel.is_none() {
            let wintun = std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("engine").join("wintun.dll")))
                .unwrap_or_default();
            match Tunnel::establish(&profile, &wintun) {
                Ok(t) => self.tunnel = Some(t),
                Err(e) => DiagnosticsLog::w(
                    "tun",
                    &format!(
                        "Wintun unavailable ({e}); continuing with the system-proxy data path."
                    ),
                ),
            }
        }
    }

    /// استیج ۲ را در ترد پس‌زمینه بالا می‌آورد.
    ///
    /// ترتیب کل نکتهٔ ماجراست و عیناً همان `connectExternal` اندروید است:
    ///
    /// ```text
    ///   stage 1  موتور اِتِر → SOCKS5 127.0.0.1:1819   (هنوز هیچ مسیر داده‌ای!)
    ///   stage 2  Psiphon    → SOCKS5 127.0.0.1:1825   از راه 1819 dial می‌کند
    ///   سپس     پل + پروکسی سیستمی → 1825            خروجی = Psiphon
    /// ```
    ///
    /// استیج ۱ **نباید** مسیر داده بسازد: استیج ۲ باید از لوپ‌بک به موتور برسد
    /// در حالی که خود موتور هنوز از شبکهٔ واقعی به اینترنت می‌رسد. اگر پروکسی
    /// سیستمی همین‌جا روشن شود، Psiphon از داخل تونلی بیرون می‌رود که خودش
    /// دارد می‌سازد و همه‌چیز داخل خودش قفل می‌شود.
    ///
    /// مسدودکننده است (تا سه دقیقه در هر پاس)، پس روی ترد خودش می‌رود و
    /// حلقهٔ ۲۰۰ms هرگز فریز نمی‌شود.
    fn begin_chain(&mut self) {
        let slot: Arc<Mutex<Option<Result<u16, String>>>> = Arc::new(Mutex::new(None));
        self.chain_slot = Some(slot.clone());
        // مهلتِ پلهٔ نردبان کنار گذاشته می‌شود: بودجهٔ استیج ۲ مال خودش است.
        self.deadline = Some(Instant::now() + Duration::from_millis(CHAIN_BUDGET_MS));
        let psiphon = self.psiphon.clone();
        let region = self.profile.exit_region.clone();
        let upstream = ConnectionProfile::chain_upstream_url();
        // ۱.۲.۵ — در `Tor → Psiphon` استیج ۱ خودِ تور است. پورتش از لحظهٔ اجرا
        // باز است ولی تا پایان bootstrap به دست‌دادن جواب نمی‌دهد، پس دروازه
        // باید صبر کند؛ در نشست غیرتوری صفر می‌ماند و رفتار قدیمی حفظ می‌شود:
        // تونل اِتِری که فوراً دست نمی‌دهد خراب است و صبر روی آن فقط پلهٔ بعدی
        // نردبان را عقب می‌اندازد.
        let grace_ms = self.tor_budget_ms().unwrap_or(0);
        let stall_ms = self.tor_stall_ms();
        let tor_fronted = self.tor_fronted();
        // ۱.۲.۵-p2: شکلِ تور پیش از spawn حساب می‌شود. ترد زنجیره `self` را
        // ندارد و نباید داشته باشد، و پیامِ شکست باید بگوید تور کجا گیر کرد.
        let tor_shape = self.tor_shape();
        self.set_state(ConnectionState::Connecting, "Starting the Psiphon stage…");
        // در `Tor → Psiphon` استیج ۱ خودِ tor.exe است، نه موتور. نوشتنِ نامِ
        // اشتباه یعنی فرستادنِ عیب‌یاب سراغِ فرآیندی که اجرا نشده.
        let stage_one = if self.native_tor.is_some() {
            "bundled tor"
        } else {
            "Aether engine"
        };
        DiagnosticsLog::i(
            TAG,
            &format!(
                "Chained mode: stage 1 = {stage_one} on 127.0.0.1:{}, stage 2 = Psiphon on 127.0.0.1:{}",
                engine::LOCAL_SOCKS_PORT,
                engine::CHAIN_SOCKS_PORT
            ),
        );
        std::thread::Builder::new()
            .name("aether-chain".into())
            .spawn(move || {
                // دروازهٔ استیج ۱ پیش از هر چیز: بدون یک پروکسی SOCKS5 کارکنده،
                // Psiphon سه دقیقه در تاریکی تلاش می‌کند و شکست در جای اشتباه
                // ظاهر می‌شود.
                let ok = diagnostics::run_proxy_stage_with_grace(
                    engine::LOCAL_SOCKS_PORT,
                    grace_ms,
                    // زندگیِ موتور از دید این ترد: `AetherProcess` نه Send است
                    // و نه باید باشد، ولی سوکتِ گوش‌دهنده با مردنِ فرآیند بسته
                    // می‌شود — پس پورتِ بسته یعنی موتور رفته، و همان چیزی است
                    // که این انتظار باید با آن تمام شود.
                    &|| probe::socks_ready(engine::LOCAL_SOCKS_PORT),
                    &|| tor_fronted && tor_bootstrap::stalled(stall_ms),
                );
                if !ok {
                    *slot.lock() = Some(Err(if tor_fronted {
                        diagnostics::stage_failure_message(tor_shape)
                    } else {
                        "Stage 1 (the Aether engine) is not a working SOCKS5 proxy yet".to_string()
                    }));
                    return;
                }
                let outcome = psiphon.start(&region, &upstream).map_err(|e| e.to_string());
                *slot.lock() = Some(outcome);
            })
            .ok();
    }

    /// نتیجهٔ استیج ۲ را برمی‌دارد و مسیر داده را به **خروجی زنجیره** می‌چسباند.
    fn poll_chain(&mut self) {
        let outcome = self.chain_slot.as_ref().and_then(|s| s.lock().take());
        let Some(outcome) = outcome else {
            // >>> AETHER-APP-PATCH stage-one-is-not-always-the-engine
            // در `Tor → Psiphon` استیج ۱ خودِ tor.exe است و هیچ موتوری اجرا
            // نشده، پس `engine.is_alive()` همیشه «مرده» می‌گفت و این شرط،
            // ۲۰۰ms پس از رسیدنِ تور به ۱۰۰٪، نشستِ سالم را جمع می‌کرد. لاگِ
            // ۱۷ سپتامبر، دو نشستِ پشت‌سرهم:
            //
            //     13:45:59 tor is ready on 127.0.0.1:1819
            //     13:45:59 Starting the Psiphon stage…
            //     13:45:59 W/state: Stage 1 (the engine) exited …  ← همین سطر
            //
            // خطای `speaks SOCKS5 but cannot reach the internet` سه میلی‌ثانیه
            // *پس از* این تخریب ثبت شده: نتیجهٔ آن است، نه علتش.
            //
            // پاسخِ درست از قبل در همین فایل بود و `tick` از آن استفاده
            // می‌کرد؛ فقط این یک جا از قلم افتاده بود.
            if !self.carrier_alive() {
                self.chain_slot = None;
                let carrier = if self.native_tor.is_some() {
                    "Stage 1 (the bundled tor) exited while the Psiphon stage was starting"
                } else {
                    "Stage 1 (the engine) exited while the Psiphon stage was starting"
                };
                self.advance_or_fail(carrier);
            // <<< AETHER-APP-PATCH stage-one-is-not-always-the-engine
            } else if self.past_deadline() {
                self.chain_slot = None;
                self.advance_or_fail("The Psiphon stage did not come up within its budget");
            }
            return;
        };
        self.chain_slot = None;
        match outcome {
            Ok(port) => {
                // از این لحظه پل، خودآزما و نشانِ IP همه به استیج ۲ نگاه
                // می‌کنند. این تک‌خط است که خروجی را از اِتِر به Psiphon
                // منتقل می‌کند.
                engine::set_exit_socks_port(port);
                // From here the PROTOCOL tile may honestly say `Aether → Psiphon`.
                self.chain_exit_port = Some(port);
                DiagnosticsLog::i(
                    TAG,
                    &format!(
                        "Psiphon stage is up on 127.0.0.1:{port} — bringing up the data path."
                    ),
                );
                self.bring_up_data_path();
                self.begin_verification();
            }
            Err(why) => {
                engine::reset_exit_socks_port();
                self.psiphon.stop();
                // یک خطای پیکربندی/آرگومان در استیج ۲ روی **هر** پلهٔ نردبان
                // یکسان می‌افتد: در لاگ میدانی همین چهار پله را با یک پیام
                // سوزاند و کاربر فقط «کانکت نشد» دید. پس همان‌جا و با همان
                // پیام دقیق شکست می‌خوریم، نه با یک نردبانِ محکوم‌به‌شکست.
                if crate::psiphon::is_config_fault(&why) {
                    self.fail(&format!("The Psiphon stage failed: {why}"));
                    return;
                }
                self.advance_or_fail(&format!("The Psiphon stage failed: {why}"));
            }
        }
    }

    /// خودآزمای ۴ مرحله‌ای در ترد پس‌زمینه — حلقهٔ tick هرگز مسدود نمی‌شود.
    fn begin_verification(&mut self) {
        // >>> AETHER-APP-FIX a-self-test-is-a-sample-not-a-verdict
        // A fresh pipeline gets a fresh retry budget, and a window of its own -
        // see [`VERIFY_WINDOW_MS`] for why the attempt deadline is the
        // wrong clock for this phase.
        self.verify_retries = 0;
        let window = if self.profile.is_chained() {
            VERIFY_WINDOW_CHAINED_MS
        } else {
            VERIFY_WINDOW_MS
        };
        self.deadline = Some(Instant::now() + Duration::from_millis(window));
        // <<< AETHER-APP-FIX a-self-test-is-a-sample-not-a-verdict
        self.spawn_self_test();
    }

    /// Re-runs the self-test on the *same* pipeline, without touching the retry
    /// budget. See [`Self::VERIFY_RETRY_LIMIT`].
    fn respawn_self_test(&mut self) {
        self.spawn_self_test();
    }

    fn spawn_self_test(&mut self) {
        let slot: Arc<Mutex<Option<diagnostics::SelfTestOutcome>>> = Arc::new(Mutex::new(None));
        self.verify_slot = Some(slot.clone());
        let remaining = self
            .deadline
            .map(|d| d.saturating_duration_since(Instant::now()).as_millis() as u64)
            .unwrap_or(OUTBOUND_GRACE_MS);
        // نشست زنجیره‌ای گرم‌شدنِ هر دو هاپ را می‌پردازد، پس پنجرهٔ بلندتر
        // `EXTERNAL_GRACE_MS` را می‌گیرد — همان تفکیک اندروید.
        let ceiling = if self.profile.is_chained() {
            diagnostics::EXTERNAL_GRACE_MS
        } else {
            OUTBOUND_GRACE_MS
        };
        // >>> AETHER-APP-FIX a-self-test-is-a-sample-not-a-verdict
        // ...but a single sample is capped, so that one slow sample cannot eat
        // the whole window and leave nothing for the re-check.
        let grace = remaining
            .clamp(20_000, ceiling)
            .min(VERIFY_SAMPLE_GRACE_MAX_MS);
        // <<< AETHER-APP-FIX a-self-test-is-a-sample-not-a-verdict
        std::thread::Builder::new()
            .name("aether-selftest".into())
            .spawn(move || {
                let outcome = diagnostics::self_test(grace);
                *slot.lock() = Some(outcome);
            })
            .ok();
        self.set_state(ConnectionState::Verifying, "Verifying…");
    }

    /// The visible state is already Disconnecting (see [`request_toggle`]); this
    /// runs the slow teardown on the tick thread, off the UI's IPC path.
    fn disconnect(&mut self) {
        self.cleanup_native(false);
        // v16: تیک‌های سبز Diagnostics باید بلافاصله بعد از دیسکانکت
        // ریست شوند تا برای اتصال بعدی آماده باشند (معادل resetChecks اندروید).
        diagnostics::reset_checks();
        self.latency_probe_at = None;
        self.watchdog_probe_at = None;
        self.watchdog_failures = 0;
        *self.watchdog_slot.lock() = None;
        *self.latency_slot.lock() = None;
        self.connected_at = None;
        self.endpoint = None;
        // اندپوینتِ نشستِ قبل در نشستِ تازه هیچ معنایی ندارد.
        crate::firsthop::reset();
        self.latency_ms = None;
        self.effective_protocol = None;
        self.deadline = None;
        self.reconnect_at = None;
        self.verify_slot = None;
        self.chain_slot = None;
        self.prep_slot = None;
        self.plan.clear();
        self.plan_index = 0;
        self.set_state(ConnectionState::Disconnected, "");
    }

    /// ترتیب ۱.۲.۲: اول پروکسی سیستمی (تا مرورگر به پل مُرده نچسبد)، بعد
    /// اشتراک، بعد تونل، بعد موتور — بدون فریز.
    fn cleanup_native(&mut self, preserve_kill_switch: bool) {
        if self.sysproxy_on {
            sysproxy::disable();
            self.sysproxy_on = false;
        }
        // گارد بعد از پروکسی آزاد می‌شود: تا آخرین لحظه‌ای که مرورگر ممکن است
        // به پل وصل باشد، مسیر UDP هم بسته می‌ماند.
        if preserve_kill_switch {
            if let Some(g) = self.guard.as_mut() {
                g.release_for_reconnect();
            }
        } else if let Some(mut g) = self.guard.take() {
            g.release();
        }
        self.webrtc_leak = None;
        self.share.stop();
        // استیج ۲ بعد از پل و پیش از موتور می‌رود: همان ترتیب معکوسِ بالا آمدن.
        // اگر پیش از پل برود، پل برای چند صد میلی‌ثانیه به یک پروکسی مرده وصل
        // می‌ماند و مرورگر خطای واقعی می‌بیند.
        self.psiphon.stop();
        // خروجی به موتور برمی‌گردد، وگرنه پلهٔ بعدی نردبان (یا نشست بعدی) به
        // پورت استیج ۲ که دیگر وجود ندارد وصل می‌ماند.
        engine::reset_exit_socks_port();
        self.chain_exit_port = None;
        self.chain_slot = None;
        // >>> AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
        // دو نیمهٔ نشستِ قبلی نباید به نشستِ بعدی برسد: موتوری که با
        // `AETHER_UPSTREAM` به توری وصل می‌ماند که دیگر نیست، همان «وصل شد
        // ولی هیچ چیز باز نمی‌شود» است، و مرحلهٔ معلقِ باقی‌مانده یعنی
        // منتظرِ توری ماندن که هرگز اجرا نمی‌شود.
        self.tor_stage = TorStage::None;
        self.engine.set_upstream_socks(None);
        // پنجرهٔ مدار مالِ یک نشست است و با آن بسته می‌شود.
        self.circuit_hunt_until = None;
        self.circuit_tries = 0;
        // <<< AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
        if let Some(mut t) = self.tunnel.take() {
            t.close();
        }
        self.engine.stop();
        // >>> AETHER-APP-PATCH tor-native-carrier
        // پس از موتور، چون در نشستِ زنجیره‌ای موتور جلوترِ تور است و ترتیبِ
        // معکوسِ بالاآمدن یعنی هرکس آخر آمد، اول برود.
        if let Some(tor) = self.native_tor.take() {
            tor.stop();
        }
        // <<< AETHER-APP-PATCH tor-native-carrier
    }

    /// شکست یک پله → پلهٔ بعدی نردبان؛ تمام‌شدن نردبان → Failed با پیام روشن.
    fn advance_or_fail(&mut self, why: &str) {
        let final_message = if self.profile.protocol == Protocol::Smart {
            "Smart Auto tried every strategy and none passed the self-test on this network."
        } else {
            "This protocol could not establish a working tunnel on this network, even with anti-DPI hardening. Try Smart Auto or another protocol."
        };
        self.advance_or_fail_with(why, final_message);
    }

    // >>> AETHER-APP-FIX a-self-test-is-a-sample-not-a-verdict
    /// [`Self::advance_or_fail`] with a specific message for the case where the
    /// ladder runs out, so a failure that deserves its own wording does not have
    /// to skip the remaining rungs to get it.
    fn advance_or_fail_with(&mut self, why: &str, final_message: &str) {
        DiagnosticsLog::w(TAG, &format!("{why} — tearing down this attempt."));
        // فقط موتور/مسیر داده را جمع می‌کنیم، وضعیت UI همچنان busy می‌ماند.
        self.cleanup_native(true);
        self.verify_slot = None;
        self.verify_retries = 0;
        diagnostics::reset_checks();
        self.plan_index += 1;
        if self.plan_index < self.plan.len() {
            // The next rung also has to wait for the local port, so it goes back
            // through the off-lock prep instead of blocking the tick for 3s.
            self.set_state(ConnectionState::StartingEngine, "Starting engine…");
            self.begin_prep(Prep::Candidate);
        } else {
            self.fail(final_message);
        }
    }

    /// How many extra self-test samples one attempt gets before the ladder moves
    /// on.
    ///
    /// The self-test is a *sample* of a pipeline that is frequently still
    /// warming up - a chained pipeline has two hops to bring up, and the engine
    /// may be replacing a failed endpoint underneath it. Two extra samples cost
    /// a few seconds and remove the whole class of failure where a connection
    /// that would have worked ten seconds later is refused.
    const VERIFY_RETRY_LIMIT: u8 = 2;

    /// Is another sample worth taking on the pipeline we already have?
    ///
    /// Only when there is enough window left for the sample to mean something
    /// and the pipeline's exit port still answers. That port is opened by the
    /// carrier itself - `tor.exe` in "Tor only", the engine in front of it in
    /// the chained modes - so a closed port already *is* the "carrier is gone"
    /// signal, and the caller's fall-through arm, the one that asks the carrier
    /// whether it is still there when no sample has come back yet, names it as
    /// such 200 ms later, on the next tick.
    ///
    /// A second carrier question here would only move that verdict up by one
    /// tick, and it would make this a *fifth* liveness call site in a file whose
    /// four are pinned **by count**: `scripts/check-tor-native.py` requires at
    /// least four, and control 2 of `scripts/check-tor-native-negative.sh`
    /// deletes one and requires the guard to go red. A fifth call site keeps the
    /// guard green under that mutation, i.e. it silently disarms the control.
    fn can_retry_verification(&mut self) -> bool {
        if self.verify_retries >= Self::VERIFY_RETRY_LIMIT {
            return false;
        }
        let remaining = match self.deadline {
            Some(d) => d.saturating_duration_since(Instant::now()).as_millis() as u64,
            None => 0,
        };
        if remaining < VERIFY_RETRY_MIN_REMAINING_MS {
            return false;
        }
        probe::socks_ready(engine::exit_socks_port())
    }
    // <<< AETHER-APP-FIX a-self-test-is-a-sample-not-a-verdict

    fn apply_pending_security_refresh(&mut self) {
        if !self.security_refresh_pending {
            return;
        }
        self.security_refresh_pending = false;
        if self.profile.leak_guard || self.profile.kill_switch || self.profile.ipv6_protection {
            if let Some(mut old_guard) = self.guard.take() {
                old_guard.disarm_without_cleanup();
            }
            self.guard = Some(LeakGuard::engage(&self.profile));
        } else if let Some(mut guard) = self.guard.take() {
            guard.release();
        }
    }

    /// هر ۲۰۰ms از main.rs صدا زده می‌شود — معادل حلقهٔ نظارت اندروید.
    pub fn tick(&mut self) {
        // The last tap first. Both branches are slow, and both are why this runs
        // here instead of inside the IPC command. See [`Intent`].
        if let Some(intent) = self.pending_intent.take() {
            match intent {
                Intent::Connect => {
                    if let Err(e) = self.connect() {
                        let msg = e.to_string();
                        self.fail(&msg);
                    }
                }
                Intent::Disconnect => self.disconnect(),
            }
            return;
        }

        self.apply_pending_security_refresh();

        match self.state {
            // Waiting for the off-lock prep thread (port release + fingerprint).
            ConnectionState::StartingEngine => {
                let outcome = self.prep_slot.as_ref().and_then(|s| s.lock().take());
                if let Some(outcome) = outcome {
                    self.prep_slot = None;
                    let result = match self.prep_kind {
                        Prep::Plan => self.launch_plan(outcome.fingerprint),
                        Prep::Candidate => self.launch_candidate(),
                    };
                    if let Err(e) = result {
                        let msg = e.to_string();
                        self.fail(&msg);
                    }
                }
            }
            ConnectionState::Connecting => {
                // >>> AETHER-APP-PATCH tor-native-carrier
                if !self.carrier_alive() {
                    // در «تور تنها» هیچ موتوری اجرا نشده، پس گفتنِ «Engine exited»
                    // عیب‌یاب را دنبالِ موتوری می‌فرستاد که وجود ندارد: در لاگِ
                    // ۱۷ سپتامبر همین سطر کنارِ خطای واقعیِ تور نشسته بود و
                    // خواننده را به موتور مشکوک می‌کرد.
                    let carrier = if self.native_tor.is_some() {
                        "tor exited before it opened the SOCKS5 port"
                    } else {
                        "Engine exited before it opened the SOCKS5 port"
                    };
                    self.advance_or_fail(carrier);
                    return;
                }
                // <<< AETHER-APP-PATCH tor-native-carrier
                // >>> AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
                // یک نشستِ توریِ دونیمه، پیش از هر چیزِ دیگر: تا نیمهٔ دوم اجرا
                // نشده، پورتِ همیشگی (۱۸۱۹) مالِ هیچ‌کس نیست و منتظرِ آن ماندن
                // یعنی انتظارِ چیزی که قرار نیست بیاید.
                match self.tor_stage {
                    TorStage::TorThenEngine => {
                        match self.tor_gate() {
                            TorGate::Ready => {
                                if let Err(e) = self.start_engine_behind_tor() {
                                    let msg = e.to_string();
                                    self.advance_or_fail(&msg);
                                }
                            }
                            TorGate::Waiting => {
                                if self.past_deadline() {
                                    let msg = diagnostics::stage_failure_message(self.tor_shape());
                                    DiagnosticsLog::e(
                                        TAG,
                                        &format!(
                                            "Tor did not finish within its budget ({}).",
                                            tor_bootstrap::describe()
                                        ),
                                    );
                                    self.advance_or_fail(&msg);
                                }
                            }
                            TorGate::Stalled => {
                                let msg = diagnostics::stage_failure_message(self.tor_shape());
                                DiagnosticsLog::e(
                                    TAG,
                                    &format!(
                                        "Tor stopped making progress for {}s ({}).",
                                        self.tor_stall_ms() / 1_000,
                                        tor_bootstrap::describe()
                                    ),
                                );
                                self.advance_or_fail(&msg);
                            }
                        }
                        return;
                    }
                    TorStage::EngineThenTor => {
                        if probe::socks_ready(engine::LOCAL_SOCKS_PORT) {
                            self.tor_stage = TorStage::None;
                            if let Err(e) = self.start_tor_behind_engine() {
                                let msg = e.to_string();
                                self.advance_or_fail(&msg);
                            }
                        } else if self.past_deadline() {
                            self.advance_or_fail(
                                "Engine still scanning — the SOCKS5 port never opened in time",
                            );
                        }
                        return;
                    }
                    TorStage::None => {}
                }
                // <<< AETHER-APP-PATCH the-tor-in-front-is-the-real-tor
                // یک زنجیرهٔ در حال بالا آمدن، فاز خودش را دارد: استیج ۱ آماده
                // است و استیج ۲ در ترد پس‌زمینه برقرار می‌شود.
                if self.chain_slot.is_some() {
                    self.poll_chain();
                    return;
                }
                if probe::socks_ready(engine::LOCAL_SOCKS_PORT) {
                    // ۱.۲.۵ — روی حالت‌های تور، پورتِ باز هنوز چیزی را اثبات
                    // نمی‌کند: bootstrap باید تمام شده باشد.
                    match self.tor_gate() {
                        TorGate::Waiting => {
                            // همچنان منتظر، و همچنان در حرکت. تنها چیزی که
                            // این انتظار را پایان می‌دهد گیرکردنِ درصد است یا
                            // مردنِ موتور — هر دو بالاتر بررسی می‌شوند.
                            if self.past_deadline() {
                                let msg = diagnostics::stage_failure_message(self.tor_shape());
                                DiagnosticsLog::e(
                                    TAG,
                                    &format!(
                                        "Tor did not finish within its budget ({}).",
                                        tor_bootstrap::describe()
                                    ),
                                );
                                self.advance_or_fail(&msg);
                            }
                            return;
                        }
                        TorGate::Stalled => {
                            let msg = diagnostics::stage_failure_message(self.tor_shape());
                            DiagnosticsLog::e(
                                TAG,
                                &format!(
                                    "Tor stopped making progress for {}s ({}). Abandoning this \
                                     attempt instead of waiting out the whole budget.",
                                    self.tor_stall_ms() / 1_000,
                                    tor_bootstrap::describe()
                                ),
                            );
                            self.advance_or_fail(&msg);
                            return;
                        }
                        TorGate::Ready => {}
                    }
                    if self.profile.is_chained() {
                        self.begin_chain();
                    } else {
                        // ۱.۲.۵ — خروجی خط لوله همیشه پورت همیشگی نیست. هر چیزی
                        // که مسیر داده را می‌سازد (پل محلی، Wintun، خودآزما،
                        // پروبِ IP) از `engine::exit_socks_port` می‌پرسد، پس
                        // همین یک جا ست کردن کافی است.
                        let exit = self.data_path_exit_port();
                        if exit != engine::exit_socks_port() {
                            engine::set_exit_socks_port(exit);
                            DiagnosticsLog::i(
                                TAG,
                                &format!(
                                    "Pipeline exit is 127.0.0.1:{exit} ({}).",
                                    self.profile.backend.pipeline_label()
                                ),
                            );
                        }
                        DiagnosticsLog::i(TAG, "SOCKS5 port is up — bringing up the data path.");
                        self.bring_up_data_path();
                        self.begin_verification();
                    }
                } else if self.past_deadline() {
                    self.advance_or_fail(
                        "Engine still scanning — the SOCKS5 port never opened in time",
                    );
                }
            }
            ConnectionState::Verifying => {
                let outcome = self.verify_slot.as_ref().and_then(|s| s.lock().take());
                if let Some(out) = outcome {
                    self.verify_slot = None;
                    if out.ok {
                        if let Some(exit) = &out.exit {
                            // >>> AETHER-APP-PATCH endpoint-is-the-first-hop
                            // ردیفِ Endpoint نشانیِ هاپِ اول است، نه تکرارِ ردیفِ
                            // بالایی. تا وقتی هاپِ اول ثابت نشده، رفتارِ قبلی می‌ماند —
                            // چیزی جایِ اندپوینت جعل نمی‌شود.
                            self.endpoint = crate::firsthop::get().or_else(|| {
                                Some(match &exit.country_code {
                                    Some(cc) => format!("{} · {cc}", exit.ip),
                                    None => exit.ip.clone(),
                                })
                            });
                            // <<< AETHER-APP-PATCH endpoint-is-the-first-hop
                            // IP خروجی از خودآزما مستقیماً به نشان IP می‌رود —
                            // معادل offerTunnelIpInfo در Diagnostics.kt.
                            let mut g = self.ip_slot.lock();
                            g.session += 1;
                            g.info = Some(IpEndpoint {
                                ip: exit.ip.clone(),
                                country_code: exit.country_code.clone(),
                                via_tunnel: true,
                            });
                            g.loading = false;
                        }
                        // v1.2.0: نتیجهٔ سنجش نشتی مستقیم به نشانِ صفحهٔ اصلی می‌رود.
                        self.webrtc_leak = out.leak.as_ref().map(|l| l.leaking);
                        if self.webrtc_leak == Some(true) {
                            DiagnosticsLog::w(
                                TAG,
                                "Tunnel is up but WebRTC still reached a STUN server directly. Restart the browser so the WebRTC policy applies, or run Aether as administrator for the firewall layer.",
                            );
                        }
                        // `out.latency_ms` is how long the self-test's own HTTP
                        // fetch took, on a brand new dial, in the busiest second
                        // of the session. Through a chained pipeline that reads
                        // as 1600-3000 ms on a path that is actually fine, and it
                        // then sat frozen on screen — the reported bug. The badge
                        // now waits for the first real warm round trip instead of
                        // opening with a number nobody can reproduce.
                        if let Some(setup) = out.latency_ms {
                            DiagnosticsLog::i(
                                TAG,
                                &format!(
                                    "Self-test egress fetch took {setup} ms (dial + TLS + HTTP during \
                                     connect). Not shown as latency; the badge uses a warm round trip."
                                ),
                            );
                        }
                        self.latency_ms = None;
                        // A fresh pipeline needs a fresh probe session, and the
                        // first measurement should land immediately, not in 10s.
                        ping::reset();
                        self.latency_probe_at = None;
                        *self.latency_slot.lock() = None;
                        self.watchdog_probe_at =
                            Some(Instant::now() + Duration::from_secs(WATCHDOG_INTERVAL_SECS));
                        self.watchdog_failures = 0;
                        self.connected_at = Some(Instant::now());
                        self.attempts = 0;
                        // >>> AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
                        // پنجرهٔ مدار فقط در همین لحظه باز می‌شود — رجوع به
                        // [`Self::consider_new_circuit`].
                        self.circuit_tries = 0;
                        self.circuit_hunt_until = self
                            .native_tor
                            .is_some()
                            .then(|| Instant::now() + CIRCUIT_HUNT_WINDOW);
                        // <<< AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
                        // >>> AETHER-APP-FIX the-rung-that-worked-goes-first
                        // Recorded here, at the one place a session is declared
                        // good — after the self-test fetched a real page through
                        // this pipeline, not merely after the engine came up.
                        self.remember_the_rung_that_worked();
                        // <<< AETHER-APP-FIX the-rung-that-worked-goes-first
                        self.set_state(ConnectionState::Connected, "");
                        DiagnosticsLog::i(TAG, "All checks passed — tunnel is ready.");
                        if out.exit.is_none() {
                            spawn_ip_lookup(self.ip_slot.clone(), true);
                        }
                    } else if out.leak.as_ref().map(|l| l.leaking).unwrap_or(false) {
                        // Fail closed. A tunnel that exposes the real IP is not
                        // a successful connection, even when TCP/DNS passed.
                        //
                        // >>> AETHER-APP-FIX a-self-test-is-a-sample-not-a-verdict
                        // Through the ladder, not straight to `fail`. The
                        // previous code called `fail` here, which skipped every
                        // remaining rung: the 2026-09-22 WARP-in-WARP log says
                        // `Plan ready (2 attempt(s))` and `Attempt 1/2`, and the
                        // hardened anti-DPI rung was never tried. A verdict about
                        // *this* pipeline is not a verdict about the other rungs.
                        //
                        // But the ladder gets one look, not an unlimited number:
                        // see [`Self::leak_refused`]. A leak verdict is about the
                        // protection layer, which no rung changes.
                        let why = "Connection refused: WebRTC can still reach the real IP over \
                                   direct UDP and no browser-scoped protection is installed.";
                        let final_message = "This protocol could not establish a protected tunnel \
                                              on this network: WebRTC could still reach the real IP \
                                              over direct UDP. Turn the leak guard on, or restart \
                                              the browser so the new policy is picked up.";
                        if self.leak_refused {
                            self.fail(final_message);
                        } else {
                            self.leak_refused = true;
                            self.advance_or_fail_with(why, final_message);
                        }
                        // <<< AETHER-APP-FIX a-self-test-is-a-sample-not-a-verdict
                    } else if self.can_retry_verification() {
                        // >>> AETHER-APP-FIX a-self-test-is-a-sample-not-a-verdict
                        // The engine is alive and still owns the local port, so
                        // the pipeline is not necessarily broken - it may simply
                        // not have been ready when the sample was taken. The
                        // 2026-09-22 WARP-in-WARP log shows exactly that: the
                        // self-test ran while the engine was mid-reconnect and
                        // reported `TCP via proxy failed`, and ~16 s later the
                        // engine had a fresh validated pair of endpoints. The
                        // connection had already been refused by then.
                        self.verify_retries = self.verify_retries.saturating_add(1);
                        DiagnosticsLog::w(
                            TAG,
                            &format!(
                                "Self-test failed, but the engine is still up and the local port is \
                                 still open — re-checking ({}/{}) before giving up on this attempt.",
                                self.verify_retries,
                                Self::VERIFY_RETRY_LIMIT
                            ),
                        );
                        self.respawn_self_test();
                        // <<< AETHER-APP-FIX a-self-test-is-a-sample-not-a-verdict
                    } else {
                        self.advance_or_fail("Tunnel started, but the end-to-end self-test failed");
                    }
                // >>> AETHER-APP-PATCH tor-native-carrier
                } else if !self.carrier_alive() {
                    self.advance_or_fail("The engine stopped during verification");
                    // <<< AETHER-APP-PATCH tor-native-carrier
                }
            }
            ConnectionState::Connected => {
                // v1.2.0 watchdog: every 30s run three end-to-end probes in a
                // worker thread. Three consecutive failed rounds are required
                // before restarting, so short network jitter is tolerated.
                let watchdog_result = { self.watchdog_slot.lock().take() };
                if let Some(result) = watchdog_result {
                    if result {
                        self.watchdog_failures = 0;
                        DiagnosticsLog::i(TAG, "Watchdog probe passed (at least 2 of 3 targets reachable through SOCKS5).");
                    } else {
                        self.watchdog_failures = self.watchdog_failures.saturating_add(1);
                        DiagnosticsLog::w(
                            TAG,
                            &format!(
                                "Watchdog probe failed ({}/{})",
                                self.watchdog_failures, WATCHDOG_FAILURE_THRESHOLD
                            ),
                        );
                        if self.watchdog_failures >= WATCHDOG_FAILURE_THRESHOLD {
                            DiagnosticsLog::e(TAG, "Watchdog confirmed a persistent upstream failure — restarting the engine.");
                            self.cleanup_native(true);
                            self.watchdog_failures = 0;
                            self.connected_at = None;
                            self.reconnect_at = Some(Instant::now() + Duration::from_secs(2));
                            self.set_state(ConnectionState::Reconnecting, "Watchdog reconnect…");
                            return;
                        }
                    }
                }
                let watchdog_due = self
                    .watchdog_probe_at
                    .map(|t| Instant::now() >= t)
                    .unwrap_or(true);
                let watchdog_busy = { self.watchdog_slot.lock().is_some() };
                if watchdog_due && !watchdog_busy {
                    self.watchdog_probe_at =
                        Some(Instant::now() + Duration::from_secs(WATCHDOG_INTERVAL_SECS));
                    let slot = self.watchdog_slot.clone();
                    std::thread::Builder::new()
                        .name("aether-watchdog".into())
                        .spawn(move || {
                            let ok = probe::watchdog_probe();
                            *slot.lock() = Some(ok);
                        })
                        .ok();
                }

                // v16: پینگ نمایشی قبلاً فقط یک‌بار هنگام خودآزمای اتصال اندازه
                // گرفته می‌شد (شامل زمان دریافت HTTP در شلوغی لحظهٔ اتصال)
                // و دیگر به‌روز نمی‌شد — برای همین عددی مثل ۸۰۰۰ms می‌ماند.
                // حالا هر ۱۵ ثانیه یک اتصال TCP سبک از داخل تونل زمان‌گیری
                // می‌شود تا پینگ واقعی و زنده نمایش داده شود (بدون فریز UI).
                // قرضِ قفل پیش از تصمیم بسته می‌شود: `consider_new_circuit`
                // خودش به همان اسلات دست می‌زند.
                let fresh = self.latency_slot.lock().take();
                if let Some(ms) = fresh {
                    self.latency_ms = Some(ms);
                    // >>> AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
                    self.consider_new_circuit(ms);
                    // <<< AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
                }
                let latency_due = self
                    .latency_probe_at
                    .map(|t| Instant::now() >= t)
                    .unwrap_or(true);
                if latency_due {
                    self.latency_probe_at =
                        Some(Instant::now() + Duration::from_secs(LATENCY_INTERVAL_SECS));
                    let slot = self.latency_slot.clone();
                    std::thread::Builder::new()
                        .name("aether-latency".into())
                        .spawn(move || {
                            // One keep-alive round trip on a warm session — no
                            // dial, no SSH channel open. See [`crate::ping`].
                            if let Some(ms) = ping::measure() {
                                *slot.lock() = Some(ms);
                            }
                        })
                        .ok();
                }
                // سوپروایز **هر دو** هاپ. یک نشست زنجیره‌ای فقط به‌قدر ضعیف‌ترین
                // استیجش زنده است، و استیج ۱ مرده یعنی استیج ۲ پروکسی‌ای در دست
                // دارد که نمی‌تواند dial کند — «متصل» با هیچ چیزی در حرکت.
                //
                // `is_alive` استیج ۲ در طول یک چرخشِ عمدی عمداً true می‌ماند
                // (نگاه کنید به psiphon.rs)، وگرنه واچ‌داگ همان نشستی را
                // می‌کشت که قرار بود نجاتش بدهد.
                if self.profile.is_chained() && !self.psiphon.is_alive() {
                    DiagnosticsLog::e(
                        TAG,
                        "The Psiphon stage died while connected — rebuilding the session.",
                    );
                    self.cleanup_native(true);
                    self.connected_at = None;
                    self.reconnect_at = Some(Instant::now() + Duration::from_secs(2));
                    self.set_state(ConnectionState::Reconnecting, "Rebuilding the chain…");
                    return;
                }
                // >>> AETHER-APP-PATCH tor-native-carrier
                if !self.carrier_alive() {
                    // <<< AETHER-APP-PATCH tor-native-carrier
                    // معادل superviseEngine: بک‌آف پلکانی ۲/۵/۱۰ ثانیه، حداکثر ۳ تلاش.
                    let max_retries = self.profile.reconnect_attempts.max(DEFAULT_MAX_RETRIES);
                    if self.attempts >= max_retries {
                        self.fail("The engine keeps dying — giving up after repeated restarts.");
                        return;
                    }
                    let backoff = BACKOFF_MS[(self.attempts as usize).min(BACKOFF_MS.len() - 1)];
                    self.attempts += 1;
                    self.connected_at = None;
                    self.reconnect_at = Some(Instant::now() + Duration::from_millis(backoff));
                    DiagnosticsLog::w(
                        TAG,
                        &format!(
                            "Engine died while connected — restarting in {}s.",
                            backoff / 1000
                        ),
                    );
                    let detail = format!("Attempt {} of {}", self.attempts, max_retries);
                    self.set_state(ConnectionState::Reconnecting, &detail);
                }
            }
            ConnectionState::Reconnecting => {
                if let Some(at) = self.reconnect_at {
                    if Instant::now() >= at {
                        self.reconnect_at = None;
                        self.cleanup_native(true);
                        // همان پلهٔ برنده دوباره اجرا می‌شود — معادل restart در
                        // superviseEngine. The fingerprint and the port wait go
                        // to the prep thread, so a reconnect no longer freezes
                        // the UI for several seconds either.
                        let kind = if self.plan.is_empty() {
                            Prep::Plan
                        } else {
                            Prep::Candidate
                        };
                        self.set_state(ConnectionState::StartingEngine, "Reconnecting…");
                        self.begin_prep(kind);
                    }
                }
            }
            _ => {}
        }
    }

    fn past_deadline(&self) -> bool {
        self.deadline.map(|d| Instant::now() > d).unwrap_or(false)
    }

    fn fail(&mut self, why: &str) {
        DiagnosticsLog::e(TAG, why);
        self.cleanup_native(true);
        self.error = Some(why.to_string());
        self.connected_at = None;
        self.deadline = None;
        self.reconnect_at = None;
        self.verify_slot = None;
        self.prep_slot = None;
        self.pending_intent = None;
        self.latency_ms = None;
        ping::reset();
        self.set_state(ConnectionState::Failed, "Connection failed");
    }

    fn set_state(&mut self, state: ConnectionState, detail: &str) {
        let prev = self.state;
        // >>> AETHER-APP-FIX no-duplicate-status-events
        // این متد از دلِ حلقهٔ tick صدا زده می‌شود و پیش از این هر بار — یعنی
        // هر ۲۰۰ms — یک خط لاگ می‌نوشت و یک snapshot به UI می‌داد، حتی وقتی
        // نه وضعیت عوض شده بود و نه متن. در لاگ ۲۰۲۶-۰۹-۱۶ نتیجه‌اش ~۳۷۵ بار
        // «Reaching the Tor network… 15%» در ۷۵ ثانیه است: همان یک جمله، که
        // هر بارش یک نوشتنِ دیسک، یک عبور از IPC و یک رندر در WebView است.
        // آن کار هیچ‌چیز به کاربر نمی‌گوید و مستقیم روی CPU می‌نشیند.
        //
        // تغییرِ واقعی هنوز فوراً دیده می‌شود؛ فقط تکرارِ بی‌خبر حذف شده است.
        let unchanged = prev == state && self.detail == detail;
        self.state = state;
        self.detail = detail.to_string();
        if unchanged {
            return;
        }
        DiagnosticsLog::i(TAG, &format!("{state:?} {detail}"));
        // <<< AETHER-APP-FIX no-duplicate-status-events
        if prev != state {
            self.on_phase_change(state);
        }
    }

    /// معادل LaunchedEffect فازهای IP در MainActivity.kt:
    ///   connected → IP سرور از دل تونل — idle/failed → IP واقعی کاربر — busy → خالی.
    fn on_phase_change(&mut self, state: ConnectionState) {
        match state {
            ConnectionState::Connected => { /* خودآزما قبلاً IP را تحویل داده است */
            }
            ConnectionState::Disconnected | ConnectionState::Failed => {
                spawn_ip_lookup(self.ip_slot.clone(), false);
            }
            _ => {
                let mut g = self.ip_slot.lock();
                g.session += 1;
                g.info = None;
                g.loading = false;
            }
        }
    }

    // >>> AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network
    /// اگر این خواندنِ تأخیر روی مقیاسِ تور «ضعیف» است، یک مدارِ تازه می‌خواهد.
    ///
    /// پنجره کوتاه و شمارش محدود است، و هر دو عدد دلیل دارند:
    ///
    /// * تنها در نشستی که تور در آن هست. روی خطِ لولهٔ معمولی مدار وجود ندارد
    ///   و چیزی هم برای عوض‌کردن نیست.
    /// * تنها در ~۲۰ ثانیهٔ اولِ اتصال. کاربری که ده دقیقه است وصل است و در
    ///   حالِ بارگیری، نباید مدارش را زیرِ پایش عوض کنیم چون یک نمونه بد شد.
    /// * حداکثر سه بار. `NEWNYM` مجانی نیست (ساختِ مدارِ تازه چند ثانیه) و
    ///   شبکه‌ای که هر سه مدارش کند است، با مدارِ چهارم هم کند می‌ماند.
    /// * و به‌محضِ رسیدن به عددِ قابل‌قبول، پنجره بسته می‌شود.
    fn consider_new_circuit(&mut self, ms: u64) {
        // همان آستانهٔ «ضعیف» در مقیاسِ توریِ UI (`PING_BANDS_TOR.fair` در
        // `connectioncard.js`). یک عدد در دو جا بد است، ولی بدتر آن است که
        // برنامه بر پایهٔ آستانه‌ای تصمیم بگیرد که با آنچه کاربر می‌بیند یکی
        // نباشد — پس همان عدد، با ارجاعِ صریح.
        const POOR_MS: u64 = 800;
        const MAX_ROTATIONS: u8 = 3;
        /// فرصت به تور برای ساختِ مدارِ تازه، پیش از اندازه‌گیریِ بعدی.
        const SETTLE: Duration = Duration::from_secs(3);

        if self.native_tor.is_none() || !self.tor_fronted() {
            return;
        }
        let Some(until) = self.circuit_hunt_until else {
            return;
        };
        if Instant::now() >= until {
            self.circuit_hunt_until = None;
            return;
        }
        if ms <= POOR_MS {
            DiagnosticsLog::i(
                TAG,
                &format!("Tor circuit is good enough at {ms} ms — keeping it."),
            );
            self.circuit_hunt_until = None;
            return;
        }
        if self.circuit_tries >= MAX_ROTATIONS {
            DiagnosticsLog::i(
                TAG,
                &format!(
                    "Still {ms} ms after {} new circuits — this is the network, not the circuit; \
                     keeping the current one.",
                    self.circuit_tries
                ),
            );
            self.circuit_hunt_until = None;
            return;
        }

        let Some(tor) = self.native_tor.clone() else {
            return;
        };
        self.circuit_tries += 1;
        match tor.new_circuit(Duration::from_secs(5)) {
            Ok(()) => {
                DiagnosticsLog::i(
                    TAG,
                    &format!(
                        "{ms} ms is poor for Tor — asked tor for a new circuit \
                         (attempt {}/{MAX_ROTATIONS}).",
                        self.circuit_tries
                    ),
                );
                // نشستِ گرمِ پینگ روی مدارِ قدیم است و باید بیفتد، وگرنه
                // اندازه‌گیریِ بعدی همان مدار را می‌سنجد.
                ping::reset();
                self.latency_ms = None;
                *self.latency_slot.lock() = None;
                self.latency_probe_at = Some(Instant::now() + SETTLE);
                // مدارِ تازه یعنی خروجیِ تازه: هم نشانی، هم پرچم، هم اولین هاپ.
                crate::firsthop::reset();
                spawn_ip_lookup(self.ip_slot.clone(), true);
            }
            Err(error) => {
                // شکستِ NEWNYM نشست را نمی‌کُشد: مدارِ فعلی کار می‌کند و فقط
                // کند است. یک سطرِ لاگ، و پنجره بسته می‌شود.
                DiagnosticsLog::w(
                    TAG,
                    &format!("Could not ask tor for a new circuit: {error}"),
                );
                self.circuit_hunt_until = None;
            }
        }
    }
    // <<< AETHER-APP-PATCH a-bad-circuit-is-not-a-bad-network

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }
}

impl Drop for AetherController {
    fn drop(&mut self) {
        // خروج برنامه هرگز نباید پروکسی سیستمی را فعال رها کند.
        self.cleanup_native(false);
    }
}

/// جست‌وجوی IP در ترد پس‌زمینه — همان تعداد تلاش/تأخیرهای NetProbe اندروید:
/// مستقیم ۶×۲۰۰۰ms، از دل تونل ۱۲×۱۰۰۰ms.
fn spawn_ip_lookup(slot: Arc<Mutex<IpSlot>>, via_tunnel: bool) {
    let session = {
        let mut g = slot.lock();
        g.session += 1;
        g.loading = true;
        if !via_tunnel {
            g.info = None;
        }
        g.session
    };
    std::thread::Builder::new()
        .name("aether-ipinfo".into())
        .spawn(move || {
            let result = if via_tunnel {
                probe::fetch_ip_via_socks_retry(12, 1_000, 6_000)
            } else {
                probe::fetch_ip_direct_retry(6, 2_000, 6_000)
            };
            let mut g = slot.lock();
            if g.session != session {
                return; // نتیجهٔ کهنه — فاز عوض شده است.
            }
            g.info = result.map(|i| IpEndpoint {
                ip: i.ip,
                country_code: i.country_code,
                via_tunnel,
            });
            g.loading = false;
        })
        .ok();
}
