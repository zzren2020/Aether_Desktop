//! اندپوینتِ نشست: نخستین هاپی که این نشست واقعاً به آن وصل شد.
//!
//! # چرا این ماژول هست
//!
//! کارتِ اتصال تا ۱.۲.۵ در ردیفِ `Endpoint` همان چیزی را می‌نوشت که ردیفِ
//! `Server IP` هم می‌گفت: IPِ خروجی و نامِ کشور. در تصویرِ کاربر از حالتِ «تور
//! تنها» هر دو ردیف `185.220.101.146` بودند، یکی با ` · T1`. یک ردیف دو بار.
//!
//! اندپوینتِ راستین چیزِ دیگری است: نشانی و پورتی که سوکتِ ما به آن نشسته —
//! لبهٔ WARP در حالت‌های تونلی، و پلِ obfs4 در حالت‌های توری. هر دو در لاگِ
//! خودِ نشست هست، فقط تا امروز کسی برنمی‌داشتش:
//!
//! ```text
//! [+] using cloudflare edge 162.159.195.224:908
//! [+] tor first hop: 212.83.43.74:80 via obfs4
//! ```
//!
//! هر دو سطر از دو مسیرِ کاملاً جدا می‌آیند (خروجیِ فرآیندِ موتور و سینکِ تورِ
//! بومی)، پس اینجا یک حالتِ فرآیندی است، نه فیلدی در یکی از آن دو.
//!
//! هیچ حدسی زده نمی‌شود: تا وقتی یک `ip:port`ِ درست دیده نشده، پاسخ `None`
//! است و کارت رفتارِ قبلی‌اش را نگه می‌دارد.

use std::net::SocketAddr;
use std::sync::Mutex;

/// عبارت‌هایی که پس از آن‌ها یک `ip:port` می‌آید.
const MARKERS: [&str; 2] = ["using cloudflare edge ", "tor first hop: "];

static HOP: Mutex<Option<String>> = Mutex::new(None);

/// نشستِ تازه، اندپوینتِ تازه. بی این، کارت نشانیِ نشستِ قبلی را نشان می‌دهد.
pub fn reset() {
    if let Ok(mut hop) = HOP.lock() {
        *hop = None;
    }
}

/// یک سطرِ لاگ. برای هر سطرِ نامربوط با یک `contains` برمی‌گردد.
pub fn ingest(line: &str) {
    for marker in MARKERS {
        let Some(rest) = line.split(marker).nth(1) else {
            continue;
        };
        let token = rest.split_whitespace().next().unwrap_or_default();
        // `to_string` فقط پس از آنکه ثابت شد نشانی است — نه پیش از آن.
        if let Ok(addr) = token.parse::<SocketAddr>() {
            if let Ok(mut hop) = HOP.lock() {
                *hop = Some(addr.to_string());
            }
            return;
        }
    }
}

/// `ip:port`ِ نخستین هاپ، یا `None` وقتی هنوز چیزی ثابت نشده.
pub fn get() -> Option<String> {
    HOP.lock().ok().and_then(|hop| hop.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    // >>> AETHER-APP-FIX shared-static-tests-must-not-race
    // Rust 的测试默认多线程并行跑，而 `HOP` 是全进程共享的静态。四个测试并发
    // 读写它就会互相踩：CI 上 `a_line_without_a_port_is_not_an_endpoint` 在
    // `fresh()` 断言 None 之后、自己的断言之前，读到了并行测试刚 ingest 进去的
    // 边缘，`assert_eq!(get(), None)` 随即失败（268 过 1 挂，且逐次运行结果
    // 不定 —— 典型的竞态形态）。这把锁把本模块的测试串行化；锁中毒时直接
    // 拿回守卫（`into_inner`），因为 poisoned 只说明某个测试 panic 过，
    // 串行化的目的本身不受影响。
    static TEST_SERIALIZER: Mutex<()> = Mutex::new(());
    // <<< AETHER-APP-FIX shared-static-tests-must-not-race

    fn fresh() {
        reset();
        assert_eq!(get(), None);
    }

    #[test]
    fn takes_the_warp_edge_from_the_engine_line() {
        let _serial = TEST_SERIALIZER.lock().unwrap_or_else(|e| e.into_inner());
        fresh();
        ingest(
            "1789627203863 D/engine: [2026-09-17T06:40:03.863Z INFO  aether] \
             [+] using cloudflare edge 162.159.195.224:908",
        );
        assert_eq!(get().as_deref(), Some("162.159.195.224:908"));
    }

    #[test]
    fn takes_the_bridge_from_the_tor_line() {
        let _serial = TEST_SERIALIZER.lock().unwrap_or_else(|e| e.into_inner());
        fresh();
        ingest("[+] tor first hop: 212.83.43.74:80 via obfs4");
        assert_eq!(get().as_deref(), Some("212.83.43.74:80"));
    }

    /// سطرِ بی‌ربط چیزی را عوض نمی‌کند — و مهم‌تر، سطرِ نزدیک‌ولی‌بی‌پورت هم نه.
    #[test]
    fn a_line_without_a_port_is_not_an_endpoint() {
        let _serial = TEST_SERIALIZER.lock().unwrap_or_else(|e| e.into_inner());
        fresh();
        ingest("[tor] new bridge descriptor 'torfnase' (fresh): $3956… at 212.83.43.74");
        ingest("[+] socks5 server listening on 127.0.0.1:1819");
        assert_eq!(get(), None);
    }

    /// نشستِ بعدی نشانیِ نشستِ قبلی را به ارث نمی‌برد.
    #[test]
    fn reset_forgets_the_previous_session() {
        let _serial = TEST_SERIALIZER.lock().unwrap_or_else(|e| e.into_inner());
        fresh();
        ingest("[+] using cloudflare edge 162.159.192.163:859");
        assert!(get().is_some());
        reset();
        assert_eq!(get(), None);
    }
}
