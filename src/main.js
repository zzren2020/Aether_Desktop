// =============================================================================
//  Aether Desktop — پوستهٔ کاربری
//  پورت یک‌به‌یک از ui/ مخزن اندروید (Jetpack Compose → DOM).
// =============================================================================
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { getCurrentWindow } from '@tauri-apps/api/window'

import { renderHome } from './views/home.js'
import { renderSettings } from './views/settings.js'
import { renderDiagnostics } from './views/diagnostics.js'
import { renderShare } from './views/share.js'
import { renderAbout } from './views/about.js'

import { t, applyLang } from './i18n.js'
// >>> AETHER-APP-FIX remove-assistant-chat
// 助手（assistant）与聊天（chat）两个界面连同 AI 层入口一并下线：
// 视图文件（views/assistant.js、views/chat.js、ai.js）仍留在源码树里作死代码，
// 但没有任何导航入口指向它们。恢复时把下面三处 import、NAV_ICONS/VIEWS/
// NAV_LABELS 里的条目和 index.html 的两个 rail 按钮加回来即可。
// <<< AETHER-APP-FIX
import { setTabRouter } from './ui/nav.js'

// --- وضعیت سراسری ------------------------------------------------------
export const app = {
  snapshot: {
    state: 'DISCONNECTED',
    detail: '',
    error: null,
    endpoint: null,
    protocol: null,
    latencyMs: null,
    uptimeSecs: 0,
    rxBytes: 0,
    txBytes: 0,
    shareSocks: null,
    shareHttp: null,
    ipInfo: null,
    ipLoading: true,
    // v1.2.0 — سنجش نشتی WebRTC: null = هنوز سنجیده نشده.
    webrtcLeak: null,
    leakGuard: false,
    torPercent: null,
  },
  profile: null,
  tab: 'home',
  listeners: new Set(),
}

// A repaint listener is owned by the DOM node it paints. Detached owners are
// skipped instead of being torn down, which is what lets a view be cached and
// re-attached rather than rebuilt from scratch on every tab switch.
export function onChange(fn, owner = null) {
  const entry = { fn, owner }
  app.listeners.add(entry)
  return () => app.listeners.delete(entry)
}

export function emit() {
  for (const l of app.listeners) {
    if (l.owner && !l.owner.isConnected) continue
    l.fn(app)
  }
}

/**
 * یک تنظیم را ذخیره می‌کند.
 *
 * # چرا اول خوانده می‌شود و بعد نوشته
 *
 * `set_profile` **کلِ** پروفایل را می‌گیرد و نه یک تغییر. پس نوشتن روی کپیِ
 * محلی یعنی هر فیلدی که این کپی از آن بی‌خبر است، با مقدارِ کهنه‌اش بازنویسی
 * می‌شود. تا وقتی هر نوشتنی از خودِ رابط شروع می‌شد این بی‌ضرر بود؛ مسیرهای
 * هوش مصنوعی که در Rust می‌نویسند، این فرض را شکستند: کاربر تغییرِ دستیار را
 * اعمال می‌کرد، بعد یک تنظیمِ بی‌ربط را عوض می‌کرد، و تغییرِ دستیار بی‌صدا
 * برمی‌گشت.
 *
 * حالا مرجع، همیشه سمت Rust است: پروفایلِ فعلی خوانده می‌شود، تغییر روی همان
 * می‌نشیند، و همان نوشته می‌شود. رخدادِ `aether://profile` هم هست، ولی این
 * تابع به رسیدنِ آن **تکیه نمی‌کند** — یک رخدادِ ازدست‌رفته نباید به از‌دست‌رفتنِ
 * تنظیمات ترجمه شود.
 *
 * فیلدهای محرمانه از این قاعده مستثنا نیستند و لازم هم نیست باشند:
 * `get_profile` آن‌ها را برنمی‌گرداند (رشتهٔ خالی) و `set_profile` رشتهٔ خالی را
 * «دست نزن» تفسیر می‌کند، پس رازِ این نشست با یک خواندن پاک نمی‌شود.
 */
export async function saveProfile(patch) {
  let base = app.profile
  try {
    base = await invoke('get_profile')
  } catch (e) {
    // خواندن شکست خورد: با کپیِ محلی جلو می‌رویم، چون نوشتنِ تنظیمِ کاربر مهم‌تر
    // از تازه‌بودنِ بقیهٔ فیلدهاست — ولی *گفته* می‌شود.
    console.error('get_profile before save failed; writing on the local copy', e)
  }
  app.profile = { ...base, ...patch }
  await invoke('set_profile', { profile: app.profile })
  emit()
}

/**
 * درِ پشتیِ تست برای رخدادِ `aether://profile` — بدونِ Tauri.
 *
 * هیچ کدِ محصولی صدایش نمی‌زند؛ هارنسِ jsdom با آن همان چیزی را بازی می‌کند که
 * Rust پس از نوشتنِ پروفایل می‌فرستد.
 */
export function applyProfileSnapshot(profile) {
  app.profile = profile
  dropProfileViews()
  emit()
}

export async function toggleConnection() {
  try {
    await invoke('toggle_connection')
  } catch (e) {
    app.snapshot.error = String(e)
    emit()
  }
}

// --- رنگ حالت — دقیقاً همان قانون ConnectButton.kt --------------------
export function accentFor(state) {
  if (state === 'CONNECTED') return '#32E0C4'
  if (state === 'FAILED') return '#FF5C7A'
  return '#4C8DFF'
}

// --- متن حالت — همان رشته‌های strings.xml -----------------------------
export const STATE_LABEL = {
  DISCONNECTED: 'Disconnected',
  STARTING_ENGINE: 'Starting engine…',
  CONNECTING: 'Connecting…',
  VERIFYING: 'Verifying…',
  CONNECTED: 'Connected',
  RECONNECTING: 'Reconnecting…',
  DISCONNECTING: 'Disconnecting…',
  FAILED: 'Connection failed',
}

export function formatBytes(n) {
  if (!n) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1)
  return `${(n / 1024 ** i).toFixed(i === 0 ? 0 : 1)} ${units[i]}`
}

export function formatUptime(secs) {
  const h = Math.floor(secs / 3600)
  const m = Math.floor((secs % 3600) / 60)
  const s = secs % 60
  const pad = (x) => String(x).padStart(2, '0')
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`
}

// --- نوار عنوان سفارشی (decorations: false) ---------------------------
// رفع ریشه‌ای آیکون‌های خراب (مربع): آیکون‌های قبلی گلیف فونت
// «Segoe MDL2 Assets» در index.html بودند که بدون آن فونت به‌صورت مربع
// رندر می‌شدند. حالا هر سه آیکون SVG داخلی هستند و همین‌جا در زمان
// اجرا داخل دکمه‌ها تزریق می‌شوند؛ یعنی منبع آیکون‌ها فقط همین باندل
// جاوااسکریپت است و حتی با index.html قدیمی هم درست رندر می‌شوند.
const ICON_MINIMIZE =
  '<svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true"><path d="M0 5h10" stroke="currentColor" stroke-width="1" fill="none"/></svg>'
const ICON_MAXIMIZE =
  '<svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true"><rect x="0.5" y="0.5" width="9" height="9" fill="none" stroke="currentColor" stroke-width="1"/></svg>'
const ICON_RESTORE =
  '<svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true"><path d="M2.5 2.5V0.5h7v7h-2" fill="none" stroke="currentColor" stroke-width="1"/><rect x="0.5" y="2.5" width="7" height="7" fill="none" stroke="currentColor" stroke-width="1"/></svg>'
const ICON_CLOSE =
  '<svg viewBox="0 0 10 10" width="10" height="10" aria-hidden="true"><path d="M0 0l10 10M10 0L0 10" stroke="currentColor" stroke-width="1.1" fill="none"/></svg>'

// v9: Material-style outline icons for the permanent navigation rail.
const NAV_ICONS = {
  home: '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 10.5 12 3l9 7.5"/><path d="M5.5 9.5V20h13V9.5"/></svg>',
  advanced: '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M4 7h8M18 7h2M4 17h2M10 17h10"/><circle cx="15" cy="7" r="2.4"/><circle cx="7" cy="17" r="2.4"/></svg>',
  // >>> AETHER-APP-FIX remove-assistant-chat：assistant/chat 图标随界面一并下线
  diagnostics: '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12h4l2.5-6 5 12 2.5-6h4"/></svg>',
  share: '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M4.5 12a10.5 10.5 0 0 1 15 0"/><path d="M7.8 15.2a6 6 0 0 1 8.4 0"/><circle cx="12" cy="18.6" r="1.5" fill="currentColor" stroke="none"/></svg>',
  about: '<svg viewBox="0 0 24 24" width="22" height="22" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><circle cx="12" cy="12" r="8.5"/><path d="M12 11v5"/><circle cx="12" cy="7.8" r="1" fill="currentColor" stroke="none"/></svg>',
}

async function refreshMaximizeButton(win, btn) {
  if (!btn) return
  try {
    const maximized = await win.isMaximized()
    btn.innerHTML = maximized ? ICON_RESTORE : ICON_MAXIMIZE
    btn.setAttribute('aria-label', maximized ? 'Restore' : 'Maximize')
    btn.title = maximized ? 'Restore' : 'Maximize'
  } catch {
    btn.innerHTML = ICON_MAXIMIZE
  }
}

function wireTitlebar() {
  const win = getCurrentWindow()
  const minBtn = document.querySelector('.twin--min')
  const maxBtn = document.querySelector('.twin--max')
  const closeBtn = document.querySelector('.twin--close')

  // تزریق آیکون‌ها — جایگزین هر محتوای قبلی (از جمله گلیف فونت خراب).
  if (minBtn) minBtn.innerHTML = ICON_MINIMIZE
  if (closeBtn) closeBtn.innerHTML = ICON_CLOSE
  refreshMaximizeButton(win, maxBtn)

  document.querySelector('.titlebar')?.addEventListener('mousedown', (e) => {
    if (e.target.closest('.twin')) return
    win.startDragging()
  })
  // دقیقاً مثل ویندوز: دابل‌کلیک روی نوار عنوان هم بزرگ/کوچک می‌کند.
  document.querySelector('.titlebar')?.addEventListener('dblclick', async (e) => {
    if (e.target.closest('.twin')) return
    await win.toggleMaximize()
    refreshMaximizeButton(win, maxBtn)
  })
  minBtn?.addEventListener('click', () => win.minimize())
  maxBtn?.addEventListener('click', async () => {
    await win.toggleMaximize()
    refreshMaximizeButton(win, maxBtn)
  })
  closeBtn?.addEventListener('click', () => win.close())
  win.onResized(() => refreshMaximizeButton(win, maxBtn))
}

// --- مسیریابی تب‌ها (در اندروید باتم‌شیت بود، در دسکتاپ ریل کناری) --
const VIEWS = {
  home: renderHome,
  advanced: renderSettings,
  // >>> AETHER-APP-FIX remove-assistant-chat：assistant/chat 视图不再注册
  diagnostics: renderDiagnostics,
  share: renderShare,
  about: renderAbout,
}

// Built views, kept by tab.
//
// Root cause of the slow menu: every tab click threw the old view's DOM away and
// rebuilt the next one from strings — and "Advanced" means 56 country rows, each
// with an inline SVG flag, plus a fresh `core_caps` IPC round trip, every single
// time. Views are built once and re-attached after that, so switching a tab is a
// single `appendChild`. `emit()` already skips detached owners, so a cached view
// costs nothing while it is off screen.
const BUILT = new Map()
let mounted = null

// A view may expose lifecycle hooks on its root node; only the diagnostics panel
// needs them (it polls the log while visible and must stop when it is not).
function renderTab() {
  const host = document.getElementById('view')
  if (mounted && mounted.parentElement === host) {
    mounted.__onHide?.()
    host.removeChild(mounted)
  }
  let node = BUILT.get(app.tab)
  if (!node) {
    node = VIEWS[app.tab](app)
    BUILT.set(app.tab, node)
  }
  host.replaceChildren(node)
  mounted = node
  node.__onShow?.()
  for (const b of document.querySelectorAll('.rail__item')) {
    b.classList.toggle('is-active', b.dataset.tab === app.tab)
  }
  // v14 — یک آپدیت را که وقتی این تب پنهان بود از دست رفت، همین‌جا برمی‌گردانیم.
  //
  // `emit()` هر listenerی را که مالکش هنوز `isConnected` نیست رد می‌کند —
  // دقیقاً همان چیزی که این تب را تا این لحظه ارزان نگه می‌داشت. مشکل این بود
  // که هیچ‌کس، درست در لحظه‌ای که یک نودِ کش‌شده دوباره متصل می‌شود، این
  // رد‌شده‌ها را دوباره صدا نمی‌زد؛ یک `emit()` که *وسطِ* غیبتِ این تب اتفاق
  // می‌افتاد (مثلاً `saveProfile` از تبِ Settings) برای همیشه گم می‌شد و تنها
  // با رخداد بعدیِ `emit` (که مقدارِ *آن لحظه* را می‌داد، نه لزوماً مقدارِ درست
  // برای این ردیف) جایش پر می‌شد. همین‌جا، بعد از اتصالِ دوبارهٔ نود، یک
  // `emit()` تازه تضمین می‌کند هر چیزی که این تب نشان می‌دهد با `app.profile`/
  // `app.snapshot` *همین الان* یکی است — نه با آخرین باری که این تب دیده شد.
  emit()
}

// Drops a cached view so the next visit rebuilds it. Used by panels whose markup
// depends on the profile (revealing a section, switching endpoint mode).
export function refreshTab(tab = app.tab) {
  const node = BUILT.get(tab)
  if (node === mounted) mounted = null
  BUILT.delete(tab)
  if (tab === app.tab) renderTab()
}

/// Tabs whose MARKUP is built from the profile.
///
/// Only one, and that is the point: `advanced.js` reads `app.profile` while it
/// builds its controls and never subscribes to `onChange`. Combined with the
/// view cache above, a profile that Rust writes -- the assistant applying a
/// change, Smart Auto lowering the noize, `reset_profile` -- left the built
/// panel showing the OLD value for the rest of the session. The hub row updated
/// (it has an `onChange`), so the row said one thing and the control under it
/// said another.
const PROFILE_TABS = ['advanced']

/// A rebuild pending because the user is typing. See [`dropProfileViews`].
let profileTabStale = false

/// True while the caret sits in an editable control inside [node].
function editingInside(node) {
  const active = document.activeElement
  if (!active || active === document.body || !node.contains(active)) return false
  return active.matches('input, textarea, select, [contenteditable="true"]')
}

/// Throws away the profile-built views so the next paint reads the new profile.
///
/// The one case that must NOT rebuild immediately is a user typing into the
/// panel (a bridge line, a team name): a snapshot arriving mid-keystroke would
/// replace the field under the caret and eat the edit. There the rebuild is
/// deferred to the next time the tab is shown.
function dropProfileViews() {
  for (const tab of PROFILE_TABS) {
    const node = BUILT.get(tab)
    if (!node) continue
    if (node === mounted && editingInside(node)) {
      profileTabStale = true
      continue
    }
    if (node === mounted) refreshTab(tab)
    else BUILT.delete(tab)
  }
}

/// Switches tab. The rail and the jsdom harness go through here, so the cache
/// invalidation cannot be true on one path and false on the other.
export function showTab(tab) {
  app.tab = tab
  if (profileTabStale && PROFILE_TABS.includes(tab)) {
    profileTabStale = false
    BUILT.delete(tab)
    if (mounted && BUILT.get(tab) === undefined) mounted = null
  }
  renderTab()
}

function wireRail() {
  for (const b of document.querySelectorAll('.rail__item')) {
    b.addEventListener('click', () => {
      showTab(b.dataset.tab)
    })
  }
}

// --- راه‌اندازی ---------------------------------------------------------
// >>> AETHER-APP-FIX remove-assistant-chat：标签表同步去掉 assistant/chat
const NAV_LABELS = { home: 'Home', advanced: 'Settings', diagnostics: 'Diagnostics', share: 'Share over LAN', about: 'About' }

// v9: retranslate the chrome (nav rail icons + labels + window title) for the
// active language. The rail is a permanent Material-style navigation rail.
function translateChrome() {
  for (const b of document.querySelectorAll('.rail__item')) {
    const label = t(NAV_LABELS[b.dataset.tab] ?? b.dataset.tab)
    b.innerHTML =
      '<span class="rail__icon">' + (NAV_ICONS[b.dataset.tab] ?? '') + '</span>' +
      '<span class="rail__label"></span>'
    b.querySelector('.rail__label').textContent = label
    b.title = label
  }
  const title = document.querySelector('.titlebar__title')
  if (title) title.textContent = t('Aether')
}

// v8: re-render chrome + current tab after a language change.
export function rerender() {
  translateChrome()
  // A language change invalidates every built view, not just the visible one.
  for (const [tab, node] of BUILT) {
    if (node === mounted) mounted = null
    BUILT.delete(tab)
  }
  renderTab()
}

async function boot() {
  applyLang()
  wireTitlebar()
  wireRail()
  translateChrome()
  // درِ ناوبری برای بقیهٔ ماژول‌ها — رجوع به مستند `src/ui/nav.js` برای اینکه
  // چرا این ثبت است و نه یک import مستقیم به `renderTab`.
  setTabRouter((tab) => {
    if (!(tab in VIEWS)) return
    app.tab = tab
    renderTab()
  })

  // Paint a tiny, dependency-free shell immediately. Rendering a full view
  // before profile IPC caused the advanced view to do expensive work twice.
  const host = document.getElementById('view')
  host.innerHTML = '<div class="boot-skeleton" aria-busy="true"></div>'

  // Fetch initial state in parallel instead of serializing two IPC round trips.
  const [profile, snapshot] = await Promise.all([
    invoke('get_profile'),
    invoke('get_snapshot'),
  ])
  app.profile = profile
  app.snapshot = snapshot

  // پروفایلی که خودِ Rust نوشته — مسیرهای هوش مصنوعی. بی این، صفحهٔ تنظیمات
  // مقدارِ پیش از اعمال را نشان می‌داد و کاربر نتیجه می‌گرفت که «اعمال نشد».
  await listen('aether://profile', (event) => {
    if (event.payload) applyProfileSnapshot(event.payload)
  })

  // جریان زندهٔ وضعیت — معادل StateFlow در اندروید (هر ۲۰۰ میلی‌ثانیه).
  let lastAccent = null
  await listen('aether://state', (event) => {
    app.snapshot = event.payload
    // فقط وقتی رنگ واقعاً عوض شده بنویس — نوشتن مداوم متغیر CSS روی <html>
    // هر ۲۰۰ms باعث style-recalc کل صفحه و گیرکردن انیمیشن کمان می‌شد.
    const accent = accentFor(app.snapshot.state)
    if (accent !== lastAccent) {
      lastAccent = accent
      document.documentElement.style.setProperty('--accent', accent)
    }
    emit()
  })

  // >>> AETHER-APP-FIX remove-assistant-chat：AI 层入口随助手/聊天一并下线
  // （原 initAi() 调用与"AI 状态流"注释一并移除——页面没有消费方了。）

  // Repaint the already-visible shell with the real state once IPC returns.
  renderTab()
  emit()
}

boot().catch((error) => {
  console.error('Aether UI bootstrap failed', error)
})
