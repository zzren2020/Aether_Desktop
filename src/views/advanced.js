// پورت از ui/AdvancedPanel.kt (+ SegmentedSelector.kt ، DropdownSelector.kt ، LtrInput.kt ، AppPickerDialog.kt)
// توجه: گزینهٔ Proxy Mode عمداً حذف شده — در ویندوز کاربردی ندارد.
// v8:
//   * پروتکل «Auto» به «Smart» تغییر نام داد — دقیقاً هم‌نام نسخهٔ موبایل.
//   * انتخاب زبان برنامه (English/فارسی) + دکمهٔ «بازنشانی به تنظیمات پیش‌فرض».
import { invoke } from '@tauri-apps/api/core'
import { app, saveProfile, rerender, refreshTab } from '../main.js'
import { t, getLang, setLang, LANGS } from '../i18n.js'
import { flagHtml } from '../flags.js'

// v11 (هستهٔ 1.7.0):
//   * پروکسی بالادست (--upstream) — زنجیره‌کردن اِتِر پشت یک VPN/پروکسی دیگر.
//   * تطبیق قواعد دامنه‌ای از روی نام واقعی میزبان (SNI/Host) پشت Wintun.
//   * ثبت دوبارهٔ خودکار هویتی که Cloudflare دیگر قبولش ندارد.
// v12 (۱.۲.۳) — بک‌اند ترابرد، پورت مستقیم از model/TransportBackend.kt.
// «Aether → Psiphon» خروجی را با یک IP هاستینگ عادی عوض می‌کند و هاپ اول را
// روی ترابرد مبهم‌سازی‌شدهٔ اِتِر نگه می‌دارد. حالت تک‌هاپیِ Psiphon عمداً وجود
// ندارد: نمی‌توانست هاپ اول خودش را رد کند.
// v13 (۱.۲.۵ / هستهٔ 2.0.0) — چهار حالت تور، عیناً `TransportBackend.entries`
// موبایل و به همان ترتیب. هر کدام کاری می‌کند که بقیه نمی‌کنند، پس هیچ‌یک
// «همان قبلی با یک گزینهٔ بیشتر» نیست؛ توضیحِ هر کدام در BACKEND_HELP است.
const BACKENDS = [
  ['AETHER', 'Aether'],
  ['AETHER_PSIPHON', 'Aether \u2192 Psiphon'],
  ['TOR', 'Tor'],
  ['AETHER_TOR', 'Aether \u2192 Tor'],
  ['TOR_PSIPHON', 'Tor \u2192 Psiphon'],
  ['TOR_AETHER', 'Tor \u2192 Aether'],
]

// توضیحِ زیرِ انتخابگر، برای هر بک‌اند جدا — پورت از `backendHelp` موبایل.
// تا ۱.۲.۴ اینجا یک جملهٔ ثابت بود که فقط دربارهٔ Psiphon حرف می‌زد؛ با شش
// بک‌اند، آن یک جمله برای چهارتایشان حرفِ نادرست می‌شد.
const BACKEND_HELP = {
  // این دو از `backend_help_aether` و `backend_help_chained` موبایل می‌آیند.
  // تا ۱.۲.۴ یک جملهٔ واحد برای هر دو بود؛ حالا که توضیح به بک‌اند وابسته است،
  // آن جمله وقتی «Aether» انتخاب بود هم دربارهٔ سایفون حرف می‌زد.
  AETHER: 'One hop through the bundled Aether/WARP engine. Fastest.',
  AETHER_PSIPHON: 'Two hops: Aether connects first, then Psiphon tunnels through it. Your exit IP becomes Psiphon\u2019s, so sites that block Aether/WARP addresses open again.',
  TOR: 'Tor alone, without the Aether tunnel. Your exit is a Tor exit node and your traffic passes three relays, which is the slowest and the most private of the modes. Tor has to reach the Tor network by itself here, so it uses bridges when it is blocked.',
  AETHER_TOR: 'Two hops: Aether connects first, then Tor is built INSIDE that tunnel. The network you are on sees only Aether\u2019s obfuscated transport, never Tor \u2014 so this is the mode to use where Tor is blocked. Your exit is a Tor exit node.',
  TOR_PSIPHON: 'Three hops: Tor first, then Psiphon dialled through it. Your exit IP is Psiphon\u2019s, reached from a Tor address, so sites that block Tor exit nodes open again while your own address stays behind Tor. The slowest mode.',
  TOR_AETHER: 'The reverse chain: Tor first, then the Aether tunnel built INSIDE it. Your exit is a WARP address \u2014 the same as plain Aether \u2014 but the network you are on sees only Tor, and cannot tell that a VPN tunnel exists at all. Use it where Cloudflare/WARP itself is blocked or throttled but Tor still gets through. Carries normal UDP, unlike the Tor-exit modes.',
}

// حالت‌هایی که تور در آن‌ها هست — آینهٔ `uses_tor` و `tor_mode` در profile.rs.
const TOR_BACKENDS = ['TOR', 'AETHER_TOR', 'TOR_PSIPHON', 'TOR_AETHER']
const usesTor = (b) => TOR_BACKENDS.includes(b || 'AETHER')
// در زنجیرهٔ عادی، تور از داخلِ تونل زنگ می‌زند: شبکهٔ محلی هرگز آن را
// نمی‌بیند، پس پل و کشورِ پل بی‌معنی‌اند.
const torChained = (b) => b === 'AETHER_TOR'
const torReverse = (b) => b === 'TOR_AETHER'

const TOR_BRIDGES = [
  ['AUTO', 'Automatic'],
  ['ALWAYS', 'Always'],
  ['OFF', 'Off'],
]

// همان فهرست transport/TorCountries.kt — کشورهایی که bridgedb برایشان پل دارد.
const TOR_COUNTRIES = [
  ['', 'Detect automatically'], ['ir', 'Iran'], ['ru', 'Russia'], ['cn', 'China'],
  ['tm', 'Turkmenistan'], ['by', 'Belarus'], ['eg', 'Egypt'], ['sa', 'Saudi Arabia'],
  ['ae', 'United Arab Emirates'], ['tr', 'T\u00fcrkiye'],
]

// صبر برای مسیر مستقیم، پیش از رفتن به پل‌ها. صفر = همان ۷۵ ثانیهٔ خود موتور.
const TOR_DIRECT_PRESETS = [0, 20, 45, 120, 240]

// همان کدهای transport/ExitRegions.kt و src-tauri/src/exit_regions.rs.
// ⚠ Psiphon این را فیلتر سخت می‌داند؛ اگر کشور سرور نداشته باشد سمت Rust
// خودکار به خروجی automatic برمی‌گردد.
const EXIT_REGIONS = [
  ['', 'Automatic'], ['AE', 'United Arab Emirates'], ['AR', 'Argentina'], ['AT', 'Austria'],
  ['AU', 'Australia'], ['BE', 'Belgium'], ['BG', 'Bulgaria'], ['BR', 'Brazil'],
  ['CA', 'Canada'], ['CH', 'Switzerland'], ['CL', 'Chile'], ['CO', 'Colombia'],
  ['CY', 'Cyprus'], ['CZ', 'Czechia'], ['DE', 'Germany'], ['DK', 'Denmark'],
  ['EE', 'Estonia'], ['ES', 'Spain'], ['FI', 'Finland'], ['FR', 'France'],
  ['GB', 'United Kingdom'], ['GR', 'Greece'], ['HK', 'Hong Kong'], ['HR', 'Croatia'],
  ['HU', 'Hungary'], ['IE', 'Ireland'], ['IL', 'Israel'], ['IN', 'India'],
  ['IS', 'Iceland'], ['IT', 'Italy'], ['JP', 'Japan'], ['KR', 'South Korea'],
  ['LT', 'Lithuania'], ['LU', 'Luxembourg'], ['LV', 'Latvia'], ['MD', 'Moldova'],
  ['MX', 'Mexico'], ['MY', 'Malaysia'], ['NL', 'Netherlands'], ['NO', 'Norway'],
  ['NZ', 'New Zealand'], ['PH', 'Philippines'], ['PL', 'Poland'], ['PT', 'Portugal'],
  ['RO', 'Romania'], ['RS', 'Serbia'], ['SE', 'Sweden'], ['SG', 'Singapore'],
  ['SK', 'Slovakia'], ['TH', 'Thailand'], ['TR', 'Turkey'], ['TW', 'Taiwan'],
  ['UA', 'Ukraine'], ['US', 'United States'], ['VN', 'Vietnam'], ['ZA', 'South Africa'],
]

const PROTOCOLS = [
  ['SMART', 'Smart'],
  ['MASQUE', 'MASQUE'],
  ['WIREGUARD', 'WireGuard'],
  ['GOOL', 'WARP×2'],
  ['MIM', 'MASQUE×2'],
]
const SCAN_MODES = [
  ['TURBO', 'Turbo'],
  ['BALANCED', 'Balanced'],
  ['THOROUGH', 'Thorough'],
  ['STEALTH', 'Stealth'],
  ['IRONCLAD', 'Ironclad'],
]
const IP_VERSIONS = [['V4', 'IPv4'], ['V6', 'IPv6'], ['BOTH', 'Both']]
const NOIZE = [
  ['OFF', 'Off'], ['LIGHT', 'Light'], ['FIREWALL', 'Firewall'],
  ['BALANCED', 'Balanced'], ['GFW', 'GFW'], ['AGGRESSIVE', 'Aggressive'],
]
const ENDPOINT_MODES = [
  ['AUTO', 'Automatic'],
  ['MANUAL_PEER', 'Manual peer'],
  ['MANUAL_RANGE', 'Manual range'],
]
const SPLIT_MODES = [['OFF', 'Off'], ['INCLUDE', 'Only these apps'], ['EXCLUDE', 'All except these']]
const MTU_PRESETS = [1280, 1380, 1420, 1500]
const KEEPALIVE_PRESETS = [0, 10, 25, 45]
const RECONNECT_ATTEMPTS = Array.from({ length: 18 }, (_, i) => i + 3)

// v10 — هستهٔ 1.5.0: روش‌های ورود Zero Trust (همان گزینه‌های موبایل/هسته).
const ACCESS_MODES = [
  ['OFF', 'Off'],
  ['EMAIL', 'Email code'],
  ['SERVICE_TOKEN', 'Service token'],
  ['TOKEN', 'Access token'],
]

// v11 — آینهٔ دقیق parse_upstream در profile.rs (و upstream.rs هسته).
// فقط برای بازخورد زنده به کاربر است؛ تصمیم نهایی همیشه سمت Rust گرفته می‌شود.
export function parseUpstream(raw) {
  const value = (raw || '').trim()
  if (!value) return null
  const at = value.indexOf('://')
  const scheme = at === -1 ? 'socks5' : value.slice(0, at).toLowerCase()
  const rest = at === -1 ? value : value.slice(at + 3)
  let kind
  if (['socks5', 'socks5h', 'socks'].includes(scheme)) kind = 'socks5'
  else if (['http', 'https'].includes(scheme)) kind = 'http'
  else return null

  const cut = rest.lastIndexOf('@')
  let endpoint = cut === -1 ? rest : rest.slice(cut + 1)
  endpoint = endpoint.replace(/\/+$/, '')

  let host
  let port
  if (endpoint.startsWith('[')) {
    const end = endpoint.indexOf(']')
    if (end === -1 || endpoint[end + 1] !== ':') return null
    host = endpoint.slice(1, end)
    port = endpoint.slice(end + 2)
  } else {
    const colon = endpoint.lastIndexOf(':')
    if (colon === -1) return null
    host = endpoint.slice(0, colon)
    port = endpoint.slice(colon + 1)
  }
  if (!host || !/^[0-9]{1,5}$/.test(port)) return null
  const number = Number(port)
  if (number < 1 || number > 65535) return null
  return { kind, host, port: number }
}

function segmented(label, key, options, current) {
  return `
    <section class="field">
      <span class="field__label">${label}</span>
      <div class="seg" role="radiogroup" data-key="${key}">
        ${options.map(([v, tx]) => `
          <button type="button" role="radio" class="seg__item ${current === v ? 'is-active' : ''}"
                  data-value="${v}" aria-checked="${current === v}">${t(tx)}</button>`).join('')}
      </div>
    </section>`
}

function dropdown(label, key, options, current) {
  return `
    <section class="field field--row">
      <span class="field__label">${label}</span>
      <select class="select" data-key="${key}">
        ${options.map(([v, tx]) => `<option value="${v}" ${current === v ? 'selected' : ''}>${t(tx)}</option>`).join('')}
      </select>
    </section>`
}

// v1.2.3 — انتخابگر کشور خروج با پرچم.
//
// ریشهٔ مشکل: این فیلد یک `<select>` بومی بود و `<option>` بومی هیچ‌وقت
// نمی‌تواند SVG (یا هر المان دیگری) داخلش داشته باشد، پس فهرست کشورها فقط
// اسم بود — درست همان چیزی که کاربر دید — در حالی که نسخهٔ موبایل کنار هر
// کشور پرچمش را دارد. اموجی پرچم هم راه‌حل نیست: ویندوز فونت
// regional-indicator ندارد و «DE» را دو حرف خام رندر می‌کند (همان چیزی که
// `flags.js` برای نشان IP حلش کرده بود).
//
// پس یک listbox واقعی جای `<select>` را می‌گیرد: هر ردیف = پرچم SVG درون‌خطی
// + نام کشور، ردیف «Automatic» یک کرهٔ زمین می‌گیرد تا تنها ردیف بی‌نشان
// نباشد (عیناً قاعدهٔ ExitRegions.kt). ناوبری کیبورد کامل است، وگرنه یک
// select بومی را با یک div بی‌دسترسی عوض کرده بودیم.
function flagRow(cc, label) {
  return `<span class="fdrop__flag">${flagHtml(cc)}</span><span class="fdrop__name">${label}</span>`
}

const CARET =
  '<svg class="fdrop__caret" viewBox="0 0 24 24" aria-hidden="true"><path d="M7 10l5 5 5-5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>'

function flagDropdown(label, key, options, current) {
  const index = Math.max(0, options.findIndex(([v]) => v === current))
  const [value] = options[index]
  return `
    <section class="field field--row">
      <span class="field__label">${label}</span>
      <div class="fdrop" data-key="${key}" data-value="${value}">
        <button type="button" class="fdrop__btn" aria-haspopup="listbox" aria-expanded="false"
                aria-label="${label}">
          ${flagRow(value, t(options[index][1]))}${CARET}
        </button>
        <ul class="fdrop__menu" role="listbox" tabindex="-1" aria-label="${label}" hidden>
          ${options.map(([v, tx]) => `
            <li class="fdrop__item ${v === value ? 'is-selected' : ''}" role="option"
                data-value="${v}" aria-selected="${v === value}">${flagRow(v, t(tx))}</li>`).join('')}
        </ul>
      </div>
    </section>`
}

// سیم‌کشی انتخابگر: باز/بسته، کیبورد، تایپ‌اِهد، و کلیک بیرون.
// شنوندهٔ سطح-سند فقط تا وقتی منو باز است زنده می‌ماند، پس بازرندرهای پیاپی
// این نما هیچ شنوندهٔ سرگردانی جا نمی‌گذارند.
function wireFlagDropdowns(root, onPick) {
  root.querySelectorAll('.fdrop').forEach((drop) => {
    const btn = drop.querySelector('.fdrop__btn')
    const menu = drop.querySelector('.fdrop__menu')
    const items = Array.from(menu.querySelectorAll('.fdrop__item'))
    let typed = ''
    let typedAt = 0

    const activeIndex = () => {
      const at = items.findIndex((i) => i.classList.contains('is-active'))
      return at === -1 ? items.findIndex((i) => i.classList.contains('is-selected')) : at
    }
    const setActive = (at) => {
      const next = Math.max(0, Math.min(items.length - 1, at))
      items.forEach((i, n) => i.classList.toggle('is-active', n === next))
      items[next].scrollIntoView({ block: 'nearest' })
    }
    const onOutside = (e) => {
      if (!drop.contains(e.target)) close()
    }
    const open = () => {
      if (!menu.hidden) return
      menu.hidden = false
      drop.classList.add('is-open')
      btn.setAttribute('aria-expanded', 'true')
      // اگر پایین جا نیست، منو بالای دکمه باز می‌شود: در انتهای صفحهٔ
      // «پیشرفته» فهرست ۵۶ ردیفی وگرنه از پایینِ ناحیهٔ اسکرول می‌زد بیرون.
      const box = drop.getBoundingClientRect()
      const room = window.innerHeight - box.bottom
      menu.classList.toggle('is-above', room < Math.min(264, menu.scrollHeight + 12) && box.top > room)
      setActive(activeIndex() === -1 ? 0 : activeIndex())
      menu.focus()
      document.addEventListener('pointerdown', onOutside, true)
    }
    function close() {
      if (menu.hidden) return
      menu.hidden = true
      drop.classList.remove('is-open')
      btn.setAttribute('aria-expanded', 'false')
      document.removeEventListener('pointerdown', onOutside, true)
    }
    const pick = async (item) => {
      const value = item.dataset.value
      items.forEach((i) => {
        const on = i === item
        i.classList.toggle('is-selected', on)
        i.setAttribute('aria-selected', String(on))
      })
      drop.dataset.value = value
      btn.innerHTML = `${flagRow(value, item.querySelector('.fdrop__name').textContent)}${CARET}`
      close()
      btn.focus()
      await onPick(drop.dataset.key, value)
    }

    btn.addEventListener('click', () => (menu.hidden ? open() : close()))
    btn.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp' || e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        open()
      }
    })
    items.forEach((item) => {
      item.addEventListener('click', () => pick(item))
      item.addEventListener('mousemove', () => setActive(items.indexOf(item)))
    })
    menu.addEventListener('keydown', (e) => {
      switch (e.key) {
        case 'ArrowDown': e.preventDefault(); setActive(activeIndex() + 1); break
        case 'ArrowUp': e.preventDefault(); setActive(activeIndex() - 1); break
        case 'Home': e.preventDefault(); setActive(0); break
        case 'End': e.preventDefault(); setActive(items.length - 1); break
        case 'PageDown': e.preventDefault(); setActive(activeIndex() + 8); break
        case 'PageUp': e.preventDefault(); setActive(activeIndex() - 8); break
        case 'Enter':
        case ' ': {
          e.preventDefault()
          const at = activeIndex()
          if (at >= 0) pick(items[at])
          break
        }
        case 'Escape': e.preventDefault(); close(); btn.focus(); break
        case 'Tab': close(); break
        default:
          // تایپ‌اِهد: با ۵۶ کشور، پیمایش با فلش تنها آزاردهنده است.
          if (e.key.length === 1 && /\S/.test(e.key)) {
            const now = Date.now()
            typed = now - typedAt > 900 ? e.key : typed + e.key
            typedAt = now
            const needle = typed.toLowerCase()
            const hit = items.findIndex((i) =>
              i.querySelector('.fdrop__name').textContent.toLowerCase().startsWith(needle))
            if (hit !== -1) setActive(hit)
          }
      }
    })
  })
}

function toggle(label, key, hint, on) {
  return `
    <section class="field field--row">
      <div>
        <span class="field__label">${label}</span>
        ${hint ? `<span class="field__hint">${hint}</span>` : ''}
      </div>
      <button type="button" class="switch ${on ? 'is-on' : ''}" data-key="${key}" role="switch" aria-checked="${on}">
        <span class="switch__knob"></span>
      </button>
    </section>`
}

function textField(label, key, value, placeholder, opts = {}) {
  const type = opts.secret ? 'password' : 'text'
  const hint = opts.hint ? `<span class=\"field__hint\">${opts.hint}</span>` : ''
  return `
    <section class="field">
      <span class="field__label">${label}</span>
      <input class="input ltr" dir="ltr" type="${type}" data-key="${key}" value="${value ?? ''}" placeholder="${placeholder}" ${opts.secret ? 'autocomplete="off"' : ''}>
      ${hint}
    </section>`
}

// v10: تری‌ایریای چندخطی برای فهرست‌ها (routing/dns) — هر خط یک قاعده.
function listArea(label, key, values, placeholder, hint) {
  return `
    <section class="field">
      <span class="field__label">${label}</span>
      <textarea class="input input--area ltr" dir="ltr" data-key="${key}"
        placeholder="${placeholder}">${(values || []).join('\n')}</textarea>
      ${hint ? `<span class=\"field__hint\">${hint}</span>` : ''}
    </section>`
}

// Cached promise for `core_caps` — see the call site at the bottom of this file.
let CAPS_ONCE = null

// =============================================================================
//  بخش‌های تنظیمات
// =============================================================================
//
//  چرا این پنل به قطعه‌های نام‌دار شکسته شد: منوی تنظیماتِ موبایل (a2) هر گروه
//  را در صفحهٔ خودش نشان می‌دهد، و راه ساده‌اش این بود که آن صفحه‌ها کنترل‌های
//  خودشان را از نو بسازند. آن راه یعنی دو نسخه از هر کنترل و دو سیم‌کشیِ ذخیره،
//  و روزی که یکی از دو نسخه ثابت شود و دیگری نه. پس همان یک قالب و همان یک
//  سیم‌کشی می‌ماند و `renderAdvanced` می‌تواند زیرمجموعه‌ای از آن را بدهد.
const SECTIONS = {
  language: (p) => segmented(t('Language'), '__lang', LANGS, getLang()),

  connection: (p) => `
    <section class="field" id="tor-caps-note" hidden>
      <span class="field__hint" id="tor-caps-note-text"></span>
    </section>
    ${segmented(t('Backend'), 'backend', BACKENDS, p.backend || 'AETHER')}
    <section class="field">
      <span class="field__hint">${t(BACKEND_HELP[p.backend || 'AETHER'] ?? BACKEND_HELP.AETHER)}</span>
    </section>
    ${flagDropdown(t('Exit country'), 'exitRegion', EXIT_REGIONS, p.exitRegion || '')}
    <section class="field">
      <span class="field__hint">${usesTor(p.backend) && !torReverse(p.backend)
        ? t('Tor chooses its own exit node, and a new one per circuit. No setting can pin it to a country.')
        : t('Only applies to the chained backend. If no server is reachable in that country, Aether falls back to an automatic exit instead of hanging.')}</span>
    </section>
    ${usesTor(p.backend) ? SECTIONS.tor(p) : ''}
    ${segmented(t('Protocol'), 'protocol', PROTOCOLS, p.protocol)}
    ${torReverse(p.backend) ? `
    <section class="field">
      <span class="field__hint">${t('Fixed to MASQUE over HTTP/2 in this mode. Tor carries TCP only and WARP\u2019s WireGuard endpoints answer on UDP alone, so the engine refuses WireGuard and WARP\u00d72 here.')}</span>
    </section>` : ''}
    ${segmented(t('Scan mode'), 'scanMode', SCAN_MODES, p.scanMode)}
    ${segmented(t('IP version'), 'ipVersion', IP_VERSIONS, p.ipVersion)}`,

  // v13 — گروه تور، پورت از بخش Tor در SettingsScreen.kt. فقط وقتی رندر
  // می‌شود که حالتِ انتخابی واقعاً تور داشته باشد: گروهی که همیشه آنجاست و
  // همیشه غیرفعال، تنها پنل را شلوغ می‌کند.
  tor: (p) => `
    <div id="v20-tor">
    <h3 class="view__subtitle">${t('Tor')}</h3>
    ${dropdown(t('Bridges'), 'torBridges', TOR_BRIDGES, p.torBridges || 'AUTO')}
    <section class="field">
      <span class="field__hint">${torChained(p.backend)
        ? t('Not needed in this mode: Tor is dialled through the Aether tunnel, so the network you are on never sees it.')
        : t('How Tor reaches the network when it is blocked.')}</span>
    </section>
    ${torChained(p.backend) ? '' : `
    ${dropdown(t('Bridge country'), 'torCountry', TOR_COUNTRIES, (p.torCountry || '').trim().toLowerCase())}
    <section class="field">
      <span class="field__hint">${t('Which country bridgedb hands out bridges for. Detection asks the network where you are, which is the request most likely to fail here.')}</span>
    </section>
    ${dropdown(t('Bootstrap patience'), 'torDirectSecs',
      TOR_DIRECT_PRESETS.map((v) => [String(v), v === 0 ? t('Automatic (75 s)') : t('{0} seconds').replace('{0}', String(v))]),
      String(p.torDirectSecs ?? 0))}
    <section class="field">
      <span class="field__hint">${t('How long Tor tries the direct path before falling back to bridges. Shorten it where Tor is definitely blocked.')}</span>
    </section>
    ${listArea(t('Own bridge lines'), 'torBridgeLines', (p.torBridgeLines || '').split('\n').filter(Boolean),
      'obfs4 192.0.2.55:38114 &lt;FINGERPRINT&gt; cert=… iat-mode=0',
      t('One per line, in the format bridges.torproject.org hands out. Leave empty to use the bridges the app fetches for your country. A line naming a transport the app does not ship is ignored.'))}`}
    ${textField(t('Reachability check'), 'torCheck', p.torCheck, 'check.torproject.org:443', {
      hint: t('The address Tor must reach before the bootstrap counts as working. Change it only if bootstrap keeps failing on a Tor that seems fine \u2014 the default target is itself blocked on some networks.'),
    })}
    <section class="field">
      <span class="field__hint">${t('Tor carries TCP only \u2014 in every app, on every platform. Aether answers DNS over TCP inside Tor and drops other UDP, so QUIC-capable apps fall back to TCP. That is normal and nothing is leaking: dropped UDP goes nowhere, least of all around Tor. Expect noticeably higher latency, and expect the first connect to take a while \u2014 Tor downloads its directory before it can build a circuit.')}</span>
    </section>
    </div>`,

  transport: (p) => `
    ${toggle(t('TUN mode (virtual adapter)'), 'tun', t('Route all traffic through the Aether adapter instead of the system proxy'), p.tun)}
    ${dropdown(t('Noize'), 'noize', NOIZE, p.noize)}
    ${dropdown(t('Endpoint'), 'endpointMode', ENDPOINT_MODES, p.endpointMode)}
    <div id="endpoint-extra">
      ${p.endpointMode === 'MANUAL_PEER' ? textField(t('Peer address'), 'manualPeer', p.manualPeer, '1.2.3.4:443') : ''}
      ${p.endpointMode === 'MANUAL_RANGE' ? textField(t('Address range'), 'manualRange', p.manualRange, '162.159.192.0/24') : ''}
    </div>
    ${dropdown('MTU', 'mtu', MTU_PRESETS.map((v) => [String(v), String(v)]), String(p.mtu))}
    ${dropdown('Keepalive', 'keepalive', KEEPALIVE_PRESETS.map((v) => [String(v), v === 0 ? t('Off') : `${v}s`]), String(p.keepalive))}
    ${toggle(t('Quick reconnect'), 'quickReconnect', t('Reconnect instantly after a drop'), p.quickReconnect)}
    ${toggle(t('MASQUE over HTTP/2'), 'masqueHttp2', t('Helps on networks that block HTTP/3'), p.masqueHttp2)}
    ${toggle(t('Packet fragmentation'), 'fragment', t('Splits the handshake to evade filtering'), p.fragment)}
    ${toggle('ECH', 'ech', t('Encrypted Client Hello (auto)'), p.ech)}`,

  safety: (p) => `
    ${toggle(t('Kill switch'), 'killSwitch', t('Block browser traffic if the tunnel drops'), p.killSwitch)}
    ${toggle(t('IPv6 leak protection'), 'ipv6Protection', t('Keep the IPv6 default route protected or block it safely'), p.ipv6Protection)}
    ${dropdown(t('Automatic reconnect attempts'), 'reconnectAttempts', RECONNECT_ATTEMPTS.map((v) => [String(v), `${v}`]), String(p.reconnectAttempts ?? 3))}`,

  apps: (p) => `
    ${toggle(t('Share over LAN'), 'lanShare', t('Let other devices on your network use this tunnel'), p.lanShare)}
    ${dropdown(t('Split tunneling'), 'splitMode', SPLIT_MODES, p.splitMode)}
    <section class="field" id="split-apps" ${p.splitMode === 'OFF' ? 'hidden' : ''}>
      <span class="field__label">${t('Applications')}</span>
      <textarea class="input input--area ltr" dir="ltr" data-key="splitApps"
        placeholder="chrome.exe&#10;telegram.exe">${(p.splitApps || []).join('\n')}</textarea>
      <span class="field__hint">${t('One executable name per line.')}</span>
    </section>`,

  zerotrust: (p) => `
    <section class="field" id="caps-note" hidden>
      <span class="field__hint" id="caps-note-text"></span>
    </section>
    <div id="v15-zt">
    ${textField(t('Team name'), 'team', p.team, 'your-team', { hint: t('Connect as a managed device of a Cloudflare Zero Trust organization. Leave empty for normal WARP.') })}
    <div id="zt-extra" ${(p.team || '').trim() ? '' : 'hidden'}>
      ${segmented(t('Sign-in method'), 'accessMode', ACCESS_MODES, p.accessMode)}
      <div id="zt-fields">
        ${p.accessMode === 'EMAIL' ? textField(t('Access email'), 'accessEmail', p.accessEmail, 'user@example.com', { hint: t('A one-time code is sent to this mailbox on connect.') }) : ''}
        ${p.accessMode === 'SERVICE_TOKEN' ? textField('Access ID', 'accessId', p.accessId, 'xxxxxxxx.access', {}) : ''}
        ${p.accessMode === 'SERVICE_TOKEN' ? textField('Access Secret', 'accessSecret', '', '••••••', { secret: true, hint: t('Stored in memory only — never written to disk.') }) : ''}
        ${p.accessMode === 'TOKEN' ? textField('Access Token (JWT)', 'accessToken', '', '••••••', { secret: true, hint: t('Stored in memory only — never written to disk.') }) : ''}
      </div>
      ${toggle(t('Gateway proxy'), 'gateway', t('Route HTTP/HTTPS through your organization\'s Gateway (adds a hop and logs browsing)'), p.gateway)}
    </div>
    </div>
    <div id="v17-identity">
    <h3 class="view__subtitle">${t('Account identity')}</h3>
    ${toggle(t('Replace a refused identity'), 'reprovision', t('If Cloudflare stops accepting the saved device, register a fresh one instead of handshaking a tunnel that carries no traffic'), p.reprovision !== false)}
    </div>`,

  dns: (p) => `
    <div id="v15-dns">
    <h3 class="view__subtitle">DNS</h3>
    ${listArea(t('In-tunnel DNS servers'), 'dns', p.dns, '1.1.1.1&#10;9.9.9.9', t('Resolvers used inside the tunnel. Empty = engine defaults.'))}
    </div>
    <div id="v15-routing">
    <h3 class="view__subtitle">${t('Routing rules')}</h3>
    ${listArea(t('Blocked destinations'), 'routeBlock', p.routeBlock, 'ads.example.com&#10;203.0.113.0/24', t('One rule per line — domain, IP or CIDR. These connections are refused.'))}
    ${listArea(t('Direct destinations'), 'routeDirect', p.routeDirect, 'bank-domain.ir&#10;192.168.0.0/16', t('One rule per line. These bypass the tunnel — for banking apps, LAN services and domestic sites.'))}
    <div id="v17-sniff">
    ${toggle(t('Match domain rules by real host name'), 'routeSniff', t('Reads the name from the first bytes (TLS SNI or HTTP Host), so domain rules keep working even though Windows hands the tunnel an IP address'), p.routeSniff !== false)}
    </div>
    </div>`,

  upstream: (p) => `
    <div id="v17-upstream">
    ${textField(t('Proxy address'), 'upstream', p.upstream, 'socks5://127.0.0.1:1080', { hint: t('Aether dials out through this proxy — use it to chain behind another VPN or proxy already running on this PC. Empty = direct.') })}
    <section class="field">
      <span class="field__hint" id="upstream-note"></span>
    </section>
    </div>`,

}

/**
 * کنترل‌های بخش‌های نام‌بُرده را می‌سازد و سیم‌کشی می‌کند.
 *
 * @param {string[]} sections کلیدهایی از `SECTIONS`.
 *
 * نمای یک‌تکهٔ قدیمی حذف شد و این تابع فقط زیرمجموعه می‌دهد: منوی a2 تنها
 * مصرف‌کننده است و نگه‌داشتن یک صفحهٔ تختِ موازی یعنی دو مسیر به یک گزینه —
 * دو جایی که کاربر باید بگردد و دو چیدمانی که باید هم‌گام بمانند.
 */
export function renderAdvanced(sections) {
  const p = app.profile
  const root = document.createElement('div')
  root.className = 'view view--advanced'
  root.innerHTML = sections.map((key) => SECTIONS[key](p)).join('\n')

  // --- سیم‌کشی — هر تغییر فوراً ذخیره می‌شود (مثل DataStore در اندروید)
  root.querySelectorAll('.seg__item').forEach((b) => {
    b.addEventListener('click', async () => {
      const key = b.closest('.seg').dataset.key
      // زبان برنامه عضو profile نیست؛ جدا ذخیره و کل پوسته دوباره رندر می‌شود.
      if (key === '__lang') {
        setLang(b.dataset.value)
        rerender()
        return
      }
      await saveProfile({ [key]: b.dataset.value })
      b.closest('.seg').querySelectorAll('.seg__item').forEach((x) => {
        x.classList.toggle('is-active', x === b)
        x.setAttribute('aria-checked', String(x === b))
      })
      // v10: تغییر روش ورود Zero Trust فیلدهای متفاوتی می‌خواهد — بازرندر.
      // v13: عوض شدن بک‌اند هم — گروه تور می‌آید/می‌رود، توضیحِ بک‌اند و
      // متنِ کشورِ خروجی عوض می‌شود، و در زنجیرهٔ برعکس انتخابگر پروتکل
      // دلیلِ قفل‌بودنش را می‌نویسد. بدون بازرندر، پنل حرفِ حالتِ قبلی را می‌زد.
      if (key === 'accessMode' || key === 'backend') {
        refreshTab('advanced')
      }
    })
  })

  root.querySelectorAll('.select').forEach((s) => {
    s.addEventListener('change', async () => {
      const key = s.dataset.key
      const raw = s.value
      const value = ['mtu', 'keepalive', 'reconnectAttempts', 'torDirectSecs'].includes(key)
        ? Number(raw)
        : raw
      await saveProfile({ [key]: value })
      if (key === 'endpointMode' || key === 'splitMode') {
        refreshTab('advanced')
      }
    })
  })

  wireFlagDropdowns(root, async (key, value) => {
    await saveProfile({ [key]: value })
  })

  root.querySelectorAll('.switch').forEach((tg) => {
    tg.addEventListener('click', async () => {
      const on = !tg.classList.contains('is-on')
      tg.classList.toggle('is-on', on)
      tg.setAttribute('aria-checked', String(on))
      await saveProfile({ [tg.dataset.key]: on })
    })
  })

  // v11 — پیام زندهٔ پروکسی بالادست: مقدار نامعتبر را هسته بی‌صدا دور
  // می‌ریزد، پس همین‌جا به کاربر گفته می‌شود. پروکسی HTTP هم UDP حمل
  // نمی‌کند، پس تنها MASQUE روی HTTP/2 از آن رد می‌شود.
  const upstreamNote = () => {
    const el = root.querySelector('#upstream-note')
    const input = root.querySelector('[data-key="upstream"]')
    if (!el || !input) return
    const raw = input.value.trim()
    if (!raw) {
      el.textContent = ''
      return
    }
    const parsed = parseUpstream(raw)
    if (!parsed) {
      el.textContent = t('That is not a proxy address Aether can use. Expected socks5://host:port or http://host:port — the port is required.')
      return
    }
    el.textContent =
      parsed.kind === 'http'
        ? t('An HTTP proxy cannot carry UDP, so MASQUE is switched to HTTP/2 automatically and WireGuard / WARP×2 will not pass through it. Use a SOCKS5 proxy for those.')
        : t('SOCKS5 with UDP support carries every protocol: MASQUE, WireGuard and WARP×2.')
  }
  upstreamNote()

  root.querySelectorAll('.input').forEach((i) => {
    i.addEventListener('input', () => {
      if (i.dataset.key === 'upstream') upstreamNote()
    })
    i.addEventListener('change', async () => {
      const key = i.dataset.key
      // v10: فیلدهای فهرستی — هر خط یک مقدار (مثل splitApps).
      const LIST_KEYS = ['splitApps', 'routeBlock', 'routeDirect', 'dns']
      // `torBridgeLines` هم چندخطی است ولی در پروفایل یک رشتهٔ واحد می‌ماند —
      // همان‌طور که در موبایل هست، چون سَنیتایزرِ سمت Rust خط‌به‌خط پارس و
      // اعتبارسنجی می‌کند و شکستنِ آن به آرایه، آن اعتبارسنجی را دور می‌زد.
      const value = LIST_KEYS.includes(key)
        ? i.value.split('\n').map((x) => x.trim()).filter(Boolean)
        : key === 'torBridgeLines'
          ? i.value.split('\n').map((x) => x.trim()).filter(Boolean).join('\n')
          : i.value.trim()
      await saveProfile({ [key]: value })
      // v10: پاک/پر شدن نام تیم، بخش Zero Trust را نشان/پنهان می‌کند.
      if (key === 'team') {
        refreshTab('advanced')
      }
      // سخت‌سازی امنیتی: مقدار محرمانه بعد از ذخیره از DOM پاک می‌شود تا
      // در اسکرین‌شات/بازرسی DOM نماند (ذخیره فقط در حافظهٔ بک‌اند است).
      if (key === 'accessSecret' || key === 'accessToken') {
        i.value = ''
        i.placeholder = '•••••• (saved)'
      }
    })
  })

  // v10: قابلیت‌سنجی هسته — اگر هستهٔ همراه قدیمی‌تر از 1.5.0 باشد (مثلاً
  // وقتی کاربر نسخهٔ هسته را در پایپ‌لاین پین کرده)، این بخش‌ها غیرفعال و
  // با توضیح نشان داده می‌شوند تا کاربر تنظیمی را پر نکند که بی‌اثر است.
  // خطای این فراخوانی هرگز صفحه را نمی‌شکند.
  // The bundled core cannot change while the app is running, so this is asked
  // for once per launch. It used to be an IPC round trip plus a disk read on
  // every single render of this panel.
  CAPS_ONCE ??= invoke('core_caps')
  CAPS_ONCE
    .then((caps) => {
      const gate = (id, enabled) => {
        const el = root.querySelector(id)
        if (!el || enabled) return
        el.querySelectorAll('input, textarea, button, select').forEach((c) => {
          c.disabled = true
        })
        el.style.opacity = '0.45'
      }
      gate('#v15-zt', caps.zeroTrust)
      gate('#v15-routing', caps.routing)
      gate('#v15-dns', caps.customDns)
      // v11: قابلیت‌های هستهٔ 1.7.0 جداگانه گیت می‌شوند.
      gate('#v17-upstream', caps.upstream)
      gate('#v17-sniff', caps.routeSniff)
      gate('#v17-identity', caps.routeSniff)
      // v13 — تور از هستهٔ 2.0.0. اگر هستهٔ همراه قدیمی‌تر باشد، بک‌اندهای تور
      // انتخاب‌شدنی‌اند ولی بی‌اثر: profile.rs فلگ‌هایشان را نمی‌فرستد. پس
      // همان‌جا گفته می‌شود، نه بعد از یک اتصالِ ساکتاً معمولی.
      if (!caps.tor) {
        root.querySelectorAll('.seg[data-key="backend"] .seg__item').forEach((b) => {
          if (usesTor(b.dataset.value)) {
            b.disabled = true
            b.style.opacity = '0.45'
          }
        })
        gate('#v20-tor', false)
        const note = root.querySelector('#tor-caps-note')
        const text = root.querySelector('#tor-caps-note-text')
        if (note && text) {
          text.textContent = t('The Tor modes need engine core 2.0.0 or newer. The bundled core is older, so they are disabled.')
          note.hidden = false
        }
      }
      const missing15 = !caps.zeroTrust || !caps.routing || !caps.customDns
      const missing17 = !caps.upstream || !caps.routeSniff
      if (missing15 || missing17) {
        const note = root.querySelector('#caps-note')
        const text = root.querySelector('#caps-note-text')
        if (note && text) {
          text.textContent = missing15
            ? t('These features need engine core 1.5.0 or newer. The bundled core is older, so they are disabled.')
            : t('The upstream proxy, host-name routing and identity replacement need engine core 1.7.0 or newer. The bundled core is older, so they are disabled.')
          note.hidden = false
        }
      }
    })
    .catch(() => {})

  return root
}
