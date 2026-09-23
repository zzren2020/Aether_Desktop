// =============================================================================
//  i18n — دوزبانه: English + فارسی
//  انتخاب کاربر در localStorage می‌ماند و عمداً جدا از profile است تا با
//  «بازنشانی به تنظیمات پیش‌فرض» زبان کاربر عوض نشود.
//
//  قاعده: کلیدها همان جمله‌های انگلیسی رابط هستند؛ اگر ترجمه‌ای نبود
//  همان انگلیسی نمایش داده می‌شود. واژه‌های لاتین داخل جمله‌های فارسی در
//  <bdi> می‌نشینند تا چپ‌به‌راست رندر شوند و متن راست‌به‌چپ بهم نریزد
//  (فقط در رشته‌هایی که با innerHTML رندر می‌شوند).
// =============================================================================

const STORAGE_KEY = 'aether.lang'

export const LANGS = [
  ['en', 'English'],
  ['zh', '中文'],
  ['fa', 'فارسی'],
]

const FA = {

  // --- ۱.۲.۵: پیام‌های شکستِ تور (از diagnostics.rs، از راهِ snapshot.detail)
  'The tunnel started but the self-test failed.':
    'تونل بالا آمد ولی خودآزما شکست خورد.',
  'The tunnel is up, but Tor never reported any progress from inside it. Try Tor on its own, which lets Tor pick its own way to the network.':
    'تونل بالاست، ولی تور از داخلش هیچ پیشرفتی گزارش نکرد. «تنها تور» را امتحان کنید تا تور خودش راهش به شبکه را انتخاب کند.',
  'The tunnel is up, but Tor stopped at {0}% inside it and did not reach the Tor network. Try another protocol for the tunnel, or Tor on its own with bridges.':
    'تونل بالاست، ولی تور داخلش روی {0}٪ ایستاد و به شبکهٔ تور نرسید. پروتکل دیگری برای تونل امتحان کنید، یا «تنها تور» با پل.',
  'Tor stopped at {0}% and could not reach the Tor network. No pluggable transport is installed, so only plain bridges can be tried — and a network that filters Tor usually blocks those too. Use the Aether → Tor mode: Tor is then dialled through the tunnel, where the operator cannot see or block it.':
    'تور روی {0}٪ ایستاد و به شبکهٔ تور نرسید. هیچ ترابرِ افزودنی نصب نیست، پس فقط پلِ ساده ممکن است — و شبکه‌ای که تور را فیلتر می‌کند معمولاً آن را هم می‌بندد. از حالتِ <bdi>Aether → Tor</bdi> استفاده کنید: آن‌وقت تور از داخلِ تونل شماره‌گیری می‌شود، جایی که اپراتور نه می‌بیندش نه می‌تواند ببندد.',
  'The engine started but Tor never reported any progress towards the Tor network, and no pluggable transport is installed. Use the Aether → Tor mode, which builds Tor inside the tunnel.':
    'موتور اجرا شد ولی تور هیچ پیشرفتی به سمتِ شبکهٔ تور گزارش نکرد، و هیچ ترابرِ افزودنی نصب نیست. از حالتِ <bdi>Aether → Tor</bdi> استفاده کنید که تور را داخلِ تونل می‌سازد.',
  // --- v12 (۱.۲.۴-p4): صفحهٔ گفت‌وگو، پورت از AiChatScreen.kt ---
  // ترجمه‌ها همان `ai_chat_*` در values-fa/strings.xml هستند؛ جملهٔ تازه‌ای
  // ساخته نشده تا کاربری که موبایل را می‌شناسد همان کلمات را ببیند.
  'Chat': 'گفت‌وگو',
  'Chat with Gemini': 'گفت‌وگو با جمینای',
  'Open the chat': 'باز کردن گفت‌وگو',
  'Ask anything, or say what you want changed': 'هر چیزی بپرسید، یا بگویید چه چیزی عوض شود',
  'Model: {0}': 'مدل: {0}',
  '{0} message(s) in the conversation': '{0} پیام در گفت‌وگو',
  'Hi, I am Aether AI': 'سلام، من هوش مصنوعی اتر هستم',
  'I can explain any setting in this app, read this session’s log and propose tuning, or just answer a question.':
    'می‌توانم هر تنظیمی در این برنامه را توضیح بدهم، لاگ همین نشست را بخوانم و تنظیمات پیشنهاد کنم، یا فقط به سؤالتان جواب بدهم.',
  'Why is my connection slow right now?': 'چرا اتصالم الان کند است؟',
  'Which protocol should I use on mobile data?': 'روی دیتای همراه چه پروتکلی بهتر است؟',
  'Explain MTU and pick the best one for me': 'MTU را توضیح بده و بهترینش را انتخاب کن',
  'Make the tunnel harder to detect': 'تونل را سخت‌تر قابل تشخیص کن',
  'Ask Aether AI…': 'از هوش مصنوعی اتر بپرسید…',
  'Stop': 'توقف',
  'Clear the conversation': 'پاک کردن گفت‌وگو',
  'Thinking…': 'در حال فکر کردن…',
  'Copy answer': 'کپی پاسخ',
  'Copied': 'کپی شد',
  'Could not copy — your system refused clipboard access.': 'کپی نشد — سیستم شما اجازهٔ دسترسی به کلیپ‌بورد را نداد.',
  'Try again': 'تلاش مجدد',
  'Edit': 'ویرایش',
  'Delete': 'حذف',
  'edited': 'ویرایش‌شده',
  'Cancel': 'انصراف',
  'Edit message': 'ویرایش پیام',
  'Send again': 'ارسال دوباره',
  'Everything after this message will be removed and the assistant will answer the edited question.':
    'هر چیزی پس از این پیام حذف می‌شود و دستیار به پرسش ویرایش‌شده پاسخ می‌دهد.',
  '{0} selected': '{0} مورد انتخاب شد',
  'Select all': 'انتخاب همه',
  'Cancel selection': 'لغو انتخاب',
  'Delete selected': 'حذف موارد انتخاب‌شده',
  // تأییدِ حذف — یک دیالوگ برای هر سه مسیر (سطلِ حباب، حذفِ گروهی، پاک‌کردنِ همه).
  // متن‌ها از `ai_chat_delete_*` در `values-fa/strings.xml` موبایل می‌آیند.
  'Delete {0} message(s)?': '{0} پیام حذف شود؟',
  'This cannot be undone. Deleted messages are no longer sent to the assistant as context.':
    'این کار قابل بازگشت نیست. پیام‌های حذف‌شده دیگر به‌عنوان زمینهٔ گفت‌وگو برای دستیار فرستاده نمی‌شوند.',
  'Clear the whole conversation?': 'کلِ گفت‌وگو پاک شود؟',
  Clear: 'پاک کردن',
  // کارتِ تنظیماتِ پیشنهادی و دیالوگِ پس از اعمال — از `ai_changes_title`،
  // `ai_apply`، `ai_applied`، `ai_apply_note` و `ai_applied_dialog_*` موبایل.
  'Proposed settings ({0})': 'تنظیمات پیشنهادی ({0})',
  Apply: 'اعمال',
  Applied: 'اعمال شد',
  'Tunnel settings are handed to the engine when it starts, so these take effect on your next connect.':
    'تنظیمات تونل هنگام راه‌اندازی به موتور داده می‌شوند، پس این تغییرها در اتصال بعدی اثر می‌گذارند.',
  'Saved for the next connection': 'برای اتصال بعدی ذخیره شد',
  'The new settings are stored, but the tunnel is already running with the old ones. Tunnel settings are handed to the engine when it starts, so disconnect and connect again for them to take effect.':
    'تنظیمات جدید ذخیره شد، اما تونل همچنان با تنظیمات قبلی در حال اجراست. تنظیمات تونل هنگام شروع به موتور داده می‌شود؛ پس یک‌بار قطع و دوباره وصل کنید تا اعمال شوند.',
  'Got it': 'متوجه شدم',
  // پایکِ حبابِ ✨ و پرسشی که به گفت‌وگو منتقل می‌کند.
  'Did not understand? Ask the assistant': 'متوجه نشدید؟ از دستیار بپرسید',
  'Explain this more simply: “{0}”. This is what the app told me: {1}':
    'این را ساده‌تر توضیح بده: «{0}». چیزی که برنامه به من گفت این بود: {1}',
  // جمله‌های شکست — از `errorKind` ساخته می‌شوند، نه از متنِ خامِ گوگل.
  'Google rejected this key. Check it in AI Studio, or paste it again.':
    'گوگل این کلید را رد کرد. آن را در <bdi>AI Studio</bdi> بررسی کنید یا دوباره بچسبانید.',
  'The free quota for this key is used up for now. Try again later.':
    'سهمیهٔ رایگان این کلید فعلاً تمام شده. بعداً دوباره تلاش کنید.',
  'This key cannot use the selected model. Discover the models again.':
    'این کلید نمی‌تواند از مدل انتخاب‌شده استفاده کند. مدل‌ها را دوباره کشف کنید.',
  'The request never reached Google. Check the tunnel and try again.':
    'درخواست هرگز به گوگل نرسید. تونل را بررسی کنید و دوباره تلاش کنید.',
  'Google failed on its own side. This is not your connection — try again.':
    'گوگل سمت خودش شکست خورد. مشکل از اتصال شما نیست — دوباره تلاش کنید.',
  'Google sent back something this app could not read.': 'گوگل چیزی برگرداند که این برنامه نتوانست بخواند.',
  'The answer was cut off before it finished.': 'پاسخ پیش از تمام‌شدن بریده شد.',
  'The model returned no answer.': 'مدل هیچ پاسخی برنگرداند.',
  'The request failed.': 'درخواست شکست خورد.',
  // --- v12 (۱.۲.۳): بک‌اند ترابرد زنجیره‌ای ---
  'Transport': 'ترابرد',
  'Backend': 'بک‌اند',
  'Exit country': 'کشور خروج',
  'Automatic': 'خودکار',
  'Aether alone exits through a Cloudflare WARP edge. Chaining Psiphon keeps Aether as the first hop and swaps the exit for an ordinary hosting IP, which is what opens sites that reject WARP ranges.':
    'اِتِر تنها از یک لبهٔ <bdi>Cloudflare WARP</bdi> بیرون می‌رود. زنجیره‌کردن <bdi>Psiphon</bdi> هاپ اول را همان اِتِر نگه می‌دارد و خروجی را با یک آی‌پی هاستینگ عادی عوض می‌کند؛ همین است که سایت‌هایی را باز می‌کند که رنج‌های <bdi>WARP</bdi> را رد می‌کنند.',
  'Only applies to the chained backend. If no server is reachable in that country, Aether falls back to an automatic exit instead of hanging.':
    'فقط برای بک‌اند زنجیره‌ای است. اگر در آن کشور هیچ سروری در دسترس نباشد، اِتِر به‌جای معلق‌ماندن به خروجی خودکار برمی‌گردد.',
  'Starting the Psiphon stage…': 'در حال راه‌اندازی مرحلهٔ <bdi>Psiphon</bdi>…',
  'Rebuilding the chain…': 'بازسازی زنجیره…',
  // --- v12 (۱.۲.۴): دستیار هوش مصنوعی ---
  'Assistant': 'دستیار',
  'Gemini API key': 'کلید API جمینای',
  'The key is stored sealed on this PC with Windows DPAPI and is never written to the log.':
    'کلید روی همین رایانه با <bdi>DPAPI</bdi> ویندوز مهر و ذخیره می‌شود و هرگز در لاگ نوشته نمی‌شود.',
  'Save': 'ذخیره',
  'Forget': 'فراموش کن',
  'No key stored.': 'کلیدی ذخیره نشده.',
  'A key ending in …{0} is stored.': 'کلیدی که به …{0} ختم می‌شود ذخیره است.',
  'Get a free key from Google AI Studio': 'یک کلید رایگان از <bdi>Google AI Studio</bdi> بگیرید',
  'Model': 'مدل',
  'Only fast Flash-class models are offered: they answer on a free key.':
    'فقط مدل‌های سریعِ ردهٔ <bdi>Flash</bdi> پیشنهاد می‌شوند؛ همان‌هایی که روی کلید رایگان پاسخ می‌دهند.',
  'Discover models for this key': 'کشف مدل‌های این کلید',
  'No models discovered yet.': 'هنوز مدلی کشف نشده.',
  'Add a key first.': 'اول یک کلید وارد کنید.',
  'Tune for my network': 'تنظیم برای شبکهٔ من',
  'Reads the recent connection log — with addresses masked and identifiers removed — and changes at most one or two transport settings.':
    'لاگ اخیر اتصال را می‌خواند — با نشانی‌های ماسک‌شده و شناسه‌های حذف‌شده — و حداکثر یکی دو تنظیم ترابرد را عوض می‌کند.',
  'Analyse and tune': 'تحلیل و تنظیم',
  'Changed': 'تغییر داده شد',
  'Nothing needed changing.': 'چیزی نیاز به تغییر نداشت.',
  'Refused by the app': 'ردشده توسط برنامه',
  'Dismiss': 'بستن',
  'Ask anything': 'هر چه می‌خواهید بپرسید',
  'Ask about a setting, an error, or censorship…': 'دربارهٔ یک تنظیم، یک خطا، یا فیلترینگ بپرسید…',
  'Send': 'بفرست',
  'Clear conversation': 'پاک‌کردن گفت‌وگو',
  'Close': 'بستن',
  'Ask the assistant about this setting': 'از دستیار دربارهٔ این تنظیم بپرس',
  'Add your Gemini API key to use the assistant.': 'برای استفاده از دستیار، کلید <bdi>API</bdi> جمینای را وارد کنید.',
  'No model has been discovered for this key yet.': 'هنوز هیچ مدلی برای این کلید کشف نشده است.',
  'The assistant needs the tunnel to be connected — Google is not reachable otherwise.':
    'دستیار به تونلِ وصل نیاز دارد — وگرنه گوگل در دسترس نیست.',
  'Switch the connection to Aether → Psiphon: Google refuses the Cloudflare WARP addresses that Aether alone exits from.':
    'اتصال را به «اِتِر ← <bdi>Psiphon</bdi>» عوض کنید: گوگل نشانی‌های <bdi>Cloudflare WARP</bdi> را که اِتِرِ تنها از آن‌ها بیرون می‌رود رد می‌کند.',
  'The assistant is not available right now.': 'دستیار در این لحظه در دسترس نیست.',
  // --- v12 (۱.۲.۴): منوی تنظیمات (پورت a2) ---
  'Settings': 'تنظیمات',
  'Tunnel settings': 'تنظیمات تونل',
  'Back': 'بازگشت',
  'On': 'روشن',
  'Tunnel': 'تونل',
  'Connection': 'اتصال',
  'Network backend, exit country, protocol and scanning': 'بک‌اند شبکه، کشور خروج، پروتکل و اسکن',
  'Transport & anti-DPI': 'ترابرد و ضدDPI',
  'Obfuscation, endpoint, MTU and anti-DPI': 'مبهم‌سازی، اندپوینت، <bdi>MTU</bdi> و ضدDPI',
  'DNS & routing rules': 'DNS و قواعد مسیریابی',
  'Resolvers inside the tunnel, block and bypass lists': 'ریزالورهای داخل تونل، فهرست‌های مسدود و عبور',
  'Upstream proxy (chaining)': 'پروکسی بالادست (زنجیره‌ای)',
  'Dial out through a proxy already running on this PC': 'خروج از طریق پروکسی‌ای که همین حالا روی این رایانه اجراست',
  'Kill switch & leak protection': 'قطع‌کن و محافظت از نشتی',
  'What happens the moment the tunnel drops': 'وقتی تونل می‌افتد چه می‌شود',
  'Join a Cloudflare organisation instead of plain WARP': 'به‌جای <bdi>WARP</bdi> ساده، عضو یک سازمان <bdi>Cloudflare</bdi> شوید',
  'Application': 'برنامه',
  'Apps & LAN sharing': 'برنامه‌ها و اشتراک شبکه',
  'Which programs use the tunnel, and who else may': 'کدام برنامه‌ها از تونل استفاده کنند، و چه کسی دیگر اجازه دارد',
  'Interface language': 'زبان رابط کاربری',
  'Reset all settings to defaults': 'بازنشانی همهٔ تنظیمات به پیش‌فرض',
  'Every setting goes back to its default, including endpoint ranges, routing rules and enrolment details.':
    'هر تنظیم به مقدار پیش‌فرضش برمی‌گردد، از جمله بازه‌های اندپوینت، قواعد مسیریابی و جزئیات ثبت‌نام.',
  'Reset every setting to its default?': 'همهٔ تنظیمات به پیش‌فرض برگردند؟',
  'The tunnel is running. Changes are saved now and handed to the engine the next time it starts — reconnect to apply them.':
    'تونل در حال اجراست. تغییرها همین حالا ذخیره می‌شوند و در استارت بعدی به هسته داده می‌شوند — برای اعمال، دوباره وصل شوید.',
  // --- پوسته (منو + نوار عنوان) ---
  'Home': 'خانه',
  'Advanced': 'پیشرفته',
  'Diagnostics': 'عیب‌یابی',
  'Share over LAN': 'اشتراک در شبکه',
  'About': 'درباره',
  'Menu': 'منو',
  'Aether': 'اِتِر',

  // --- صفحهٔ اصلی ---
  'Freedom, in one tap': 'آزادی، با یک لمس',
  'Tap to connect securely': 'برای اتصال امن لمس کنید',
  'Tap to disconnect': 'برای قطع اتصال لمس کنید',
  'Something went wrong': 'مشکلی پیش آمد',
  'Verifying connection…': 'در حال راستی‌آزمایی اتصال…',
  'Disconnected': 'قطع',
  'Starting engine…': 'در حال راه‌اندازی موتور…',
  'Connecting…': 'در حال اتصال…',
  'Verifying…': 'در حال راستی‌آزمایی…',
  'Connected': 'متصل',
  'Reconnecting…': 'اتصال دوباره…',
  'Disconnecting…': 'در حال قطع اتصال…',
  'Connection failed': 'اتصال ناموفق بود',
  'Your IP': 'آی‌پی شما',
  'Server IP': 'آی‌پی سرور',
  'Checking IP…': 'در حال بررسی آی‌پی…',
  'IP unavailable': 'آی‌پی در دسترس نیست',
  'Connected for': 'مدت اتصال',
  'Protocol': 'پروتکل',
  'MASQUE×2': 'ماسک×۲',
  'Endpoint': 'نقطهٔ اتصال',
  'Latency': 'تأخیر',
  'Download': 'دانلود',
  'Upload': 'آپلود',

  // --- ۱.۲.۴: کارت اتصال (پورت از ConnectionCard.kt) ---
  'Total': 'مجموع',
  'Ping strength': 'قدرت پینگ',
  'Excellent': 'عالی',
  'Good': 'خوب',
  'Fair': 'متوسط',
  'Poor': 'ضعیف',
  'Measuring…': 'در حال سنجش…',
  'Offline': 'قطع',

  // --- v1.2.0: محافظت در برابر نشتی WebRTC ---
  'Connection safety': 'امنیت اتصال',
  'Kill switch': 'کیل‌سوییچ',
  'Block browser traffic if the tunnel drops': 'اگر تونل قطع شد، ترافیک مرورگرها را مسدود می‌کند',
  'IPv6 leak protection': 'محافظت در برابر نشت IPv6',
  'Keep the IPv6 default route protected or block it safely': 'مسیر پیش‌فرض IPv6 را داخل مسیر امن نگه می‌دارد یا ایمن مسدود می‌کند',
  'Automatic reconnect attempts': 'تعداد تلاش‌های اتصال مجدد خودکار',
  'WebRTC protected — no IP leak': 'WebRTC محافظت شد — بدون نشت آی‌پی',
  'WebRTC is leaking your real IP': 'WebRTC آی‌پی واقعی شما را لو می‌دهد',
  'Checking for WebRTC leaks…': 'در حال بررسی نشتی WebRTC…',
  'WebRTC leak test': 'آزمایش نشتی WebRTC',
  'Testing for WebRTC leaks…': 'در حال آزمایش نشتی WebRTC…',

  // --- تنظیمات پیشرفته ---
  'Language': 'زبان برنامه',
  'Scan mode': 'حالت اسکن',
  'IP version': 'نسخهٔ آی‌پی',
  'Noize': 'نویز',
  // v17: گزینه‌های حالت اسکن و نویز — تا کل صفحهٔ پیشرفته فارسی باشد.
  'Turbo': 'توربو',
  'Balanced': 'متعادل',
  'Thorough': 'موشکافانه',
  'Stealth': 'پنهان‌کار',
  'Ironclad': 'آهنین',
  'Light': 'ملایم',
  'Firewall': 'فایروال',
  'GFW': 'فیلترینگ چین (GFW)',
  'Aggressive': 'تهاجمی',
  'Automatic': 'خودکار',
  'Manual peer': 'سرور دستی',
  'Manual range': 'بازهٔ دستی',
  'Peer address': 'آدرس سرور',
  'Address range': 'بازهٔ آدرس',
  'Off': 'خاموش',
  'Both': 'هر دو',
  'Quick reconnect': 'اتصال مجدد سریع',
  'Reconnect instantly after a drop': 'بعد از قطعی بلافاصله دوباره وصل می‌شود',
  'MASQUE over HTTP/2': '<bdi>MASQUE</bdi> روی <bdi>HTTP/2</bdi>',
  'Helps on networks that block HTTP/3': 'برای شبکه‌هایی که <bdi>HTTP/3</bdi> را مسدود می‌کنند',
  'Packet fragmentation': 'قطعه‌قطعه‌سازی بسته‌ها',
  'Splits the handshake to evade filtering': 'دست‌دادن <bdi>TLS</bdi> را تکه‌تکه می‌کند تا از فیلترینگ عبور کند',
  'Encrypted Client Hello (auto)': '<bdi>Encrypted Client Hello</bdi> (خودکار)',
  'Let other devices on your network use this tunnel': 'دستگاه‌های دیگر شبکه بتوانند از این تونل استفاده کنند',
  'Split tunneling': 'تونل تفکیکی',
  'Only these apps': 'فقط این برنامه‌ها',
  'All except these': 'همه به‌جز این‌ها',
  'Applications': 'برنامه‌ها',
  'One executable name per line.': 'در هر خط نام یک فایل اجرایی (<bdi>exe</bdi>).',

  // --- v10: Zero Trust، مسیریابی و DNS (هستهٔ 1.5.0) ---
  'Zero Trust': '<bdi>Zero Trust</bdi> (سازمانی)',
  'Team name': 'نام تیم (سازمان)',
  'Connect as a managed device of a Cloudflare Zero Trust organization. Leave empty for normal WARP.': 'اتصال به‌عنوان دستگاه مدیریت‌شدهٔ یک سازمان <bdi>Cloudflare Zero Trust</bdi>. برای <bdi>WARP</bdi> معمولی خالی بگذارید.',
  'Sign-in method': 'روش ورود',
  'Email code': 'کد ایمیلی',
  'Service token': 'توکن سرویس',
  'Access token': 'توکن دسترسی',
  'Access email': 'ایمیل ورود',
  'A one-time code is sent to this mailbox on connect.': 'هنگام اتصال، یک کد یک‌بارمصرف به این صندوق ایمیل فرستاده می‌شود.',
  'Stored in memory only — never written to disk.': 'فقط در حافظه نگه داشته می‌شود — هرگز روی دیسک نوشته نمی‌شود.',
  'Gateway proxy': 'پروکسی <bdi>Gateway</bdi>',
  "Route HTTP/HTTPS through your organization's Gateway (adds a hop and logs browsing)": 'عبور <bdi>HTTP/HTTPS</bdi> از <bdi>Gateway</bdi> سازمان (یک هاپ اضافه می‌کند و مرور شما را لاگ می‌کند)',
  'Routing rules': 'قوانین مسیریابی',
  'Blocked destinations': 'مقصدهای مسدود',
  'One rule per line — domain, IP or CIDR. These connections are refused.': 'در هر خط یک قاعده — دامنه، آی‌پی یا <bdi>CIDR</bdi>. این اتصال‌ها کاملاً رد می‌شوند.',
  'Direct destinations': 'مقصدهای مستقیم',
  'One rule per line. These bypass the tunnel — for banking apps, LAN services and domestic sites.': 'در هر خط یک قاعده. این مقصدها از تونل عبور نمی‌کنند — برای بانک، سرویس‌های شبکهٔ محلی و سایت‌های داخلی.',
  'In-tunnel DNS servers': 'سرورهای <bdi>DNS</bdi> داخل تونل',
  'Resolvers used inside the tunnel. Empty = engine defaults.': 'حل‌کننده‌های نام داخل تونل. خالی = پیش‌فرض موتور.',
  'These features need engine core 1.5.0 or newer. The bundled core is older, so they are disabled.': 'این قابلیت‌ها به هستهٔ <bdi>1.5.0</bdi> یا بالاتر نیاز دارند. هستهٔ همراه این بیلد قدیمی‌تر است، پس غیرفعال شده‌اند.',

  // --- v11: پروکسی بالادست، تشخیص نام میزبان و هویت (هستهٔ 1.7.0) ---
  'Upstream proxy': 'پروکسی بالادست',
  'Proxy address': 'نشانی پروکسی',
  'Aether dials out through this proxy — use it to chain behind another VPN or proxy already running on this PC. Empty = direct.':
    'اِتِر همهٔ اتصال‌های بیرونی‌اش را از این پروکسی می‌گیرد — برای زنجیره‌کردن پشت یک <bdi>VPN</bdi> یا پروکسیِ در حال اجرا روی همین ویندوز. خالی = اتصال مستقیم.',
  'That is not a proxy address Aether can use. Expected socks5://host:port or http://host:port — the port is required.':
    'این نشانی برای اِتِر قابل‌استفاده نیست. قالب درست: <bdi>socks5://host:port</bdi> یا <bdi>http://host:port</bdi> — نوشتن پورت الزامی است.',
  'An HTTP proxy cannot carry UDP, so MASQUE is switched to HTTP/2 automatically and WireGuard / WARP×2 will not pass through it. Use a SOCKS5 proxy for those.':
    'پروکسی <bdi>HTTP</bdi> نمی‌تواند <bdi>UDP</bdi> حمل کند؛ پس <bdi>MASQUE</bdi> خودکار روی <bdi>HTTP/2</bdi> می‌رود و <bdi>WireGuard</bdi> و <bdi>WARP×2</bdi> از این پروکسی رد نمی‌شوند. برای آن‌ها از پروکسی <bdi>SOCKS5</bdi> استفاده کنید.',
  'SOCKS5 with UDP support carries every protocol: MASQUE, WireGuard and WARP×2.':
    'پروکسی <bdi>SOCKS5</bdi> با پشتیبانی <bdi>UDP</bdi> هر سه پروتکل را حمل می‌کند: <bdi>MASQUE</bdi>، <bdi>WireGuard</bdi> و <bdi>WARP×2</bdi>.',
  'Match domain rules by real host name': 'تطبیق قواعد دامنه با نام واقعی میزبان',
  'Reads the name from the first bytes (TLS SNI or HTTP Host), so domain rules keep working even though Windows hands the tunnel an IP address':
    'نام میزبان را از بایت‌های اول (<bdi>TLS SNI</bdi> یا هدر <bdi>Host</bdi>) می‌خواند؛ پس قواعد دامنه حتی وقتی ویندوز فقط یک آی‌پی به تونل می‌دهد هم کار می‌کنند',
  'Account identity': 'هویت حساب',
  'Replace a refused identity': 'جایگزینی هویتِ ردشده',
  'If Cloudflare stops accepting the saved device, register a fresh one instead of handshaking a tunnel that carries no traffic':
    'اگر <bdi>Cloudflare</bdi> دیگر دستگاه ذخیره‌شده را نپذیرد، یک دستگاه تازه ثبت می‌شود؛ وگرنه تونل دست می‌دهد ولی هیچ ترافیکی عبور نمی‌کند',
  'The upstream proxy, host-name routing and identity replacement need engine core 1.7.0 or newer. The bundled core is older, so they are disabled.':
    'پروکسی بالادست، مسیریابی براساس نام میزبان و جایگزینی هویت به هستهٔ <bdi>1.7.0</bdi> یا بالاتر نیاز دارند. هستهٔ همراه این بیلد قدیمی‌تر است، پس غیرفعال شده‌اند.',

  'Reset to defaults': 'بازنشانی به تنظیمات پیش‌فرض',
  'Restores every setting above to its factory value': 'همهٔ تنظیمات بالا به مقدار کارخانه برمی‌گردد',
  'Reset': 'بازنشانی',

  // --- عیب‌یابی ---
  'Run the test to verify connectivity': 'برای بررسی اتصال، آزمایش را اجرا کنید',
  'A problem was detected — see the failing check': 'مشکلی پیدا شد — بررسیِ ناموفق را ببینید',
  'All checks passed — traffic should flow': 'همهٔ بررسی‌ها موفق بود — ترافیک باید برقرار باشد',
  'Testing connectivity…': 'در حال آزمایش اتصال…',
  'Run test': 'اجرای آزمایش',
  'Copy logs': 'کپی لاگ‌ها',
  'Clear': 'پاک‌سازی',
  'Environment check': 'بررسی محیط',
  'Log': 'لاگ',
  'No logs yet. Connect or run a test.': 'هنوز لاگی ثبت نشده. متصل شوید یا آزمایش را اجرا کنید.',
  'Logs copied to clipboard': 'لاگ‌ها در کلیپ‌بورد کپی شد',
  'Running…': 'در حال اجرا…',

  // --- اشتراک در شبکه ---
  'Other devices on the same Wi‑Fi can route their traffic through this computer. Point them at one of the addresses below.': 'دستگاه‌های دیگر روی همین <bdi>Wi‑Fi</bdi> می‌توانند ترافیکشان را از این رایانه عبور دهند. یکی از آدرس‌های زیر را در آن‌ها وارد کنید.',
  'Enable sharing': 'فعال‌سازی اشتراک',
  'Only listens on your local network address.': 'فقط روی آدرس شبکهٔ محلی شما گوش می‌دهد.',
  'Copy': 'کپی',
  'Sharing only works while Aether is connected.': 'اشتراک فقط وقتی کار می‌کند که <bdi>Aether</bdi> متصل باشد.',
  'Both ports accept HTTP and SOCKS5 automatically — either port works in either field.': 'هر دو پورت به‌صورت خودکار هم <bdi>HTTP</bdi> و هم <bdi>SOCKS5</bdi> را می‌پذیرند — هر پورتی را هر جا وارد کنید کار می‌کند.',
  'Apps like Telegram ignore the system proxy; set a SOCKS5 proxy inside the app instead.': 'برنامه‌هایی مثل تلگرام پروکسی سیستم را نادیده می‌گیرند؛ در تنظیمات خودِ برنامه یک پروکسی <bdi>SOCKS5</bdi> تنظیم کنید.',

  // --- درباره ---
  'App version': 'نسخهٔ برنامه',
  'Core version': 'نسخهٔ هسته',
  'Architecture': 'معماری',
  'Credits, links & what this build adds': 'سازندگان، لینک‌ها و امکانات این بیلد',
  'Version': 'نسخه',
  'Original project — Cluvex Studio': 'پروژهٔ اصلی — <bdi>Cluvex Studio</bdi>',
  'The core engine powering this app': 'موتور اصلیِ این برنامه',
  'Windows edition — QW-AI-Code': 'نسخهٔ ویندوز — <bdi>QW-AI-Code</bdi>',
  'The native Windows desktop edition of Aether — what we upgraded in this build': 'نسخهٔ بومی ویندوزِ <bdi>Aether</bdi> — بهبودهای همین بیلد',

  // --- ۱.۲.۴-p1: ذخیرهٔ کلید و تست اتصال ---
  'Show': 'نمایش',
  'Hide': 'پنهان',
  'API key saved.': 'کلید API ذخیره شد.',
  'API key removed': 'کلید API حذف شد',
  'Test the API connection': 'تست اتصال به API',
  'Testing…': 'در حال تست…',
  'Checks the key and lists the models it may use': 'کلید را بررسی می‌کند و مدل‌هایی که اجازهٔ استفاده دارد را فهرست می‌کند',
  'Working — {0} model(s) available through {1}': 'سالم — {0} مدل از مسیر {1} در دسترس است',
  'Not working: {0}': 'کار نمی‌کند: {0}',
  // --- v13 (۱.۲.۵ / هستهٔ 2.0.0): تور -----------------------------------
  // ترجمه‌ها همان رشته‌های `tor_*` و `backend_help_*` در values-fa/strings.xml
  // هستند. نام کشورهای پل ترجمه نشده — نه در این برنامه (فهرست کشور خروجی هم
  // انگلیسی است) و نه در موبایل.
  'Tor': 'تور',
  'Bridges': 'پل‌ها',
  'How Tor reaches the network when it is blocked.': 'وقتی تور بلاک است، چگونه به شبکه برسد.',
  'Not needed in this mode: Tor is dialled through the Aether tunnel, so the network you are on never sees it.':
    'در این حالت لازم نیست: تور از داخل تونل اتر وصل می‌شود، پس شبکه‌ای که در آن هستید هرگز آن را نمی‌بیند.',
  'Always': 'همیشه',
  'Bridge country': 'کشور پل',
  'Detect automatically': 'تشخیص خودکار',
  'Which country bridgedb hands out bridges for. Detection asks the network where you are, which is the request most likely to fail here.':
    'اینکه <bdi>bridgedb</bdi> پل‌های مربوط به کدام کشور را بدهد. تشخیص خودکار از شبکه می‌پرسد کجا هستید، و همین درخواست بیشتر از هر چیز اینجا شکست می‌خورد.',
  'Bootstrap patience': 'مدت صبر برای بوت‌استرپ',
  'Automatic (75 s)': 'خودکار (۷۵ ثانیه)',
  '{0} seconds': '{0} ثانیه',
  'How long Tor tries the direct path before falling back to bridges. Shorten it where Tor is definitely blocked.':
    'تور چقدر مسیر مستقیم را امتحان کند پیش از رفتن به سراغ پل‌ها. اگر مطمئنید تور بلاک است، کوتاه‌ترش کنید.',
  'Own bridge lines': 'خطوط پل خودتان',
  'One per line, in the format bridges.torproject.org hands out. Leave empty to use the bridges the app fetches for your country. A line naming a transport the app does not ship is ignored.':
    'هر خط یکی، در قالبی که <bdi>bridges.torproject.org</bdi> می‌دهد. خالی بگذارید تا برنامه پل‌های مناسب کشور شما را خودش بگیرد. خطی که نام ترانسپورتی را بگوید که برنامه ندارد، نادیده گرفته می‌شود.',
  'Reachability check': 'بررسی دسترسی',
  'The address Tor must reach before the bootstrap counts as working. Change it only if bootstrap keeps failing on a Tor that seems fine \u2014 the default target is itself blocked on some networks.':
    'آدرسی که تور باید به آن برسد تا بوت‌استرپ موفق شمرده شود. فقط وقتی عوضش کنید که بوت‌استرپ مدام شکست می‌خورد در حالی که تور سالم به نظر می‌رسد — خود مقصد پیش‌فرض در بعضی شبکه‌ها بلاک است.',
  'Tor carries TCP only \u2014 in every app, on every platform. Aether answers DNS over TCP inside Tor and drops other UDP, so QUIC-capable apps fall back to TCP. That is normal and nothing is leaking: dropped UDP goes nowhere, least of all around Tor. Expect noticeably higher latency, and expect the first connect to take a while \u2014 Tor downloads its directory before it can build a circuit.':
    'تور فقط <bdi>TCP</bdi> را حمل می‌کند — در هر برنامه و روی هر پلتفرم. اتر <bdi>DNS</bdi> را روی <bdi>TCP</bdi> داخل تور پاسخ می‌دهد و بقیهٔ <bdi>UDP</bdi> را دور می‌ریزد، پس برنامه‌هایی که <bdi>QUIC</bdi> دارند به <bdi>TCP</bdi> برمی‌گردند. این طبیعی است و چیزی لیک نمی‌شود: <bdi>UDP</bdi> دورریخته به هیچ‌جا نمی‌رود، چه برسد به دور زدن تور. منتظر تاخیر محسوساً بیشتر باشید، و اینکه اولین اتصال طول بکشد — تور قبل از ساخت مدار، دایرکتوری خود را دانلود می‌کند.',
  'Fixed to MASQUE over HTTP/2 in this mode. Tor carries TCP only and WARP\u2019s WireGuard endpoints answer on UDP alone, so the engine refuses WireGuard and WARP\u00d72 here.':
    'در این حالت روی <bdi>MASQUE</bdi> بر <bdi>HTTP/2</bdi> قفل است. تور فقط <bdi>TCP</bdi> را حمل می‌کند و اندپوینت‌های <bdi>WireGuard</bdi> مربوط به <bdi>WARP</bdi> فقط روی <bdi>UDP</bdi> پاسخ می‌دهند، پس موتور اینجا <bdi>WireGuard</bdi> و <bdi>WARP×۲</bdi> را قبول نمی‌کند.',
  'Tor chooses its own exit node, and a new one per circuit. No setting can pin it to a country.':
    'تور خودش گره خروجی را انتخاب می‌کند، و برای هر مدار یکی تازه. هیچ تنظیمی آن را به یک کشور محدود نمی‌کند.',
  'The Tor modes need engine core 2.0.0 or newer. The bundled core is older, so they are disabled.':
    'حالت‌های تور به هستهٔ <bdi>2.0.0</bdi> یا بالاتر نیاز دارند. هستهٔ همراه این بیلد قدیمی‌تر است، پس غیرفعال شده‌اند.',

  // وضعیتِ زندهٔ bootstrap — همان `state_tor_*`. درصد را رابط جاگذاری می‌کند.
  'Reaching the Tor network… {0}%': 'در حال رسیدن به شبکهٔ تور… {0}%',
  'Reaching the Tor network…': 'در حال رسیدن به شبکهٔ تور…',
  'Tor is not getting through directly — trying bridges…': 'تور بلاک شده است — تلاش با پل‌ها…',
  'Tor is ready — opening its local proxy…': 'تور آماده است — در حال باز کردن پروکسی محلی آن…',

  // توضیحِ هر بک‌اند — همان `backend_help_*`.
  'One hop through the bundled Aether/WARP engine. Fastest.':
    'یک هاپ از موتور اتر/<bdi>WARP</bdi> همراه برنامه. سریع‌ترین حالت.',
  'Two hops: Aether connects first, then Psiphon tunnels through it. Your exit IP becomes Psiphon\u2019s, so sites that block Aether/WARP addresses open again.':
    'دو هاپ: اول اتر وصل می‌شود، بعد سایفون از داخل آن تونل می‌زند. آی‌پی خروجی شما به سایفون تغییر می‌کند، پس سایت‌هایی که آدرس‌های اتر/<bdi>WARP</bdi> را بلاک می‌کنند باز می‌شوند.',
  'Tor alone, without the Aether tunnel. Your exit is a Tor exit node and your traffic passes three relays, which is the slowest and the most private of the modes. Tor has to reach the Tor network by itself here, so it uses bridges when it is blocked.':
    'تور به تنهایی، بدون تونل اتر. خروجی شما یک گره خروجی تور است و ترافیک از سه رله می‌گذرد: کندترین و خصوصی‌ترین حالت. اینجا تور باید خودش به شبکهٔ تور برسد، پس اگر بلاک باشد از پل استفاده می‌کند.',
  'Two hops: Aether connects first, then Tor is built INSIDE that tunnel. The network you are on sees only Aether\u2019s obfuscated transport, never Tor \u2014 so this is the mode to use where Tor is blocked. Your exit is a Tor exit node.':
    'دو هاپ: اول اتر وصل می‌شود، بعد تور داخل همان تونل ساخته می‌شود. شبکه‌ای که در آن هستید فقط ترانسپورت مخفی‌شدهٔ اتر را می‌بیند، هرگز تور را — پس هر جا تور بلاک است، این حالت را انتخاب کنید. خروجی شما گره خروجی تور است.',
  'Three hops: Tor first, then Psiphon dialled through it. Your exit IP is Psiphon\u2019s, reached from a Tor address, so sites that block Tor exit nodes open again while your own address stays behind Tor. The slowest mode.':
    'سه هاپ: اول تور، بعد سایفون از داخل آن. آی‌پی خروجی شما مال سایفون است که از یک آدرس تور به آن رسیده‌اید؛ پس سایت‌هایی که گره‌های خروجی تور را بلاک می‌کنند باز می‌شوند و آدرس خود شما پشت تور می‌ماند. کندترین حالت.',
  'The reverse chain: Tor first, then the Aether tunnel built INSIDE it. Your exit is a WARP address \u2014 the same as plain Aether \u2014 but the network you are on sees only Tor, and cannot tell that a VPN tunnel exists at all. Use it where Cloudflare/WARP itself is blocked or throttled but Tor still gets through. Carries normal UDP, unlike the Tor-exit modes.':
    'زنجیرهٔ معکوس: اول تور، بعد تونل اتر داخل آن ساخته می‌شود. خروجی شما یک آدرس <bdi>WARP</bdi> است — همان چیزی که اتر ساده می‌دهد — اما شبکه‌ای که در آن هستید فقط تور را می‌بیند و اصلاً نمی‌تواند بفهمد که تونل <bdi>VPN</bdi>‌ی وجود دارد. جایی به کار بیاید که خود <bdi>Cloudflare/WARP</bdi> بلاک یا کند شده اما تور هنوز رد می‌شود. برخلاف حالت‌های با خروجی تور، <bdi>UDP</bdi> عادی را حمل می‌کند.',
}

let current = (() => {
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    if (v === 'fa' || v === 'en') return v
  } catch { /* localStorage ممکن است در دسترس نباشد */ }
  return 'en'
})()

// >>> AETHER-APP-FIX chinese-interface
// 简体中文：键与 FA 完全一致（英文原句），由构建此交付的轮次全文翻译。
// 新增的界面字符串（如 TUN 模式开关）也在此补齐；缺键时回退英文（t() 的兜底）。
const ZH = {
  'The tunnel started but the self-test failed.': '隧道已启动，但自检未通过。',
  'The tunnel is up, but Tor never reported any progress from inside it. Try Tor on its own, which lets Tor pick its own way to the network.': '隧道已连通，但 Tor 在其中没有任何进展报告。请试试“仅 Tor”，让 Tor 自己选择连网方式。',
  'The tunnel is up, but Tor stopped at {0}% inside it and did not reach the Tor network. Try another protocol for the tunnel, or Tor on its own with bridges.': '隧道已连通，但 Tor 在其中停留在 {0}%，未能接入 Tor 网络。请为隧道换一个协议，或使用带网桥的“仅 Tor”。',
  'Tor stopped at {0}% and could not reach the Tor network. No pluggable transport is installed, so only plain bridges can be tried — and a network that filters Tor usually blocks those too. Use the Aether → Tor mode: Tor is then dialled through the tunnel, where the operator cannot see or block it.': 'Tor 停留在 {0}%，无法接入 Tor 网络。未安装任何可插拔传输，因此只能尝试普通网桥——而会过滤 Tor 的网络通常也会封掉它们。请使用“<bdi>Aether → Tor</bdi>”模式：Tor 将在隧道内建立连接，运营商既看不到也无法封堵。',
  'The engine started but Tor never reported any progress towards the Tor network, and no pluggable transport is installed. Use the Aether → Tor mode, which builds Tor inside the tunnel.': '引擎已启动，但 Tor 没有任何朝向 Tor 网络的进展报告，且未安装任何可插拔传输。请使用“<bdi>Aether → Tor</bdi>”模式，它会在隧道内构建 Tor。',
  'Chat': '聊天',
  'Chat with Gemini': '与 Gemini 聊天',
  'Open the chat': '打开聊天',
  'Ask anything, or say what you want changed': '随便问，或告诉我要修改什么',
  'Model: {0}': '模型：{0}',
  '{0} message(s) in the conversation': '会话中共 {0} 条消息',
  'Hi, I am Aether AI': '你好，我是 Aether AI',
  'I can explain any setting in this app, read this session’s log and propose tuning, or just answer a question.': '我可以解释本应用的任何设置、读取本次会话日志并提出调优建议，或直接回答问题。',
  'Why is my connection slow right now?': '为什么我的连接现在很慢？',
  'Which protocol should I use on mobile data?': '用手机流量时该选哪种协议？',
  'Explain MTU and pick the best one for me': '解释 MTU 并帮我选最合适的值',
  'Make the tunnel harder to detect': '让隧道更难被识别',
  'Ask Aether AI…': '问问 Aether AI…',
  'Stop': '停止',
  'Clear the conversation': '清空会话',
  'Thinking…': '思考中…',
  'Copy answer': '复制回答',
  'Copied': '已复制',
  'Could not copy — your system refused clipboard access.': '复制失败——系统拒绝了剪贴板访问。',
  'Try again': '重试',
  'Edit': '编辑',
  'Delete': '删除',
  'edited': '已编辑',
  'Cancel': '取消',
  'Edit message': '编辑消息',
  'Send again': '重新发送',
  'Everything after this message will be removed and the assistant will answer the edited question.': '此消息之后的内容将被删除，助手将回答编辑后的问题。',
  '{0} selected': '已选中 {0} 项',
  'Select all': '全选',
  'Cancel selection': '取消选择',
  'Delete selected': '删除所选',
  'Delete {0} message(s)?': '删除 {0} 条消息？',
  'This cannot be undone. Deleted messages are no longer sent to the assistant as context.': '此操作无法撤销。已删除的消息不再作为上下文发送给助手。',
  'Clear the whole conversation?': '清空整个会话？',
  'Clear': '清空',
  'Proposed settings ({0})': '建议的设置（{0}）',
  'Apply': '应用',
  'Applied': '已应用',
  'Tunnel settings are handed to the engine when it starts, so these take effect on your next connect.': '隧道设置在引擎启动时下发，因此将在下次连接时生效。',
  'Saved for the next connection': '已保存，下次连接生效',
  'The new settings are stored, but the tunnel is already running with the old ones. Tunnel settings are handed to the engine when it starts, so disconnect and connect again for them to take effect.': '新设置已保存，但隧道仍在用旧设置运行。隧道设置在引擎启动时下发，请断开并重新连接以使其生效。',
  'Got it': '知道了',
  'Did not understand? Ask the assistant': '没看懂？问一下助手',
  'Explain this more simply: “{0}”. This is what the app told me: {1}': '请用更简单的话解释：“{0}”。应用告诉我的是：{1}',
  'Google rejected this key. Check it in AI Studio, or paste it again.': 'Google 拒绝了这个密钥。请在 AI Studio 中检查，或重新粘贴。',
  'The free quota for this key is used up for now. Try again later.': '此密钥的免费额度暂时用完。请稍后再试。',
  'This key cannot use the selected model. Discover the models again.': '此密钥无法使用所选模型。请重新发现模型。',
  'The request never reached Google. Check the tunnel and try again.': '请求未能到达 Google。请检查隧道后重试。',
  'Google failed on its own side. This is not your connection — try again.': 'Google 自身出现故障。这不是你的连接问题——请重试。',
  'Google sent back something this app could not read.': 'Google 返回了本应用无法读取的内容。',
  'The answer was cut off before it finished.': '回答尚未完成就被截断了。',
  'The model returned no answer.': '模型没有返回回答。',
  'The request failed.': '请求失败。',
  'Transport': '传输',
  'Backend': '后端',
  'Exit country': '出口国家',
  'Automatic': '自动',
  'Aether alone exits through a Cloudflare WARP edge. Chaining Psiphon keeps Aether as the first hop and swaps the exit for an ordinary hosting IP, which is what opens sites that reject WARP ranges.': '仅 Aether 时通过 Cloudflare WARP 边缘出口。链式连接 Psiphon 后，Aether 仍是第一跳，但出口换为普通主机 IP，这正是能打开拒绝 WARP 网段网站的原因。',
  'Only applies to the chained backend. If no server is reachable in that country, Aether falls back to an automatic exit instead of hanging.': '仅对链式后端生效。如果该国没有可连的服务器，Aether 会回退到自动出口，而不会一直卡住。',
  'Starting the Psiphon stage…': '正在启动 Psiphon 阶段…',
  'Rebuilding the chain…': '正在重建链路…',
  'Assistant': '助手',
  'Gemini API key': 'Gemini API 密钥',
  'The key is stored sealed on this PC with Windows DPAPI and is never written to the log.': '密钥用 Windows DPAPI 加密保存在本机，绝不写入日志。',
  'Save': '保存',
  'Forget': '清除',
  'No key stored.': '未保存密钥。',
  'A key ending in …{0} is stored.': '已保存以 …{0} 结尾的密钥。',
  'Get a free key from Google AI Studio': '从 Google AI Studio 获取免费密钥',
  'Model': '模型',
  'Only fast Flash-class models are offered: they answer on a free key.': '只提供快速的 Flash 级模型：免费密钥即可使用。',
  'Discover models for this key': '为此密钥发现可用模型',
  'No models discovered yet.': '尚未发现任何模型。',
  'Add a key first.': '请先添加密钥。',
  'Tune for my network': '为我的网络调优',
  'Reads the recent connection log — with addresses masked and identifiers removed — and changes at most one or two transport settings.': '读取最近的连接日志（地址已打码、标识符已移除），最多修改一两项传输设置。',
  'Analyse and tune': '分析并调优',
  'Changed': '已修改',
  'Nothing needed changing.': '无需修改。',
  'Refused by the app': '被应用拒绝',
  'Dismiss': '关闭',
  'Ask anything': '随便问',
  'Ask about a setting, an error, or censorship…': '询问设置、报错或审查相关的问题…',
  'Send': '发送',
  'Clear conversation': '清空会话',
  'Close': '关闭',
  'Ask the assistant about this setting': '向助手询问此设置',
  'Add your Gemini API key to use the assistant.': '请添加你的 Gemini API 密钥以使用助手。',
  'No model has been discovered for this key yet.': '此密钥尚未发现可用模型。',
  'The assistant needs the tunnel to be connected — Google is not reachable otherwise.': '助手需要隧道已连接——否则无法访问 Google。',
  'Switch the connection to Aether → Psiphon: Google refuses the Cloudflare WARP addresses that Aether alone exits from.': '请将连接切换为 <bdi>Aether → Psiphon</bdi>：Google 拒绝仅 Aether 模式出口的 Cloudflare WARP 地址。',
  'The assistant is not available right now.': '助手当前不可用。',
  'Settings': '设置',
  'Tunnel settings': '隧道设置',
  'Back': '返回',
  'On': '开',
  'Tunnel': '隧道',
  'Connection': '连接',
  'Network backend, exit country, protocol and scanning': '网络后端、出口国家、协议与扫描',
  'Transport & anti-DPI': '传输与抗 DPI',
  'Obfuscation, endpoint, MTU and anti-DPI': '混淆、端点、MTU 与抗 DPI',
  'DNS & routing rules': 'DNS 与路由规则',
  'Resolvers inside the tunnel, block and bypass lists': '隧道内解析器、封堵与直连列表',
  'Upstream proxy (chaining)': '上游代理（链式）',
  'Dial out through a proxy already running on this PC': '通过本机已在运行的代理向外拨号',
  'Kill switch & leak protection': '终止开关与防泄漏',
  'What happens the moment the tunnel drops': '隧道断开瞬间会发生什么',
  'Join a Cloudflare organisation instead of plain WARP': '加入 Cloudflare 组织，而非普通 WARP',
  'Application': '应用',
  'Apps & LAN sharing': '应用与局域网共享',
  'Which programs use the tunnel, and who else may': '哪些程序使用隧道，还有谁可以使用',
  'Interface language': '界面语言',
  'Reset all settings to defaults': '将所有设置恢复为默认值',
  'Every setting goes back to its default, including endpoint ranges, routing rules and enrolment details.': '所有设置将恢复默认，包括端点范围、路由规则与注册信息。',
  'Reset every setting to its default?': '将所有设置恢复为默认值？',
  'The tunnel is running. Changes are saved now and handed to the engine the next time it starts — reconnect to apply them.': '隧道正在运行。更改会立即保存，并在引擎下次启动时下发——重新连接后生效。',
  'Home': '主页',
  'Advanced': '高级',
  'Diagnostics': '诊断',
  'Share over LAN': '局域网共享',
  'About': '关于',
  'Menu': '菜单',
  'Aether': 'Aether',
  'Freedom, in one tap': '一键即得自由',
  'Tap to connect securely': '点击安全连接',
  'Tap to disconnect': '点击断开',
  'Something went wrong': '出错了',
  'Verifying connection…': '正在验证连接…',
  'Disconnected': '已断开',
  'Starting engine…': '正在启动引擎…',
  'Connecting…': '正在连接…',
  'Verifying…': '正在验证…',
  'Connected': '已连接',
  'Reconnecting…': '正在重连…',
  'Disconnecting…': '正在断开…',
  'Connection failed': '连接失败',
  'Your IP': '你的 IP',
  'Server IP': '服务器 IP',
  'Checking IP…': '正在检查 IP…',
  'IP unavailable': 'IP 不可用',
  'Connected for': '已连接时长',
  'Protocol': '协议',
  'MASQUE×2': 'MASQUE×2',
  'Endpoint': '端点',
  'Latency': '延迟',
  'Download': '下载',
  'Upload': '上传',
  'Total': '总计',
  'Ping strength': 'Ping 强度',
  'Excellent': '极佳',
  'Good': '良好',
  'Fair': '一般',
  'Poor': '较差',
  'Measuring…': '测量中…',
  'Offline': '离线',
  'Connection safety': '连接安全',
  'Kill switch': '终止开关',
  'Block browser traffic if the tunnel drops': '隧道断开时封锁浏览器流量',
  'IPv6 leak protection': 'IPv6 泄漏防护',
  'Keep the IPv6 default route protected or block it safely': '保护 IPv6 默认路由或安全地封堵它',
  'Automatic reconnect attempts': '自动重连次数',
  'WebRTC protected — no IP leak': 'WebRTC 已受保护——无 IP 泄漏',
  'WebRTC is leaking your real IP': 'WebRTC 正在泄漏你的真实 IP',
  'Checking for WebRTC leaks…': '正在检查 WebRTC 泄漏…',
  'WebRTC leak test': 'WebRTC 泄漏测试',
  'Testing for WebRTC leaks…': '正在测试 WebRTC 泄漏…',
  'Language': '语言',
  'Scan mode': '扫描模式',
  'IP version': 'IP 版本',
  'Noize': 'Noize',
  'Turbo': '极速',
  'Balanced': '均衡',
  'Thorough': '彻底',
  'Stealth': '隐匿',
  'Ironclad': '铁壁',
  'Light': '轻量',
  'Firewall': '防火墙',
  'GFW': 'GFW',
  'Aggressive': '激进',
  'Automatic': '自动',
  'Manual peer': '手动端点',
  'Manual range': '手动范围',
  'Peer address': '对端地址',
  'Address range': '地址范围',
  'Off': '关',
  'Both': '双栈',
  'Quick reconnect': '快速重连',
  'Reconnect instantly after a drop': '断开后立即重连',
  'MASQUE over HTTP/2': 'MASQUE over HTTP/2',
  'Helps on networks that block HTTP/3': '在封堵 HTTP/3 的网络上有帮助',
  'Packet fragmentation': '数据包分片',
  'Splits the handshake to evade filtering': '拆分握手以规避过滤',
  'Encrypted Client Hello (auto)': '加密客户端握手 ECH（自动）',
  'Let other devices on your network use this tunnel': '让局域网内的其他设备使用此隧道',
  'Split tunneling': '分流',
  'Only these apps': '仅这些应用',
  'All except these': '除这些之外',
  'Applications': '应用列表',
  'One executable name per line.': '每行一个可执行文件名。',
  'Zero Trust': 'Zero Trust',
  'Team name': '团队名称',
  'Connect as a managed device of a Cloudflare Zero Trust organization. Leave empty for normal WARP.': '以 Cloudflare Zero Trust 组织的受管设备身份连接。留空则为普通 WARP。',
  'Sign-in method': '登录方式',
  'Email code': '邮箱验证码',
  'Service token': '服务令牌',
  'Access token': '访问令牌',
  'Access email': '访问邮箱',
  'A one-time code is sent to this mailbox on connect.': '连接时会有一次性验证码发送到此邮箱。',
  'Stored in memory only — never written to disk.': '仅存于内存——绝不写入磁盘。',
  'Gateway proxy': '网关代理',
  'Routing rules': '路由规则',
  'Blocked destinations': '封堵目标',
  'One rule per line — domain, IP or CIDR. These connections are refused.': '每行一条规则——域名、IP 或 CIDR。这些连接将被拒绝。',
  'Direct destinations': '直连目标',
  'One rule per line. These bypass the tunnel — for banking apps, LAN services and domestic sites.': '每行一条规则。这些目标绕过隧道——适用于银行应用、局域网服务和国内网站。',
  'In-tunnel DNS servers': '隧道内 DNS 服务器',
  'Resolvers used inside the tunnel. Empty = engine defaults.': '隧道内使用的解析器。留空 = 引擎默认。',
  'These features need engine core 1.5.0 or newer. The bundled core is older, so they are disabled.': '这些功能需要 1.5.0 或更新的引擎核心。内置核心较旧，因此已禁用。',
  'Upstream proxy': '上游代理',
  'Proxy address': '代理地址',
  'Aether dials out through this proxy — use it to chain behind another VPN or proxy already running on this PC. Empty = direct.': 'Aether 通过此代理向外拨号——用于在本机已有的 VPN 或代理后面做链式。留空 = 直连。',
  'That is not a proxy address Aether can use. Expected socks5://host:port or http://host:port — the port is required.': '这不是 Aether 可用的代理地址。应为 socks5://host:port 或 http://host:port——端口必填。',
  'An HTTP proxy cannot carry UDP, so MASQUE is switched to HTTP/2 automatically and WireGuard / WARP×2 will not pass through it. Use a SOCKS5 proxy for those.': 'HTTP 代理无法承载 UDP，因此 MASQUE 会自动切换到 HTTP/2，而 WireGuard / WARP×2 无法通过它。这些协议请使用 SOCKS5 代理。',
  'SOCKS5 with UDP support carries every protocol: MASQUE, WireGuard and WARP×2.': '支持 UDP 的 SOCKS5 可承载所有协议：MASQUE、WireGuard 与 WARP×2。',
  'Match domain rules by real host name': '按真实主机名匹配域名规则',
  'Reads the name from the first bytes (TLS SNI or HTTP Host), so domain rules keep working even though Windows hands the tunnel an IP address': '从首字节读取主机名（TLS SNI 或 HTTP Host），即使 Windows 交给隧道的是 IP 地址，域名规则也能继续生效',
  'Account identity': '账户身份',
  'Replace a refused identity': '更换被拒绝的身份',
  'If Cloudflare stops accepting the saved device, register a fresh one instead of handshaking a tunnel that carries no traffic': '如果 Cloudflare 不再接受已保存的设备，就注册一个全新设备，而不是反复握手一条不载客的隧道',
  'The upstream proxy, host-name routing and identity replacement need engine core 1.7.0 or newer. The bundled core is older, so they are disabled.': '上游代理、主机名路由与身份更换需要 1.7.0 或更新的引擎核心。内置核心较旧，因此已禁用。',
  'Reset to defaults': '恢复默认',
  'Restores every setting above to its factory value': '将以上所有设置恢复为出厂值',
  'Reset': '重置',
  'Run the test to verify connectivity': '运行测试以验证连通性',
  'A problem was detected — see the failing check': '检测到问题——查看未通过项',
  'All checks passed — traffic should flow': '全部检查通过——流量应当正常',
  'Testing connectivity…': '正在测试连通性…',
  'Run test': '运行测试',
  'Copy logs': '复制日志',
  'Clear': '清空',
  'Environment check': '环境检查',
  'Log': '日志',
  'No logs yet. Connect or run a test.': '暂无日志。请连接或运行测试。',
  'Logs copied to clipboard': '日志已复制到剪贴板',
  'Running…': '运行中…',
  'Other devices on the same Wi‑Fi can route their traffic through this computer. Point them at one of the addresses below.': '同一 Wi-Fi 下的其他设备可将流量经由本机转发。将它们指向下面的任一地址。',
  'Enable sharing': '启用共享',
  'Only listens on your local network address.': '只监听你的局域网地址。',
  'Copy': '复制',
  'Sharing only works while Aether is connected.': '只有 Aether 处于连接状态时共享才有效。',
  'Both ports accept HTTP and SOCKS5 automatically — either port works in either field.': '两个端口都自动识别 HTTP 与 SOCKS5——任一字段填任一端口都可以。',
  'Apps like Telegram ignore the system proxy; set a SOCKS5 proxy inside the app instead.': 'Telegram 之类的应用会忽略系统代理；请在该应用内设置 SOCKS5 代理。',
  'App version': '应用版本',
  'Core version': '核心版本',
  'Architecture': '架构',
  'Credits, links & what this build adds': '致谢、链接与本构建的新增内容',
  'Version': '版本',
  'Original project — Cluvex Studio': '原项目——Cluvex Studio',
  'The core engine powering this app': '驱动本应用的核心引擎',
  'Windows edition — QW-AI-Code': 'Windows 版——QW-AI-Code',
  'The native Windows desktop edition of Aether — what we upgraded in this build': 'Aether 的原生 Windows 桌面版——本构建升级的内容',
  'Show': '显示',
  'Hide': '隐藏',
  'API key saved.': 'API 密钥已保存。',
  'API key removed': 'API 密钥已移除',
  'Test the API connection': '测试 API 连接',
  'Testing…': '测试中…',
  'Checks the key and lists the models it may use': '检查密钥并列出它可用的模型',
  'Working — {0} model(s) available through {1}': '正常——通过 {1} 有 {0} 个可用模型',
  'Not working: {0}': '不可用：{0}',
  'Tor': 'Tor',
  'Bridges': '网桥',
  'How Tor reaches the network when it is blocked.': 'Tor 被封时如何接入网络。',
  'Not needed in this mode: Tor is dialled through the Aether tunnel, so the network you are on never sees it.': '此模式下无需网桥：Tor 通过 Aether 隧道拨号，所在网络完全看不到它。',
  'Always': '始终',
  'Bridge country': '网桥国家',
  'Detect automatically': '自动检测',
  'Which country bridgedb hands out bridges for. Detection asks the network where you are, which is the request most likely to fail here.': 'bridgedb 为哪个国家发放网桥。检测会向网络询问你的位置，而这正是当前最可能失败的请求。',
  'Bootstrap patience': '引导耐心',
  'Automatic (75 s)': '自动（75 秒）',
  '{0} seconds': '{0} 秒',
  'How long Tor tries the direct path before falling back to bridges. Shorten it where Tor is definitely blocked.': 'Tor 在回退到网桥之前尝试直连的时长。在 Tor 必被封的网络请调短。',
  'Own bridge lines': '自有网桥',
  'One per line, in the format bridges.torproject.org hands out. Leave empty to use the bridges the app fetches for your country. A line naming a transport the app does not ship is ignored.': '每行一条，格式与 bridges.torproject.org 发放的相同。留空则使用应用为你的国家获取的网桥。应用未内置的传输所在的行会被忽略。',
  'Reachability check': '可达性检查',
  'The address Tor must reach before the bootstrap counts as working. Change it only if bootstrap keeps failing on a Tor that seems fine \u2014 the default target is itself blocked on some networks.': '引导被视为有效前 Tor 必须能到达的地址。仅当引导一直失败而 Tor 看似正常时才修改——默认目标在某些网络本身就被封。',
  'Tor carries TCP only \u2014 in every app, on every platform. Aether answers DNS over TCP inside Tor and drops other UDP, so QUIC-capable apps fall back to TCP. That is normal and nothing is leaking: dropped UDP goes nowhere, least of all around Tor. Expect noticeably higher latency, and expect the first connect to take a while \u2014 Tor downloads its directory before it can build a circuit.': 'Tor 只承载 TCP— 在任何应用、任何平台上都是如此。Aether 在 Tor 内用 TCP 回应 DNS 并丢弃其余 UDP，因此支持 QUIC 的应用会回退到 TCP。这是正常现象，没有任何泄漏：被丢弃的 UDP 不会去任何地方，更不会绕过 Tor。延迟会明显升高，首次连接也需要更久— Tor 要先下载目录才能建立链路。',
  'Fixed to MASQUE over HTTP/2 in this mode. Tor carries TCP only and WARP\u2019s WireGuard endpoints answer on UDP alone, so the engine refuses WireGuard and WARP\u00d72 here.': '此模式下固定为 MASQUE over HTTP/2。Tor 只承载 TCP，而 WARP 的 WireGuard 端点只在 UDP 应答，因此引擎在此模式下拒绝 WireGuard 与 WARP×2。',
  'Tor chooses its own exit node, and a new one per circuit. No setting can pin it to a country.': 'Tor 自行选择出口节点，且每条链路都不同。任何设置都无法将其固定到某个国家。',
  'The Tor modes need engine core 2.0.0 or newer. The bundled core is older, so they are disabled.': 'Tor 模式需要引擎核心 2.0.0 或更新。内置核心较旧，因此已禁用。',
  'Reaching the Tor network… {0}%': '正在接入 Tor 网络… {0}%',
  'Reaching the Tor network…': '正在接入 Tor 网络…',
  'Tor is not getting through directly — trying bridges…': 'Tor 无法直连——正在尝试网桥…',
  'Tor is ready — opening its local proxy…': 'Tor 已就绪——正在打开其本地代理…',
  'One hop through the bundled Aether/WARP engine. Fastest.': '经由内置 Aether/WARP 引擎的一跳。最快。',
  'Two hops: Aether connects first, then Psiphon tunnels through it. Your exit IP becomes Psiphon\u2019s, so sites that block Aether/WARP addresses open again.': '两跳：先连 Aether，再由 Psiphon 在其中隧道。出口 IP 变为 Psiphon 的，被封 Aether/WARP 地址的网站即可重新打开。',
  'Tor alone, without the Aether tunnel. Your exit is a Tor exit node and your traffic passes three relays, which is the slowest and the most private of the modes. Tor has to reach the Tor network by itself here, so it uses bridges when it is blocked.': '仅 Tor，不经过 Aether 隧道。出口为 Tor 出口节点，流量经过三个中继，是最慢也最隐私的模式。此模式下 Tor 必须自行接入 Tor 网络，被封时会使用网桥。',
  'Two hops: Aether connects first, then Tor is built INSIDE that tunnel. The network you are on sees only Aether\u2019s obfuscated transport, never Tor \u2014 so this is the mode to use where Tor is blocked. Your exit is a Tor exit node.': '两跳：先连 Aether，然后 Tor 在该隧道之内构建。所在网络只能看到 Aether 的混淆传输，看不到 Tor— 所以在封 Tor 的地方请用此模式。出口为 Tor 出口节点。',
  'Three hops: Tor first, then Psiphon dialled through it. Your exit IP is Psiphon\u2019s, reached from a Tor address, so sites that block Tor exit nodes open again while your own address stays behind Tor. The slowest mode.': '三跳：先 Tor，再经其拨号 Psiphon。出口 IP 为 Psiphon 的，但从 Tor 地址到达，因此封 Tor 出口的网站也能打开，同时你的真实地址仍藏在 Tor 之后。最慢的模式。',
  'The reverse chain: Tor first, then the Aether tunnel built INSIDE it. Your exit is a WARP address \u2014 the same as plain Aether \u2014 but the network you are on sees only Tor, and cannot tell that a VPN tunnel exists at all. Use it where Cloudflare/WARP itself is blocked or throttled but Tor still gets through. Carries normal UDP, unlike the Tor-exit modes.': '反向链：先 Tor，然后 Aether 隧道在其内构建。出口是 WARP 地址——与普通 Aether 相同—— 但所在网络只看得到 Tor，完全无法察觉 VPN 隧道的存在。适用于 Cloudflare/WARP 本身被封或被限速、而 Tor 仍可用的网络。与 Tor 出口模式不同，它承载普通 UDP。',
  'TUN mode (virtual adapter)': 'TUN 模式（虚拟网卡）',
  "Route HTTP/HTTPS through your organization's Gateway (adds a hop and logs browsing)": '让 HTTP/HTTPS 流量经由你所在组织的网关（多加一跳，并会记录浏览记录）',
  'Route all traffic through the Aether adapter instead of the system proxy': '让全部流量经由 Aether 虚拟网卡而非系统代理转发',
};

// <<< AETHER-APP-FIX chinese-interface

export function getLang() {
  return current
}

export function setLang(lang) {
  current = lang === 'fa' ? 'fa' : lang === 'zh' ? 'zh' : 'en'
  try {
    localStorage.setItem(STORAGE_KEY, current)
  } catch { /* بی‌اثر */ }
  applyLang()
}

/** جهت و فونت کل سند را با زبان فعلی هماهنگ می‌کند. */
export function applyLang() {
  const fa = current === 'fa'
  const html = document.documentElement
  html.lang = current === 'zh' ? 'zh-CN' : fa ? 'fa' : 'en'
  html.dir = fa ? 'rtl' : 'ltr' // 中文与英文同为左到右；只有波斯语翻转方向
  document.body.classList.toggle('lang-fa', fa)
  document.body.classList.toggle('lang-zh', current === 'zh')
}

/** ترجمهٔ یک رشتهٔ رابط — کلید = متن انگلیسی. */
/**
 * `<bdi>` را به جداسازهای دوسویهٔ یونیکد تبدیل می‌کند و هر تگِ دیگر را دور
 * می‌ریزد.
 *
 * # چرا این تابع وجود دارد
 *
 * ترجمه‌های فارسی برای محافظت از تکه‌های لاتین (`chrome.exe`، `SOCKS5`) از
 * `<bdi>` استفاده می‌کنند، و `app.css` هم قاعده‌ای برایش دارد. ولی همهٔ نماها
 * متن را با `textContent` می‌نشانند — که تنها راه درست است، چون یک رشتهٔ ترجمه
 * هرگز نباید به‌عنوان HTML اجرا شود. نتیجه این بود که کاربر عیناً
 * `<bdi>chrome.exe</bdi>` را روی صفحه می‌دید.
 *
 * `U+2068 FIRST STRONG ISOLATE` و `U+2069 POP DIRECTIONAL ISOLATE` دقیقاً همان
 * کاری را می‌کنند که `<bdi>` می‌کرد — جداسازیِ دوسویه — ولی نویسه‌اند و نه
 * نشانه‌گذاری، پس در `textContent` هم کار می‌کنند و هیچ راهی برای تزریق باز
 * نمی‌کنند.
 */
export function isolateBidi(text) {
  if (typeof text !== 'string' || !text.includes('<')) return text
  return text
    .replace(/<bdi>/g, '\u2068')
    .replace(/<\/bdi>/g, '\u2069')
    // هر تگِ دیگری که از قلم افتاده باشد پاک می‌شود: به کاربر نشان دادنِ
    // `<b>` بهتر از اجرایش نیست.
    .replace(/<[^>]*>/g, '')
}

export function t(key) {
  if (current === 'fa') return isolateBidi(FA[key] ?? numbered(key, FA) ?? key)
  if (current === 'zh') return isolateBidi(ZH[key] ?? numbered(key, ZH) ?? key)
  return isolateBidi(key)
}

/// دومین تلاشِ ترجمه برای جمله‌هایی که یک عدد داخلشان است.
///
/// وضعیتِ اتصال از سمتِ Rust به‌صورت **جملهٔ کامل** می‌آید (`snapshot.detail`)،
/// پس جمله‌ای مثل «Tor stopped at 15% …» هیچ‌وقت در جدولی که به متنِ دقیق کلید
/// می‌زند پیدا نمی‌شود — و درست همان جمله‌ای است که کاربر در لحظهٔ خطا می‌خواند.
/// این‌جا عدد با {0} جایگزین می‌شود، ترجمه پیدا می‌شود، و عدد سرِ جایش برمی‌گردد.
function numbered(key, table) {
  const digits = key.match(/\d+/)
  if (!digits) return null
  const pattern = key.replace(/\d+/, '{0}')
  const hit = table[pattern]
  return hit ? hit.replace('{0}', digits[0]) : null
}
