این سناریو برای مصاحبه‌ی SOC T2 / Threat Hunter خیلی مهم است؛ چون ترکیبِ «ایجاد یک Process جدید» و «برقراری اتصال خارجی بلافاصله پس از اجرا» می‌تواند نشانه‌ای از اجرای بدافزار، ارتباط با C2 یا دانلود مرحله‌ی بعدی حمله باشد. اما یک نکته‌ی کلیدی وجود دارد:

صرفِ نزدیک بودن زمانیِ ایجاد Process و اتصال شبکه‌ای، به‌تنهایی اثبات نمی‌کند که Process مخرب است یا خودش اتصال را ایجاد کرده است. باید رابطه‌ی بین Process و اتصال را با Telemetry معتبر بررسی کنیم.

# سناریو: ایجاد Process جدید و برقراری فوری اتصال خارجی

## 1. Hunt Objective & Hypothesis — هدف و فرضیه

هدف من این است که مشخص کنم آیا اتصال خارجی بخشی از رفتار عادی برنامه است یا نشان‌دهنده‌ی فعالیت مشکوک.

فرضیه‌هایی که بررسی می‌کنم:

- H1 — ارتباط C2: Process پس از اجرا با زیرساخت فرماندهی و کنترل مهاجم ارتباط گرفته است.
- H2 — دانلود یا اجرای مرحله‌ی بعدی: Process برای دریافت فایل، Payload یا دستورات بیشتر به اینترنت متصل شده است.
- H3 — اجرای عادی برنامه: برنامه برای Update، احراز هویت، API یا سرویس ابری خودش ارتباط برقرار کرده است.
- H4 — اجرای Process توسط یک والد مشکوک: یک Process غیرعادی، برنامه‌ای را اجرا کرده که سپس به مقصد خارجی متصل شده است.

نکته‌ی مهم: فرضیه‌ها را از ابتدا قطعی فرض نمی‌کنم؛ هدف Hunt جمع‌آوری شواهد برای تأیید یا رد آن‌هاست.

## 2. Telemetry & Data Sources — چه داده‌هایی لازم دارم؟

Process Creation — ساخت پردازش

Sysmon Event ID 1، Windows Event ID 4688، یا EDR Process Telemetry

نام و مسیر فایل، Command Line، Process والد، حساب کاربری، زمان اجرا، Hash و شناسه‌ی یکتای Process.

Network Connection — اتصال شبکه

Sysmon Event ID 3، EDR Network Events، Firewall، Proxy و DNS

زمان اتصال، IP و دامنه‌ی مقصد، پورت، پروتکل، Process مرتبط و در صورت دسترس، حجم داده‌های ارسالی و دریافتی.

Supporting Telemetry — شواهد تکمیلی

Sysmon Event ID 7، رویدادهای فایل، امضای دیجیتال، DNS و EDR

برای بررسی DLLهای بارگذاری‌شده، منشأ فایل، رفتار پس از اتصال و احتمال اجرای Payload یا فعالیت‌های مشکوک دیگر.

محدودیت مهم: Sysmon Event ID 3 باید از قبل فعال و پیکربندی شده باشد. همچنین Windows Event ID 4688 به‌تنهایی معمولاً جزئیات کامل اتصال شبکه را نشان نمی‌دهد؛ برای ارتباط دقیق Process و اتصال، EDR مناسب‌تر است.

## 3. Hunt Execution & Queries — اجرای Hunt

### مرحله‌ی اول: Process مشکوک را پیدا می‌کنم

اگر محیط ما Microsoft Defender XDR باشد، از جدول `DeviceProcessEvents` برای مشاهده‌ی ساخت پردازش استفاده می‌کنم.

```
DeviceProcessEvents
| where Timestamp > ago(24h)
| project
    Timestamp,
    DeviceName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    ProcessId,
    ProcessUniqueId,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    InitiatingProcessUniqueId,
    AccountName,
    SHA1
| order by Timestamp desc
```

این Query همه‌ی Processهای ثبت‌شده در ۲۴ ساعت گذشته را نشان می‌دهد. در این مرحله دنبال مواردی مثل اجرای فایل از مسیرهای موقت، Command Line غیرعادی، والد ناشناس یا اجرای برنامه توسط Office، اسکریپت‌ها و Processهای غیرمنتظره هستم.

چرا از ابتدا فقط Processهای دارای اتصال خارجی را فیلتر نمی‌کنم؟ چون ابتدا می‌خواهم زمینه‌ی اجرای Process را ببینم و از حذف زودهنگام سرنخ‌های مهم جلوگیری کنم.

### مرحله‌ی دوم: اتصال خارجی را به Process مرتبط می‌کنم

در Defender XDR، جدول `DeviceNetworkEvents` برای بررسی اتصال‌های شبکه مناسب است.

```
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| project
    Timestamp,
    DeviceName,
    InitiatingProcessFileName,
    InitiatingProcessFolderPath,
    InitiatingProcessCommandLine,
    InitiatingProcessId,
    InitiatingProcessUniqueId,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    Protocol,
    ActionType
| order by Timestamp desc
```

این Query اتصال‌های ثبت‌شده به IPهای عمومی را بررسی می‌کند؛ اما چند محدودیت دارد:

- `Public IP` الزاماً مخرب نیست.
- بعضی اتصال‌ها از طریق Proxy یا سرویس‌های واسط انجام می‌شوند و مقصد نهایی ممکن است مستقیماً مشخص نباشد.
- نام دامنه یا IP به‌تنهایی برای قضاوت کافی نیست.
- اگر رویداد شبکه ثبت نشده باشد، نبود نتیجه به معنای نبود اتصال نیست.

### مرحله‌ی سوم: ارتباط زمانی را بررسی می‌کنم

برای یک Process مشخص، زمان ساخت و زمان اولین اتصال شبکه را مقایسه می‌کنم. در این نمونه، از شناسه‌ی یکتای Process استفاده می‌کنیم تا احتمال اشتباه ناشی از استفاده‌ی مجدد از PID کاهش یابد.

```
let Proc =
    DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where isnotempty(ProcessUniqueId)
    | project
        DeviceId,
        DeviceName,
        ProcessUniqueId,
        ProcessStart = Timestamp,
        FileName,
        FolderPath,
        ProcessCommandLine,
        ParentProcess = InitiatingProcessFileName,
        ParentCommandLine = InitiatingProcessCommandLine,
        SHA1;
let Net =
    DeviceNetworkEvents
    | where Timestamp > ago(24h)
    | where isnotempty(InitiatingProcessUniqueId)
    | project
        DeviceId,
        DeviceName,
        ProcessUniqueId = InitiatingProcessUniqueId,
        ConnectionTime = Timestamp,
        RemoteIP,
        RemotePort,
        RemoteUrl,
        Protocol;
Proc
| join kind=inner Net
    on DeviceId, DeviceName, ProcessUniqueId
| where ConnectionTime >= ProcessStart
| extend DelaySeconds =
    datetime_diff("second", ConnectionTime, ProcessStart)
| where DelaySeconds between (0 .. 60)
| project
    ProcessStart,
    ConnectionTime,
    DelaySeconds,
    DeviceName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    ParentProcess,
    ParentCommandLine,
    RemoteIP,
    RemotePort,
    RemoteUrl,
    Protocol,
    SHA1
| order by DelaySeconds asc
```

این Query نمونه، اتصال‌هایی را پیدا می‌کند که در ۶۰ ثانیه‌ی پس از ایجاد Process رخ داده‌اند.

تفسیر نتیجه: اگر اتصال ۲ ثانیه بعد رخ داده باشد، یک سرنخ برای بررسی بیشتر داریم؛ نه اثبات C2. همچنین ممکن است یک Process مدت‌ها اجرا شده باشد و بعداً اتصال برقرار کند، یا ارتباط از طریق Process دیگری انجام شده باشد.

نکته‌ی فنی: این Query به موجود بودن و سازگاری `ProcessUniqueId` در هر دو جدول وابسته است. اگر این فیلد در Telemetry محیط شما در دسترس نباشد، باید از شناسه‌های جایگزین و همبستگی زمان، دستگاه و Process ID استفاده کرد؛ با این محدودیت که احتمال اتصال اشتباه بیشتر می‌شود.

## 4. Pivoting & Evidence Correlation — از کجا به کجا Pivot می‌کنم؟

پس از یافتن یک Process مشکوک، بررسی را در چند مسیر ادامه می‌دهم.

Process Creation

نام، مسیر، Command Line و زمان اجرا

Process ↔ Network

شناسه‌ی Process، زمان، IP، پورت و دامنه

Process Tree

والد، فرزندان و زنجیره‌ی اجرای Processها

Destination

اعتبار دامنه، IP، پورت و سابقه‌ی ارتباط

File & Hash

امضای دیجیتال، منشأ فایل و Hash

Post-Execution

فایل‌سازی، Persistence، اسکریپت و فعالیت‌های بعدی

سؤالات کلیدی که در این مرحله پاسخ می‌دهم:

- آیا Process والد نیز مشکوک است؟ مثلاً یک فایل دانلودشده یا یک سند Office آن را اجرا کرده؟
- آیا اتصال واقعاً متعلق به همین Process است یا فقط در همان بازه‌ی زمانی روی همان میزبان اتفاق افتاده؟
- آیا مقصد با سرویس تجاری شناخته‌شده، CDN، Update Server یا زیرساخت مشکوک تطابق دارد؟
- آیا همین Hash، Command Line یا مقصد شبکه روی میزبان‌های دیگر هم دیده شده؟
- آیا پس از اتصال، Process فایل جدیدی ساخته، دسترسی غیرعادی گرفته یا ارتباط‌های دیگری برقرار کرده است؟

بهترین حالت این است که شواهد مستقل را کنار هم قرار دهم؛ مثلاً Process مشکوک + مقصد غیرمنتظره + دریافت فایل + اجرای فایل دریافتی از یک اتصال خارجی منفرد، شواهد بسیار قوی‌تری ایجاد می‌کند.

## 5. Validation & Scope — اعتبارسنجی و تعیین گستره

پیش از اعلام Incident، این موارد را بررسی می‌کنم:

1. اعتبار Process: مسیر فایل، امضای دیجیتال، Hash، نسخه و منشأ آن.
2. اعتبار مقصد: دامنه و IP، مالکیت زیرساخت، سابقه‌ی ارتباط و ارتباط آن با فعالیت سازمان.
3. تأیید رابطه: اتصال شبکه را با شناسه‌ی یکتای Process و Telemetry مستقل بررسی می‌کنم؛ هم‌زمانی زمانی به‌تنهایی کافی نیست.
4. بررسی رفتار بعدی: آیا Download، اجرای کد، Persistence، Credential Access یا ارتباط تکرارشونده مشاهده شده است؟
5. گسترش Hunt: با Hash، نام فایل، Command Line، دامنه/IP و الگوی رفتاری، سایر میزبان‌ها را جست‌وجو می‌کنم.

اگر اتصال با یک سرویس مجاز مرتبط باشد و رفتار پس از اجرا نیز طبیعی باشد، فرضیه‌ی فعالیت مخرب تضعیف می‌شود. اگر چند شاخص مستقل و معتبر با هم هم‌راستا باشند، سطح اطمینان افزایش پیدا می‌کند.

## 6. MITRE ATT&CK Mapping — نگاشت احتمالی

نگاشت را بر اساس رفتار اثبات‌شده انجام می‌دهم، نه صرفاً بر اساس ایجاد Process یا اتصال خارجی.

| رفتار مشاهده‌شده                                            | تکنیک احتمالی                                                               |
| ----------------------------------------------------------- | --------------------------------------------------------------------------- |
| ارتباط با زیرساخت فرماندهی و کنترل، در صورت وجود شواهد کافی | T1071 — Application Layer Protocol، در صورت تطبیق با پروتکل مشاهده‌شده      |
| دریافت ابزار یا Payload از شبکه                             | T1105 — Ingress Tool Transfer                                               |
| اجرای فرمان از طریق Command Interpreter                     | T1059 — Command and Scripting Interpreter، فقط در صورت مشاهده‌ی شواهد مربوط |
| استفاده از پروتکل‌های وب برای ارتباط C2                     | T1071.001 — Web Protocols، در صورت تأیید رفتار                              |

یک اتصال HTTPS به‌تنهایی برای نگاشت T1071.001 یا اعلام C2 کافی نیست؛ باید شواهد ارتباطی و زمینه‌ی رفتاری با تکنیک موردنظر تطابق داشته باشد.

## 7. Conclusion & Confidence — نتیجه‌گیری و سطح اطمینان

در پایان، نتیجه را در یکی از این سطوح بیان می‌کنم:

- مشکوک (Suspicious): Process جدید و اتصال خارجی نزدیک به زمان اجرا مشاهده شده، اما شواهد کافی برای اثبات فعالیت مخرب نداریم.
- نیازمند بررسی بیشتر (Inconclusive): داده‌های مهم، مانند شناسه‌ی Process یا جزئیات اتصال، ناقص هستند و نمی‌توان رابطه‌ی قطعی برقرار کرد.
- تأییدشده به‌عنوان فعالیت مخرب (Confirmed Malicious): شواهد معتبر و هم‌بسته، مانند رفتار مخرب تأییدشده، Payload شناخته‌شده یا ارتباط C2 مستند، از نتیجه پشتیبانی می‌کنند.

در گزارش Hunt باید زمان رویدادها، میزبان، Process، مقصد، شواهد پشتیبان، محدودیت‌های داده و سطح اطمینان را ثبت کنم. «اتصال خارجی» را با «نشت اطلاعات» یا «اجرای موفق بدافزار» یکی نمی‌گیرم؛ هرکدام به شواهد جداگانه نیاز دارند.

## 8. Response & Detection Improvement — واکنش و بهبود Detection

اگر فعالیت مخرب تأیید شود یا خطر فوری و معتبری وجود داشته باشد:

- میزبان را مطابق رویه‌ی Incident Response سازمان مهار می‌کنم.
- در صورت امکان، شواهد EDR، اطلاعات Process، فایل، Hash و لاگ‌های شبکه را حفظ می‌کنم.
- ارتباط با مقصد مشکوک را با در نظر گرفتن اثر جانبی مسدود می‌کنم؛ نه اینکه هر IP خارجی را بدون اعتبارسنجی Block کنم.
- سایر میزبان‌ها را بر اساس Hash، مقصد، Command Line و رفتار مشابه بررسی می‌کنم.
- Detection را طوری بهبود می‌دهم که صرفاً به «Process جدید + اتصال خارجی» متکی نباشد؛ بلکه زمینه‌ی اجرا، اعتبار فایل، مقصد و رفتارهای بعدی را نیز لحاظ کند.

برای مثال، یک Detection با کیفیت بالاتر می‌تواند Processهایی را اولویت‌بندی کند که از مسیر غیرمعمول اجرا شده‌اند، والد مشکوک دارند و بلافاصله به مقصدی غیرمنتظره متصل می‌شوند. این ترکیب معمولاً از یک قانون ساده‌ی مبتنی بر زمان، هشدار مفیدتری تولید می‌کند.

## پاسخ کوتاه برای شروع جواب در مصاحبه

ابتدا Process Creation و Network Telemetry را بررسی می‌کنم تا مشخص شود چه پردازشی، با چه Command Line و توسط کدام Process والد اجرا شده و چه زمانی به مقصد خارجی متصل شده است.

سپس با استفاده از شناسه‌ی یکتای Process، در صورت دسترس، اتصال را به همان پردازش مرتبط می‌کنم و مسیر فایل، Hash، امضای دیجیتال، مقصد شبکه و رفتارهای پس از اجرا را بررسی می‌کنم.

در مرحله‌ی بعد، با Pivot کردن روی Hash، دامنه یا IP مقصد و الگوی اجرای Process، سایر میزبان‌ها را بررسی می‌کنم تا گستره‌ی احتمالی فعالیت مشخص شود.

نکته‌ی مهم این است که ایجاد Process و اتصال خارجی بلافاصله پس از آن، به‌تنهایی اثبات‌کننده‌ی بدافزار یا C2 نیست. تصمیم نهایی را بر اساس شواهد هم‌بسته می‌گیرم و در صورت تأیید تهدید، اقدامات مهار و بهبود Detection را پیشنهاد می‌کنم.
