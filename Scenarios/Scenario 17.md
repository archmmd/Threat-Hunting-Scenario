# Threat Hunt Scenario: PowerShell Abuse بدون IOC

سطح: SOC T2 / Threat Hunter | بازه بررسی: ۳۰ روز گذشته | رویکرد: Behavior-Based Hunting

در این سناریو، هیچ IOC مشخصی مثل Hash، IP، Domain یا نام فایل مخرب نداریم. بنابراین نمی‌توانیم صرفاً دنبال یک Indicator بگردیم؛ باید رفتار PowerShell را بررسی کنیم، الگوهای غیرعادی را پیدا کنیم و با شواهد مستقل اعتبارسنجی کنیم.

نکته کلیدی این است که استفاده از PowerShell به‌خودی‌خود نشانه حمله نیست. هدف ما شناسایی مواردی است که با رفتار عادی کاربران، ادمین‌ها و ابزارهای مدیریتی سازمان سازگار نیستند.

## ۱. Hypothesis — فرضیه شکار

فرضیه اصلی:

در ۳۰ روز گذشته، یک یا چند کاربر یا فرایند از PowerShell برای اجرای دستورات مشکوک، شناسایی محیط، اجرای Payload، برقراری ارتباط شبکه یا ایجاد ماندگاری استفاده کرده‌اند؛ اما این فعالیت‌ها الزاماً با IOC شناخته‌شده قابل شناسایی نیستند.

برای جلوگیری از تأیید سوگیرانه فرضیه، چند فرضیه جایگزین هم بررسی می‌کنیم:

| فرضیه                       | رفتار مورد انتظار                                                     |
| --------------------------- | --------------------------------------------------------------------- |
| H1 — اجرای مخرب             | PowerShell با دستورات مشکوک، فرایند والد غیرعادی یا رفتار پس از اجرا  |
| H2 — Discovery              | جمع‌آوری اطلاعات سیستم، کاربران، دامنه یا تنظیمات امنیتی              |
| H3 — Download / Execution   | دریافت محتوای خارجی و تلاش برای اجرای آن                              |
| H4 — Persistence یا Evasion | تغییرات ماندگار، تلاش برای دور زدن کنترل‌ها یا مخفی‌کردن فعالیت       |
| H5 — فعالیت مجاز            | اسکریپت‌های ادمینی، ابزارهای Deployment، مانیتورینگ یا Scheduled Task |

این‌ها فرضیه‌های قابل‌آزمایش‌اند، نه نتیجه‌گیری درباره وقوع حمله.

## ۲. Data Sources — منابع داده

اولویت را به منابعی می‌دهیم که هم دستور اجراشده را نشان دهند و هم امکان اتصال آن به فرایندها و فعالیت‌های بعدی را فراهم کنند.

PowerShell Operational Log

Event ID 4104 و 4103

- `4104`: محتوای Script Block، در صورت فعال بودن ثبت مناسب.
- `4103`: جزئیات Module Logging، در صورت فعال بودن.
- برای فهمیدن محتوای اسکریپت، این لاگ‌ها بسیار ارزشمندند؛ اما نبودشان به معنای نبود فعالیت مشکوک نیست.

Windows Security / Sysmon / EDR

Security 4688، Sysmon Event ID 1، EDR Process Telemetry

مشخص می‌کنند PowerShell توسط چه فرایندی اجرا شده، چه Command Lineای داشته، روی کدام میزبان بوده و فرایند والد آن چه بوده است. در دسترس بودن Command Line به پیکربندی ثبت رویداد وابسته است.

Network Telemetry

EDR Network Events، DNS، Proxy و Firewall

برای بررسی ارتباطات خارجی، DNS Resolution، مقصدهای جدید و احتمال Download یا ارتباط فرماندهی و کنترل. مشاهده اتصال به‌تنهایی اثبات C2 یا Exfiltration نیست.

منابع تکمیلی

Scheduled Tasks، Windows Services، Defender Logs، تغییرات Registry، اطلاعات حساب‌ها و سوابق مدیریت Endpoint؛ برای بررسی Persistence، Defense Evasion و تفکیک فعالیت مجاز از مخرب.

محدودیت مهم: اگر Script Block Logging فعال نبوده باشد، ممکن است فقط Command Line یا شواهد ناقص EDR در دسترس باشند. باید پوشش لاگ را برای هر میزبان مشخص کنیم.

## ۳. Query Strategy — استراتژی جست‌وجو

من Hunt را در چهار مرحله اجرا می‌کنم؛ از جست‌وجوی گسترده شروع می‌کنم و بعد به رفتارهای مشخص‌تر Pivot می‌زنم.

## 1

Baseline و پوشش داده

مشخص می‌کنم در ۳۰ روز گذشته کدام میزبان‌ها PowerShell اجرا کرده‌اند، چه حساب‌هایی استفاده شده‌اند و آیا لاگ‌های لازم روی میزبان‌های مهم وجود دارند.

## 2

Behavioral Search

جست‌وجوی الگوهایی مانند `-EncodedCommand`، گزینه‌های مخفی‌سازی، Download، اجرای محتوای پویا و دستورات Discovery. این الگوها به‌تنهایی اثبات حمله نیستند.

## 3

Process و Network Correlation

بررسی می‌کنم چه چیزی PowerShell را اجرا کرده و آیا بعد از آن فرایند غیرعادی، اتصال شبکه یا تغییر امنیتی رخ داده است.

## 4

Triage و اعتبارسنجی

موارد پیدا‌شده را با رفتار تاریخی میزبان، وظیفه حساب کاربری، تغییرات اخیر و شواهد مستقل مقایسه می‌کنم.

### Query 1 — پیدا کردن اجرای PowerShell در Microsoft Defender XDR

این Query یک نقطه شروع برای بررسی ۳۰ روز گذشته است.

```

DeviceProcessEvents
| where Timestamp >= ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| project
    Timestamp,
    DeviceName,
    AccountDomain,
    AccountName,
    FileName,
    ProcessCommandLine,
    ProcessId,
    ProcessCreationTime,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    InitiatingProcessId
| order by Timestamp desc

```

چه چیزی از این Query می‌گیریم؟

- چه میزبان‌هایی PowerShell اجرا کرده‌اند؟
- کدام حساب‌ها بیشتر از آن استفاده کرده‌اند؟
- PowerShell توسط چه فرایندی اجرا شده است؟
- آیا Command Line شامل آرگومان‌های غیرمعمول است؟

این Query فهرست اجرای PowerShell را می‌دهد، نه فهرست حملات. همچنین باید بررسی کنیم که `DeviceProcessEvents` پوشش موردنیاز و داده‌های کامل را برای تمام میزبان‌ها دارد یا نه.

### Query 2 — جست‌وجوی الگوهای مشکوک در Command Line

```

DeviceProcessEvents
| where Timestamp >= ago(30d)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| extend Cmd = tolower(ProcessCommandLine)
| where Cmd contains "-encodedcommand"
    or Cmd contains " -enc "
    or Cmd contains "-windowstyle hidden"
    or Cmd contains "-w hidden"
    or Cmd contains "downloadstring"
    or Cmd contains "downloadfile"
    or Cmd contains "invoke-expression"
    or Cmd contains "iex("
    or Cmd contains "frombase64string"
| project
    Timestamp,
    DeviceName,
    AccountName,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by Timestamp desc

```

چرا این جست‌وجو مهم است؟

این الگوها می‌توانند به اجرای مخفیانه، کدگذاری دستورات یا دریافت محتوای خارجی اشاره کنند. اما چند نکته مهم وجود دارد:

- `-EncodedCommand` می‌تواند در اسکریپت‌های مجاز هم استفاده شود.
- `Invoke-Expression` و `FromBase64String` به‌خودی‌خود مخرب نیستند.
- شکل نوشتاری و فاصله‌های آرگومان‌ها متفاوت است؛ بنابراین این Query همه حالت‌ها را پوشش نمی‌دهد.
- این Query فقط Command Line را جست‌وجو می‌کند؛ کد مخرب ممکن است داخل فایل Script یا محتوای پویا باشد و در Command Line دیده نشود.

در نتیجه، این Query یک سرنخ برای Triage است، نه یک Detection کامل.

### Query 3 — جست‌وجوی رفتار مشکوک در Script Block Logging

اگر PowerShell Operational Log به Microsoft Sentinel ارسال شده باشد، می‌توان Event ID 4104 را بررسی کرد. شکل دقیق داده‌ها به Connector و روش جمع‌آوری لاگ بستگی دارد.

نمونه برای محیطی که رویدادها در جدول `WindowsEvent` ذخیره شده‌اند:

```

WindowsEvent
| where TimeGenerated >= ago(30d)
| where EventID == 4104
| where Provider == "Microsoft-Windows-PowerShell"
| extend ScriptText = tostring(EventData)
| extend ScriptLower = tolower(ScriptText)
| where ScriptLower contains "downloadstring"
    or ScriptLower contains "invoke-expression"
    or ScriptLower contains "frombase64string"
    or ScriptLower contains "reflection.assembly"
    or ScriptLower contains "virtualalloc"
| project
    TimeGenerated,
    Computer,
    EventID,
    EventData
| order by TimeGenerated desc

```

محدودیت فنی: در برخی محیط‌ها Provider یا محتوای رویداد در فیلدهای دیگری قرار می‌گیرد. پیش از اجرای Query باید یک Event ID 4104 واقعی را بررسی و نام فیلدها را با Schema همان Workspace تطبیق دهیم. همچنین برخی از این رشته‌ها ممکن است در ابزارهای مجاز یا اسکریپت‌های امنیتی وجود داشته باشند.

برای بررسی کامل‌تر، متن Script Block را بخوان، بخش‌های مرتبط را کنار هم قرار بده و در صورت امکان آن را با Process Telemetry همان میزبان و بازه زمانی مرتبط کن.

### Query 4 — بررسی ارتباط شبکه‌ای پس از اجرای PowerShell

اگر Queryهای قبلی مورد مشکوکی پیدا کردند، بررسی شبکه مرحله بعدی است.

```

let SuspiciousPS =
    DeviceProcessEvents
    | where Timestamp >= ago(30d)
    | where FileName in~ ("powershell.exe", "pwsh.exe")
    | where ProcessCommandLine contains "-EncodedCommand"
        or ProcessCommandLine contains "DownloadString"
        or ProcessCommandLine contains "DownloadFile"
    | project DeviceId, DeviceName, ProcessId,
              ProcessCreationTime, ProcessCommandLine;
DeviceNetworkEvents
| where Timestamp >= ago(30d)
| join kind=inner SuspiciousPS on DeviceId
| where InitiatingProcessId == ProcessId
| where InitiatingProcessCreationTime == ProcessCreationTime
| project
    Timestamp,
    DeviceName,
    RemoteUrl,
    RemoteIP,
    RemotePort,
    Protocol,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    ProcessCommandLine
| order by Timestamp desc

```

این Query نمونه‌ای برای اتصال رویداد شبکه به فرایند PowerShell است. نام و نوع فیلدهای شناسه فرایند ممکن است با Schema فعلی Defender XDR متفاوت باشد؛ آن‌ها را پیش از اجرا بررسی کن. اگر تطبیق دقیق شناسه فرایند و زمان ایجاد در دسترس نباشد، باید روش Join را با فیلدهای موجود تطبیق داد.

حتی اگر اتصال شبکه پیدا شود، هنوز باید مقصد، زمان، مالکیت فرایند و رفتار بعدی را بررسی کنیم. اتصال خارجی به‌تنهایی اثبات C2 یا سرقت داده نیست.

## ۴. Pivotها — از کجا به کجا حرکت می‌کنیم؟

فرض کنیم Query دوم یک اجرای مشکوک PowerShell را روی `WS-014` با حساب `user01` پیدا کرده است. من به همان رویداد بسنده نمی‌کنم و این Pivotها را دنبال می‌کنم:

PowerShell مشکوک

Host + User + Timestamp + Process ID

Process Tree

Parent Process، فرزندان PowerShell، Command Line و سایر فرایندهای مرتبط

Network

DNS، Remote IP، Domain، Proxy و احتمال Download یا ارتباط مشکوک

Identity

هویت کاربر، نوع حساب، زمان ورود، دسترسی‌ها و فعالیت روی میزبان‌های دیگر

Persistence / Evasion

Scheduled Task، Service، Registry، تغییرات Defender و تلاش برای دور زدن کنترل‌ها

### Pivot اول: Process Tree

بررسی می‌کنم چه فرایندی PowerShell را اجرا کرده است.

- `WINWORD.EXE → powershell.exe`: ممکن است نشانه اجرای زنجیره‌ای مشکوک از یک سند باشد.
- `services.exe → powershell.exe`: ممکن است مربوط به سرویس یا ابزار مدیریتی باشد؛ نیاز به بررسی بیشتر دارد.
- `Intune` یا ابزار Deployment → PowerShell: ممکن است کاملاً مجاز باشد، مشروط به تأیید Job و زمینه اجرا.

نکته: نام Parent Process به‌تنهایی تعیین‌کننده نیست. Command Line، فرایندهای فرزند و زمینه اجرای واقعی اهمیت دارند.

### Pivot دوم: Script Content

اگر Event ID 4104 موجود باشد:

- محتوای اسکریپت را بدون اجرا تحلیل می‌کنم.
- در صورت وجود Base64، آن را به‌عنوان متن Decode می‌کنم؛ نه اینکه Payload را اجرا کنم.
- به دنبال Discovery، Download، Dynamic Code Execution، دستکاری تنظیمات امنیتی و رفتارهای غیرمعمول می‌گردم.
- بررسی می‌کنم چند رویداد Script Block به یک اجرای منطقی مربوط‌اند.

### Pivot سوم: Network

بررسی می‌کنم آیا همان فرایند PowerShell به مقصدی غیرعادی متصل شده است.

- آیا Domain یا IP برای سازمان جدید است؟
- آیا DNS و Proxy شواهد مکمل دارند؟
- آیا ارتباط با زمان اجرای اسکریپت و شناسه همان فرایند تطبیق دارد؟
- آیا پاسخ یا محتوای دریافت‌شده قابل بررسی است؟

وجود اتصال به اینترنت به‌تنهایی ثابت نمی‌کند که دانلود مخرب، C2 یا Exfiltration رخ داده است.

### Pivot چهارم: Scope و Lateral Movement

اگر فعالیت مشکوک تأیید شد، جست‌وجو را به موارد زیر گسترش می‌دهم:

- سایر میزبان‌هایی که همان حساب روی آن‌ها فعالیت داشته است.
- اجرای PowerShell با الگوی مشابه در بازه زمانی نزدیک.
- ورودهای غیرعادی، دسترسی‌های ممتاز و اجرای Remote PowerShell.
- ایجاد Task یا Service، تغییرات Registry و فعالیت‌های پس از اجرای اولیه.
- شواهد استفاده از اعتبارنامه‌ها یا حرکت جانبی، در صورت وجود.

هدف این است که مشخص شود با یک اجرای منفرد روبه‌رو هستیم یا بخشی از یک زنجیره حمله.

## ۵. روش اعتبارسنجی Hunt

برای اینکه یک اجرای PowerShell را به‌اشتباه Incident اعلام نکنم، چهار محور را اعتبارسنجی می‌کنم.

| محور        | سؤال کلیدی                                                                                    |
| ----------- | --------------------------------------------------------------------------------------------- |
| Context     | آیا این اجرا با وظیفه کاربر، میزبان و زمان اجرا سازگار است؟                                   |
| Baseline    | آیا این رفتار قبلاً روی همین میزبان یا توسط همین گروه کاربری دیده شده است؟                    |
| Correlation | آیا شواهد مستقل مثل Script Block، Process Tree، Network یا تغییرات سیستم آن را تأیید می‌کنند؟ |
| Coverage    | آیا لاگ‌های لازم فعال بوده‌اند و آیا نبود شواهد واقعاً معنی‌دار است؟                          |

### چه چیزی فرضیه را تقویت می‌کند؟

- اجرای PowerShell توسط یک فرایند والد غیرعادی، همراه با Command Line مشکوک.
- محتوای Script Block که رفتار مخرب مشخصی را نشان می‌دهد.
- ارتباط شبکه‌ای که با همان فرایند و رفتار اسکریپت ارتباط قابل‌دفاع دارد.
- شواهد مستقل از Persistence، دسترسی غیرمجاز یا فعالیت پس از اجرا.

### چه چیزی فرضیه را تضعیف می‌کند؟

- وجود Job یا Change Ticket معتبر که اجرا را توضیح دهد.
- تطابق Script و زمان اجرا با یک ابزار مدیریتی شناخته‌شده.
- تأیید مالک سیستم یا تیم مسئول همراه با شواهد فنی مستقل.
- نبود رفتار مشکوک در منابعی که پوشش مناسب و قابل‌اعتماد دارند.

البته نبود رویدادهای مشکوک فقط زمانی ارزش منفی دارد که مطمئن باشیم لاگ مربوطه جمع‌آوری شده و برای آن میزبان و بازه زمانی قابل‌اتکاست.

### خروجی نهایی Hunt

در پایان، نتیجه را در یکی از این دسته‌ها ثبت می‌کنم:

- Benign / Authorized: فعالیت با شواهد معتبر به یک عملیات مجاز نسبت داده شده است.
- Suspicious — Unconfirmed: رفتار غیرعادی است، اما شواهد کافی برای تأیید حمله نداریم.
- Likely Malicious: چند شاهد مستقل فرضیه مخرب را تقویت می‌کنند، ولی بخشی از زنجیره هنوز اثبات نشده است.
- Confirmed Malicious Activity: شواهد کافی برای تأیید رفتار مخرب مشخص وجود دارد.

در صورت تأیید یا احتمال قوی حمله، بر اساس سطح خطر و رویه سازمان، شواهد را حفظ می‌کنم، Scope را گسترش می‌دهم و اقدامات Containment متناسب را پیشنهاد می‌دهم.

## ۶. MITRE ATT&CK Mapping

بسته به شواهد واقعی، ممکن است این تکنیک‌ها مرتبط باشند:

| تکنیک                                                    | شناسه     | چه زمانی مناسب است؟                                                                                       |
| -------------------------------------------------------- | --------- | --------------------------------------------------------------------------------------------------------- |
| PowerShell                                               | T1059.001 | وقتی از PowerShell برای اجرای دستورات یا اسکریپت‌ها استفاده شده باشد؛ مخرب بودن باید جداگانه ارزیابی شود. |
| Command and Scripting Interpreter: Windows Command Shell | T1059.003 | فقط اگر شواهد استفاده از Windows Command Shell وجود داشته باشد.                                           |
| Deobfuscate/Decode Files or Information                  | T1140     | وقتی شواهد رفتار Decode یا Deobfuscation با هدف مرتبط وجود داشته باشد.                                    |
| Ingress Tool Transfer                                    | T1105     | وقتی انتقال ابزار یا فایل به محیط تأیید یا به‌اندازه کافی پشتیبانی شده باشد.                              |
| Scheduled Task/Job                                       | T1053     | وقتی شواهد ایجاد یا سوءاستفاده از Task یا مکانیزم مرتبط وجود داشته باشد.                                  |

صرف استفاده از PowerShell برای انتساب رفتار به تمام این تکنیک‌ها کافی نیست. برای مثال، مشاهده `-EncodedCommand` به‌تنهایی نه مخرب بودن اجرا را ثابت می‌کند و نه لزوماً انتساب T1140 را توجیه می‌کند.

## پاسخ کوتاه برای شروع جواب در مصاحبه

برای این Hunt، چون IOC مشخصی نداریم، رویکردم Behavior-Based Hunting است. ابتدا بازه ۳۰ روز گذشته را مشخص می‌کنم و پوشش لاگ‌های PowerShell، به‌خصوص Event ID 4104 و 4103، به همراه Process Telemetry در EDR را بررسی می‌کنم.

بعد اجرای PowerShell را از نظر Command Lineهای مشکوک، Parent Process، محتوای Script Block و رفتارهایی مثل Download، Discovery و تلاش برای دور زدن کنترل‌های امنیتی جست‌وجو می‌کنم. برای موارد مشکوک، با استفاده از شناسه فرایند، زمان ایجاد، میزبان و حساب کاربری، به Process Tree، ارتباطات شبکه، فعالیت‌های احراز هویت و شواهد Persistence Pivot می‌زنم.

در مرحله اعتبارسنجی، نتایج را با Baseline سازمان و فعالیت‌های مجاز مدیریتی مقایسه می‌کنم و دنبال شواهد مستقل و متناقض می‌گردم. تأکید می‌کنم که آرگومان‌هایی مثل EncodedCommand یا یک اتصال خارجی به‌تنهایی اثبات‌کننده حمله نیستند. اگر شواهد کافی پیدا شود، Scope را گسترش می‌دهم، سطح اطمینان را مشخص می‌کنم و اقدامات Response و بهبود Detection را پیشنهاد می‌دهم.
