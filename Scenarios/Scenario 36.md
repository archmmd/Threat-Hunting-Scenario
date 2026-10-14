### 1. تعریف سناریو و هدف Hunt

یک کاربر روی **لینک ایمیل مشکوک** کلیک کرده است، اما **مدرکی از اجرای Malware** وجود ندارد. هدف Hunt، پاسخ به این سؤال است: **آیا کلیک صرفاً یک تعامل بی‌خطر بوده، یا زنجیره‌ای از رویدادها (Redirect، Download، Credential Harvesting، یا Execution) را آغاز کرده است؟**

**نکته حیاتی:** «کلیک» **به‌تنهایی** نشانه Compromise نیست. باید مشخص شود که کاربر: (۱) فقط لینک را **باز کرده**، (۲) **Credential وارد کرده**، (۳) **فایل دانلود کرده**، یا (۴) **فایل اجرا کرده**. هر لایه، شواهد متفاوتی از منابع متفاوتی تولید می‌کند .

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (Interaction Without Execution)** | کاربر روی لینک کلیک کرده، صفحه باز شده، اما **هیچ فایلی اجرا نشده است** | Browser History به Domain مشکوک، DNS Query، Proxy Log — اما **بدون** Sysmon EID 1 یا File Create  | عدم وجود DNS/Proxy Record، صفحه Line blocked توسط Gateway |
| **فرضیه جایگزین (Credential Harvesting)** | کاربر در صفحه Fake Login، **Credential وارد کرده** اما فایلی اجرا نشده | Login ناموفق/موفق غیرعادی پس از کلیک، MFA Prompt ناشناخته، Impossible Travel  | عدم وجود Login Event مشکوک |
| **فرضیه جایگزین (Execution / Malware)** | کاربر فایل دانلود و **اجرا** کرده است | Sysmon EID 1 (Process Creation)، EID 11 (File Create)، EID 3 (Network Connection به C2)  | عدم وجود Process Creation یا File Create |

### 3. Telemetry و Data Sources

| لایه | منبع | چه چیزی را بررسی کنیم | محدودیت |
|---|---|---|---|
| **Email** | `EmailEvents`، `EmailUrlInfo`، `UrlClickEvents` (Defender XDR) | آیا URL **کلیک شده** (IsClickedThrough = true)؟ آیا SafeLinks آن را Block کرده؟  | فقط Click را نشان می‌دهد، نه **مقصد نهایی** |
| **Proxy / Web Gateway** | Proxy Logs، `DeviceNetworkEvents` | `RemoteUrl`، `Method` (GET/POST)، `User-Agent`، `bytes_out/in`  | اگر کاربر خارج از VPN باشد، ممکن است ثبت نشود  |
| **DNS** | Sysmon EID 22، DNS Server Logs | `QueryName`، `Image` (Process انجام‌دهنده Query)، `QueryStatus`  | **Process Guid** برای Correlation ضروری است  |
| **Browser** | Browser History، `DeviceEvents` (ActionType = BrowserLaunchedToOpenUrl) | `RemoteUrl`، `InitiatingProcessFileName` (Browser Process)  | History ممکن است پاک شده یا Private Browsing باشد |
| **Endpoint** | Sysmon EID 1، 3، 11 | **عدم وجود** Process Creation مشکوک، **عدم وجود** File Create، **عدم وجود** Network Connection به Domain مشکوک | اگر Sysmon نصب نباشد یا Event 3 غیرفعال باشد، نمی‌توان تأیید کرد  |

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: تأیید کلیک از Email Telemetry**

```kql
// Defender XDR — بررسی کلیک روی URL
let SuspiciousUrl = "http://malicious.example/login";
EmailUrlInfo
| where Url == SuspiciousUrl
| join kind=leftouter EmailEvents on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, Subject, Url
```

**منطق Query:** این Query تأیید می‌کند که **کدام کاربر** روی **کدام URL** کلیک کرده است .

**مرحله B: بررسی DNS Query و Process انجام‌دهنده**

```kql
// Defender XDR — DNS Query به Domain مشکوک
DeviceEvents
| where ActionType == "DnsQueryResponse"
| where QueryName has "malicious.example"
| project Timestamp, DeviceName, QueryName, InitiatingProcessFileName, 
          InitiatingProcessCommandLine, InitiatingProcessAccountName
```

**منطق Query:** Sysmon EID 22 فیلد `Image` را دارد که **Process انجام‌دهنده DNS Query** را نشان می‌دهد. اگر `InitiatingProcessFileName` **Browser** (`chrome.exe`, `msedge.exe`, `firefox.exe`) باشد، این **کلیک مرورگر** است. اگر Process غیرمرورگر باشد (مثل `powershell.exe`, `cmd.exe`, `curl.exe`)، این **مشکوک‌تر** است .

**مرحله C: بررسی Proxy Log برای Download یا Redirect**

```kql
// Proxy Log — بررسی GET/POST و User-Agent
let SuspiciousDomain = "malicious.example";
CommonSecurityLog
| where TimeGenerated > ago(24h)
| where RequestURL has SuspiciousDomain
| project TimeGenerated, SourceIP, DestinationIP, RequestURL, RequestMethod, 
          RequestClientApplication, SentBytes, ReceivedBytes, DeviceAction
| order by TimeGenerated desc
```

**منطق Query:** `RequestMethod = GET` + `User-Agent = Browser` = **صفحه وب ساده**. `RequestMethod = POST` = **احتمال Credential Submission**. `ReceivedBytes` **بالا** = **احتمال Download** .

**مرحله D: بررسی عدم وجود Execution (Endpoint)**

```kql
// Defender XDR — بررسی Process Creation پس از کلیک
let ClickTime = datetime(2026-10-14 10:00:00);  // زمان کلیک
DeviceProcessEvents
| where Timestamp between (ClickTime .. ClickTime + 10m)
| where DeviceName =~ "USER-WORKSTATION"
| where FileName in~ ("powershell.exe", "cmd.exe", "rundll32.exe", "mshta.exe", "wscript.exe", "cscript.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, 
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

**منطق Query:** **عدم وجود نتیجه** در این Query **به‌تنهایی** به‌معنای عدم اجرا نیست — فقط به‌معنای عدم وجود **Process Creation Log** در بازه ۱۰ دقیقه‌ای است. باید Sysmon EID 1 فعال باشد .

### 5. Pivoting و Correlation شواهد

1. **از Email به Proxy:** `NetworkMessageId` → `EmailUrlInfo` → `RemoteUrl` → جستجو در Proxy Logs .
2. **از Proxy به DNS:** `RemoteUrl` → استخراج Domain → جستجو در `DeviceEvents` (ActionType = DnsQueryResponse) .
3. **از DNS به Process:** `InitiatingProcessFileName` → اگر Browser است، **Interaction**. اگر غیرمرورگر است، **Suspicious** .
4. **از Process به File:** اگر Process مشکوک پیدا شد، Sysmon EID 11 (File Create) را بررسی کنید .

**هشدار:** همزمانی زمانی (Temporal Proximity) **Causation** را اثبات نمی‌کند. دیدن DNS Query و Proxy Log در یک دقیقه **کافی نیست** — باید **Process Guid** یا **NetworkMessageId** یکسان تأیید شود .

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline:**
- آیا Domain در **Allowlist** سازمان است؟ (CDN، Marketing، Analytics)
- آیا کاربر **قبلاً** روی این Domain کلیک کرده؟ (Historical Browser History)
- آیا Process انجام‌دهنده DNS Query **Browser** است؟ (اگر بله، احتمالاً Interaction ساده)

**Scope:**
- آیا **کاربران دیگر** روی همان URL کلیک کرده‌اند؟ (Email Trace + UrlClickEvents) .
- آیا **Domain** روی Endpointهای دیگر دیده شده؟

**False Positive:**
- **URL Shortener:** Domainهای مثل `bit.ly`، `tinyurl.com` می‌توانند قانونی باشند .
- **Marketing Emails:** لینک‌های Track شده از SendGrid، Mailchimp.
- **SafeLinks:** اگر Gateway لینک را **Block** کرده باشد، DNS Query روی Endpoint رخ نمی‌دهد.

**معیار قطعی:** اگر **DNS Query از Browser** باشد و **هیچ Process Creation مشکوک** پس از کلیک نباشد → **Interaction Without Execution**. اگر **Process غیرمرورگر** DNS Query زده یا **File Create** دیده شود → **Likely Execution**.

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1566.002** | Phishing: Spearphishing Link | کلیک روی لینک در ایمیل  |
| **T1204.001** | User Execution: Malicious Link | اگر کاربر لینک را باز کرده باشد |
| **T1071.001** (احتمالی) | Web Protocols | اگر Network Connection به C2 برقرار شده باشد  |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** کاربر روی لینک ایمیل مشکوک کلیک کرده است.

**Likely (Interaction Without Execution):** اگر DNS Query از **Browser** باشد، Proxy Log **GET** را نشان دهد، و **هیچ Process Creation مشکوک** یا **File Create** دیده نشود.

**Confidence: Medium** — برای **High** نیاز به **تأیید عدم وجود Execution** از طریق Sysmon EID 1 + EID 11 + EID 3 داریم. اگر Sysmon Event 3 (Network Connection) **غیرفعال** باشد، نمی‌توان Connection به C2 را رد کرد .

### 9. Response و بهبود Detection

**اقدامات فوری:**
1. **Block Domain/URL** در Proxy و Email Gateway.
2. **Purge Email** از Mailboxهای دریافت‌کننده .
3. **Force Password Reset** اگر **Credential Harvesting** مشکوک باشد.
4. **Monitor Login Activity** برای ۲۴ ساعت آینده (Impossible Travel، MFA Prompt) .

**Detection Improvement:**
1. **BrowserLaunchedToOpenUrl:** استفاده از `DeviceEvents` (ActionType = BrowserLaunchedToOpenUrl) برای Correlation مستقیم Email Click با Endpoint .
2. **DNS Query Detection:** قانون برای DNS Query به Domainهای **Newly Registered** (<30 روز) .
3. **Proxy Log Enrichment:** ثبت `User-Agent` و `Method` برای تفکیک Browser از Non-Browser Request .

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

اول از **Email Telemetry** (`UrlClickEvents` یا `EmailUrlInfo`) تأیید می‌کنم که کاربر **واقعاً کلیک کرده** — نه فقط ایمیل دریافت کرده .

بعد **DNS Query** رو بررسی می‌کنم: از **Sysmon EID 22** استفاده می‌کنم که `Image` (Process انجام‌دهنده Query) رو نشون می‌ده. اگه Process **Browser** باشه (chrome, msedge)، این **Interaction ساده** هست. اگه Process غیرمرورگر باشه، شک من قطعی‌تر می‌شه .

**Proxy Log** رو هم چک می‌کنم: `RequestMethod` و `User-Agent`. اگه `GET` با Browser User-Agent باشه، صفحه ساده بوده. اگه `POST` یا `ReceivedBytes` بالا باشه، احتمال **Credential Submission** یا **Download** هست .

**محدودیت اصلی:** عدم وجود **Sysmon EID 1** یا **EID 3** به‌معنای عدم اجرا نیست — فقط به‌معنای **عدم وجود Telemetry** هست. اگه Event 3 غیرفعال باشه، نمی‌تونم Connection به C2 رو رد کنم .

**اقدام بعدی:** اگه Process مشکوک یا File Create دیده شد، Endpoint رو Isolate می‌کنم. اگه فقط Interaction ساده بود، Domain رو Block می‌کنم و ایمیل رو Purge می‌کنم .
