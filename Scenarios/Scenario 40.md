### 1. تعریف سناریو و هدف Hunt

سه IOC در دسترس است: **Hash**، **Domain** و **IP**. هدف، **Pivoting سیستماتیک** در SIEM، EDR و DNS/Proxy Logs برای یافتن **شواهد مرتبط**، و **مدیریت False Positive** یا **ارتباط تصادفی** (Coincidental Correlation) است.

**نکته حیاتی:** IOCها **ارزش متفاوتی** دارند. Hash **قطعی‌ترین** است (اگر Match شود، یعنی فایل روی سیستم است). Domain و IP **ممکن است Shared** باشند (CDN، Cloud Provider) و نیاز به **Context** دارند. هر IOC باید با **Confidence Level** خودش ثبت شود: High (Hash)، Medium (Domain اختصاصی)، Low (IP مشترک) .

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده |
|---|---|---|
| **فرضیه اصلی (IOC Match = Compromise)** | IOC روی یک یا چند Host مشاهده شده و نشان‌دهنده Compromise است | Hash در EDR Process Creation، Domain در DNS Query، IP در Network Connection  |
| **فرضیه جایگزین (Shared Infrastructure)** | Domain/IP روی سرویس‌های قانونی میزبانی می‌شود (CDN، Cloud) | WHOIS، Passive DNS، Certificate Reuse  |

### 3. Telemetry و Data Sources

| IOC Type | SIEM | EDR | DNS/Proxy | محدودیت |
|---|---|---|---|---|
| **Hash** | `DeviceFileEvents`، `DeviceProcessEvents` | Process Execution، File Create  | — | Hash در Alert ممکن است **In-Memory** باشد نه On-Disk  |
| **Domain** | `DnsEvents`، `DeviceEvents` (DnsQueryResponse) | Process انجام‌دهنده DNS Query | Proxy Log (RequestURL) | Domain ممکن است **Shared** باشد |
| **IP** | `DeviceNetworkEvents`، Firewall Logs | RemoteIP، RemotePort | Proxy Log (DestinationIP) | IP ممکن است **CDN** یا **Cloud** باشد  |

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: Pivoting Hash (قطعی‌ترین IOC)**

```kql
// جستجو در EDR برای Hash
DeviceProcessEvents
| where SHA256 == "SUSPICIOUS_HASH" or MD5 == "SUSPICIOUS_HASH"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, 
          ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

**منطق Query:** اگر Hash در **Process Creation** Match شود، Execution تأیید می‌شود. اگر فقط در **File Create** باشد، دانلود شده اما اجرا نشده .

**مرحله B: Pivoting Domain (با Context)**

```kql
// جستجو در DNS Logs
DeviceEvents
| where ActionType == "DnsQueryResponse"
| where QueryName has "malicious-domain.com"
| project Timestamp, DeviceName, QueryName, InitiatingProcessFileName, 
          InitiatingProcessAccountName
| order by Timestamp desc
```

**منطق Query:** Process انجام‌دهنده DNS Query **حیاتی** است. اگر Browser باشد، Interaction ساده. اگر `powershell.exe` یا `rundll32.exe` باشد، مشکوک .

**مرحله C: Pivoting IP (با بررسی Shared بودن)**

```kql
// جستجو در Network Connection
DeviceNetworkEvents
| where RemoteIP == "MALICIOUS_IP"
| project Timestamp, DeviceName, RemoteIP, RemotePort, 
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**منطق Query:** IP ممکن است **Shared** باشد. باید WHOIS، Passive DNS و Certificate Reuse بررسی شود .

### 5. Pivoting و Correlation شواهد

**Pivotingهای پیشرفته (فراتر از IOC ساده):**

1. **از IP به Certificate Reuse:** اگر Certificateهای SSL/TLS با **Subject یکسان** روی IPهای دیگر دیده شوند، این یک **Pivot قوی** برای یافتن Infrastructure مهاجم است .
2. **از Domain به DNS TXT Record:** TXT Recordها ممکن است شامل **C2 Fallback Addresses** یا **Encryption Keys** باشند .
3. **از Hash به Sandbox Artifacts:** اگر فایل در Sandbox اجرا شود، **Dropped Files**، **Network Connections** و **Registry Changes** به‌عنوان IOCهای جدید استخراج می‌شوند .
4. **از JA3 Fingerprint به C2 Framework:** اگر Network Telemetry شامل **JA3/JARM** باشد، می‌توان C2 Framework (مثل Cobalt Strike) را شناسایی کرد .

**هشدار:** **Temporal Proximity ≠ Causation**. دیدن IP و Domain در یک بازه زمانی **کافی نیست** — باید **ProcessGuid** یا **Network Session** یکسان تأیید شود.

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**مدیریت Shared Infrastructure:**
- **IP:** بررسی کنید آیا IP یک **CDN** (Cloudflare، Akamai) یا **Cloud Provider** (AWS، Azure) است. اگر بله، IOC **Low Confidence** است .
- **Domain:** بررسی **WHOIS** — آیا **Privacy-Protected** است؟ آیا **Registration Age** کمتر از 30 روز است؟ .

**مدیریت ارتباط تصادفی:**
- **Prevalence Check:** آیا این IOC روی **Hostهای دیگر** سازمان هم دیده می‌شود؟ اگر بله، احتمال FP بالاست .
- **Peer Group Comparison:** آیا Hostهای مشابه (همان دپارتمان، همان Role) این IOC را دارند؟

**False Positive:**
- **Hash:** اگر فایل با **Certificate معتبر** امضا شده باشد، احتمال FP بالاست.
- **Domain:** اگر Domain در **Allowlist** سازمان باشد (Marketing، CDN).
- **IP:** اگر IP متعلق به **Microsoft**، **Google** یا **Cloud Provider** باشد.

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1071.001** | Application Layer Protocol: Web | Domain/IP در Network Connection  |
| **T1204.002** | User Execution: Malicious File | Hash در Process Creation  |
| **T1665** | Hide Infrastructure | Certificate Reuse، DNS TXT Pivoting  |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** IOCها در Telemetry سازمان مشاهده شده‌اند.

**Likely (Compromise):** اگر Hash در **Process Creation** Match شود (High Confidence).

**Confidence: Medium-High** — بسته به نوع IOC و Context. Hash = High، Domain اختصاصی = Medium، IP مشترک = Low.

### 9. Response و بهبود Detection

**اقدامات فوری:**
1. **Isolate** Hostهایی که Hash در آن‌ها اجرا شده.
2. **Block** Domain/IP در Proxy و Firewall (فقط اگر **اختصاصی** باشند).
3. **Hunt** برای **Infrastructure مرتبط** از طریق Certificate Reuse و JA3 .

**Detection Improvement:**
1. **IOC Enrichment:** ثبت **Confidence Level** برای هر IOC .
2. **Automated Pivoting:** ایجاد Playbook برای Pivoting خودکار از IOC به Telemetry .
3. **Behavioral Detection:** به‌جای IOC، روی **TTP** تمرکز کنید (مثل Beaconing Pattern) .

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

اول **Hash** رو در EDR جستجو می‌کنم: اگه در **Process Creation** Match بشه، این **قطعی‌ترین شاهد** هست. اگه فقط در **File Create** باشه، یعنی دانلود شده اما اجرا نشده .

بعد **Domain** رو در DNS Logs چک می‌کنم و **Process انجام‌دهنده Query** رو بررسی می‌کنم: اگه Browser باشه، Interaction ساده. اگه `powershell.exe` باشه، مشکوک .

برای **IP**، اول بررسی می‌کنم که **Shared** هست یا نه — WHOIS، Passive DNS و Certificate Reuse .

**محدودیت اصلی:** IP ممکنه **CDN** یا **Cloud** باشه و IOC **Low Confidence** بشه. همچنین ارتباط تصادفی (Temporal Proximity) **Causation** رو اثبات نمی‌کنه — باید **ProcessGuid** تأیید بشه.

**اقدام بعدی:** اگه Hash تأیید شد، Host رو Isolate می‌کنم. اگه Domain/IP **اختصاصی** بود، Block می‌کنم و از **Certificate Reuse** برای یافتن Infrastructure بیشتر استفاده می‌کنم .
