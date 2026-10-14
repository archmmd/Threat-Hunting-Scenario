### 1. تعریف سناریو و هدف Hunt

ترافیک خروجی یک سیستم **ناگهان از الگوی معمول بیشتر شده**، اما **IOC مشخصی** در دسترس نیست. هدف Hunt، شناسایی **Data Exfiltration** (TA0010) از طریق تحلیل **حجم، مقصد، پروتکل، زمان‌بندی، Process و حساسیت داده** است.

**نکته حیاتی:** در غیاب IOC، Hunt باید **Behavior-Driven** باشد. به‌جای جستجو برای ابزار یا IP خاص، به‌دنبال **انحراف از Baseline** می‌گردیم. Data Exfiltration اغلب **آخرین مرحله** حمله است — پس از آن، داده از شبکه خارج شده و **آسیب جبران‌ناپذیر** است .

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (Data Exfiltration)** | مهاجم داده‌های حساس را از طریق کانال C2 یا Web Service به خارج منتقل می‌کند | **Outbound >> Inbound**، Process غیرسیستمی با Network Activity غیرعادی، مقصد ناشناخته، Payload Encrypted/High-Entropy  | Process قانونی (Backup، Update)، مقصد در Allowlist، نسبت Inbound/Outbound متعادل |
| **فرضیه جایگزین (Legitimate Bulk Transfer)** | یک نرم‌افزار قانونی (Backup، Cloud Sync، Update) حجم بالایی از داده را منتقل می‌کند | Process شناخته‌شده، مقصد در Baseline، زمان‌بندی منظم | Process غیرعادی، مقصد ناشناخته، زمان‌بندی خارج از Baseline |
| **فرضیه جایگزین (Misconfigured Application)** | یک Application دچار خطا شده و ترافیک غیرعادی تولید می‌کند | Volume بالا اما **Inbound/Outbound متعادل**، Process قابل شناسایی | عدم تطابق با Baseline، Payload غیرمنتظره |

### 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Zeek / NSM Flow** (Essential) | Network Flow | `orig_bytes`، `resp_bytes`، `duration`، `id.orig_h`، `id.resp_h`  |
| **Sysmon Event ID 3** (Essential) | Network Connection | `Image`، `DestinationIp`، `DestinationPort`، `ProcessGuid`  |
| **Sysmon Event ID 1** (Essential) | Process Creation | `CommandLine`، `ParentImage` — Process مسئول انتقال  |
| **Security Event 4663/4656** (Supplementary) | File Access | دسترسی به فایل‌های حساس قبل از انتقال  |
| **DLP / CASB Alerts** (Supplementary) | Sensitive Data | Upload به Cloud Storage، Email خارجی  |
| **Proxy / Firewall Logs** (Essential) | HTTP/S Traffic | `bytes_out`، `dest`، `method` (POST/PUT)  |

**محدودیت:** تحلیل Volume نیاز به **Baseline تاریخی** دارد. اگر Baseline وجود نداشته باشد، نمی‌توان انحراف را تشخیص داد .

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: شناسایی انحراف حجم ترافیک (Baseline Anomaly)**

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteIPType == "Public"
| summarize DailyBytes = sum(SentBytes) by DeviceName, bin(Timestamp, 1d)
| summarize AvgDaily = avg(DailyBytes), StdDevDaily = stdev(DailyBytes) by DeviceName
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(24h)
    | where RemoteIPType == "Public"
    | summarize TodayBytes = sum(SentBytes) by DeviceName
) on DeviceName
| extend ZScore = (TodayBytes - AvgDaily) / StdDevDaily
| where ZScore > 3 and TodayBytes > 100 * 1024 * 1024  // >100MB
| order by ZScore desc
```

**منطق Query:** محاسبه **Z-Score** بر اساس Baseline 30 روزه. انحراف بیش از **3 استاندارد** + حجم بیش از **100MB** = **Strong Indicator** .

**مرحله B: شناسایی Process غیرعادی با Network Activity**

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| summarize 
    TotalOutbound = sum(SentBytes),
    TotalInbound = sum(ReceivedBytes),
    ConnectionCount = count(),
    Destinations = dcount(RemoteIP)
    by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath
| extend OutboundRatio = TotalOutbound / (TotalInbound + 1)
| where TotalOutbound > 10 * 1024 * 1024  // >10MB
| where OutboundRatio > 10  // Outbound >> Inbound
| where InitiatingProcessFolderPath has_any ("\\Temp\\", "\\AppData\\", "\\Users\\Public\\")
| order by TotalOutbound desc
```

**منطق Query:** Processهایی که **Outbound >> Inbound** دارند و از مسیرهای غیرعادی اجرا شده‌اند. نسبت **10:1** نشان‌دهنده **Upload** است .

**مرحله C: شناسایی DNS Exfiltration**

```kql
DeviceEvents
| where ActionType == "DnsQueryResponse"
| where Timestamp > ago(24h)
| extend QueryLength = strlen(QueryName)
| where QueryLength > 50
| summarize 
    QueryCount = count(),
    AvgLength = avg(QueryLength),
    UniqueSubdomains = dcount(QueryName)
    by DeviceName, InitiatingProcessFileName, 
       tostring(split(QueryName, ".")[-2]) + "." + tostring(split(QueryName, ".")[-1])
| where QueryCount > 100 and (AvgLength > 40 or UniqueSubdomains > 50)
| order by QueryCount desc
```

**منطق Query:** DNS Tunneling با **Query Length بالا** + **Unique Subdomains زیاد** شناسایی می‌شود .

**مرحله D: Correlate File Access با Network Upload**

```kql
let SensitiveFileAccess = SecurityEvent
| where EventID == 4663
| where ObjectName has_any ("finance", "hr", "confidential", "restricted")
| project AccessTime = TimeGenerated, Computer, Account, ObjectName;
let NetworkUpload = DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| where SentBytes > 1024 * 1024  // >1MB
| project UploadTime = Timestamp, DeviceName, InitiatingProcessFileName, 
          RemoteIP, SentBytes;
SensitiveFileAccess
| join kind=inner NetworkUpload on $left.Computer == $right.DeviceName
| where UploadTime between (AccessTime .. 1h)
| project AccessTime, UploadTime, Computer, Account, ObjectName, 
          InitiatingProcessFileName, RemoteIP, SentBytes
| order by AccessTime desc
```

**منطق Query:** **دسترسی به فایل حساس** + **Upload شبکه** در بازه **1 ساعت** = **Strong Indicator** برای Exfiltration .

### 5. Pivoting و Correlation شواهد

1. **از Network به Process:** اگر یک Process غیرعادی حجم بالایی ارسال کرده، **Parent Process** و **Command Line** آن را بررسی کنید .
2. **از Process به File:** آیا Process قبل از انتقال، به فایل‌های حساس دسترسی داشته؟ (Event 4663)
3. **از Destination به Threat Intel:** مقصد را در VirusTotal / AbuseIPDB بررسی کنید. آیا در **Allowlist** سازمان نیست؟
4. **از Timing به Baseline:** آیا انتقال در **ساعات غیرکاری** یا **خارج از Backup Window** رخ داده؟
5. **از User به Peer Group:** آیا این User در گروه خود **Outlier** است؟ (مثلاً Developer که ناگهان 5GB آپلود کرده)

**هشدار:** حجم بالا **به‌تنهایی** کافی نیست. باید **Process Context** و **Destination Reputation** تأیید شود.

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline:**
- آیا این Device **قبلاً** حجم بالایی ارسال کرده؟ (Backup Server قانونی)
- آیا Destination در **Allowlist** سازمان است؟ (Microsoft، Google، AWS)
- آیا Process در **Baseline** به‌عنوان Network Client ثبت شده؟

**False Positive:**
- **Software Updates:** Windows Update، Adobe، Java (Volume بالا اما Destination شناخته‌شده) 
- **Backup Software:** Veeam، Commvault (زمان‌بندی منظم، Destination داخلی)
- **Cloud Sync:** OneDrive، Dropbox (Process قانونی، Destination شناخته‌شده) 

**معیار قطعی:** Process غیرسیستمی + مسیر `Temp`/`AppData` + Outbound Ratio > 10 + Destination ناشناخته + دسترسی به فایل حساس قبل از انتقال = **High Confidence Exfiltration** .

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1041** | Exfiltration Over C2 Channel | Outbound >> Inbound، Process غیرعادی  |
| **T1048** | Exfiltration Over Alternative Protocol | DNS Tunneling، FTP، SMB خارجی  |
| **T1567.002** | Exfiltration to Cloud Storage | Upload به Mega، Dropbox، Google Drive  |
| **T1030** | Data Transfer Size Limits | انتقال تدریجی برای فرار از Detection |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** ترافیک خروجی یک سیستم ناگهان از الگوی معمول بیشتر شده است.

**Likely:** این رفتار **مشکوک به Data Exfiltration** است اگر:
1. **Outbound >> Inbound** باشد (نسبت > 10:1).
2. **Process** از مسیر غیرعادی (`Temp`، `AppData`) باشد.
3. **Destination** در Threat Intel یا Allowlist نباشد.
4. **دسترسی به فایل حساس** قبل از انتقال رخ داده باشد.

**Confidence: Medium-High** — برای **Confirmed** نیاز به **Destination Reputation** و **Process Context** داریم.

### 9. Response و بهبود Detection

**فوری:**
1. **Network Blocking:** مقصد مشکوک را در Firewall/Proxy بلاک کنید.
2. **Endpoint Isolation:** اگر Process مخرب تأیید شد.
3. **Forensic Collection:** Memory Dump، Network Capture، Process Tree.
4. **Data Impact Assessment:** چه داده‌هایی منتقل شده؟ (DLP Logs، File Access Logs)

**Detection Improvement:**
1. **قانون Volume Anomaly:** هر Device که **Z-Score > 3** و **>100MB Outbound** داشته باشد .
2. **قانون Outbound Ratio:** هر Process با **Outbound/Inbound > 10** و مسیر غیرعادی .
3. **قانون DNS:** هر Process با **DNS Query Length > 50** و **Unique Subdomains > 50** .
4. **قانون Correlation:** **File Access (4663)** + **Network Upload** در بازه 1 ساعت .

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

اول **Baseline** رو می‌سازم: میانگین و انحراف معیار ترافیک خروجی روزانه رو برای هر Device محاسبه می‌کنم. اگه یک Device **Z-Score بالای ۳** داشته باشه و بیش از **۱۰۰MB** آپلود کرده باشه، این Strong Indicator هست .

بعد **Outbound/Inbound Ratio** رو چک می‌کنم: اگه یک Process **Outbound >> Inbound** داشته باشه (نسبت ۱۰:۱) و از مسیر `Temp` یا `AppData` اجرا شده باشه، شک من قطعی‌تر می‌شه .

برای **DNS Exfiltration**، Queryهای طولانی (بیش از ۵۰ کاراکتر) با **Unique Subdomains زیاد** رو بررسی می‌کنم .

**محدودیت اصلی:** بدون **Baseline تاریخی**، نمی‌تونم انحراف رو تشخیص بدم. همچنین، خیلی از نرم‌افزارهای قانونی (Backup، Update) هم حجم بالایی دارن .

**اقدام بعدی:** اگه تأیید شد، مقصد رو بلاک می‌کنم، Endpoint رو Isolate می‌کنم، و بررسی می‌کنم چه **فایل‌های حساسی** قبل از انتقال Access شدن.
