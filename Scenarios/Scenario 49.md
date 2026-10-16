Incident با Logهای ناقص
Endpoint آلوده شده، اما Sysmon در بخشی از بازه زمانی فعال نبوده و Network Logs هم ناقص‌اند.
چطور از Eventهای موجود، سایر منابع و Artifactهای Forensic برای بازسازی Timeline استفاده می‌کنی؟

### 1. تعریف سناریو و هدف Hunt

**سناریو:** یک Endpoint آلوده شده است، اما **Sysmon در بخشی از بازه زمانی فعال نبوده** و **Network Logs نیز ناقص** هستند. هدف، بازسازی **Timeline حمله** با استفاده از **Eventهای موجود**، **منابع جایگزین (Compensating Telemetry)** و **Artifactهای Forensic** است.

**نکته حیاتی:** فقدان Telemetry **به‌معنای عدم وقوع حمله نیست** — به‌معنای **کاهش دید** است. Timeline نهایی باید **Gapها را به‌صراحت نشان دهد** و از **پر کردن شکاف با حدس و گمان** خودداری کند. یک Timeline کوتاه با شکاف‌های صادقانه، از یک Timeline کامل اما مبتنی بر فرض، **ارزش بیشتری** دارد .

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده |
|---|---|---|
| **فرضیه اصلی (Partial Coverage)** | حمله در بازه‌ای رخ داده که Sysmon **غیرفعال** بوده، اما Artifactهای Forensic (Prefetch، Amcache، MFT) **قابل بازیابی** هستند | Prefetch/Amcache تاریخ Execution را نشان می‌دهند، $MFT زمان ایجاد فایل را ثبت کرده |
| **فرضیه جایگزین (Adversary Suppression)** | مهاجم **عمداً** Sysmon را غیرفعال کرده تا Detection را دور بزند | توقف ناگهانی Log در زمان خاص، Event ID 4 (Sysmon Service State Changed) در System Log |

### 3. Telemetry و Data Sources (منابع جایگزین)

**الف) Artifactهای Forensic روی Endpoint (مستقل از Sysmon):**

| Artifact | مسیر | چه چیزی را نشان می‌دهد | محدودیت |
|---|---|---|---|
| **Prefetch** | `C:\Windows\Prefetch\` | **تاریخ اولین و آخرین اجرا** + Run Count | فقط Windows Workstation/Server (نه Server Core) |
| **Amcache** | `C:\Windows\AppCompat\Programs\Amcache.hve` | **تاریخ اولین اجرا** + SHA1 Hash | فقط Windows 7+ |
| **ShimCache** | `SYSTEM` Registry Hive | Last Modified Time (نشانه اجرا) | محدودیت در Windows 10+ |
| **$MFT** | `\$MFT` | **Created0x10** و **Created0x30** (Timestomping Detection) | نیاز به Raw Access |
| **USN Journal** | `\$Extend\$UsnJrnl` | تاریخ ایجاد، تغییر، حذف فایل (حتی پس از حذف) | نیاز به Raw Access |
| **Event Logs (Security/System)** | `C:\Windows\System32\winevt\Logs\` | Login، Service Creation، Process Creation (اگر Auditing فعال باشد) | ممکن است پاک شده یا Rollover شده باشد |

**ب) Network Telemetry جایگزین:**

| منبع | چه چیزی را نشان می‌دهد | محدودیت |
|---|---|---|
| **Firewall Logs** | Connection به IP/Port خارجی | فقط Metadata، نه Process |
| **Proxy Logs** | HTTP/HTTPS Request (URL، Method، User-Agent) | فقط اگر Traffic از Proxy عبور کرده باشد |
| **DNS Server Logs** | QueryName، Source IP | فقط اگر DNS Server داخلی باشد |
| **Zeek/Suricata (اگر موجود)** | conn.log، dns.log، http.log، ssl.log | ممکن است برای بازه مورد نظر **Retention** نداشته باشد |

**ج) EDR Telemetry (اگر Sysmon نبود):**
- **Microsoft Defender for Endpoint:** Process Creation، Network Connection، File Create — **حتی اگر Sysmon غیرفعال باشد**، EDR همچنان Telemetry تولید می‌کند .

### 4. مراحل اجرایی Hunt و بازسازی Timeline

**مرحله A: شناسایی بازه Gap در Sysmon**

اول باید **دقیقاً** مشخص کنی Sysmon در چه بازه‌ای فعال نبوده:

```powershell
# بررسی وضعیت Sysmon Service
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5 |
Select-Object TimeCreated, Id, Message

# Event ID 4 = Sysmon Service State Changed (Started/Stopped)
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'; Id=4} |
Select-Object TimeCreated, Message | Sort-Object TimeCreated -Descending
```

**منطق:** Event ID 4 نشان می‌دهد Sysmon **چه زمانی** Start/Stop شده. این **Gap** را مشخص می‌کند.

**مرحله B: استخراج Execution Timeline از Prefetch و Amcache**

با **EZ Tools** (Eric Zimmerman) این Artifactها را Parse کن :

```powershell
# Parse Prefetch
PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\output" --csvf prefetch.csv

# Parse Amcache
AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" --csv "C:\output"

# Filter for suspicious executables (in Timeline Explorer)
# Sort by LastRun / FirstExecution
```

**منطق:** Prefetch **Run Count** و **Last 8 Execution Times** را نشان می‌دهد . Amcache **First Execution** و **SHA1** را ثبت می‌کند . اگر فایل مخرب در بازه Gap اجرا شده باشد، این Artifactها **آن را نشان می‌دهند** — حتی اگر Sysmon آن را ثبت نکرده باشد.

**مرحله C: File System Timeline از $MFT و USN Journal**

```powershell
# Parse $MFT with MFTECmd
MFTECmd.exe -f "C:\$MFT" --csv "C:\output" --csvf mft.csv

# در Timeline Explorer:
# Filter: Created0x10 (SI) vs Created0x30 (FN)
# Flag: Created0x10 < Created0x30 = Timestomping
```

**منطق:** $MFT زمان **ایجاد فایل** را ثبت می‌کند. اگر فایل مخرب در بازه Gap ایجاد شده باشد، $MFT **آن را نشان می‌دهد** . USN Journal **حتی فایل‌های حذف‌شده** را نیز ثبت می‌کند.

**مرحله D: Correlate Network Logs با Artifactهای Endpoint**

از **Community ID** برای اتصال Network Logs به Endpoint استفاده کن :

```kql
// محاسبه Retroactive Community ID برای Sysmon (اگر موجود باشد)
// یا استفاده از IP/Port برای Correlate دستی
DeviceNetworkEvents
| where Timestamp between (GapStart .. GapEnd)
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
```

**منطق:** اگر Sysmon نبود، از **Firewall/Proxy Logs** استفاده کن. IP و Port را با **Prefetch/Amcache Execution Times** مقایسه کن. اگر Connection در بازه‌ای رخ داده که فایل مخرب اجرا شده، این **زنجیره علیت** را تأیید می‌کند.

### 5. Pivoting و Correlation شواهد

1. **از Gap به Prefetch:** اگر Sysmon در بازه `10:00-11:00` غیرفعال بوده، Prefetch را برای همان بازه بررسی کن.
2. **از Prefetch به Amcache:** تاریخ Execution را با **SHA1** فایل مخرب Cross-Reference کن.
3. **از Amcache به Network:** IP/Port را از Firewall Logs استخراج کن و با Execution Time مقایسه کن.
4. **از Network به Event Logs:** اگر Connection به IP خارجی در بازه خاص رخ داده، Security Event 4624/4672 را برای همان بازه بررسی کن.

**هشدار:** **Temporal Proximity ≠ Causation**. دیدن Execution و Network Connection در یک بازه **کافی نیست** — باید **Hash یکسان** یا **Process Guid** تأیید شود .

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline:**
- آیا این فایل **قبلاً** روی سیستم اجرا شده؟ (Prefetch Run Count)
- آیا **Amcache First Execution** قدیمی‌تر از Gap است؟

**Scope:**
- روی **همه Endpointها** Prefetch و Amcache را Parse کن.
- **قدیمی‌ترین Execution Time** را پیدا کن = **Patient Zero**.

**False Positive:**
- **Software Update:** ممکن است فایل‌های موقت با نام مشابه ایجاد کند.
- **Backup Software:** ممکن است Prefetch/Amcache را تغییر دهد.

**معیار قطعی:** اگر **Amcache First Execution** در بازه Gap باشد و **Prefetch** آن را تأیید کند، **Execution تأیید** می‌شود — حتی بدون Sysmon .

### 7. MITRE ATT&CK Mapping

| رفتار | Technique ID | Name |
|---|---|---|
| اجرای Process در بازه Gap | **T1059** | Command and Scripting Interpreter |
| حذف یا غیرفعال‌سازی Sysmon | **T1562.001** | Impair Defenses: Disable or Modify Tools |
| File Creation در بازه Gap | **T1105** | Ingress Tool Transfer |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** Sysmon در بخشی از بازه غیرفعال بوده و Network Logs ناقص هستند.

**Likely (Partial Reconstruction):** اگر **Prefetch/Amcache** تاریخ Execution را نشان دهند و **Network Logs** (حتی ناقص) Connection به مقصد مشکوک را تأیید کنند.

**Confidence: Medium** — برای **High** نیاز به **تأیید چند Artifact** (Prefetch + Amcache + $MFT) و **Cross-Reference** با Network Logs داریم.

**نکته حیاتی:** اگر **Prefetch/Amcache** نیز غیرفعال یا پاک شده باشند، **بازسازی Timeline ممکن نیست** و باید به‌عنوان **Inconclusive** گزارش شود .

### 9. Response و بهبود Detection

**اقدامات فوری:**
1. **Snapshot** از Disk و Memory (قبل از هر تغییر).
2. **جمع‌آوری Artifactها:** Prefetch، Amcache، $MFT، USN Journal، Event Logs.
3. **Network Capture:** اگر هنوز فعال است، Packet Capture را شروع کن.

**Detection Improvement:**
1. **Sysmon Persistence:** اطمینان از **Auto-Start** بودن Sysmon Service.
2. **Artifact Monitoring:** قانون برای **Event ID 4** (Sysmon Service State Changed) → Alert.
3. **Retention Policy:** افزایش Retention Logs به **90 روز** (حداقل).
4. **EDR Fallback:** اگر Sysmon غیرفعال شد، EDR همچنان Telemetry تولید کند .

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

اول **بازه Gap** رو مشخص می‌کنم: از **Event ID 4** در Sysmon Log استفاده می‌کنم تا بفهمم Sysmon **چه زمانی** غیرفعال بوده .

بعد **Artifactهای Forensic** رو بررسی می‌کنم: از **Prefetch** و **Amcache** برای **Execution Timeline** استفاده می‌کنم — این‌ها مستقل از Sysmon کار می‌کنند و **تاریخ اولین اجرا** رو نشون می‌دن . از **$MFT** برای **File Creation Time** استفاده می‌کنم.

**Network Logs** رو هم با **Community ID** یا **IP/Port** به Execution Timeها Correlate می‌کنم .

**محدودیت اصلی:** اگه **Prefetch/Amcache** هم غیرفعال یا پاک شده باشن، بازسازی Timeline ممکن نیست و باید به‌عنوان **Inconclusive** گزارش بشه . همچنین **Temporal Proximity** به‌تنهایی Causation رو اثبات نمی‌کنه — باید **Hash یکسان** تأیید بشه .

**اقدام بعدی:** اگه Execution تأیید شد، Endpoint رو Isolate می‌کنم و روی **Hostهای دیگر** Prefetch/Amcache رو بررسی می‌کنم تا **Patient Zero** واقعی رو پیدا کنم .
