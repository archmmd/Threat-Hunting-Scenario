### 1. تعریف سناریو و هدف Hunt

یک سیستم داخلی در مدت کوتاهی به **تعداد زیادی IP و Port** متصل می‌شود. هدف Hunt، تفکیک **اسکن مجاز (Authorized Scan)** از **Asset Discovery** و **Reconnaissance مهاجم** است.

**نکته حیاتی:** هر سه نوع اسکن **رفتار شبکه‌ای مشابهی** تولید می‌کنند. تفاوت در **منبع (Source)**، **زمان‌بندی (Timing)**، **الگو (Pattern)** و **زمینه سازمانی (Organizational Context)** است، نه در **پروتکل** یا **ابزار** .

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (Reconnaissance مهاجم)** | مهاجم از یک Host Compromised برای نقشه‌برداری از شبکه داخلی استفاده می‌کند | Source IP **غیرمجاز**، الگوی اسکن **غیرمنتظم**، Process **غیرسیستمی** (nmap.exe, masscan)، خارج از Change Window  | Source در Allowlist، اسکن زمان‌بندی‌شده |
| **فرضیه جایگزین (اسکن مجاز)** | تیم امنیت یا Vulnerability Scanner (Nessus، Qualys) در حال اسکن برنامه‌ریزی‌شده است | Source IP در **Allowlist اسکنرها**، اسکن در **Change Window**، Ticket ثبت‌شده، Volume متعادل  | عدم وجود Ticket، Source غیرمجاز |
| **فرضیه جایگزین (Asset Discovery)** | ابزار Inventory (Lansweeper، SCCM) در حال کشف دارایی‌هاست | Source Process **شناخته‌شده**، Destination **محدود به Subnet**، اسکن دوره‌ای  | Destination غیرعادی، Source Process ناشناخته |

### 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Zeek / NSM Flow** (Essential) | Network Flow | `orig_bytes=0` (Zero Payload)، `dest_port`، `id.orig_h`، `id.resp_h`  |
| **Sysmon EID 1** (Essential) | Process Creation | `Image` (nmap.exe, masscan.exe)، `CommandLine`  |
| **Sysmon EID 3** (Essential) | Network Connection | `DestinationIp`، `DestinationPort`، `ProcessGuid` |
| **Firewall / Proxy Logs** (Supplementary) | Connection Log | `src_ip`، `dst_ip`، `dst_port`، `action` |
| **Asset Inventory / Allowlist** (Essential) | Context | آیا Source IP در **Allowlist اسکنرهای مجاز** است؟  |

**محدودیت:** اسکنرهای مجاز باید **مستند، زمان‌بندی‌شده و در Allowlist** ثبت شده باشند. بدون این Context، تفکیک **غیرممکن** است .

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: شناسایی الگوی اسکن (Horizontal vs Vertical)**

```kql
// Splunk — Zeek conn.log
index=zeek sourcetype=bro:conn:json orig_bytes=0
dest_ip IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
| bin span=5m _time
| stats dc(dest_port) as num_ports, dc(dest_ip) as num_ips by _time, src_ip
| where num_ports >= 10 or num_ips >= 50
```

**منطق Query:** `orig_bytes=0` نشان‌دهنده **اسکن بدون Payload** است . **Vertical Scan** = `num_ports` بالا. **Horizontal Scan** = `num_ips` بالا .

**مرحله B: بررسی Process اسکن‌کننده**

```kql
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("nmap.exe", "masscan.exe", "netscan.exe", "advanced_port_scanner.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, 
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

**منطق Query:** شناسایی **ابزار اسکن** روی Endpoint. اگر Process از **مسیر غیرعادی** اجرا شده باشد (Temp، AppData)، این **Strong Indicator** است .

**مرحله C: مقایسه با Allowlist اسکنرها**

```kql
// بررسی Source IP در Allowlist
let AuthorizedScanners = dynamic(["10.0.1.50", "10.0.1.51"]);  // IP اسکنرهای مجاز
DeviceNetworkEvents
| where Timestamp > ago(1h)
| where RemoteIPType == "Private"
| where RemotePort in (445, 3389, 135, 5985)
| summarize 
    TargetCount = dcount(RemoteIP),
    PortCount = dcount(RemotePort)
    by DeviceName
| where TargetCount > 20
| extend IsAuthorized = DeviceName in (AuthorizedScanners)
```

**منطق Query:** اگر Source در **Allowlist** باشد → **اسکن مجاز**. اگر نباشد → **Reconnaissance مشکوک** .

### 5. Pivoting و Correlation شواهد

1. **از Source IP به Process:** از Sysmon EID 3 به Sysmon EID 1، `ProcessGuid` را Match کنید تا **Process اسکن‌کننده** را شناسایی کنید.
2. **از Process به Command Line:** آیا `nmap -sS`، `masscan --rate`، یا `netscan` در Command Line است؟
3. **از Timing به Baseline:** آیا اسکن در **ساعات کاری** یا **Change Window** رخ داده؟ اسکنرهای مجاز معمولاً **زمان‌بندی‌شده** هستند .
4. **از Destination به Criticality:** آیا اسکن به **Hostهای Critical** (DC، Database) متمرکز است؟

**هشدار:** همزمانی زمانی به‌تنهایی Causation را اثبات نمی‌کند. برای انتساب اسکن به Process، باید **ProcessGuid یکسان** تأیید شود.

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline:**
- آیا این Source IP **قبلاً** اسکن انجام داده؟ (Historical Baseline)
- آیا اسکن در **زمان‌بندی مشخص** (مثلاً هر شنبه 2 AM) رخ می‌دهد؟

**Scope:**
- آیا **Hostهای دیگر** نیز از همان Source اسکن شده‌اند؟
- آیا **Destination** شامل Subnetهای غیرمرتبط است؟

**False Positive:**
- **Vulnerability Scanner:** Nessus، Qualys، OpenVAS (Source در Allowlist) 
- **Asset Discovery:** Lansweeper، SCCM، SolarWinds (Process شناخته‌شده) 
- **Penetration Test:** اگر **اعلام نشده** باشد، False Positive است 

**معیار قطعی:** Source **غیرمجاز** + Process **غیرسیستمی** + الگوی **غیرمنتظم** + خارج از **Change Window** = **High Confidence Reconnaissance**.

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1046** | Network Service Discovery | اسکن Port و IP برای شناسایی سرویس‌ها  |
| **T1018** (احتمالی) | Remote System Discovery | Horizontal Scan برای شناسایی Hostهای فعال |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** یک سیستم داخلی به تعداد زیادی IP و Port متصل شده است.

**Likely (Reconnaissance):** اگر Source **غیرمجاز** باشد، Process **غیرسیستمی** باشد، و اسکن خارج از **Change Window** رخ دهد.

**Confidence: Medium-High** — برای **High** نیاز به **تأیید Allowlist** و **Process Analysis** داریم.

### 9. Response و بهبود Detection

**اقدامات فوری:**
1. **Isolate Source** اگر Reconnaissance تأیید شد.
2. **Identify Process:** Kill Process اسکن‌کننده و بررسی Persistence.
3. **Check Lateral Movement:** آیا Source به Hostهای دیگر متصل شده؟

**Detection Improvement:**
1. **Allowlist Integration:** ثبت IP اسکنرهای مجاز در SIEM .
2. **Process-Based Rule:** Alert روی `nmap.exe`، `masscan.exe`، `netscan.exe` از **مسیر غیرعادی** .
3. **Threshold Tuning:** تنظیم Threshold بر اساس Baseline سازمان (مثلاً 50 IP یا 10 Port در 5 دقیقه) .

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

اول **Source IP** رو بررسی می‌کنم: آیا در **Allowlist اسکنرهای مجاز** سازمان هست یا نه؟ اگه نباشه، این **Strong Indicator** برای Reconnaissance هست .

بعد **الگوی اسکن** رو تحلیل می‌کنم: از **Zeek conn.log** با `orig_bytes=0` استفاده می‌کنم. **Vertical Scan** (Port زیاد) = دنبال سرویس خاص. **Horizontal Scan** (IP زیاد) = دنبال Hostهای فعال .

**Process اسکن‌کننده** رو از **Sysmon EID 1** استخراج می‌کنم: اگه `nmap.exe` یا `masscan.exe` از مسیر غیرعادی اجرا شده باشه، شک من قطعی‌تر می‌شه .

**محدودیت اصلی:** بدون **Allowlist اسکنرها** و **Change Window**، نمی‌تونم اسکن مجاز رو از Reconnaissance تفکیک کنم. اسکنرهای Vulnerability (Nessus، Qualys) هم **الگوی مشابهی** تولید می‌کنند .

**اقدام بعدی:** اگه Source غیرمجاز بود، Endpoint رو Isolate می‌کنم و Process اسکن‌کننده رو برای **Lateral Movement** بررسی می‌کنم.
