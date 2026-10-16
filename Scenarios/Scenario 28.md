### 1. تعریف سناریو و هدف Hunt

یک Endpoint هر **۶۰ ثانیه** به یک **مقصد خارجی مشخص** اتصال برقرار می‌کند. هدف Hunt، تأیید **C2 Beaconing** (T1071) از طریق تحلیل **Periodicity**، شناسایی **Process** مسئول، بررسی **DNS**، تحلیل **مقصد**، اندازه‌گیری **حجم ترافیک**، و ارزیابی **رفتار میزبان** است.

**نکته حیاتی:** Periodicity **به‌تنهایی** نشانه C2 نیست. بسیاری از نرم‌افزارهای قانونی (Update Checker، Telemetry Agent، NTP Client) نیز رفتار دوره‌ای دارند . تمایز اصلی در **Jitter Ratio**، **Volume Payload**، **Process Context**، و **Destination Reputation** است.

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (C2 Beaconing)** | یک Implant مخرب هر ۶۰ ثانیه به C2 Server متصل می‌شود | Jitter Ratio پایین (< 10%)، Payload کوچک (< 1KB)، Process غیرسیستمی، Destination ناشناخته  | Jitter بالا (> 30%)، Payload بزرگ، Process قانونی (Svchost، Update Service) |
| **فرضیه جایگزین (Legitimate Telemetry)** | یک Agent قانونی (Monitoring، Backup، Update) به Server سازمانی متصل می‌شود | Process شناخته‌شده، Destination در Allowlist، Payload قابل توضیح | Destination ناشناخته، Command Line مشکوک |
| **فرضیه جایگزین (Polling Application)** | یک نرم‌افزار قانونی (Email Client، Chat App) برای دریافت Update Poll می‌کند | Process قابل شناسایی (Outlook، Teams)، Jitter طبیعی | Process غیرعادی، Volume غیرمعمول |

### 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Sysmon Event ID 3** (Essential) | Network Connection | `Image`، `DestinationIp`، `DestinationPort`، `ProcessGuid`  |
| **Sysmon Event ID 22** (Essential) | DNS Query | `QueryName`، `Image`، `ProcessGuid` — اتصال DNS Query به Process  |
| **Windows Firewall Log** (Supplementary) | Connection Log | `pfirewall.log` — Source/Destination/Port/Size  |
| **EDR Network Telemetry** (Essential) | Connection Detail | Process Context، Bytes Sent/Received |

**محدودیت:** Sysmon EID 3 برای Processهای **کوتاه‌مدت** ممکن است `Image` را خالی ثبت کند و نیاز به Correlate با `ProcessGuid` دارد .

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: محاسبه Periodicity و Jitter**

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| where ActionType == "ConnectionSuccess"
| summarize 
    Connections = make_list(Timestamp),
    ConnectionCount = count(),
    AvgBytes = avg(SentBytes + ReceivedBytes)
    by DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName
| where ConnectionCount >= 10
| extend Intervals = array_sort_asc(
    range(1, array_length(Connections), 1) 
    |> extend(Interval = datetime_diff('second', Connections[this], Connections[this-1]))
    |> project(Interval)
)
| extend 
    MeanInterval = avg(Intervals),
    StdDevInterval = stdev(Intervals)
| extend JitterRatio = StdDevInterval / MeanInterval
| where JitterRatio < 0.15 and AvgBytes < 1024
| order by JitterRatio asc
```

**منطق Query:** Jitter Ratio کمتر از **15%** نشان‌دهنده **Automation** است. Jitter کمتر از **5%** = **Mechanical Clock** (Implant یا Scheduled Task) . Payload کمتر از **1KB** = **Heartbeat** .

**مرحله B: Correlate DNS Query با Connection**

```kql
let SuspiciousConnections = DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| project ConnectionTime = Timestamp, DeviceName, RemoteIP, 
          ProcessGuid = InitiatingProcessGuid, ProcessName = InitiatingProcessFileName;
let DNSQueries = DeviceEvents
| where ActionType == "DnsQueryResponse"
| project QueryTime = Timestamp, DeviceName, QueryName, 
          ProcessGuid = InitiatingProcessGuid, ProcessName = InitiatingProcessFileName;
SuspiciousConnections
| join kind=inner DNSQueries on DeviceName, ProcessGuid
| where QueryTime between (ConnectionTime - 30s .. ConnectionTime)
| project ConnectionTime, QueryTime, DeviceName, ProcessName, RemoteIP, QueryName
| order by ConnectionTime desc
```

**منطق Query:** Sysmon EID 22 فیلد `Image` را دارد که Process انجام‌دهنده DNS Query را نشان می‌دهد . این **Pivot کلیدی** از Network Layer به Process Layer است.

**مرحله C: بررسی Process Context و Command Line**

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessGuid in (
    DeviceNetworkEvents 
    | where Timestamp > ago(24h) 
    | where RemoteIPType == "Public"
    | project InitiatingProcessGuid
)
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, 
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256, FolderPath
```

**منطق Query:** بررسی اینکه چه Processی Connection را ایجاد کرده. اگر Process از **مسیر غیرعادی** (`Temp`، `AppData`، `Users\Public`) باشد یا Command Line شامل `-enc`، `IEX`، `DownloadString` باشد → **Strong Indicator** .

### 5. Pivoting و Correlation شواهد

1. **Community ID:** از **Community ID** برای Correlate بین Network Telemetry (Zeek/Suricata) و Endpoint Telemetry (Sysmon) استفاده کنید .
2. **DNS Pivot:** از `QueryName` به Threat Intel (VirusTotal، AbuseIPDB) بروید. DGA-style Domain (Long Random Alphanumeric) → **Strong Indicator** .
3. **Inbound/Outbound Ratio:** از `tshark -z conv,ip` نسبت Bytes Inbound به Outbound را محاسبه کنید. نسبت **15:1+** = Server Pushing Payload (Implant) .
4. **Process Tree:** Parent Process را بررسی کنید. اگر `explorer.exe`، `winword.exe`، یا `cmd.exe` باشد → **مشکوک**.

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline:**
- آیا این Destination در **Allowlist** سازمان است؟ (Update Server، Monitoring Endpoint)
- آیا Process در Baseline به‌عنوان Network Client ثبت شده؟

**False Positive:**
- **Software Updates:** Google Update، Adobe، Java Updater (Jitter بالاتر، Payload بزرگ‌تر) 
- **Monitoring Agents:** Datadog، New Relic (Process شناخته‌شده)
- **NTP:** Windows Time Service (Port 123، Process `svchost.exe`)

**معیار قطعی:** Jitter Ratio **< 5%** + Payload **< 500 bytes** + Process **غیرسیستمی** + Destination **ناشناخته** = **High Confidence C2** .

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1071.001** | Application Layer Protocol: Web Protocols | Beaconing به C2 از طریق HTTP/HTTPS |
| **T1071.004** | Application Layer Protocol: DNS | DNS Beaconing یا DGA |
| **T1571** | Non-Standard Port | اتصال به Port غیرعادی برای C2 |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** Endpoint هر ۶۰ ثانیه به مقصد خارجی متصل می‌شود.

**Likely:** این رفتار **مشکوک به C2 Beaconing** است اگر:
1. Jitter Ratio **< 10%** باشد.
2. Payload **< 1KB** باشد.
3. Process از **مسیر غیرعادی** باشد.
4. Destination در **Threat Intel** به‌عنوان Malicious ثبت شده باشد.

**Confidence: Medium-High** — برای **Confirmed** نیاز به تأیید **Process Context** و **Destination Reputation**.

### 9. Response و بهبود Detection

**فوری:**
1. **Endpoint Isolation** اگر C2 تأیید شد.
2. **Process Kill** و **Memory Dump** برای Forensic.
3. **Network Blocking** مقصد C2 در Firewall.

**Detection Improvement:**
1. **قانون Jitter:** هر Source/Destination با Jitter Ratio **< 10%** و Payload **< 1KB** → Alert .
2. **قانون DNS:** هر DNS Query به Domain با Entropy بالا یا DGA Pattern → Alert .
3. **قانون Process:** هر Network Connection از Process در `Temp`/`AppData` → Alert .

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

اول **Periodicity** رو با محاسبه **Jitter Ratio** چک می‌کنم: `StdDev(Intervals) / Mean(Intervals)`. اگه Jitter زیر **۱۰%** باشه، این **Automation** هست، نه Human Browsing .

بعد **Payload Size** رو بررسی می‌کنم: اگه میانگین Bytes زیر **۱KB** باشه، این **Heartbeat** هست . ترکیب **Jitter پایین + Payload کوچک** = **Strong Indicator** برای C2.

برای **Process Context**، از **Sysmon EID 22** استفاده می‌کنم که `Image` رو نشون می‌ده و می‌تونم DNS Query رو به Process نسبت بدم . اگه Process از `Temp` یا `AppData` باشه، شک من قطعی‌تر می‌شه.

**محدودیت اصلی:** Periodicity **به‌تنهایی** کافی نیست — خیلی از Agentهای قانونی هم دوره‌ای هستند . برای Confirmation نیاز به **Destination Reputation** و **Process Analysis** دارم.

**اقدام بعدی:** اگه تأیید شد، Endpoint رو Isolate می‌کنم، Process رو Kill می‌کنم، و مقصد C2 رو در Firewall بلاک می‌کنم.
