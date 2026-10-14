### 1. تعریف سناریو و هدف Hunt

سه Event در یک بازه زمانی کوتاه مشاهده می‌شوند: **Security 4624** (Successful Logon)، **Sysmon 1** (Process Creation)، و **Sysmon 3** (Network Connection). هدف، اتصال این سه رویداد به یک **Process** مشخص و یک **Logon Session** مشخص است، و تعیین اینکه آیا این زنجیره نشان‌دهنده یک **Lateral Movement** یا **Remote Execution** است.

**نکته حیاتی:** همزمانی زمانی (Temporal Proximity) **Causation** را اثبات نمی‌کند. صرفاً دیدن 4624، Sysmon 1 و Sysmon 3 در یک بازه ۵ دقیقه‌ای **کافی نیست** — باید **ProcessGuid** و **LogonId** یکسان تأیید شود تا انتساب قطعی شود.

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده |
|---|---|---|
| **فرضیه اصلی (Lateral Movement / Remote Execution)** | مهاجم از یک Source از طریق SMB/RPC/WinRM به Host متصل شده، Login کرده، و Process مخرب اجرا کرده که اتصال شبکه برقرار کرده | **LogonId** مشترک بین 4624 و Sysmon 1، **ProcessGuid** مشترک بین Sysmon 1 و Sysmon 3، LogonType 3 یا 10، Process مشکوک (`cmd.exe`، `powershell.exe`)  |
| **فرضیه جایگزین (Legitimate Admin Activity)** | یک Admin یا ابزار Management قانونی Login کرده و Process قانونی اجرا کرده | Source IP از Management Network، Process Ancestry قانونی (`mmc.exe`، `svchost.exe`)، Destination در Allowlist  |

### 3. Telemetry و Data Sources

| منبع | نقش | فیلدهای کلیدی |
|---|---|---|
| **Security Event ID 4624** (Essential) | Logon | `LogonId`، `TargetUserName`، `IpAddress`، `LogonType`، `AuthenticationPackageName`  |
| **Sysmon Event ID 1** (Essential) | Process Creation | `ProcessGuid`، `ProcessId`، `LogonId`، `Image`، `CommandLine`، `ParentProcessGuid`  |
| **Sysmon Event ID 3** (Essential) | Network Connection | `ProcessGuid`، `ProcessId`، `Image`، `DestinationIp`، `DestinationPort`  |

**محدودیت حیاتی:** **Sysmon EID 1** فیلد `LogonId` را ثبت می‌کند، اما **Sysmon EID 3** این فیلد را ندارد. بنابراین، اتصال 4624 به Sysmon 1 از طریق **LogonId** ممکن است، اما اتصال Sysmon 1 به Sysmon 3 فقط از طریق **ProcessGuid** ممکن است .

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: اتصال 4624 به Sysmon 1 (از طریق LogonId)**

```kql
let LogonEvent = SecurityEvent
| where EventID == 4624
| where LogonType in (3, 10)
| project LogonTime = TimeGenerated, Computer, TargetUser = Account, 
          LogonId = tostring(EventData.LogonId), SourceIP = IpAddress, LogonType;
let ProcessEvent = DeviceProcessEvents
| where Timestamp > ago(1h)
| where ProcessCommandLine has_any ("cmd", "powershell", "net", "whoami")
| project ProcessTime = Timestamp, DeviceName, AccountName, 
          ProcessCommandLine, InitiatingProcessFileName, 
          LogonId = tostring(AdditionalFields.LogonId), ProcessGuid = ProcessGuid;
LogonEvent
| join kind=inner ProcessEvent on $left.Computer == $right.DeviceName
| where ProcessTime between (LogonTime .. 5m)  // 5-minute window
| project LogonTime, ProcessTime, Computer, TargetUser, SourceIP, 
          LogonId, ProcessCommandLine, InitiatingProcessFileName
```

**منطق Query:** اگر `LogonId` در 4624 و Sysmon 1 یکسان باشد، این **اتصال قطعی** بین Login و Process Creation است .

**مرحله B: اتصال Sysmon 1 به Sysmon 3 (از طریق ProcessGuid)**

```kql
let ProcessCreation = DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName in~ ("cmd.exe", "powershell.exe", "rundll32.exe", "mshta.exe")
| project ProcessTime = Timestamp, DeviceName, ProcessGuid, 
          ProcessImage = FileName, ProcessCommandLine, LogonId = tostring(AdditionalFields.LogonId);
let NetworkConnection = DeviceNetworkEvents
| where Timestamp > ago(1h)
| where RemoteIPType == "Public" or RemotePort in (445, 3389, 5985)
| project NetworkTime = Timestamp, DeviceName, ProcessGuid, 
          RemoteIP, RemotePort, RemoteUrl;
ProcessCreation
| join kind=inner NetworkConnection on DeviceName, ProcessGuid
| where NetworkTime between (ProcessTime .. 5m)
| project ProcessTime, NetworkTime, DeviceName, ProcessImage, 
          ProcessCommandLine, RemoteIP, RemotePort, RemoteUrl, LogonId
```

**منطق Query:** `ProcessGuid` در Sysmon 1 و Sysmon 3 **یکسان** است و این **اتصال قطعی** بین Process و Network Connection را فراهم می‌کند .

### 5. Pivoting و Correlation شواهد

1. **از 4624 به Sysmon 1:** `LogonId` را از 4624 استخراج کنید و با `LogonId` در Sysmon 1 Match کنید .
2. **از Sysmon 1 به Sysmon 3:** `ProcessGuid` را از Sysmon 1 استخراج کنید و با `ProcessGuid` در Sysmon 3 Match کنید .
3. **از ProcessGuid به Parent Process:** از `ParentProcessGuid` در Sysmon 1 برای بررسی **Process Ancestry** استفاده کنید.
4. **از Destination به Threat Intel:** `DestinationIp` را در VirusTotal / AbuseIPDB بررسی کنید.

### 6. محدودیت‌های تطبیق زمانی و انتساب

**محدودیت ۱: Time Sync بین Hostها**
اگر Hostها **Time Sync** نباشند (اختلاف بیش از ۱ دقیقه)، `between` Clause می‌تواند رویدادهای مرتبط را از دست بدهد یا رویدادهای نامرتبط را شامل شود .

**محدودیت ۲: Sysmon EID 3 فیلد LogonId ندارد**
Sysmon 3 فقط `ProcessGuid` و `ProcessId` دارد، نه `LogonId`. بنابراین، اتصال 4624 به Sysmon 3 **مستقیم** ممکن نیست — باید از طریق **Sysmon 1** (که `LogonId` دارد) واسطه شود .

**محدودیت ۳: Process ID Reuse**
`ProcessId` در ویندوز **Reuse** می‌شود. بنابراین، استفاده از `ProcessId` به جای `ProcessGuid` برای Correlation **ناامن** است. `ProcessGuid` **Unique** است و هرگز Reuse نمی‌شود .

**محدودیت ۴: Sysmon EID 3 ممکن است Image را خالی ثبت کند**
برای Processهای **کوتاه‌مدت**، Sysmon 3 ممکن است فیلد `Image` را خالی ثبت کند و فقط `ProcessGuid` و `ProcessId` باقی بماند. این باعث می‌شود انتساب Process به Connection **نیاز به واسطه Sysmon 1** داشته باشد .

**محدودیت ۵: همزمانی ≠ علیت**
دیدن 4624 و Sysmon 1 در بازه ۵ دقیقه‌ای **کافی نیست**. باید `LogonId` **یکسان** تأیید شود. اگر `LogonId` متفاوت باشد، Process توسط User دیگری یا Logon Session دیگری ایجاد شده است.

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1021.002** | SMB/Windows Admin Shares | LogonType 3 + Process Creation + Network Connection به 445  |
| **T1059.001** | PowerShell | Process Creation با `powershell.exe`  |
| **T1071** | Application Layer Protocol | Network Connection از Process مشکوک به C2  |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** سه Event در بازه کوتاه دیده شده‌اند.

**Correlated:** اگر `LogonId` (4624 ↔ Sysmon 1) و `ProcessGuid` (Sysmon 1 ↔ Sysmon 3) **یکسان** باشند، این **زنجیره علیت** تأیید می‌شود.

**Confidence: High** — اگر `LogonId` و `ProcessGuid` Match شوند. **Medium** اگر فقط Temporal Proximity باشد و `LogonId` تأیید نشود.

### 9. Response و بهبود Detection

**فوری:** Isolation اگر Process مشکوک به C2 متصل شده باشد.

**Detection Improvement:** قانون Correlation که **LogonId + ProcessGuid** را با هم Match کند، نه فقط Timestamp.

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

اول **LogonId** رو از **Event 4624** استخراج می‌کنم و با `LogonId` در **Sysmon EID 1** Match می‌کنم. اگه یکسان باشه، این **Login** و **Process Creation** رو به هم وصل می‌کنه .

بعد **ProcessGuid** رو از **Sysmon EID 1** استخراج می‌کنم و با `ProcessGuid` در **Sysmon EID 3** Match می‌کنم. این **قطعیت** رو می‌ده که Network Connection از **همون Process** هست .

**محدودیت اصلی:** Sysmon EID 3 فیلد `LogonId` نداره، پس باید از طریق Sysmon 1 واسطه بشه . همچنین، `ProcessId` در ویندوز **Reuse** می‌شه و باید از `ProcessGuid` استفاده کنم که **Unique** هست .

**اقدام بعدی:** اگه `LogonId` و `ProcessGuid` Match شدن و Process مشکوک به C2 متصل شده بود، Endpoint رو Isolate می‌کنم.
