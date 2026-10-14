### 1. تعریف سناریو و هدف Hunt

یک User در مدت کوتاهی از **یک سیستم** به **چندین Server** با RDP متصل می‌شود. هدف Hunt، تشخیص **Lateral Movement از طریق RDP** (T1021.001) و تفکیک آن از **دسترسی مدیریتی عادی** (Admin Activity) یا **ابزارهای Management** است.

**نکته حیاتی:** RDP یک پروتکل **پرکاربرد** برای Adminها و IT Support است. اتصال به چند Server **به‌تنهایی** نشانه حمله نیست. تمایز اصلی در **Source Workstation**، **Logon Type**، **Volume و Time Window**، و **Activity پس از Login** است.

### 2. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational — Event ID 1149** (Essential) | RDP Connection Established | `Param1` (Username attempting)، `Param3` (Source IP) — روی **Destination** ثبت می‌شود  |
| **Windows Security Event ID 4624** (Essential) | Successful Logon | `LogonType 10` (RemoteInteractive) یا `7` (Unlock)، `TargetUserName`، `IpAddress`  |
| **Windows Security Event ID 4778** (Supplementary) | Session Reconnected | `ClientName`، `ClientAddress`، `SessionName` (RDP-Tcp#N)  |
| **Windows Security Event ID 4648** (Supplementary) | Explicit Credentials | `TargetUserName`، `ProcessName` — برای RDP با RunAs یا Scheduled Task  |
| **Sysmon Event ID 1** (Essential) | Process Creation | Processهایی که **پس از Login** روی Server ایجاد شده‌اند |
| **Network Flow / Zeek** (Supplementary) | RDP Connections | اتصال به Port 3389 بین Internal Hosts  |

**محدودیت مهم:** Event ID 4624 با **Logon Type 10** به‌صورت **همیشه قابل اعتماد نیست** و ممکن است در برخی Serverها به‌دلیل Latency یا Load ناقص ثبت شود . همچنین، 4624 فقط روی **Host محلی** ثبت می‌شود — برای دیدن RDP به یک Member Server، باید Security Log **همان Server** را بررسی کنید، نه Domain Controller .

### 3. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: شناسایی RDP Connectionهای گسترده از یک Source**

```kql
SecurityEvent
| where EventID == 4624
| where LogonType in (10, 7)
| where IpAddress !in ("127.0.0.1", "::1", "-")
| summarize 
    TargetCount = dcount(Computer),
    Targets = make_set(Computer),
    FirstLogon = min(TimeGenerated),
    LastLogon = max(TimeGenerated)
    by TargetUserName, IpAddress
| where TargetCount >= 3  // Threshold قابل تنظیم
| order by TargetCount desc
```

**منطق Query:** گروه‌بندی بر اساس **TargetUserName** و **Source IP**، شمارش **Hostهای متمایز** که RDP Login روی آن‌ها رخ داده. آستانه 3 Host در بازه کوتاه، **Strong Indicator** برای Lateral Movement است .

**مرحله B: Correlate Event 1149 با 4624**

Event 1149 **قبل از Authentication** ثبت می‌شود و فقط **Connection** را نشان می‌دهد، نه موفقیت Login . برای تأیید Login موفق، باید با 4624 correlate شود:

```kql
let RDPConnections = Event
| where Source == "Microsoft-Windows-TerminalServices-RemoteConnectionManager"
| where EventID == 1149
| extend Username = tostring(EventData.Param1)
| extend SourceIP = tostring(EventData.Param3)
| project ConnectionTime = TimeGenerated, Computer, Username, SourceIP;
let SuccessfulLogons = SecurityEvent
| where EventID == 4624 and LogonType in (10, 7)
| project LogonTime = TimeGenerated, Computer, TargetUser = Account, SourceIP = IpAddress;
RDPConnections
| join kind=inner SuccessfulLogons on Computer, SourceIP
| where LogonTime between (ConnectionTime .. 2m)  // 2-minute window
| project ConnectionTime, LogonTime, Computer, Username, SourceIP
| order by ConnectionTime desc
```

**منطق Query:** اتصال RDP (1149) **قبل از** Login موفق (4624) ثبت می‌شود. Correlate این دو با **همان Source IP** و **Host** در بازه 2 دقیقه، **زنجیره علیت** را تأیید می‌کند .

**مرحله C: بررسی Processهای پس از RDP Login روی Server**

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where DeviceName in ("SERVER1", "SERVER2", "SERVER3")  // Targets
| where InitiatingProcessFileName !in~ ("svchost.exe", "lsass.exe", "services.exe", "winlogon.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, 
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**منطق Query:** Processهایی که **پس از RDP Login** روی Server ایجاد شده‌اند. اگر `cmd.exe`، `powershell.exe`، `net.exe`، یا `whoami.exe` توسط `explorer.exe` یا `rdpclip.exe` spawn شده باشند، این **Hands-on-Keyboard Activity** است.

### 4. Pivoting و Correlation شواهد

1. **Source Workstation:** از `IpAddress` در 4624 و `ClientAddress` در 4778 برای شناسایی **مبدأ** RDP استفاده کنید. اگر Source IP یک **Workstation معمولی** باشد (نه Jump Server یا Management VLAN)، شک بالاتر می‌رود .
2. **Process Tree روی Server:** از Sysmon EID 1 بررسی کنید که **بلافاصله پس از 4624** چه Processهایی ایجاد شده‌اند. Parent Process چه بوده؟ (`explorer.exe` قانونی است، `cmd.exe` توسط `explorer.exe` مشکوک).
3. **Target Selection Pattern:** آیا Serverها **ترتیبی** هستند (مثل اسکنر) یا **انتخابی** (مثل مهاجم که AD را Enumeration کرده)؟ 
4. **Activity پس از Login:** آیا فایل کپی شده؟ آیا Service ایجاد شده؟ آیا Process مشکوک اجرا شده؟ RDP Login **به‌تنهایی** کافی نیست — باید **Post-Login Activity** بررسی شود.
5. **Logon Type 7 (Unlock):** اگر 4624 با Type 7 دیده شود، این **Reconnection به Session موجود** است، نه Login جدید. این می‌تواند قانونی باشد (کاربر Session خود را Reconnect کرده) یا **Session Hijacking** .

**هشدار:** همزمانی زمانی (Temporal Proximity) به‌تنهایی **Causation** را اثبات نمی‌کند. برای انتساب RDP به Lateral Movement، باید **Source IP یکسان**، **Target User یکسان**، و **Post-Login Activity** تأیید شود.

### 5. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline:**
- آیا Source IP در **Management VLAN** یا **Jump Server** است؟ (اگر بله → احتمالاً قانونی)
- آیا این User **قبلاً** به این Serverها RDP زده است؟ (Historical Baseline)
- آیا RDP در **ساعات کاری** است یا خارج از آن؟

**False Positive:**
- **IT Admin:** اتصال قانونی از Jump Server برای Maintenance 
- **Backup Software:** برخی ابزارهای Backup از RDP برای Agent Deployment استفاده می‌کنند
- **Scheduled Tasks:** Taskهایی که با Credential ذخیره‌شده به Serverها متصل می‌شوند (Event 4648) 

**معیار قطعی:** اگر Source IP از **Workstation معمولی** باشد، **Logon Type 10** باشد، و **Processهای مشکوک** پس از Login ایجاد شده باشند، احتمال **False Positive پایین** است.

### 6. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1021.001** | Remote Services: RDP | اتصال RDP از یک User به چندین Server در بازه کوتاه  |
| **T1078** (احتمالی) | Valid Accounts | اگر از Credential معتبر User استفاده شده باشد |
| **T1563.002** (احتمالی) | RDP Session Hijacking | اگر Logon Type 7 (Reconnection) بدون Logout قبلی مشاهده شود |

### 7. نتیجه‌گیری و سطح اطمینان

**Observed:** یک User از یک سیستم به چندین Server با RDP متصل شده.

**Likely:** این رفتار **مشکوک به Lateral Movement** است، به‌ویژه اگر:
1. Source IP از **Management Network** نباشد.
2. **Logon Type 10** باشد (نه 7).
3. **Processهای مشکوک** پس از Login ایجاد شده باشند.
4. Target Selection **انتخابی** باشد (نه ترتیبی).

**Confidence: Medium-High** — برای **Confirmed** نیاز به تأیید **Post-Login Activity** روی Serverها.

### 8. Response و بهبود Detection

**فوری:**
1. **Account Containment:** اگر حساب Compromised شده.
2. **Investigation روی Serverها:** بررسی Process Creation، Persistence، Lateral Movement.
3. **Source Isolation:** اگر Workstation Compromised شده.

**Detection Improvement:**
1. **قانون RDP Burst:** هر User که در **15 دقیقه** به **3+ Host** RDP متصل شود → Alert .
2. **قانون Source Context:** هر RDP از IP غیر Management به Server حساس → Alert.
3. **قانون Post-Login:** هر Process مشکوک (`cmd.exe`، `powershell.exe`) که **بلافاصله پس از RDP Login** ایجاد شود → Alert.

### 9. پاسخ کوتاه برای شروع جواب در مصاحبه

اول **Event ID 4624** رو روی **Serverهای Target** بررسی می‌کنم و **Logon Type** رو چک می‌کنم: Type 10 (RDP) یا Type 7 (Reconnection). اگه یک User در بازه کوتاه به **3+ Server** RDP زده باشه، این **Strong Indicator** برای Lateral Movement هست.

بعد **Event ID 1149** رو روی همون Serverها correlate می‌کنم: این Event **قبل از Authentication** ثبت می‌شه و **Source IP** رو نشون می‌ده . اگه Source IP از **Management VLAN** یا **Jump Server** نباشه، شک من قطعی‌تر می‌شه.

**Processهای پس از Login** رو هم از Sysmon EID 1 چک می‌کنم: اگه `cmd.exe` یا `powershell.exe` توسط `explorer.exe` یا `rdpclip.exe` spawn شده باشه، این **Hands-on-Keyboard** هست و باید Endpoint رو Isolate کنم.

**محدودیت اصلی:** Event ID 4624 با Type 10 همیشه قابل اعتماد نیست و ممکنه ناقص ثبت بشه . همچنین 4624 فقط روی **Host محلی** ثبت می‌شه، نه Domain Controller .

**اقدام بعدی:** اگه تأیید شد، Source رو Isolate می‌کنم و روی Serverها بررسی می‌کنم که آیا Persistence یا Lateral Movement بیشتری رخ داده.
