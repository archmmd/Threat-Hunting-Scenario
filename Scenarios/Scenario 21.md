### 1. تعریف سناریو و هدف Hunt

یک Workstation طی **۲۰ دقیقه** به **۱۵ سیستم داخلی** از طریق SMB متصل شده است. هدف Hunt، تشخیص **Lateral Movement** از طریق SMB (T1021.002) و تفکیک آن از **دسترسی مدیریتی عادی** (Admin Activity) و **اسکنرهای شبکه** است.

**نکته حیاتی:** SMB پروتکل **پرترافیک** در محیط‌های Windows است و اتصال به چندین Host **به‌تنهایی** نشانه حمله نیست. تمایز اصلی در **Volume**، **Target Selection**، **Activity پس از اتصال**، و **Source Context** است .

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (Malicious Lateral Movement)** | مهاجم از یک Workstation Compromised برای حرکت جانبی به ۱۵ سیستم استفاده می‌کند | اتصال به **ADMIN$** یا **C$**، Activity پس از اتصال (Service Creation، Process Execution)، Source Process غیرسیستمی (`powershell.exe`، `cmd.exe`)، اتصال خارج از ساعات کاری، Target Selection **غیرترتیبی**  | اتصال فقط به **File Share** عمومی، Source Process `explorer.exe`، Activity فقط Read/Write |
| **فرضیه جایگزین (Admin Activity)** | یک Admin یا ابزار Management (مثل SCCM، Backup) به‌صورت قانونی به چندین Host متصل می‌شود | Source IP از **Jump Server** یا **Management VLAN**، Process شناخته‌شده (`mmc.exe`، `net.exe`)، Activity مطابق Baseline | عدم تطابق با Baseline، Source IP از Workstation معمولی |
| **فرضیه جایگزین (Network Scanner)** | یک Vulnerability Scanner یا Asset Discovery Tool در حال اسکن شبکه است | اتصال به **همه** Hostها (نه فقط ۱۵)، Volume بالا، Process شناخته‌شده (Scanner Agent) | Target Selection خاص (۱۵ Host)، Activity پس از اتصال (نه فقط Handshake) |

### 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Windows Security Event ID 4624** (Essential) | Network Logon | `LogonType 3` (Network)، `IpAddress`، `AuthenticationPackageName` (NTLM/Kerberos)  |
| **Windows Security Event ID 5140** (Essential) | Share Access | `ShareName` (ADMIN$، C$، IPC$)، `SourceAddress`، `SubjectUserName`  |
| **Windows Security Event ID 5145** (Supplementary) | Detailed File Share | `ShareName`، `RelativeTargetName`، `AccessList` — نیاز به **Detailed File Share Auditing**  |
| **Windows System Event ID 7045** (Essential) | Service Installation | `ServiceName` (PSEXESVC، RemCom)، `ServiceFileName` — **Critical برای PsExec Detection**  |
| **Sysmon Event ID 3** (Essential) | Network Connection | اتصال به Port 445 از Processهای غیرسیستمی  |
| **Sysmon Event ID 1** (Essential) | Process Creation | Source Process که SMB Connection را ایجاد کرده |

**محدودیت مهم:** Event ID 5145 **به‌صورت پیش‌فرض Audited نیست** و باید **Detailed File Share Auditing** فعال شود . بدون آن، فقط 5140 (Share Access) را داریم.

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: شناسایی SMB Connectionهای گسترده از یک Source**

```kql
SecurityEvent
| where EventID == 5140
| where ShareName has_any ("ADMIN$", "C$", "IPC$")
| summarize 
    TargetCount = dcount(Computer),
    Targets = make_set(Computer),
    FirstAccess = min(TimeGenerated),
    LastAccess = max(TimeGenerated)
    by IpAddress, Account
| where TargetCount >= 5  // Threshold قابل تنظیم
| order by TargetCount desc
```

**منطق Query:** گروه‌بندی بر اساس `IpAddress` (Source) و شمارش **Hostهای متمایز** که Shareهای Administrative روی آن‌ها Access شده .

**مرحله B: شناسایی PsExec (Service Creation)**

```kql
Event
| where Source == "Service Control Manager"
| where EventID == 7045
| where ServiceName has_any ("PSEXESVC", "RemCom", "csexec", "paexec")
| project TimeGenerated, Computer, ServiceName, ServiceFileName, AccountName
| order by TimeGenerated desc
```

**منطق Query:** PsExec همیشه یک Service موقت به نام **PSEXESVC** روی Target ایجاد می‌کند — این **High-Confidence Indicator** برای Lateral Movement است .

**مرحله C: Correlate 4624 (Type 3) با 7045**

```kql
let SMBLogons = SecurityEvent
| where EventID == 4624 and LogonType == 3
| project LogonTime = TimeGenerated, Computer, TargetUser = Account, 
          SourceIP = IpAddress, LogonID = EventData.LogonId;
let ServiceInstalls = Event
| where EventID == 7045
| project ServiceTime = TimeGenerated, Computer, ServiceName, ServiceFileName;
SMBLogons
| join kind=inner ServiceInstalls on Computer
| where ServiceTime between (LogonTime .. 5m)  // 5-minute window
| project LogonTime, ServiceTime, Computer, TargetUser, SourceIP, ServiceName, ServiceFileName
```

**منطق Query:** Correlate Network Logon با Service Installation از **همان Host** در بازه زمانی کوتاه — این **الگوی PsExec** است .

### 5. Pivoting و Correlation شواهد

1. **Process Tree روی Target:** از Sysmon EID 1 بررسی کنید که **چه Processی** توسط `PSEXESVC` یا `services.exe` ایجاد شده. اگر `cmd.exe` یا `powershell.exe` توسط `PSEXESVC` spawn شده باشد → **Lateral Movement تأیید** .
2. **Named Pipe:** Sysmon EID 17 — PipeName `\PSEXESVC*` یا `\RemCom*` .
3. **Source Process روی Workstation:** چه Processی SMB Connection را ایجاد کرده؟ اگر `powershell.exe`، `cmd.exe`، یا `net.exe` باشد → مشکوک .
4. **Target Selection Pattern:** آیا Hostها **ترتیبی** هستند (مثل اسکنر) یا **انتخابی** (مثل مهاجم که AD را Enumeration کرده)؟ 
5. **Activity پس از Connection:** آیا فایل کپی شده؟ آیا Process اجرا شده؟ فقط Share Access **کافی نیست** — باید **Execution** تأیید شود .

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline:**
- آیا Source IP در **Management VLAN** یا **Jump Server** است؟ 
- آیا Process Source (`explorer.exe`، `mmc.exe`) در Baseline به‌عنوان SMB Client ثبت شده؟
- آیا زمان Activity در **ساعات کاری** است؟ 

**False Positive:**
- **SCCM/Backup:** اتصال قانونی به ADMIN$ با Volume بالا 
- **Vulnerability Scanner:** اتصال به همه Hostها، نه ۱۵ Host خاص
- **IT Admin:** اتصال از Jump Server با Ticket ثبت‌شده 

**معیار قطعی:** اگر **ADMIN$** Access شود، **Service Creation (7045)** رخ دهد، و **Process Execution** پس از Logon مشاهده شود → **False Positive پایین** .

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1021.002** | Remote Services: SMB/Windows Admin Shares | اتصال به ADMIN$/C$ از Workstation به ۱۵ Host  |
| **T1569.002** | System Services: Service Execution | Service Creation (7045) با PSEXESVC  |
| **T1570** | Lateral Tool Transfer | File Copy از طریق ADMIN$ یا C$ |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** یک Workstation به ۱۵ Host با SMB متصل شده.

**Likely:** این رفتار **مشکوک به Lateral Movement** است، به‌ویژه اگر:
1. ShareName شامل **ADMIN$** یا **C$** باشد.
2. **Service Creation** (7045) روی Hostهای Target رخ داده باشد.
3. Source Process **غیرسیستمی** باشد (`powershell.exe`، `cmd.exe`).
4. Activity **خارج از ساعات کاری** یا از **IP غیر Management** باشد.

**Confidence: Medium-High** — برای **Confirmed** نیاز به تأیید **Process Execution** روی Target.

### 9. Response و بهبود Detection

**فوری:**
1. **Endpoint Isolation** روی Source Workstation.
2. **Investigation روی ۱۵ Host Target:** بررسی Service Creation، Process Execution، Persistence.
3. **Credential Revocation:** اگر حساب Admin Compromised شده.

**Detection Improvement:**
1. **قانون CISA:** Correlate **4624 (Type 3)** + **Process Creation در ADMIN$** + **File Share Access مکرر** در 10 دقیقه .
2. **قانون PsExec:** هر **7045** با ServiceName `PSEXESVC` → Alert .
3. **قانون SMB Spread:** هر Source که در **1 ساعت** به **3+ Host** با ADMIN$ متصل شود → Alert .

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

اول **ShareName** رو چک می‌کنم: اگه اتصال به **ADMIN$** یا **C$** باشه، این **Strong Indicator** برای Lateral Movement هست، چون این Shareها دسترسی مستقیم به Windows Directory می‌دن .

بعد **Activity پس از اتصال** رو بررسی می‌کنم: از **Event ID 7045** (Service Creation) استفاده می‌کنم — اگه ServiceName **PSEXESVC** باشه، این **High-Confidence** برای PsExec هست . همچنین **Sysmon EID 1** رو چک می‌کنم که آیا `cmd.exe` یا `powershell.exe` توسط `PSEXESVC` spawn شده.

**Source Context** هم مهمه: اگه Source IP از **Management VLAN** یا **Jump Server** نباشه، و Process Source `powershell.exe` باشه، شک من قطعی‌تر می‌شه .

**محدودیت اصلی:** اگه **Detailed File Share Auditing** فعال نباشه، فقط **5140** (Share Access) رو داریم، نه **5145** (File Operation) . و اگه **Event 7045** نباشه، نمی‌تونم PsExec رو تأیید کنم.

**اقدام بعدی:** اگه تأیید شد، Source رو Isolate می‌کنم و روی ۱۵ Host Target بررسی می‌کنم که آیا Service Creation یا Process Execution رخ داده.
