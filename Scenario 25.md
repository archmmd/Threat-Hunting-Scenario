### 1. تعریف سناریو و هدف Hunt

یک **Host آلوده** (Patient Zero) شناسایی شده و پس از آن، **Login**، **SMB** و **Process Creation مشکوک** روی **دو Server دیگر** مشاهده شده است. هدف Hunt، **بازسازی Timeline حرکت مهاجم**، شناسایی **Hostهای درگیر**، و **Scope کردن Incident** است.

**نکته حیاتی:** این سناریو یک **Incident Response چندمرحله‌ای** است، نه یک Hunt تک‌Event. باید از **Patient Zero** به‌عنوان نقطه شروع استفاده کنیم و **زنجیره علیت** را از طریق **Timestamp Correlation**، **Account Correlation**، و **Network Correlation** بازسازی کنیم. صرفاً همزمانی زمانی (Temporal Proximity) **کافی نیست** — باید **Process Ancestry** و **Authentication Chain** تأیید شود .

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (Multi-Stage Lateral Movement)** | مهاجم از Patient Zero به دو Server حرکت کرده و از Credentialهای سرقت‌شده یا Valid Account استفاده کرده است | Timeline پیوسته، **Account مشترک** بین Hostها، SMB Connection از Patient Zero به Serverها، Process Creation مشکوک پس از Login  | Timeline ناپیوسته، Accountهای متفاوت، Source IP متفاوت |
| **فرضیه جایگزین (Separate Incidents)** | دو Server به‌صورت مستقل Compromised شده‌اند و ارتباطی با Patient Zero ندارند | Accountهای متفاوت، Source IP متفاوت، Timeline غیرمرتبط | Account مشترک، Network Connection از Patient Zero |
| **فرضیه جایگزین (Legitimate Admin Activity)** | یک Admin قانونی از Patient Zero (که آلوده شده) به‌صورت قانونی به Serverها متصل شده | Account در Group IT Admins، Source IP از Jump Server، Command Line قانونی | Command Line مشکوک، Account غیرAdmin |

### 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Windows Security Event ID 4624** (Essential) | Logon | `LogonType` (3/10)، `TargetUserName`، `IpAddress`، `LogonId` — روی **همه Hostها**  |
| **Windows Security Event ID 4648** (Supplementary) | Explicit Credentials | `TargetUserName`، `ProcessName`، `IpAddress`  |
| **Sysmon Event ID 1** (Essential) | Process Creation | `Image`، `CommandLine`، `ParentImage`، `ProcessGuid`، `User`  |
| **Sysmon Event ID 3** (Essential) | Network Connection | اتصال به Port 445 (SMB)، 3389 (RDP)، 5985 (WinRM)  |
| **Sysmon Event ID 11** (Supplementary) | File Creation | File Copy از طریق SMB  |
| **Windows Security Event ID 5140/5145** (Supplementary) | Share Access | `ShareName` (ADMIN$، C$)، `SourceAddress`  |
| **Windows System Event ID 7045** (Essential) | Service Installation | `ServiceName` (PSEXESVC)، `ServiceFileName`  |

**محدودیت مهم:** برای بازسازی Timeline، **Time Sync** بین Hostها **حیاتی** است. اختلاف ساعت بیش از ۱ دقیقه می‌تواند Correlation را خراب کند .

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: ساخت Timeline اولیه از Patient Zero**

```kql
let PatientZero = "HOST-A";
union 
    (SecurityEvent
        | where Computer == PatientZero
        | where EventID in (4624, 4648, 5140, 5145)
        | project TimeGenerated, Computer, EventID, Account, IpAddress, 
                  LogonType = tostring(EventData.LogonType), 
                  ShareName = tostring(EventData.ShareName),
                  Activity = "Auth/Share"),
    (DeviceProcessEvents
        | where DeviceName == PatientZero
        | project TimeGenerated = Timestamp, Computer = DeviceName, 
                  EventID = 1, Account = AccountName, 
                  ProcessCommandLine, InitiatingProcessFileName,
                  Activity = "Process")
| order by TimeGenerated asc
```

**منطق Query:** این Query یک **Timeline یکپارچه** از Authentication، Share Access و Process Creation روی Patient Zero می‌سازد. این **نقطه شروع** برای بازسازی است.

**مرحله B: شناسایی Connection از Patient Zero به Serverها**

```kql
let PatientZero = "HOST-A";
DeviceNetworkEvents
| where DeviceName == PatientZero
| where RemotePort in (445, 3389, 5985, 135)
| project Timestamp, DeviceName, RemoteIP, RemotePort, 
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**منطق Query:** اتصالات خروجی از Patient Zero به Portهای **Lateral Movement** (SMB، RDP، WinRM، WMI) را شناسایی می‌کند.

**مرحله C: Correlate Login روی Serverها با Connection از Patient Zero**

```kql
let PatientZeroIP = "10.0.0.5";  // IP Patient Zero
let TimeWindow = 10m;
let SuspiciousLogons = SecurityEvent
| where EventID == 4624
| where LogonType in (3, 10)
| where IpAddress == PatientZeroIP
| project LogonTime = TimeGenerated, Computer, TargetUser = Account, 
          LogonType, IpAddress, LogonId;
let SuspiciousProcesses = DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("wsmprovhost.exe", "WmiPrvSE.exe", "PSEXESVC.exe")
| project ProcessTime = Timestamp, Computer = DeviceName, 
          FileName, ProcessCommandLine, InitiatingProcessFileName;
SuspiciousLogons
| join kind=inner SuspiciousProcesses on Computer
| where ProcessTime between (LogonTime .. TimeWindow)
| project LogonTime, ProcessTime, Computer, TargetUser, LogonType, 
          FileName, ProcessCommandLine, InitiatingProcessFileName
| order by LogonTime asc
```

**منطق Query:** این Query **Login از Patient Zero** را با **Process Creation مشکوک** روی همان Host correlate می‌کند. اگر Process Creation **بلافاصله پس از Login** رخ داده باشد، این **زنجیره علیت** را تأیید می‌کند.

**مرحله D: شناسایی Scope کامل (همه Hostهای درگیر)**

```kql
let SuspiciousAccounts = dynamic(["user1", "admin1", "svc_backup"]);
let SuspiciousIPs = dynamic(["10.0.0.5", "10.0.0.6"]);
SecurityEvent
| where EventID == 4624
| where LogonType in (3, 10)
| where Account in (SuspiciousAccounts) or IpAddress in (SuspiciousIPs)
| summarize 
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated),
    LogonCount = count(),
    LogonTypes = make_set(LogonType),
    SourceIPs = make_set(IpAddress)
    by Computer, Account
| order by LogonCount desc
```

**منطق Query:** با استفاده از **Accountهای مشکوک** و **IPهای مشکوک**، همه Hostهایی که Login مرتبط داشته‌اند را شناسایی می‌کند. این **Scope Incident** را مشخص می‌کند.

### 5. Pivoting و Correlation شواهد

1. **Account Correlation:** آیا **همان Account** روی Patient Zero و دو Server استفاده شده؟ اگر بله، احتمال **Credential Theft** بالاست.
2. **Process Ancestry:** روی Serverها، آیا Process Creation توسط `wsmprovhost.exe`، `WmiPrvSE.exe`، یا `PSEXESVC.exe` بوده؟ 
3. **Network Correlation:** آیا اتصال SMB/RDP/WinRM از **IP Patient Zero** به Serverها ثبت شده؟
4. **File Transfer:** آیا فایل از Patient Zero به Serverها کپی شده؟ (Sysmon EID 11، Event 5145)
5. **Persistence:** آیا روی Serverها، Persistence Mechanism (Scheduled Task، Service، WMI Subscription) ایجاد شده؟

**هشدار:** همزمانی زمانی (Temporal Proximity) به‌تنهایی **Causation** را اثبات نمی‌کند. برای انتساب، باید **Account یکسان**، **Source IP یکسان**، و **Process Ancestry** تأیید شود.

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline:**
- آیا Account در **Group IT Admins** است؟ (اگر بله → احتمالاً قانونی)
- آیا Source IP از **Jump Server** است؟ (اگر بله → احتمالاً قانونی)
- آیا Login در **ساعات کاری** است؟ 

**Scope Determination:**
- روی **همه Hostها** Query بزنید: آیا **Account مشکوک** یا **IP مشکوک** روی Hostهای دیگر دیده می‌شود؟
- آیا **Process Ancestry** مشابه روی Hostهای دیگر وجود دارد؟
- آیا **Network Connection** به IPهای خارجی از Hostهای درگیر دیده می‌شود؟

**False Positive:**
- **IT Admin Activity:** اگر Account در IT Admins باشد و از Jump Server متصل شده باشد
- **SCCM/Backup:** اگر Process Ancestry قابل توضیح باشد
- **Scheduled Tasks:** اگر Taskهای قانونی باعث Login شده باشند

**معیار قطعی:** اگر **Account مشترک**، **Process Ancestry مشکوک** (`wsmprovhost.exe` → `cmd.exe`)، و **Network Connection از Patient Zero** تأیید شود، احتمال **False Positive پایین** است.

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1021.002** | Remote Services: SMB/Windows Admin Shares | SMB Connection از Patient Zero به Serverها  |
| **T1021.001** | Remote Services: RDP | RDP Connection بین Hostها  |
| **T1021.006** | Remote Services: WinRM | `wsmprovhost.exe` spawning child process  |
| **T1047** | Windows Management Instrumentation | `WmiPrvSE.exe` spawning child process  |
| **T1569.002** | System Services: Service Execution | Service Creation (7045) با PSEXESVC  |
| **T1078** | Valid Accounts | استفاده از Account معتبر برای Lateral Movement  |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** یک Host آلوده شناسایی شده و Login، SMB و Process Creation مشکوک روی دو Server دیگر دیده شده است.

**Likely:** این یک **Multi-Stage Lateral Movement** است، به‌ویژه اگر:
1. **Account مشترک** بین Patient Zero و Serverها استفاده شده باشد.
2. **Process Ancestry** شامل `wsmprovhost.exe`، `WmiPrvSE.exe`، یا `PSEXESVC.exe` باشد .
3. **Network Connection** از IP Patient Zero به Serverها ثبت شده باشد.
4. **Persistence Mechanism** روی Serverها ایجاد شده باشد.

**Confidence: Medium-High** — برای **Confirmed** نیاز به تأیید **Account Correlation** و **Process Ancestry** روی همه Hostها.

### 9. Response و بهبود Detection

**فوری:**
1. **Isolation:** Patient Zero و دو Server را Isolate کنید.
2. **Account Containment:** Password Reset برای Accountهای درگیر.
3. **Session Revocation:** بستن Sessionهای فعال (Kerberos Tickets، RDP Sessions).
4. **Forensic Collection:** Memory Dump، Disk Image، Logs از همه Hostها.

**Detection Improvement:**
1. **قانون Lateral Movement:** هر Source که در **1 ساعت** به **3+ Host** با SMB/RDP/WinRM متصل شود → Alert.
2. **قانون Process Ancestry:** هر `wsmprovhost.exe` → `cmd.exe` یا `WmiPrvSE.exe` → `powershell.exe` → Alert.
3. **قانون Account Correlation:** هر Account که روی **3+ Host** در **1 ساعت** Login کند → Alert.
4. **قانون Service Creation:** هر **7045** با ServiceName `PSEXESVC` → Alert.

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

اول از **Patient Zero** شروع می‌کنم و یک **Timeline** از Authentication، Share Access و Process Creation می‌سازم. بعد اتصالات خروجی از Patient Zero به Portهای **SMB (445)، RDP (3389)، WinRM (5985)** رو بررسی می‌کنم .

در قدم بعدی، **Login روی Serverها** رو با **IP Patient Zero** correlate می‌کنم: اگه یک **Network Logon (Type 3)** یا **RDP (Type 10)** از IP Patient Zero ثبت شده باشه، این **Lateral Movement** رو تأیید می‌کنه.

**Process Ancestry** روی Serverها رو هم چک می‌کنم: اگه `wsmprovhost.exe` یا `WmiPrvSE.exe` یک `cmd.exe` یا `powershell.exe` spawn کرده باشه، این **Remote Execution** هست .

**محدودیت اصلی:** **Time Sync** بین Hostها حیاتی است — اگه اختلاف ساعت بیش از ۱ دقیقه باشه، Correlation خراب می‌شه. همچنین، اگه **Command Line Auditing** فعال نباشه، نمی‌تونم دقیقاً ببینم چه دستوری اجرا شده.

**اقدام بعدی:** اگه تأیید شد، Patient Zero و دو Server رو Isolate می‌کنم، Password Accountهای درگیر رو Reset می‌کنم، و روی همه Hostها **Persistence Mechanism** (Scheduled Task، Service، WMI Subscription) رو بررسی می‌کنم.
