### 1. تعریف سناریو و هدف Hunt

**سناریو:** هیچ IOC مشخصی وجود ندارد (No Known IOCs)، اما احتمال **Credential Access** در سازمان وجود دارد. هدف Hunt، شناسایی **رفتارهای منتهی به سرقت Credential** بدون وابستگی به IOCهای از پیش شناخته‌شده (مثل Hash یا IP مشخص) است.

**نکته حیاتی:** در غیاب IOC، Hunt باید **Behavior-Driven** باشد. به‌جای جستجو برای «ابزار خاص»، به‌دنبال **الگوهای رفتاری** می‌گردیم که در تمام تکنیک‌های Credential Access مشترک هستند: **دسترسی به LSASS**، **دسترسی به فایل‌های حساس** (SAM, NTDS.dit, Cached Creds)، و **Kerberos Ticket Abuse** .

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (LSASS Memory Dumping)** | مهاجم از یک Process غیرمجاز برای خواندن حافظه LSASS و استخراج Credential استفاده می‌کند | Sysmon EID 10 با `TargetImage=lsass.exe` و `GrantedAccess` مشکوک (مثل `0x1FFFFF`، `0x1410`) از Process غیرسیستمی  | Source Image در لیست سفید (EDR، Antivirus، System Process) |
| **فرضیه جایگزین (Cached Credential Theft)** | مهاجم فایل‌های Cached Credential (SAM, SECURITY) را از Disk استخراج می‌کند | دسترسی به `%SystemRoot%\System32\config\SAM` یا `SECURITY`، اجرای `reg save` یا `secretsdump`  | Backup Software یا System Process قانونی |
| **فرضیه جایگزین (DCSync)** | مهاجم با دسترسی بالا، فرآیند Replication Domain Controller را جعل می‌کند تا Credentialها را از AD استخراج کند | Event 4662 روی DC با دسترسی `Replicating Directory Changes`، Account غیر DC  | Account در لیست DC Computer Accounts یا Tier 0 Admins |

### 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Sysmon Event ID 10** (Essential) | Process Access | `TargetImage=lsass.exe`، `GrantedAccess` مشکوک، `SourceImage` غیرسیستمی  |
| **Sysmon Event ID 1** (Essential) | Process Creation | Command Line مشکوک: `sekurlsa`، `lsadump`، `reg save`، `procdump -ma`  |
| **Windows Security Event ID 4656/4663** (Supplementary) | Object Access | دسترسی به فایل‌های حساس (SAM, SECURITY) اگر SACL فعال باشد  |
| **Windows Security Event ID 4662** (Essential for DCSync) | Directory Service Access | `Properties` شامل Replicating Directory Changes، `SubjectUserSid` غیر DC  |
| **Sysmon Event ID 11** (Supplementary) | File Creation | ایجاد فایل Dump (مثل `lsass.dmp`) در مسیرهای غیرعادی |

**محدودیت:** Sysmon EID 10 باید **صریحاً** برای `TargetImage=lsass.exe` فعال شده باشد . Event 4662 نیاز به **Directory Service Access Auditing** روی DC دارد.

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: LSASS Access Detection (اولویت اول)**

```kql
DeviceProcessEvents
| where ActionType == "ProcessAccess"
| where TargetProcessFileName =~ "lsass.exe"
| where GrantedAccess in ("0x1FFFFF", "0x1F3FFF", "0x143A", "0x1410", "0x1010")
| where InitiatingProcessFileName !in~ (
    "csrss.exe", "lsass.exe", "svchost.exe", "MsMpEng.exe", 
    "WmiPrvSE.exe", "taskmgr.exe", "procexp.exe", "SecurityHealthService.exe"
)
| project Timestamp, DeviceName, InitiatingProcessFileName, 
          InitiatingProcessCommandLine, GrantedAccess, CallTrace
| order by Timestamp desc
```

**منطق Query:** `GrantedAccess`های `0x1FFFFF` (Full Access)، `0x1410`، `0x1010` برای **Memory Dumping** استفاده می‌شوند. Processهای سیستمی Exclude شده‌اند .

**مرحله B: Credential Dumping Tool Command Line**

```kql
DeviceProcessEvents
| where ProcessCommandLine has_any (
    "sekurlsa", "lsadump", "kerberos::list", "crypto::certificates",
    "reg save hklm\\sam", "reg save hklm\\security", "reg save hklm\\system",
    "procdump -ma lsass", "comsvcs.dll MiniDump",
    "ntdsutil \"ac i ntds\" ifm"
)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
```

**منطق Query:** الگوهای Command Line که ابزارهای شناخته‌شده Credential Dumping استفاده می‌کنند .

**مرحله C: DCSync Detection (Event 4662)**

```kql
SecurityEvent
| where EventID == 4662
| where Properties has_any (
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  // Replicating Directory Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  // Replicating Directory Changes All
    "89e95b76-444d-4c62-991a-0facbeda640c"   // Replicating Directory Changes In Filtered Set
)
| where SubjectUserSid !endswith "$"  // Exclude Computer Accounts
| where Account !in ("Domain Admins", "Enterprise Admins")
| project TimeGenerated, Computer, Account, SubjectUserSid, Properties
| order by TimeGenerated desc
```

**منطق Query:** DCSync نیاز به **Replicating Directory Changes** دارد. اگر Account یک User عادی باشد (نه DC Computer Account)، این **Strong Indicator** است .

### 5. Pivoting و Correlation شواهد

1. **از LSASS Access به Process Tree:** اگر `SourceImage` مشکوک بود، Parent Process و Child Processهای آن را بررسی کنید.
2. **از DCSync به Post-Exploitation:** اگر Event 4662 مشکوک بود، Loginهای بعدی با همان Account را بررسی کنید (Golden Ticket / Pass-the-Hash).
3. **از Command Line به File Artifacts:** اگر `procdump -ma lsass` دیده شد، فایل `lsass.dmp` در Sysmon EID 11 جستجو کنید.
4. **Correlation بین 4662 و 4624:** آیا Accountی که DCSync انجام داده، بلافاصله پس از آن Login غیرعادی داشته است؟

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline:**
- آیا `SourceImage` در Baseline سازمان به‌عنوان Process مجاز برای دسترسی به LSASS ثبت شده است؟
- آیا `GrantedAccess` در Baseline دیده شده است؟

**False Positive:**
- **EDR/Antivirus:** `MsMpEng.exe`، `CrowdStrike`، `SentinelOne` به‌صورت قانونی به LSASS دسترسی دارند .
- **Backup Software:** ممکن است `reg save` برای Backup انجام دهد.
- **System Processes:** `svchost.exe`، `lsass.exe`، `csrss.exe` .

**معیار قطعی:** اگر `SourceImage` یک Process غیرسیستمی باشد و `GrantedAccess` شامل `0x1FFFFF` باشد، احتمال **False Positive پایین** است.

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1003.001** | LSASS Memory | Sysmon EID 10 با `TargetImage=lsass.exe` و `GrantedAccess` مشکوک  |
| **T1003.002** | Security Account Manager | دسترسی به `SAM` یا `SECURITY` hive |
| **T1003.003** | NTDS | دسترسی به `ntds.dit` یا `ntdsutil` |
| **T1003.005** | Cached Domain Credentials | دسترسی به `%SystemRoot%\System32\config\SAM`  |
| **T1003.006** | DCSync | Event 4662 با Replicating Directory Changes  |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** فعالیت‌های دسترسی به LSASS و فایل‌های حساس Credential در سازمان مشاهده شده است.

**Likely:** این رفتار **مشکوک به Credential Access** است، به‌ویژه اگر:
1. `SourceImage` یک Process غیرسیستمی باشد.
2. `GrantedAccess` شامل `0x1FFFFF` باشد.
3. Command Line شامل `sekurlsa`، `lsadump`، یا `reg save hklm\sam` باشد.
4. Event 4662 با Replicating Directory Changes از یک User غیر DC باشد.

**Confidence: Medium-High** — برای **Confirmed** نیاز به تأیید **Process Ancestry** و **Context**.

### 9. Response و بهبود Detection

**فوری:**
1. **Kill Process:** اگر Process مشکوک در حال اجراست.
2. **Account Containment:** اگر Account درگیر Compromised شده.
3. **Forensic Collection:** Memory Dump، Sysmon Logs، Security Logs.

**Detection Improvement:**
1. **قانون LSASS Access:** هر Process غیرسیستمی که `TargetImage=lsass.exe` با `GrantedAccess=0x1FFFFF` → Alert .
2. **قانون DCSync:** هر Event 4662 با Replicating Directory Changes از Account غیر DC → Alert .
3. **قانون Command Line:** هر Command Line شامل `sekurlsa`، `lsadump`، `reg save hklm\sam` → Alert .
4. **Credential Guard:** فعال‌سازی Windows Defender Credential Guard برای محافظت از LSASS .

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

برای Hunt بدون IOC، اول روی **LSASS Access** تمرکز می‌کنم. از **Sysmon Event ID 10** استفاده می‌کنم و به‌دنبال Processهای غیرسیستمی می‌گردم که `TargetImage=lsass.exe` با `GrantedAccess` مشکوک مثل `0x1FFFFF` یا `0x1410` دارند. Processهای سیستمی مثل `MsMpEng.exe` و `svchost.exe` رو Exclude می‌کنم .

بعد **Command Line** رو بررسی می‌کنم: الگوهایی مثل `sekurlsa`، `lsadump`، `reg save hklm\sam` یا `procdump -ma lsass` .

برای **DCSync**، از **Event 4662** روی DC استفاده می‌کنم و به‌دنبال Replicating Directory Changes از Account غیر DC می‌گردم .

**محدودیت اصلی:** بدون Sysmon EID 10 با فیلتر LSASS، نمی‌تونم دسترسی به حافظه رو ببینم. همچنین Credential Guard می‌تونه از LSASS محافظت کنه.

**اقدام بعدی:** اگه تأیید شد، Process رو Kill می‌کنم، Account رو Contain می‌کنم و روی **Golden Ticket / Pass-the-Hash** بعدی بررسی می‌کنم.
