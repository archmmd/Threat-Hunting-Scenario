احتمال Compromise حساب ادمین
Domain Admin وارد سیستم شده، LDAP Query انجام داده و بعد به چند Server متصل شده است.
چطور Severity را تعیین می‌کنی، اقدامات فوری را انتخاب می‌کنی و از گسترش Incident جلوگیری می‌کنی؟

این سناریو یک **Domain Admin Compromise** کلاسیک است که الگوی حمله به زیرساخت Active Directory را نشان می‌دهد. ترکیب **LDAP Query** (Reconnaissance) و سپس **SMB Connection** به چندین Server، نشان‌دهنده یک زنجیره حمله برنامه‌ریزی‌شده است که در آن مهاجم از یک حساب ممتاز برای نقشه‌برداری و سپس حرکت جانبی استفاده می‌کند .

### ۱. تعیین Severity (اولویت‌بندی)

Severity این Incident را باید **Critical** ارزیابی کنم، نه High. دلیل این ارزیابی:

- **حساب ممتاز (Tier 0):** Domain Admin بالاترین سطح دسترسی در AD را دارد. Compromise این حساب به معنای **Domain Dominance** است .
- **ترکیب دو Technique:** LDAP Query به‌تنهایی Medium است (Reconnaissance)، SMB به‌تنهایی High است (Lateral Movement)، اما **ترکیب این دو توسط یک Domain Admin** = Critical .
- **پتانسیل DCSync/Golden Ticket:** اگر مهاجم Credential این حساب را داشته باشد، می‌تواند **DCSync** انجام دهد و **تمام Hashهای دامنه** را استخراج کند .

### ۲. شواهدی که باید جمع‌آوری کنم (قبل از هر اقدام)

قبل از هرگونه Containment، باید این شواهد را **تضمین** کنم:

**الف) روی Domain Controller (LDAP Query Source):**
- **Event 4662** (Directory Service Access) با **SubjectUserName** = حساب Domain Admin و **ObjectName** شامل `CN=Domain Admins` یا `CN=Certificate Templates` .
- **Microsoft Defender for Identity Alert:** Alertهایی مانند **"Suspicious LDAP query"** (External ID 2437) یا **"Security principal reconnaissance (LDAP)"** (External ID 2038) .

**ب) روی Workstation مبدأ (Domain Admin Login):**
- **Event 4624** با **LogonType 10** (RDP) یا **LogonType 3** (Network) و **IpAddress** مبدأ.
- **Sysmon Event ID 1:** Processهای ایجادشده پس از Login (مثل `powershell.exe`، `cmd.exe`).
- **Event 4672:** اعطای Special Privileges به Session .

**ج) روی Serverهای مقصد (SMB Connection):**
- **Event 5140** (Network Share Access) با **ShareName** = `ADMIN$` یا `C$` و **SourceAddress** = Workstation مبدأ .
- **Event 7045** (Service Installation): بررسی نام سرویس (مثل `PSEXESVC`) .
- **Sysmon Event ID 3:** Network Connection به Port 445 از Process مشکوک.

### ۳. Queryهای عملی برای Scope Assessment

**Query 1: LDAP Query مشکوک روی DC**

```kql
SecurityEvent
| where EventID == 4662
| where SubjectUserName has "Domain Admin Account Name"
| where ObjectName has_any ("Domain Admins", "Enterprise Admins", "Certificate Templates")
| project TimeGenerated, Computer, SubjectUserName, ObjectName, Properties
| order by TimeGenerated desc
```

**Query 2: SMB Lateral Movement از Domain Admin**

```kql
// روی Serverهای مقصد
SecurityEvent
| where EventID == 5140
| where ShareName has_any ("ADMIN$", "C$")
| where SubjectUserName has "Domain Admin Account Name"
| summarize 
    TargetCount = dcount(Computer),
    Targets = make_set(Computer)
    by IpAddress, SubjectUserName
| where TargetCount >= 3
```

**Query 3: Processهای پس از Login (روی Workstation)**

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where DeviceName has "WORKSTATION_NAME"
| where AccountName has "Domain Admin Account Name"
| where FileName in~ ("powershell.exe", "cmd.exe", "net.exe", "whoami.exe")
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp asc
```

### ۴. اقدامات فوری (Containment)

**اولویت ۱: قطع دسترسی مهاجم (فوری)**
- **Disable** حساب Domain Admin Compromised .
- **Revoke** تمام Sessionهای فعال (Kerberos TGT/TGS، RDP Sessions) با `klist purge` یا Disable Account .
- **Isolate** Workstation مبدأ از شبکه (Disable NIC در Hypervisor، نه Firewall محلی) .

**اولویت ۲: حفظ شواهد (قبل از Cleanup)**
- **Memory Dump** از Workstation و DCهای درگیر .
- **Snapshot** از VMها.
- **Export** Event Logs (Security، Sysmon، Defender for Identity) .

**اولویت ۳: Credential Reset (Tiered)**
- **Tier 0 (Domain Admins، Enterprise Admins):** Reset فوری .
- **Service Accounts:** Reset پس از Inventory و با هماهنگی Business Owner .
- **Accounts Authenticated روی Workstation:** با Event 4624/4672 شناسایی و Reset .

**هشدار:** **Blanket Password Reset** در کل دامنه انجام **ندهید** — باعث Disruption سرویس‌ها می‌شود. روی Tier 0 و Accounts درگیر تمرکز کنید .

### ۵. MITRE ATT&CK Mapping

| رفتار مشاهده‌شده | Technique ID | Name |
|---|---|---|
| Login Domain Admin روی Workstation | **T1078.002** | Valid Accounts: Domain Accounts |
| LDAP Query برای Enumeration | **T1087.002** | Account Discovery: Domain Account  |
| SMB Connection به چند Server | **T1021.002** | Remote Services: SMB/Admin Shares  |
| (احتمالی) Credential Dumping | **T1003.001** | LSASS Memory |

### ۶. پاسخ کوتاه برای شروع جواب در مصاحبه

**Severity** رو **Critical** ارزیابی می‌کنم، چون یک **Domain Admin** (Tier 0) هم **LDAP Enumeration** انجام داده و هم به چند **Server** با SMB متصل شده. این ترکیب، الگوی **Domain Dominance** هست .

**اول** از **Defender for Identity** روی DC، Alert **"Suspicious LDAP query"** (External ID 2437) رو تأیید می‌کنم . **بعد** روی Workstation، **Event 4624** با **LogonType 10** و **Event 4672** برای تأیید Privileges بالا رو چک می‌کنم .

**اقدام فوری:** حساب Domain Admin رو **Disable** می‌کنم، **Sessionها** رو **Revoke** می‌کنم، و **Workstation** رو از شبکه **Isolate** می‌کنم . **قبل از Cleanup**، **Memory Dump** و **Event Logs** رو **حفظ** می‌کنم .

**محدودیت اصلی:** اگر **Defender for Identity** نصب نباشد، **Event 4662** روی DC نیاز به **Directory Service Access Auditing** دارد که پیش‌فرض فعال نیست .

**اقدام بعدی:** **Credential Reset** رو از **Tier 0** شروع می‌کنم و روی **Serverهای Target** بررسی می‌کنم که آیا **Persistence** (Scheduled Task، Service) ایجاد شده یا نه .
