### 1. تعریف سناریو و هدف Hunt

**Ransomware فعال** در چندین Host: نشانه‌های **File Modification انبوه**، **حذف Shadow Copy**، و **اجرای Process مشکوک** گزارش شده است. اولویت، **توقف گسترش**، **شناسایی Scope واقعی**، و **حفظ شواهد** است.

**نکته حیاتی:** در Ransomware، **سرعت Containment** مستقیماً شدت خسارت را تعیین می‌کند. هر دقیقه تأخیر = داده بیشتر رمزنگاری‌شده. اولویت اول **قطع گسترش** است، نه تحلیل کامل.

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده |
|---|---|---|
| **فرضیه اصلی (Ransomware Active Spread)** | یک Ransomware در حال **انتشار Lateral** از Host اولیه به Hostهای دیگر است | Shadow Copy Deletion، File Encryption انبوه، Process مشکوک، Network Connection به SMB/RDP  |
| **فرضیه جایگزین (Isolated Infection)** | فقط یک Host آلوده است و گسترش متوقف شده | عدم وجود Connection بین Hostها، Timeline غیرپیوسته |

### 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **EDR Alert Queue** (Essential) | Ransomware Detection | Alertهای **File Encryption**، **Shadow Copy Deletion**، **Process Blocking**  |
| **Sysmon EID 1** (Essential) | Process Creation | `vssadmin delete shadows`، `wbadmin delete`، `cipher /w`، `bcdedit`  |
| **Sysmon EID 11** (Essential) | File Create | فایل‌های با پسوند جدید (`.encrypted`، `.locked`، `.ENCRT`)  |
| **Sysmon EID 3** (Essential) | Network Connection | اتصال به SMB (445)، RDP (3389)، C2 (IP خارجی) از Process مشکوک  |
| **Security EID 4624** (Essential) | Logon | Logon Type 3 (Network) یا 10 (RDP) از Hostهای درگیر  |

### 4. اولویت اقدامات دفاعی (First 1-2 Hours)

**مرحله A: Containment فوری**

**اولویت ۱: قطع گسترش**
- **Isolate** Hostهای آلوده از **همه** اتصالات: Wired، Wi-Fi، Bluetooth، USB .
- **Disable** RDP، VPN، و Remote Access Tools اگر Compromised شده‌اند .
- **Block** Connections به C2 Servers در Firewall .
- **Disconnect** NAS و File Shares از Hostهای آلوده .

**اولویت ۲: حفظ شواهد**
- **Memory Dump** از Hostهای آلوده **قبل از** Shutdown .
- **Snapshot** از VMها و Cloud Volumes .
- **عکس‌برداری** از Ransom Note و فایل‌های Encrypted (Timestamp، Owner) .

**اولویت ۳: محافظت از Backup**
- **Isolate** Backup Servers و Immutable Storage **فوراً** .
- **Disable** Credentials که در Hostهای آلوده بودند .

**هشدار:** **Restart نکنید** — Volatile Data (Memory، Decryption Keys) از بین می‌رود .

### 5. شناسایی Scope و Hostهای تحت تأثیر

**Query 1: Shadow Copy Deletion Pattern**

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("vssadmin.exe", "wbadmin.exe", "bcdedit.exe", "cipher.exe", "wmic.exe")
| where ProcessCommandLine has_any ("delete shadows", "delete catalog", "delete", "shadowcopy")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, 
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**منطق Query:** دستورات حذف Shadow Copy (مثل `vssadmin delete shadows`) یکی از **قطعی‌ترین شواهد** Ransomware است .

**Query 2: File Encryption Pattern**

```kql
DeviceFileEvents
| where Timestamp > ago(24h)
| where ActionType in ("FileModified", "FileRenamed", "FileCreated")
| where FileName has_any (".encrypted", ".locked", ".ENCRT", ".crypt")
| summarize 
    FileCount = count(),
    Hosts = dcount(DeviceName),
    FirstSeen = min(Timestamp),
    LastSeen = max(Timestamp)
    by DeviceName
| where FileCount > 100
| order by FileCount desc
```

**منطق Query:** حجم بالای File Modification با پسوندهای Encrypted = **Scope Host** .

**Query 3: Lateral Movement Correlation**

```kql
let InfectedHosts = DeviceFileEvents
| where Timestamp > ago(24h)
| where FileName has_any (".encrypted", ".locked", ".ENCRT")
| distinct DeviceName;
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where DeviceName in (InfectedHosts)
| where RemotePort in (445, 3389, 135, 5985)
| project Timestamp, DeviceName, RemoteIP, RemotePort, 
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**منطق Query:** اتصالات SMB/RDP/WinRM از Hostهای آلوده = **Lateral Movement**.

### 6. Pivoting و Correlation شواهد

1. **از Shadow Copy Deletion به Process Ancestry:** چه Processی `vssadmin.exe` را اجرا کرده؟
2. **از File Encryption به Owner:** Owner فایل‌های Encrypted را بررسی کنید — Account Compromised را نشان می‌دهد .
3. **از Network Connection به Ransomware Spread:** اتصال SMB از Host آلوده به Host دیگر = **Lateral Movement** .
4. **از Timeline به Patient Zero:** اولین Hostی که Shadow Copy Deletion یا Encryption در آن رخ داده = **Patient Zero**.

### 7. اعتبارسنجی و False Positive

**Baseline:**
- آیا `vssadmin delete shadows` در **Baseline سازمان** (Backup Tool) وجود دارد؟
- آیا پسوند `.encrypted` بخشی از **Software قانونی** است؟

**False Positive:**
- **Backup Software:** Veeam، Commvault ممکن است Shadow Copy را حذف کنند (زمان‌بندی منظم).
- **Disk Encryption:** BitLocker، VeraCrypt (پسوند متفاوت).

**معیار قطعی:** `vssadmin delete shadows` + File Encryption انبوه + Lateral Movement = **High Confidence Ransomware**.

### 8. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1486** | Data Encrypted for Impact | File Encryption انبوه  |
| **T1490** | Inhibit System Recovery | Shadow Copy Deletion  |
| **T1021.002** | SMB/Admin Shares | Lateral Movement از طریق SMB  |
| **T1078** | Valid Accounts | استفاده از Credential Compromised  |

### 9. نتیجه‌گیری و سطح اطمینان

**Observed:** Ransomware فعال در چندین Host.

**Confirmed:** Shadow Copy Deletion + File Encryption + Lateral Movement = **Ransomware Outbreak**.

**Confidence: High** — شواهد کافی برای تأیید.

**Next Best Action:** **Containment فوری** — Isolate همه Hostهای درگیر و Block C2.

### 10. Response و بهبود Detection

**اقدامات فوری:**
1. **Isolate** همه Hostهای آلوده .
2. **Block** C2 IPs/Domains.
3. **Disable** Compromised Accounts.
4. **Protect** Backups .
5. **Notify** Incident Response Team و Management .

**Detection Improvement:**
1. **قانون Shadow Copy Deletion:** هر `vssadmin delete shadows` → Alert .
2. **قانون File Encryption:** هر Host با **>100 File Modification** با پسوند Encrypted در **10 دقیقه** → Alert.
3. **قانون Lateral Movement:** هر Host آلوده که به **SMB/RDP** Hostهای دیگر متصل شود → Alert.

### 11. پاسخ کوتاه برای شروع جواب در مصاحبه

اول **Containment** رو انجام می‌دم: Hostهای آلوده رو از **همه اتصالات** قطع می‌کنم — Wired، Wi-Fi، Bluetooth — و **Shadow Copy Deletion** رو تأیید می‌کنم چون یکی از **قطعی‌ترین شواهد** Ransomware هست .

بعد **Scope** رو مشخص می‌کنم: از **Sysmon EID 11** برای File Encryption انبوه استفاده می‌کنم و Hostهایی که **بیش از ۱۰۰ فایل** با پسوند Encrypted دارن رو شناسایی می‌کنم. بعد از **Sysmon EID 3** برای بررسی **Lateral Movement** از طریق SMB/RDP استفاده می‌کنم .

**محدودیت اصلی:** اگه **Sysmon EID 3** فعال نباشه، نمی‌تونم گسترش از طریق Network رو تأیید کنم. همچنین **Memory Dump** باید **قبل از** Shutdown گرفته بشه .

**اقدام بعدی:** Hostها رو Isolate می‌کنم، C2 رو Block می‌کنم، و از **Backupهای Immutable** برای Recovery استفاده می‌کنم .
