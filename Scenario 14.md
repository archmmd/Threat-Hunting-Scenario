## 1. تعریف سناریو و هدف Hunt

یک Process Creation با **Sysmon Event ID 1** مشاهده شده که نام فایل اجرایی آن `svchost.exe` است، اما از مسیر `C:\Users\Public\` اجرا شده است. هدف Hunt، تشخیص **Masquerading** (جعل هویت فرآیندهای سیستمی) و تعیین اینکه آیا این یک فرآیند مخرب است یا یک اجرای قانونی نادر.

**نکته حیاتی:** مسیر `C:\Users\Public\` هرگز محل اجرای قانونی `svchost.exe` نیست. `svchost.exe` واقعی فقط از `C:\Windows\System32\svchost.exe` یا `C:\Windows\SysWOW64\svchost.exe` اجرا می‌شود . **این به‌تنهایی یک نشانه قوی (Strong Indicator)** است، اما برای تأیید نهایی نیاز به شواهد تکمیلی داریم.

## 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهدی که آن را تقویت می‌کند | شواهدی که آن را تضعیف می‌کند |
|---|---|---|---|
| **فرضیه اصلی (Malicious Masquerading)** | یک باینری مخرب با نام `svchost.exe` در مسیر Public قرار گرفته و اجرا شده تا به‌عنوان فرآیند سیستمی جعل هویت کند | Parent Process غیرعادی، Signature نامعتبر، Hash ناشناخته، اتصالات شبکه به خارج از سازمان | Signature معتبر Microsoft، Parent Process قابل توضیح |
| **فرضیه جایگزین (Misconfiguration)** | یک اسکریپت یا نرم‌افزار قانونی (مثلاً Update مکانیزم ضعیف) باینری سیستمی را در مسیر Public کپی کرده است | Presence در Baseline قبلی، ارتباط با نرم‌افزار شناخته‌شده | عدم وجود مستندات، Signature نامعتبر |
| **فرضیه جایگزین (Penetration Test)** | یک تیم Red Team عمداً این رفتار را برای تست Detection ایجاد کرده است | زمان‌بندی مشخص، وجود Ticket، Hostname خاص آزمایشی | عدم وجود اطلاع‌رسانی، رفتار جانبی مخرب |

## 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را باید بررسی کنیم |
|---|---|---|
| **Sysmon Event ID 1** (Essential) | منبع اصلی | `Image`, `ParentImage`, `CommandLine`, `Hashes`, `OriginalFileName`, `Company`, `ProcessGuid`  |
| **EDR Process Tree** (Essential) | Correlate | زنجیره Parent-Child، آیا `services.exe` یا `explorer.exe` والد آن است؟ |
| **Authenticode Signature** (Essential) | Validation | آیا فایل با گواهی Microsoft امضا شده؟ `Get-AuthenticodeSignature`  |
| **Network Telemetry** (Supplementary) | Behavioral | اتصالات خروجی، DNS Queryها، پورت‌های غیرعادی |
| **File Metadata** (Supplementary) | Static Analysis | `OriginalFileName` (آیا «svchost.exe» است یا نام دیگری؟) |

**محدودیت:** اگر Sysmon فقط با فیلتر Process Creation و بدون **Hash logging** و **Signature logging** پیکربندی شده باشد، بخشی از این تحلیل ممکن نخواهد بود.

## 4. مراحل اجرایی Hunt و Queryهای عملی

### مرحله A: استخراج جزئیات Process Creation از Sysmon

در **KQL (Defender XDR / Sentinel)**:

```kql
DeviceProcessEvents
| where TimeGenerated > ago(24h)
| where FileName =~ "svchost.exe"
| where FolderPath !startswith "C:\\Windows\\System32" and FolderPath !startswith "C:\\Windows\\SysWOW64"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine,
          FolderPath, ProcessId, ProcessGuid, ParentProcessId,
          InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, SHA256, MD5, FileSize, SignatureStatus
| order by TimeGenerated desc
```

**فیلدهای کلیدی:**
- `FolderPath`: تأیید مسیر غیراستاندارد
- `ParentProcessId` / `InitiatingProcessFileName`: بررسی والد (آیا `services.exe` است یا چیز غیرمنتظره؟)
- `SignatureStatus`: `Valid` / `Unavailable` / `Unverified`
- `SHA256`: برای بررسی در VirusTotal یا Threat Intel

**در PowerShell (بررسی سریع روی Endpoint زنده):**

```powershell
Get-Process svchost -ErrorAction SilentlyContinue |
  Where-Object { $_.Path -notlike "C:\Windows\System32\*" -and $_.Path -notlike "C:\Windows\SysWOW64\*" } |
  Select-Object Id, ProcessName, Path, StartTime
```

### مرحله B: بررسی Signature و Hash

```powershell
$path = "C:\Users\Public\svchost.exe"
Get-AuthenticodeSignature -FilePath $path | Select-Object Status, SignerCertificate, Path
Get-FileHash -Path $path -Algorithm SHA256
```

**معیار قضاوت:**
- `Status = Valid` + `SignerCertificate.Subject -like "*Microsoft*"` → احتمالاً یک کپی از باینری اصلی (اما همچنان مسیر غیرعادی است)
- `Status = NotSigned` یا `UnknownError` → **نشانه قوی مخرب بودن** 
- Hash در VirusTotal → Malicious / Suspicious

### مرحله C: بررسی Parent Process

طبق Baseline ویندوز، `svchost.exe` **فقط باید توسط `services.exe` ایجاد شود** . اگر Parent Process موارد زیر باشد، بسیار مشکوک است:

- `explorer.exe` → کاربر مستقیماً آن را اجرا کرده
- `cmd.exe` یا `powershell.exe` → اجرای اسکریپتی
- `winword.exe` / `excel.exe` → Macro execution
- `UserInit.exe` → Persistence mechanism

```kql
DeviceProcessEvents
| where FileName =~ "svchost.exe"
| where FolderPath !startswith "C:\\Windows\\"
| where InitiatingProcessFileName !in~ ("services.exe")
| project TimeGenerated, DeviceName, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine
```

### مرحله D: بررسی Network Behavior

`svchost.exe` قانونی اتصالات خاصی دارد: DNS (UDP 53)، DHCP، RPC (TCP 135)، SMB (445)، LLMNR (5355) . اتصالات زیر **غیرعادی** هستند:

- اتصال به IPهای خارجی روی پورت‌های غیراستاندارد (8080، 443 به IP ناشناخته)
- Beaconing رفتار (اتصالات منظم در فواصل زمانی)
- DNS Queryهای طولانی یا DGA-like

```kql
DeviceNetworkEvents
| where InitiatingProcessFileName =~ "svchost.exe"
| where InitiatingProcessFolderPath !startswith "C:\\Windows\\"
| project TimeGenerated, DeviceName, RemoteIP, RemotePort,
          RemoteUrl, InitiatingProcessCommandLine
```

## 5. Pivoting و Correlation شواهد

از `ProcessGuid` و `ProcessId` اولیه برای Pivot استفاده کنید:

1. **File Creation Events (Sysmon EID 11):** آیا فایل `C:\Users\Public\svchost.exe` **قبل از** اجرا ایجاد شده؟ `ProcessGuid` ایجادکننده آن چه بوده؟
2. **Parent Process Chain:** `ParentImage` → والد آن → والد والد... تا رسیدن به یک Process شناخته‌شده (مثلاً `explorer.exe` یا `cmd.exe`).
3. **همان Host:** آیا Processهای مشکوک دیگری از همان Parent یا در همان بازه زمانی اجرا شده‌اند؟
4. **همان User:** آیا این User در Hostهای دیگر نیز رفتار مشابهی داشته؟
5. **Network Timeline:** اتصالات شبکه همان `ProcessId` را قبل و بعد از اجرای Process بررسی کنید.

**هشدار Correlation:** همزمانی زمانی (`Timestamp proximity`) به‌تنهایی **Causation** را اثبات نمی‌کند. برای اتصال Events به یک زنجیره حمله، نیاز به **Shared Process Tree** یا **Shared Network Session** داریم.

## 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline مقایسه:**
- آیا در ۳۰ روز گذشته، `svchost.exe` از مسیر غیر System32 اجرا شده است؟ (اگر نه، این Event یک Anomaly است)
- آیا Hostname در گروه Peer مشابه، رفتار مشابهی دارد؟ (اگر خیر، احتمال Compromise بالا می‌رود)

**Scope Determination:**
- روی همه Endpointها Query بزنید: آیا `C:\Users\Public\svchost.exe` در Hostهای دیگر وجود دارد؟
- آیا فایل با همان SHA256 در Endpointهای دیگر دیده شده؟

**False Positive ممکن:**
- برخی Installerها (نادر) باینری‌های سیستمی را در Temp کپی می‌کنند. اما `C:\Users\Public\` **مسیر بسیار غیرمعمول** برای این کار است.
- Sysinternals یا ابزارهای جانبی ممکن است نام مشابه داشته باشند، اما Hash و Signature متفاوت خواهد بود.

**اگر Signature معتبر Microsoft باشد:** احتمالاً یک کپی از باینری اصلی است، اما **اجرای آن از Public همچنان یک IOC** است (ممکن است attacker فایل سیستمی را کپی کرده و با DLL Side-Loading اجرا کند).

## 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1036.005** | Masquerading: Match Legitimate Name or Location | نام `svchost.exe` در مسیر `C:\Users\Public\` — تطابق نام قانونی در مکان غیرقانونی  |
| **T1036.003** | Masquerading: Rename System Utilities | اگر مشخص شود باینری اصلی کپی و Rename شده است  |
| **T1055** (احتمالی) | Process Injection | اگر `svchost.exe` جعلی در واقع یک Loader باشد که کد را در Process دیگر تزریق می‌کند |

**هشدار:** Mapping فقط بر اساس شواهد **مشاهده‌شده** انجام شده. اگر Parent Process `services.exe` باشد و Signature معتبر باشد، ممکن است این یک **False Positive** باشد و T1036.005 اعمال نشود.

## 8. نتیجه‌گیری و سطح اطمینان

**وضعیت فعلی: Observed (مشاهده‌شده)**

- **آنچه مسلم است:** یک Process با نام `svchost.exe` از مسیر `C:\Users\Public\` اجرا شده است.
- **آنچه Likely است:** این رفتار **قویاً مشکوک به Masquerading** است، زیرا `svchost.exe` قانونی هرگز از این مسیر اجرا نمی‌شود .
- **آنچه هنوز اثبات نشده:** اینکه این Process واقعاً **مخرب** است. برای Confirmation نیاز به:
  1. Signature نامعتبر (یا عدم Signature)
  2. Parent Process غیرعادی (غیر از `services.exe`)
  3. Hash در Threat Intel به‌عنوان Malicious
  4. Network Connection مشکوک از همان Process

**سطح اطمینان اولیه: Medium-High** که این یک **Anomaly امنیتی** است. برای رسیدن به **High** (Confirmed Malicious) به شواهد Signature و Parent بستگی دارد.

**Next Best Action:** بررسی Signature و Parent Process در اولویت اول؛ اگر این دو مشکوک بودند، Process را Isolate کنید.

## 9. Response و بهبود Detection

**اقدامات فوری (اگر Signature نامعتبر یا Parent غیرعادی بود):**
1. **Endpoint Isolation** از طریق EDR
2. **جمع‌آوری Forensic:** کپی فایل `C:\Users\Public\svchost.exe`، Memory Dump از Process، Sysmon Logs
3. **بررسی Persistence:** Registry Run Keys، Scheduled Tasks، Services
4. **بررسی Lateral Movement:** آیا همین رفتار روی Hostهای دیگر دیده می‌شود؟

**اقدامات بلندمدت (Detection Improvement):**
1. **قانون Detection جدید:** هر `svchost.exe` که از مسیر غیر `System32` / `SysWOW64` اجرا شود → Alert 
2. **قانون Parent Process:** هر `svchost.exe` که والد آن `services.exe` **نباشد** → Alert 
3. **Hash-based Detection:** مقایسه Hash با Baseline Hashهای مجاز سازمان
4. **Audit Policy:** اطمینان از فعال بودن **Command Line Auditing** در Event ID 4688 و **Sysmon Process Creation با Hash**

## 10. پاسخ کوتاه برای شروع جواب در مصاحبه

من اول از Sysmon Event ID 1 مسیر کامل `Image` رو چک می‌کنم — اینکه `svchost.exe` از `C:\Users\Public\` اجرا شده، به‌تنهایی یک نشانه قوی Masquerading است، چون نسخه قانونی فقط در `System32` یا `SysWOW64` قرار داره.

بعد **Parent Process** رو بررسی می‌کنم: در حالت عادی `svchost.exe` باید توسط `services.exe` اجرا بشه. اگر والدش `explorer.exe`، `cmd.exe` یا چیز غیرمنتظره‌ای باشه، شک من قطعی‌تر می‌شه.

در قدم بعدی **Signature** و **Hash** رو چک می‌کنم: با `Get-AuthenticodeSignature` ببینم آیا با گواهی Microsoft امضا شده و SHA256 رو با Threat Intel مقایسه کنم. اگر Signature نامعتبر یا Hash در VirusTotal مخرب بود، احتمال Compromise قطعی می‌شه.

**محدودیت اصلی:** اگر Sysmon فقط Process Creation رو لاگ کرده باشه و Hash یا Signature رو ثبت نکرده باشه، نمی‌تونم بدون بررسی روی خود Endpoint قضاوت قطعی کنم.

**اقدام بعدی:** اگر این سه مورد (مسیر غیرعادی، والد مشکوک، Signature/Hash بد) تأیید شد، Endpoint رو Isolate می‌کنم و روی Persistence و Lateral Movement بررسی می‌کنم.
