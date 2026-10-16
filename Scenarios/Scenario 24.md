### 1. تعریف سناریو و هدف Hunt

یک Endpoint (Source) به شکل غیرمعمول از طریق **WinRM** یا **WMI** روی چندین Host دستور اجرا می‌کند. هدف Hunt، تشخیص **Remote Execution** از طریق این دو مکانیزم مدیریتی قانونی و تفکیک آن از **Automation عادی** (SCCM، Ansible، DSC) و **دسترسی مدیریتی قانونی** است.

**نکته حیاتی:** هر دو WinRM و WMI ابزارهای **دوکاربردی (Dual-Use)** هستند. SCCM، Puppet، Ansible، و DSC از WMI/WinRM به‌صورت قانونی استفاده می‌کنند. تمایز اصلی در **Source Context**، **Process Ancestry**، **Command Line**، و **Volume/Pattern** است .

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (Malicious Remote Execution)** | مهاجم از Source Compromised برای اجرای دستور روی چندین Host استفاده می‌کند | Source IP از Workstation معمولی (نه Management)، `wsmprovhost.exe` spawning `cmd.exe`/`powershell.exe`، `wmic /node:` command line، Volume بالا خارج از ساعات کاری  | Source IP از Jump Server یا SCCM، Process Ancestry قابل توضیح |
| **فرضیه جایگزین (Legitimate Automation)** | SCCM، Ansible، یا DSC از WMI/WinRM به‌صورت قانونی استفاده می‌کند | Source IP در **Management VLAN**، Process Ancestry (`CcmExec.exe`، `svchost.exe`)، Command Line مطابق Baseline  | Command Line غیرعادی، Process Ancestry مشکوک |
| **فرضیه جایگزین (Admin Activity)** | یک Admin از Jump Server برای Management از WinRM/WMI استفاده می‌کند | Source IP از **Jump Server**، User در Group **IT Admins**، Activity در ساعات کاری | عدم تطابق با Baseline، Source IP از Workstation معمولی |

### 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Sysmon Event ID 1** (Essential) | Process Creation | `wsmprovhost.exe` spawning `cmd.exe`/`powershell.exe` (WinRM)، `WmiPrvSE.exe` spawning child process (WMI)  |
| **Windows Security Event ID 4688** (Essential) | Process Creation | Placeholder برای Sysmon EID 1 اگر Sysmon نصب نیست  |
| **Sysmon Event ID 3** (Essential) | Network Connection | اتصال به **Port 5985/5986** (WinRM) یا **Port 135** (WMI)  |
| **Microsoft-Windows-WinRM/Operational** (Supplementary) | WinRM Activity | **Event ID 224** (Listener Created)، **Event ID 4102** (Session Started)  |
| **Microsoft-Windows-WMI-Activity/Operational** (Supplementary) | WMI Activity | **Event ID 5857/5860/5861** (Subscription Persistence)، **ClientMachine** field  |

**محدودیت مهم:** برای WMI، **WMI-Activity/Operational** باید فعال باشد و شامل فیلد `ClientMachine` (Source) است . برای WinRM، **Event ID 4102** (Session Started) روی Target ثبت می‌شود .

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: شناسایی WinRM Remote Execution (Source و Target)**

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "wsmprovhost.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "whoami.exe", "net.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          InitiatingProcessFileSize, InitiatingProcessSHA256
| order by Timestamp desc
```

**منطق Query:** `wsmprovhost.exe` (Windows Remote Management Provider Host) **فقط** زمانی ظاهر می‌شود که یک WinRM Session فعال شود . Child Process آن نشان‌دهنده **دستور اجرا شده** است.

**Query مکمل روی Source (WinRM Client):**

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("Invoke-Command", "Enter-PSSession", "New-PSSession")
| where ProcessCommandLine has "-ComputerName"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

**منطق Query:** Source Process که WinRM Connection را **ایجاد** می‌کند .

**مرحله B: شناسایی WMI Remote Execution**

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "wmic.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**منطق Query:** `WmiPrvSE.exe` (WMI Provider Host) spawning child process = **Remote WMI Execution** .

**Query مکمل برای Source (WMIC):**

```kql
DeviceProcessEvents
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has_all ("/node:", "process", "call", "create")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

**منطق Query:** `wmic /node:<target> process call create <command>` — الگوی **کلاسیک** Remote WMI Execution .

**مرحله C: Network Layer (WinRM/WMI Ports)**

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemotePort in (5985, 5986, 135)
| where InitiatingProcessFileName !in~ ("svchost.exe", "lsass.exe", "System")
| where InitiatingProcessFileName has_any ("powershell.exe", "cmd.exe", "wmic.exe", "winrs.exe")
| project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**منطق Query:** اتصال از Processهای غیرسیستمی به **5985/5986** (WinRM) یا **135** (WMI RPC) .

### 5. Pivoting و Correlation شواهد

1. **Process Ancestry روی Target:** آیا Parent Process `wsmprovhost.exe` (WinRM) یا `WmiPrvSE.exe` (WMI) است؟ اگر بله، این **Remote Execution** است .
2. **Source IP از WinRM Session:** از **Microsoft-Windows-WinRM/Operational Event ID 4102** روی Target، `ClientMachine` را استخراج کنید .
3. **WMI ClientMachine:** از **WMI-Activity/Operational**، فیلد `ClientMachine` (Source) و `User` را استخراج کنید .
4. **Command Line Analysis:** آیا دستور شامل `-EncodedCommand`، `IEX`، `DownloadString`، یا مسیر `Temp`/`AppData` است؟ 
5. **Volume و Pattern:** آیا Source در **بازه کوتاه** به چندین Host متصل شده؟ (مثل RDP Scenario)

**هشدار:** همزمانی زمانی به‌تنهایی Causation را اثبات نمی‌کند. برای انتساب، باید **Source IP یکسان** و **Process Ancestry تأییدشده** داشته باشیم.

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline:**
- آیا Source IP در **Management VLAN** یا **SCCM Server** است؟
- آیا `wsmprovhost.exe` spawning `cmd.exe` در Baseline سازمان **قبلاً** دیده شده؟
- آیا Command Line مطابق Automation Scriptهای شناخته‌شده است؟

**False Positive:**
- **SCCM / Puppet / Ansible:** از WinRM/WMI قانونی استفاده می‌کنند 
- **DSC (Desired State Configuration):** از WinRM برای اجرای Script استفاده می‌کند 
- **Vulnerability Scanner:** ممکن است از WMI برای Discovery استفاده کند

**معیار قطعی:** اگر Source IP از **Workstation معمولی** باشد، Command Line شامل **EncodedCommand** یا **Download Cradle** باشد، و **Process Ancestry** (`wsmprovhost.exe` → `cmd.exe`) تأیید شود، احتمال **False Positive پایین** است .

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1021.006** | Remote Services: Windows Remote Management | `wsmprovhost.exe` spawning child process، اتصال به Port 5985/5986  |
| **T1047** | Windows Management Instrumentation | `WmiPrvSE.exe` spawning child process، `wmic /node:` command  |
| **T1059.001** | PowerShell | اگر Command Line شامل `powershell.exe` باشد |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** یک Endpoint از طریق WinRM/WMI روی چندین Host دستور اجرا کرده.

**Likely:** این رفتار **مشکوک به Remote Execution** است، به‌ویژه اگر:
1. Source IP از **Management Network** نباشد.
2. Process Ancestry شامل `wsmprovhost.exe` → `cmd.exe` یا `WmiPrvSE.exe` → `powershell.exe` باشد .
3. Command Line شامل **EncodedCommand** یا **Download Cradle** باشد.
4. Volume بالا و **خارج از ساعات کاری** باشد.

**Confidence: Medium-High** — برای **Confirmed** نیاز به تأیید **Source IP** و **Command Line Analysis**.

### 9. Response و بهبود Detection

**فوری:**
1. **Endpoint Isolation** روی Source.
2. **Kill Process Tree:** `wsmprovhost.exe` یا `WmiPrvSE.exe` و Child Processها.
3. **Investigation روی Targetها:** بررسی Persistence (WMI Event Subscription, Scheduled Tasks).

**Detection Improvement:**
1. **قانون WinRM:** هر `wsmprovhost.exe` که `cmd.exe`/`powershell.exe` spawn کند → Alert .
2. **قانون WMI:** هر `WmiPrvSE.exe` که Child Process غیرسیستمی spawn کند → Alert .
3. **قانون Source Context:** هر WinRM/WMI Connection از **IP غیر Management** → Alert.
4. **WMI Subscription Monitoring:** بررسی Event ID **5861** برای Persistence .

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

اول **Process Ancestry** رو روی **Target** بررسی می‌کنم: اگه `wsmprovhost.exe` یک `cmd.exe` یا `powershell.exe` spawn کرده باشه، این **WinRM Remote Execution** هست. اگه `WmiPrvSE.exe` Child Process غیرسیستمی داشته باشه، این **WMI Remote Execution** هست .

بعد **Source IP** رو از **Event ID 4102** (WinRM) یا **WMI-Activity ClientMachine** استخراج می‌کنم و چک می‌کنم که آیا از **Management VLAN** هست یا از یک Workstation معمولی .

**Command Line** رو هم تحلیل می‌کنم: اگه شامل `-EncodedCommand`، `IEX`، یا `DownloadString` باشه، شک من قطعی‌تر می‌شه .

**محدودیت اصلی:** WMI-Activity/Operational و WinRM Operational **به‌صورت پیش‌فرض Audited نیستند** و باید فعال بشن. اگه فعال نباشن، فقط Sysmon داریم که **Source IP** رو مستقیم نشون نمی‌ده.

**اقدام بعدی:** اگه تأیید شد، Source رو Isolate می‌کنم و روی Targetها **WMI Event Subscription** (Event 5861) رو برای Persistence بررسی می‌کنم .
