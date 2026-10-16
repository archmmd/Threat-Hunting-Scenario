## 1. تعریف سناریو و هدف Hunt

یک Scheduled Task جدید با دسترسی **SYSTEM** ایجاد شده که یک Script را در فواصل زمانی مشخص اجرا می‌کند. هدف Hunt، تشخیص **Persistence** از طریق Scheduled Task (T1053.005) و تعیین اینکه این Task یک Automation قانونی است یا یک مکانیزم Persistence مخرب.

**نکته حیاتی:** Scheduled Tasks یکی از رایج‌ترین مکانیزم‌های Persistence مورد سوءاستفاده مهاجمان است، زیرا:
- به‌صورت پیش‌فرض روی همه نسخه‌های Windows وجود دارد.
- اجرای Script در فواصل زمانی، امکان **Execution مکرر** و **Beaconing به C2** را فراهم می‌کند.
- Taskهای قانونی زیادی در سیستم وجود دارند که مهاجم می‌تواند در میان آن‌ها مخفی شود.

بنابراین، **نام Task به‌تنهایی ارزش تشخیصی ندارد** و باید **TaskContent**، **Action**، **Trigger**، **Principal** و **Process ایجادکننده** را بررسی کنیم.

## 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (Malicious Persistence)** | مهاجم یک Task با دسترسی SYSTEM ایجاد کرده تا Payload خود را به‌صورت دوره‌ای اجرا کند و Persistence را حفظ کند | TaskContent شامل `powershell -enc`، `mshta`، `rundll32`، `\\AppData\\`، `\\Temp\\`، `\\Users\\Public\\`، URL خارجی، یا Base64 encoded command  | TaskContent به یک باینری امضاشده Microsoft در `System32` اشاره دارد، Task در لیست Baseline سازمان وجود دارد |
| **فرضیه جایگزین (Legitimate Automation)** | یک تیم IT یا نرم‌افزار قانونی (مثل Backup، Monitoring، Update) این Task را ایجاد کرده | Parent Process شناخته‌شده (مثل `msiexec.exe`، `svchost.exe`، Management Agent)، TaskName مطابق الگوی Baseline | عدم تطابق با Baseline، زمان ایجاد خارج از ساعات کاری، مسیر Action مشکوک |
| **فرضیه جایگزین (Red Team / PenTest)** | تیم Red Team عمداً برای تست Detection این Task را ایجاد کرده است | زمان‌بندی مشخص، اطلاع‌رسانی قبلی، Hostname آزمایشی | عدم اطلاع‌رسانی، رفتار جانبی مخرب |

## 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Windows Security Event ID 4698** (Essential) | Task Created | `TaskName`، `TaskContent` (XML کامل شامل Action، Trigger، Principal)، `SubjectUserName`، `ClientProcessId`، `ParentProcessId`  |
| **Windows Security Event ID 4702** (Essential) | Task Updated | `TaskContentNew` — برای تشخیص **Tampering** روی Taskهای قانونی  |
| **Sysmon Event ID 1** (Essential) | Process Creation | اجرای `schtasks.exe` با پارامتر `/create`، Parent Process، CommandLine کامل  |
| **Sysmon Event ID 11** (Supplementary) | File Creation | ایجاد فایل XML در `C:\Windows\System32\Tasks\`  |
| **Microsoft-Windows-TaskScheduler/Operational** (Supplementary) | Task Registration/Execution | Event ID 106 (Task Registered)، Event ID 200/201 (Task Started/Completed)  |
| **Registry** (Supplementary) | TaskCache | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\<TaskName>` — بررسی حذف `SD` value (Tarrask Technique)  |

**محدودیت مهم:** هیچ‌کدام از این دو Channel (Security و TaskScheduler/Operational) **به‌صورت پیش‌فرض Audited نیستند** و باید صریحاً توسط Administrator فعال شوند . اگر Audit Policy سازمان فعال نباشد، **هیچ Event 4698 ثبت نخواهد شد** و ما فقط از Sysmon (اگر نصب باشد) می‌توانیم استفاده کنیم.

## 4. مراحل اجرایی Hunt و Queryهای عملی

### مرحله A: استخراج Task Creation Events

**KQL (Sentinel / Defender XDR):**

```kql
SecurityEvent
| where EventID == 4698
| extend TaskName = tostring(EventData.TaskName)
| extend TaskContent = tostring(EventData.TaskContent)
| extend SubjectUser = tostring(EventData.SubjectUserName)
| extend ClientProcessId = tostring(EventData.ClientProcessId)
| where TaskName !startswith "\\Microsoft\\"
| project TimeGenerated, Computer, SubjectUser, TaskName, TaskContent, ClientProcessId
| order by TimeGenerated desc
```

**منطق Query:** Taskهایی که در **Library Root** (`\TaskName`) ثبت می‌شوند، برخلاف Taskهای Microsoft که در `\Microsoft\...` قرار دارند، **بیشتر مشکوک** هستند .

### مرحله B: تحلیل محتوای XML (TaskContent)

**KQL (Sentinel):**

```kql
SecurityEvent
| where EventID == 4698
| extend TaskContent = tostring(EventData.TaskContent)
| where TaskContent has_any (
    "powershell", 
    "-enc", 
    "-EncodedCommand",
    "mshta",
    "rundll32",
    "regsvr32",
    "\\AppData\\",
    "\\Temp\\",
    "\\Users\\Public\\",
    "http://",
    "https://"
)
| project TimeGenerated, Computer, TaskName, TaskContent
```

**منطق Query:** این الگوها **High-Confidence Indicators** برای Persistence مخرب هستند .

### مرحله C: بررسی ایجاد Task از طریق schtasks.exe

**KQL (Defender XDR / Sentinel):**

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any (
    "powershell", 
    "cmd.exe", 
    "wscript", 
    "cscript",
    "mshta",
    "rundll32",
    "\\Temp\\",
    "\\AppData\\",
    "\\Users\\Public\\"
)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, 
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**منطق Query:** اگر `schtasks.exe` توسط `cmd.exe`، `powershell.exe`، یا یک Process غیرعادی ایجاد شده باشد، این **Strong Indicator** است .

### مرحله D: بررسی Task Execution

**KQL (Sentinel — TaskScheduler Operational):**

```kql
Event
| where Source == "Microsoft-Windows-TaskScheduler"
| where EventID in (200, 201, 129)
| extend TaskName = tostring(EventData.TaskName)
| where TaskName !startswith "\\Microsoft\\"
| project TimeGenerated, Computer, TaskName, EventID
```

**منطق Query:** Event ID 200/201 (Task Started/Completed) نشان می‌دهد که Task **واقعاً اجرا شده است**. این برای تشخیص **Create, Run, Delete** pattern حیاتی است .

### مرحله E: بررسی Registry (Tarrask Technique)

**PowerShell (روی Endpoint):**

```powershell
$taskCachePath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
Get-ChildItem -Path $taskCachePath -ErrorAction SilentlyContinue | ForEach-Object {
    $sdValue = Get-ItemProperty -Path $_.PSPath -Name "SD" -ErrorAction SilentlyContinue
    if (-not $sdValue) {
        Write-Output "HIDDEN TASK: $($_.PSChildName)"
    }
}
```

**منطق Query:** Tarrask Technique با حذف مقدار `SD` از Registry، Task را از `schtasks /query` و Task Scheduler Console **مخفی** می‌کند، اما Task همچنان در Registry وجود دارد .

## 5. Pivoting و Correlation شواهد

از `TaskName`، `ClientProcessId` و `ParentProcessId` برای Pivot استفاده کنید:

1. **Parent Process Chain:** از `ClientProcessId` در Event 4698 به Sysmon Event ID 1 مراجعه کنید. چه Processی `schtasks.exe` را ایجاد کرده؟ اگر والد `powershell.exe`، `cmd.exe` یا `wscript.exe` باشد → **بسیار مشکوک** .
2. **Task Execution:** با `TaskName` در TaskScheduler Operational Log جستجو کنید. آیا Task اجرا شده است؟ چه Processی spawn کرده؟
3. **File System:** آیا Script یا Payload در مسیر اشاره‌شده در `TaskContent` وجود دارد؟ (Sysmon Event ID 11 — File Creation)
4. **Network Activity:** اگر Task یک Script اجرا می‌کند، آیا آن Script اتصال شبکه‌ای برقرار کرده است؟
5. **همان Host:** آیا Taskهای جدید دیگری با همان `SubjectUserName` یا `ClientProcessId` ایجاد شده‌اند؟

**هشدار:** همزمانی زمانی (Temporal Proximity) به‌تنهایی **Causation** را اثبات نمی‌کند. برای اتصال Events به یک زنجیره Persistence، نیاز به **Shared TaskName** یا **Shared Process Tree** داریم.

## 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline مقایسه:**
- آیا این `TaskName` در Baseline سازمان وجود دارد؟ (اگر خیر → **New Persistence**)
- آیا `SubjectUserName` یک Service Account شناخته‌شده است یا یک User عادی؟
- آیا زمان ایجاد Task در **ساعات کاری** است یا خارج از آن؟ (Taskهای مخرب اغلب در 3 صبح ایجاد می‌شوند) 

**Scope Determination:**
- روی همه Endpointها Query بزنید: آیا همان `TaskName` یا همان `TaskContent` در Hostهای دیگر وجود دارد؟
- اگر Task از طریق **GPO** یا **Remote System** ایجاد شده باشد، Scope ممکن است **کل Domain** باشد .

**False Positive ممکن:**
- **Software Installers:** برخی Installerها (مثل Adobe، Google Update) Taskهایی با نام شبیه به Microsoft ایجاد می‌کنند .
- **Management Agents:** SCCM، Intune، یا Antivirus ممکن است Taskهای قانونی ایجاد کنند.
- **Taskهای سیستمی:** Windows خودش Taskهایی در `\Microsoft\Windows\` ایجاد می‌کند.

**معیار قطعی:** اگر `TaskContent` شامل `powershell -enc` یا مسیر `AppData`/`Temp` باشد، احتمال **False Positive بسیار پایین** است .

## 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1053.005** | Scheduled Task/Job: Scheduled Task | ایجاد Task جدید با دسترسی SYSTEM و اجرای Script در فواصل زمانی  |
| **T1036** (احتمالی) | Masquerading | اگر TaskName شبیه به Taskهای قانونی Microsoft باشد (مثل `WinUpdate` یا `WindowsDefenderScheduledScan`)  |
| **T1059.001** (احتمالی) | PowerShell | اگر TaskContent شامل `powershell.exe` باشد |
| **T1027** (احتمالی) | Obfuscated Files or Information | اگر TaskContent شامل Base64 encoded command باشد  |

**هشدار:** Mapping فقط بر اساس **شواهد مشاهده‌شده** انجام شده. اگر Parent Process قانونی باشد و TaskContent به یک باینری امضاشده اشاره کند، ممکن است T1053.005 **اعمال نشود**.

## 8. نتیجه‌گیری و سطح اطمینان

**وضعیت فعلی: Observed (مشاهده‌شده)**

- **آنچه مسلم است:** یک Scheduled Task با دسترسی SYSTEM ایجاد شده که یک Script را در فواصل زمانی اجرا می‌کند.
- **آنچه Likely است:** این رفتار **مشکوک به Persistence** است، به‌ویژه اگر:
  1. TaskName شبیه به Taskهای Microsoft باشد.
  2. TaskContent شامل `powershell`، `cmd`، `mshta`، یا مسیرهای `Temp`/`AppData` باشد.
  3. Parent Process غیرعادی باشد (`powershell.exe`، `cmd.exe`).
  4. Task در ساعات غیرکاری ایجاد شده باشد.
- **آنچه هنوز اثبات نشده:** اینکه این Task واقعاً **مخرب** است. برای Confirmation نیاز به:
  1. بررسی Signature و Hash فایل‌های اشاره‌شده در TaskContent.
  2. بررسی Network Activity مرتبط با اجرای Task.
  3. بررسی Persistenceهای دیگر روی همان Host.

**سطح اطمینان اولیه: Medium-High** که این یک **Anomaly امنیتی** است. اگر `TaskContent` شامل `-enc` یا مسیر `AppData` باشد، اطمینان به **High** ارتقا می‌یابد.

## 9. Response و بهبود Detection

**اقدامات فوری (اگر شواهد مشکوک تأیید شد):**
1. **جمع‌آوری Forensic:** کپی فایل XML Task از `C:\Windows\System32\Tasks\`، کپی Registry Key مربوطه.
2. **Disable Task:** با `schtasks /change /tn "<TaskName>" /disable` یا از طریق Task Scheduler.
3. **بررسی Persistenceهای دیگر:** Registry Run Keys، Services، WMI Subscriptions.
4. **بررسی Lateral Movement:** آیا همان Task روی Hostهای دیگر ایجاد شده؟

**اقدامات بلندمدت (Detection Improvement):**
1. **فعال‌سازی Audit Policy:** `Audit Other Object Access Events` برای ثبت Event ID 4698 .
2. **فعال‌سازی TaskScheduler Operational Log:** `wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true` .
3. **قانون Detection جدید:** هر Task جدید خارج از `\Microsoft\` که شامل `powershell`، `cmd`، `mshta`، یا مسیرهای `Temp`/`AppData` باشد → Alert .
4. **قانون Baseline:** مقایسه Task Inventory فعلی با Baseline سازمان.
5. **قانون Tarrask:** بررسی حذف مقدار `SD` از Registry TaskCache .

## 10. پاسخ کوتاه برای شروع جواب در مصاحبه

برای بررسی Persistence از طریق Scheduled Task، اول از **Event ID 4698** در Security Log استفاده می‌کنم که **XML کامل Task** رو شامل می‌شه — این مهم‌ترین منبعه چون Action، Trigger و Principal رو نشون می‌ده.

بعد **TaskContent** رو تحلیل می‌کنم: اگه شامل `powershell -enc`، `mshta`، `rundll32`، یا مسیری مثل `\\AppData\\` یا `\\Temp\\` باشه، این **Strong Indicator** برای Persistence مخربه. همچنین **Parent Process** رو از Sysmon Event ID 1 چک می‌کنم — اگه `schtasks.exe` توسط `cmd.exe` یا `powershell.exe` اجرا شده باشه، شک من قطعی‌تر می‌شه.

**محدودیت اصلی:** Event ID 4698 به‌صورت پیش‌فرض Audited نیست و باید از طریق Group Policy فعال بشه. اگه سازمان این Audit Policy رو فعال نکرده باشه، من فقط به Sysmon وابسته‌ام که ممکنه Parent Process رو ثبت نکرده باشه.

**اقدام بعدی:** اگه Task مشکوک تأیید شد، اول Task رو Disable می‌کنم، بعد Registry Key مربوطه رو بررسی می‌کنم که آیا Tarrask Technique (حذف `SD`) استفاده شده یا نه، و در نهایت Persistenceهای دیگه روی همون Host رو چک می‌کنم.
