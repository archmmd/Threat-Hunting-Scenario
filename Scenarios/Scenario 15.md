## 1. تعریف سناریو و هدف Hunt

یک **rundll32.exe** با آرگومان‌های غیرمعمول اجرا شده و کمی بعد از اجرا، یک **Network Connection** برقرار کرده است. هدف Hunt، تفکیک **سوءاستفاده مخرب از LOLBin** (Living Off the Land Binary) از **رفتار قانونی ویندوز** است.

**نکته حیاتی:** `rundll32.exe` یک باینری امضاشده مایکروسافت است که روزانه در محیط‌های ویندوزی برای اجرای DLLهای قانونی استفاده می‌شود . بنابراین، **نام فرآیند به‌تنهایی هیچ ارزش تشخیصی ندارد**. تمایز اصلی در **CommandLine**، **Parent Process**، **DLL Path**، و **رفتار پس از اجرا (Network)** است .

## 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (Malicious Proxy Execution)** | مهاجم از `rundll32.exe` برای اجرای یک DLL مخرب یا اسکریپت (JavaScript/VBScript/HTA) استفاده کرده تا از Allowlisting فرار کند | CommandLine شامل `javascript:`، `mshtml`، `RunHTMLApplication`، `.cpl`، یا مسیرهای `Temp`/`Public`  | DLL Path در `System32`، Signature معتبر Microsoft، Parent Process قابل توضیح |
| **فرضیه جایگزین (Legitimate Software)** | یک نرم‌افزار قانونی (Installer، Printer Driver، یا Windows Component) از `rundll32.exe` برای اجرای DLL خود استفاده کرده | Parent Process شناخته‌شده (`msiexec.exe`، `svchost.exe`)، DLL Path در Program Files، Signature معتبر | عدم تطابق با Baseline، Network Connection به مقصد ناشناخته |
| **فرضیه جایگزین (Process Injection / Hollowing)** | یک فرآیند مخرب از `rundll32.exe` به‌عنوان Host برای Injection استفاده کرده و Network Connection از آن فرآیند دیده می‌شود | CommandLine خالی، DLL از Unbacked Memory بارگذاری شده، Network Connection به C2  | CommandLine پر و قابل توضیح، DLL از Disk با Signature معتبر |

## 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Sysmon Event ID 1** (Essential) | Process Creation | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `Hashes`, `OriginalFileName`, `ProcessGuid`  |
| **Sysmon Event ID 7** (Essential) | Image/DLL Load | چه DLLهایی توسط `rundll32.exe` بارگذاری شده‌اند؟ آیا از Disk یا Memory؟  |
| **Sysmon Event ID 3** (Essential) | Network Connection | `DestinationIp`, `DestinationHostname`, `DestinationPort`, `ProcessGuid` — **توجه:** فیلد `Image` ممکن است برای فرآیندهای کوتاه‌مدت خالی باشد  |
| **Sysmon Event ID 11** (Supplementary) | File Creation | آیا DLL یا Script قبل از اجرا روی Disk نوشته شده؟ از کجا؟ |
| **EDR Process Tree** (Essential) | Correlation | زنجیره Parent-Child و Connection بین Processها |

**محدودیت مهم:** در Sysmon Event ID 3، برای فرآیندهای **کوتاه‌مدت** (مثل `rundll32.exe` که سریع اجرا و خاتمه می‌یابد)، ممکن است فیلد `Image` و `User` **خالی** باشد و فقط `ProcessGuid` و `ProcessId` ثبت شود . بنابراین Correlation با **Event ID 1** از طریق `ProcessGuid` **ضروری** است.

## 4. مراحل اجرایی Hunt و Queryهای عملی

### مرحله A: استخراج CommandLine غیرمعمول

**KQL (Defender XDR / Sentinel):**

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine has_any (
    "javascript:", 
    "mshtml", 
    "RunHTMLApplication",
    ".cpl,",
    "url.dll,OpenURL",
    "shell32.dll,Control_RunDLL",
    "\\Temp\\",
    "\\Users\\Public\\",
    "\\AppData\\Local\\Temp\\"
)
| where InitiatingProcessFileName !in~ ("explorer.exe", "svchost.exe", "msiexec.exe")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, 
          InitiatingProcessFileName, InitiatingProcessCommandLine, 
          FolderPath, SHA256
| order by Timestamp desc
```

**منطق Query:** این Query به‌دنبال **الگوهای CommandLine** شناخته‌شده سوءاستفاده است . آرگومان‌های `javascript:` و `mshtml` برای اجرای اسکریپت در حافظه استفاده می‌شوند و در محیط‌های قانونی **بسیار نادر** هستند .

### مرحله B: بررسی DLL Load شده

**KQL (Defender XDR):**

```kql
DeviceImageLoadEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "rundll32.exe"
| where FolderPath !startswith "C:\\Windows\\"
| project Timestamp, DeviceName, FolderPath, FileName, SHA256, 
          InitiatingProcessCommandLine, InitiatingProcessProcessId
```

**منطق Query:** اگر `rundll32.exe` یک DLL از مسیر غیر `System32` (مثل `Temp` یا `Public`) بارگذاری کرده باشد، **نشانه قوی مخرب بودن** است. DLLهای قانونی معمولاً از `System32` یا مسیر نصب نرم‌افزار بارگذاری می‌شوند.

### مرحله C: بررسی Network Connection

**KQL (Defender XDR):**

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "rundll32.exe"
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl, 
          InitiatingProcessCommandLine, InitiatingProcessProcessId
| order by Timestamp desc
```

**یا با Sysmon Event ID 3 (KQL Sentinel):**

```kql
SysmonEvent
| where EventID == 3
| where Image has "rundll32.exe" or ProcessGuid in (
    SysmonEvent | where EventID == 1 and Image has "rundll32.exe" 
    | project ProcessGuid
)
| project TimeGenerated, Image, DestinationIp, DestinationHostname, 
          DestinationPort, ProcessGuid
```

**منطق Query:** `rundll32.exe` قانونی معمولاً **اتصال شبکه خارجی برقرار نمی‌کند**. هر اتصال به IP عمومی از این فرآیند مشکوک است .

## 5. Pivoting و Correlation شواهد

از `ProcessGuid` و `ProcessId` برای Pivot استفاده کنید:

1. **Correlation با Event ID 1:** اگر در Event ID 3 فیلد `Image` خالی بود، با `ProcessGuid` به Event ID 1 مراجعه کنید تا CommandLine و Parent را ببینید .
2. **Parent Process Chain:** `ParentImage` → والد آن → تا رسیدن به یک Process شناخته‌شده. اگر والد `explorer.exe`، `winword.exe`، یا `cmd.exe` باشد → **بسیار مشکوک** .
3. **DLL Path:** آیا DLL از `Temp`، `Public`، یا `AppData` بارگذاری شده؟ اگر بله → **Strong Indicator**.
4. **File Creation (EID 11):** آیا DLL یا Script **قبل از** اجرای `rundll32.exe` روی Disk نوشته شده؟ Process ایجادکننده آن چه بوده؟
5. **Network Timeline:** آیا اتصال شبکه **بلافاصله پس از** اجرای `rundll32.exe` رخ داده؟ بازه زمانی بین دو Event چقدر است؟ (Correlation از طریق `ProcessGuid`، نه فقط Timestamp)

**هشدار:** همزمانی زمانی (Temporal Proximity) به‌تنهایی **Causation** را اثبات نمی‌کند. اتصال شبکه باید از **همان ProcessGuid** باشد تا قابل انتساب به `rundll32.exe` باشد.

## 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline مقایسه:**
- آیا `rundll32.exe` در ۳۰ روز گذشته از این Host با **همین CommandLine** اجرا شده؟
- آیا در گروه Peer (سایر Hostهای همان دپارتمان) رفتار مشابهی دیده می‌شود؟ اگر نه → **Anomaly** .
- آیا Parent Process در Baseline سازمان به‌عنوان Parent مجاز `rundll32.exe` ثبت شده؟

**Scope Determination:**
- روی همه Endpointها Query بزنید: آیا همان CommandLine یا همان DLL Hash در Hostهای دیگر دیده می‌شود؟
- آیا Network Connection به همان IP/Port در Endpointهای دیگر تکرار شده؟ (C2 Beaconing)

**False Positive ممکن:**
- **Print Drivers:** برخی Driverهای Printer از `rundll32.exe` برای اجرای DLLهای خود استفاده می‌کنند (Parent: `spoolsv.exe`) .
- **MSI Installers:** `msiexec.exe` ممکن است `rundll32.exe` را برای اجرای Custom Actionها فراخوانی کند .
- **Windows Components:** برخی Componentهای ویندوز مثل `LogiLDA.dll` یا `Windows.Storage.ApplicationData.dll` به‌صورت قانونی از `rundll32.exe` استفاده می‌کنند .

**معیار قطعی:** اگر CommandLine شامل `javascript:` یا `mshtml` باشد و Parent Process غیرعادی باشد، احتمال **False Positive بسیار پایین** است .

## 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1218.011** | System Binary Proxy Execution: Rundll32 | اجرای `rundll32.exe` با آرگومان‌های غیرمعمول (`javascript:`، `mshtml`، `.cpl`) برای Proxy Execution  |
| **T1036** (احتمالی) | Masquerading | اگر DLL با نام جعلی یا در مسیر غیراستاندارد قرار گرفته باشد  |
| **T1071** (اگر Network تأیید شود) | Application Layer Protocol | اتصال شبکه از `rundll32.exe` به C2 خارجی  |
| **T1055** (اگر Unbacked Memory تأیید شود) | Process Injection | بارگذاری DLL از Unbacked Memory Region  |

**هشدار:** Mapping فقط بر اساس **شواهد مشاهده‌شده** انجام شده. اگر Parent Process قانونی باشد و DLL از System32 بارگذاری شده باشد، ممکن است T1218.011 **اعمال نشود**.

## 8. نتیجه‌گیری و سطح اطمینان

**وضعیت فعلی: Observed (مشاهده‌شده)**

- **آنچه مسلم است:** `rundll32.exe` با آرگومان‌های غیرمعمول اجرا شده و اتصال شبکه برقرار کرده است.
- **آنچه Likely است:** این رفتار **مشکوک به Proxy Execution** است، به‌ویژه اگر CommandLine شامل `javascript:`، `mshtml`، یا مسیرهای `Temp` باشد.
- **آنچه هنوز اثبات نشده:** اینکه این Process واقعاً **مخرب** است. برای Confirmation نیاز به:
  1. DLL Path غیراستاندارد (خارج از System32/Program Files)
  2. Parent Process غیرعادی (غیر از `explorer.exe`، `svchost.exe`، `msiexec.exe`)
  3. Network Connection به IP/دومین ناشناخته یا مشکوک
  4. DLL Hash در Threat Intel به‌عنوان Malicious

**سطح اطمینان اولیه: Medium-High** که این یک **Anomaly امنیتی** است. اگر CommandLine شامل `javascript:` یا `mshtml` باشد، اطمینان به **High** ارتقا می‌یابد .

## 9. Response و بهبود Detection

**اقدامات فوری (اگر شواهد مشکوک تأیید شد):**
1. **Endpoint Isolation** از طریق EDR
2. **جمع‌آوری Forensic:** کپی DLL بارگذاری‌شده، Memory Dump از Process، Sysmon Logs
3. **بررسی Persistence:** Registry Run Keys، Scheduled Tasks، Services
4. **بررسی Lateral Movement:** آیا همان CommandLine روی Hostهای دیگر دیده می‌شود؟

**اقدامات بلندمدت (Detection Improvement):**
1. **قانون Detection جدید:** هر `rundll32.exe` با `javascript:`، `mshtml`، یا `.cpl` → Alert 
2. **قانون Parent Process:** هر `rundll32.exe` که والد آن `explorer.exe`، `winword.exe`، یا `cmd.exe` باشد → Alert 
3. **قانون DLL Path:** هر `rundll32.exe` که DLL از `Temp`، `Public`، یا `AppData` بارگذاری کند → Alert
4. **قانون Network:** هر اتصال خارجی از `rundll32.exe` → Alert 
5. **Baseline Tuning:** شناسایی DLLهای قانونی که در سازمان از `rundll32.exe` استفاده می‌کنند (مثل Printer Drivers) و Exclude کردن آن‌ها 

## 10. پاسخ کوتاه برای شروع جواب در مصاحبه

برای تفکیک سوءاستفاده از `rundll32.exe`، **CommandLine مهم‌ترین فیلد** است. `rundll32.exe` قانونی معمولاً یک DLL از `System32` یا مسیر نصب نرم‌افزار با یک Export Function مشخص اجرا می‌کند.

من دنبال الگوهای خاص می‌گردم: `javascript:`، `mshtml,RunHTMLApplication`، `.cpl`، یا DLL از مسیر `Temp` یا `Users\Public`. این‌ها در محیط قانونی **بسیار نادر** هستند .

**Parent Process** رو هم چک می‌کنم: اگر والدش `explorer.exe`، `winword.exe`، یا `cmd.exe` باشه، شک من قطعی‌تر می‌شه. در مقابل، `msiexec.exe` یا `svchost.exe` می‌تونن قانونی باشن .

برای **Network Connection**، از `ProcessGuid` استفاده می‌کنم چون در Sysmon Event ID 3 ممکنه فیلد `Image` برای فرآیندهای کوتاه‌مدت خالی باشه . اگه `rundll32.exe` به IP عمومی خارجی وصل شده باشه، این **Strong Indicator** است چون `rundll32.exe` قانونی معمولاً اتصال خارجی نداره .

**محدودیت اصلی:** بدون CommandLine و Parent Process قابل اعتماد، نمی‌تونم فقط بر اساس نام `rundll32.exe` قضاوت کنم. اگه CommandLine شامل `javascript:` یا `mshtml` باشه، احتمال مخرب بودن **بالا** است و Endpoint رو Isolate می‌کنم.
