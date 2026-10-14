### 1. تعریف سناریو و هدف Hunt

می‌خواهید یک Technique مشخص (مثلاً **T1053.005 Scheduled Task** یا **T1021.002 SMB/Admin Shares**) را Hunt کنید، اما Logهای لازم در SIEM **وجود ندارند**. هدف، **شناسایی دقیق Data Gap**، **ارزیابی منابع جایگزین**، و **گزارش شفاف محدودیت نتیجه** است.

**نکته حیاتی:** در این شرایط، Hunt **شکست نخورده** — بلکه به یک **Telemetry Gap Assessment** تبدیل شده است. نتیجه‌ای که بدون داده کافی گرفته شود، **گمراه‌کننده** است و باید به‌صراحت به‌عنوان **Inconclusive / Telemetry Gap** علامت‌گذاری شود، نه «No Evidence of Compromise» .

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (Data Gap)** | Log منبع ضروری در SIEM **وجود ندارد** یا **ناقص** است | نبود Event ID موردنیاز، Parse Failure، Retention کوتاه، Source غیرفعال  | وجود Log در منبع دیگر، Retention کافی |
| **فرضیه جایگزین (Compensating Telemetry)** | Log اصلی نیست، اما **منبع جایگزین** می‌تواند بخشی از رفتار را نشان دهد | Network Flow، DNS، Proxy Log، EDR Telemetry  | عدم تطابق Schema، فقدان Correlation Key |
| **فرضیه جایگزین (Adversary Suppression)** | خود مهاجم Telemetry را **قطع کرده** است (Defense Evasion) | توقف ناگهانی Log پس از Alert، Agent Heartbeat قطع  | Maintenance Window، Outage شناخته‌شده |

### 3. Telemetry و Data Sources (ارزیابی شکاف)

**مرحله A: شناسایی شکاف دقیق**

شکاف Telemetry فقط «نبود Log» نیست. باید **دقیقاً مشخص شود** کدام لایه خراب است :

| نوع شکاف | توضیح | مثال |
|---|---|---|
| **Collection Gap** | Log **تولید** می‌شود اما **جمع‌آوری نمی‌شود** | Sysmon EID 10 روی سرور فعال است اما به SIEM Forward نمی‌شود |
| **Parsing Gap** | Log جمع‌آوری می‌شود اما **Parse نمی‌شود** | Event 4698 در SIEM است اما فیلد `TaskContent` Parse نشده |
| **Retention Gap** | Log بود اما **حذف شده** | Retention فقط 7 روز است، اما Incident 30 روز پیش رخ داده |
| **Source Gap** | Log **تولید نمی‌شود** | Audit Policy برای Event 4698 فعال نیست  |

**مرحله B: ارزیابی منابع جایگزین (Compensating Telemetry)**

| Technique | Log ضروری (غایب) | منبع جایگزین | محدودیت جایگزین |
|---|---|---|---|
| **T1053.005** (Scheduled Task) | Security 4698 | Sysmon EID 1 (`schtasks.exe /create`) | فقط **ایجاد** را نشان می‌دهد، نه **محتوای Task**  |
| **T1021.002** (SMB) | Security 5145 (Detailed File Share) | Sysmon EID 3 (Network Connection به 445) | فقط **Connection** را نشان می‌دهد، نه **Share Access**  |
| **T1003.001** (LSASS) | Sysmon EID 10 | EDR Process Access Telemetry | وابسته به Vendor، Schema متفاوت  |
| **T1071** (C2) | Proxy Log | NetFlow / DNS Log | فقط **Metadata**، نه Payload  |

**منابع جایگزین باید از نظر «Joinability» ارزیابی شوند** :
- آیا **ProcessGuid** یا **LogonId** برای Correlation وجود دارد؟
- آیا **Timestamp** قابل اعتماد است؟ (Time Sync)
- آیا **Retention** کافی است؟

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: تأیید شکاف (Gap Verification)**

```kql
// بررسی وجود Event 4698 در SIEM
SecurityEvent
| where EventID == 4698
| summarize Count = count() by bin(TimeGenerated, 1d)
| order by TimeGenerated desc

// اگر نتیجه خالی بود، شکاف تأیید می‌شود
```

**مرحله B: بررسی وجود منبع جایگزین**

```kql
// بررسی Sysmon EID 1 برای schtasks.exe
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| summarize Count = count() by bin(Timestamp, 1d)
```

**مرحله C: اجرای Hunt با منبع جایگزین (با محدودیت مشخص)**

```kql
DeviceProcessEvents
| where FileName =~ "schtasks.exe"
| where ProcessCommandLine has "/create"
| where ProcessCommandLine has_any ("powershell", "cmd", "mshta", "\\Temp\\", "\\AppData\\")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, 
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**هشدار:** این Query **فقط** ایجاد Task را نشان می‌دهد. **محتوای Task**، **Trigger**، و **Principal** **قابل مشاهده نیستند** .

### 5. Pivoting و Correlation شواهد

با منابع جایگزین، Pivoting **محدودتر** است:

1. **از Process Creation به Parent Process:** از `InitiatingProcessFileName` استفاده کنید. اگر Parent `cmd.exe` یا `powershell.exe` باشد → **Strong Indicator**.
2. **از Host به Network:** اگر Host به IP خارجی متصل شده، Sysmon EID 3 را بررسی کنید.
3. **از Account به Account:** آیا همان Account روی Hostهای دیگر `schtasks.exe` اجرا کرده؟

**محدودیت حیاتی:** بدون Event 4698، نمی‌توان **TaskContent** را دید. بنابراین، نمی‌توان تأیید کرد که Task چه **Action**ی دارد .

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline:**
- آیا `schtasks.exe /create` در **Baseline سازمان** وجود دارد؟ (Software Installer، SCCM)
- آیا Parent Process قانونی است؟

**Scope:**
- روی **همه Hostها** Query بزنید. اما **توجه:** عدم وجود نتیجه **به‌معنای عدم وجود Task نیست** — فقط به‌معنای عدم وجود **Process Creation Log** است.

**False Positive:**
- Software Installers (Adobe، Google Update)
- SCCM Deployment
- Admin Automation Scripts

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | وضعیت Mapping |
|---|---|---|
| **T1053.005** | Scheduled Task | **Partial** — فقط Process Creation قابل مشاهده است، نه Task Content  |
| **T1021.002** | SMB/Admin Shares | **Partial** — فقط Network Connection قابل مشاهده است، نه Share Access  |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** Log ضروری در SIEM وجود ندارد.

**Likely:** این یک **Telemetry Gap** است، نه **No Evidence of Compromise**.

**Confidence: Low** — نتیجه Hunt **Inconclusive** است. عدم وجود شواهد **به‌معنای عدم وجود حمله نیست** — فقط به‌معنای **عدم توانایی مشاهده** است .

**Next Best Action:** ثبت **Telemetry Gap** با Owner، Priority، و Due Date برای Remediation .

### 9. Response و بهبود Detection

**گزارش محدودیت باید شامل موارد زیر باشد** :

| مورد | توضیح |
|---|---|
| **Missing Source** | Event 4698 در SIEM وجود ندارد |
| **Affected Hypothesis** | T1053.005 قابل Hunt نیست |
| **Business Risk** | Persistence مخرب قابل تشخیص نیست |
| **Compensating Telemetry** | Sysmon EID 1 (فقط Process Creation) |
| **Limitation** | TaskContent، Trigger، Principal قابل مشاهده نیستند |
| **Remediation Owner** | تیم Detection Engineering |
| **Verification Test** | پس از فعال‌سازی Audit Policy، Event 4698 در SIEM مشاهده شود |

**Detection Improvement:**
1. **فعال‌سازی Audit Policy:** `Audit Other Object Access Events` برای Event 4698 .
2. **اطمینان از Sysmon:** EID 1 با Command Line فعال باشد.
3. **Telemetry Coverage Map:** ثبت شکاف در DeTT&CT یا Coverage Map .

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

اول **نوع شکاف** رو مشخص می‌کنم: آیا Log **تولید نمی‌شه** (Source Gap)، **جمع‌آوری نمی‌شه** (Collection Gap)، یا **Parse نمی‌شه** (Parsing Gap)؟ 

بعد **منبع جایگزین** رو ارزیابی می‌کنم: اگه Event 4698 ندارم، می‌تونم از Sysmon EID 1 برای `schtasks.exe /create` استفاده کنم، اما **فقط Process Creation رو نشون می‌ده، نه TaskContent** .

**محدودیت اصلی:** عدم وجود شواهد **به‌معنای عدم وجود حمله نیست**. نتیجه Hunt **Inconclusive** است و باید به‌عنوان **Telemetry Gap** ثبت بشه .

**اقدام بعدی:** Gap رو با **Owner**، **Priority**، و **Verification Test** ثبت می‌کنم تا پس از Remediation، Hunt دوباره اجرا بشه .
