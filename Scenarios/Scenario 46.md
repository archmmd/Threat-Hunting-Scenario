Phishing تا Lateral Movement
Word، سپس PowerShell، بعد Credential Access و در نهایت SMB روی چند Server دیده شده است.
چطور کل زنجیره را بازسازی، Techniqueها را Map و Scope را تعیین می‌کنی؟

این سناریو دقیقاً یک زنجیره حمله کلاسیک چندمرحله‌ای را توصیف می‌کند که در گزارش‌های Threat Intel (مانند FIN8) نیز به‌عنوان یک الگوی شناخته‌شده ثبت شده است . برای بازسازی این زنجیره، باید از **Process Ancestry** و **زمان‌بندی** برای اتصال نقاط استفاده کنی، نه صرفاً نگاه به Alertهای جداگانه.

### 🧩 گام اول: بازسازی زنجیره از Word تا PowerShell

همه‌چیز از یک سند Word آلوده شروع می‌شود. وقتی کاربر ماکرو را فعال می‌کند، Word یک Process فرزند (مانند PowerShell) ایجاد می‌کند.

**شواهد کلیدی:**
*   **Sysmon Event ID 1 (Process Creation):** به دنبال **ParentImage** بگرد که `winword.exe` باشد و **Image** آن `powershell.exe` باشد. این **قطعی‌ترین شاهد** برای ورود اولیه از طریق ماکرو است.
*   **Command Line:** به دنبال الگوهای **Download Cradle** در Command Line بگرد (مانند `IEX`, `DownloadString`, یا `-enc`) .

**Query نمونه (KQL):**
```kql
DeviceProcessEvents
| where InitiatingProcessFileName =~ "winword.exe"
| where FileName in~ ("powershell.exe", "cmd.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

### 🔑 گام دوم: شناسایی Credential Access (LSASS)

پس از استقرار Backdoor، مهاجم برای حرکت جانبی به Credential نیاز دارد. اینجاست که **LSASS** هدف قرار می‌گیرد.

**شواهد کلیدی:**
*   **Sysmon Event ID 10 (Process Access):** به دنبال دسترسی به `lsass.exe` با **GrantedAccess**های مشکوک مانند `0x1010` یا `0x1410` بگرد . این Access Maskها نشان‌دهنده تلاش برای خواندن حافظه و استخراج Credential هستند.
*   **CallTrace:** مسیر فراخوانی توابع (Call Trace) ممکن است شامل `dbgcore.dll` یا `dbghelp.dll` باشد که نشان‌دهنده استفاده از APIهای دیباگ برای Dump کردن حافظه است .

**Query نمونه (KQL):**
```kql
DeviceEvents
| where ActionType == "ProcessAccess"
| where TargetProcessFileName =~ "lsass.exe"
| where GrantedAccess in ("0x1010", "0x1410", "0x1fffff")
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "svchost.exe", "csrss.exe")
```

### 🌐 گام سوم: تشخیص Lateral Movement از طریق SMB

با Credentialهای استخراج‌شده، مهاجم به سراغ سرورها می‌رود. الگوی رایج استفاده از **PsExec** یا ابزارهای مشابه است که از **Admin Shares** (`ADMIN$`, `C$`) برای کپی فایل و ایجاد سرویس استفاده می‌کنند .

**شواهد کلیدی:**
*   **Security Event ID 5140 (Network Share Access):** دسترسی به `ADMIN$` یا `C$` از یک Workstation (نه از یک Management Server) . این نشان‌دهنده **Staging** فایل مخرب قبل از اجراست .
*   **System Event ID 7045 (Service Installation):** ایجاد سرویس جدید با نامی مانند `PSEXESVC`. این **قطعی‌ترین شاهد** برای Remote Execution از طریق PsExec است.
*   **Sysmon Event ID 1:** روی سرور هدف، یک Process (مانند `cmd.exe` یا `powershell.exe`) که **ParentImage** آن `services.exe` یا `PSEXESVC.exe` است.

**Query نمونه (KQL):**
```kql
// روی سرور هدف
Event
| where EventID == 7045
| where ServiceName has "PSEXESVC" or ServiceFileName has "PSEXESVC"
| project TimeGenerated, Computer, ServiceName, ServiceFileName, AccountName
```

### 🗺️ گام چهارم: MITRE ATT&CK Mapping و تعیین Scope

برای Mapping، هر مرحله از زنجیره را به Technique مربوطه نسبت بده:

| مرحله زنجیره | شواهد | Technique |
| :--- | :--- | :--- |
| **Initial Access** | Word spawning PowerShell | **T1566.001** (Spearphishing Attachment) |
| **Execution** | PowerShell Download Cradle | **T1059.001** (PowerShell) |
| **Credential Access** | LSASS Access (`0x1010`) | **T1003.001** (LSASS Memory)  |
| **Lateral Movement** | SMB Admin Share Access (`5140`) | **T1021.002** (SMB/Admin Shares)  |
| **Lateral Movement** | Service Creation (`7045`) | **T1569.002** (Service Execution) |

**تعیین Scope:**
1.  **Hostهای درگیر:** با استفاده از **Source IP** در Event 5140، لیست تمام سرورهایی که از Workstation آلوده Access شده‌اند را استخراج کن.
2.  **Accountهای درگیر:** بررسی کن که **Credential استخراج‌شده** متعلق به چه حسابی بوده. تمام Loginهای بعدی با آن Account را در کل شبکه ردیابی کن (Lateral Movement بیشتر).
3.  **زمان‌بندی:** یک **Unified Timeline** از اولین دسترسی LSASS تا آخرین Service Creation بساز.

### 💎 جمع‌بندی برای مصاحبه

برای بازسازی این زنجیره، اول از **Process Ancestry** استفاده می‌کنم: `winword.exe` که `powershell.exe` را spawn کرده. بعد با **Sysmon EID 10**، دسترسی به `lsass.exe` با Access Mask `0x1010` رو پیدا می‌کنم که نشون‌دهنده Credential Dumping هست .

برای حرکت جانبی، **Security Event 5140** روی سرورها رو چک می‌کنم: Access به `ADMIN$` از یک Workstation معمولی، و بعد **System Event 7045** برای ایجاد سرویس `PSEXESVC`. این **زنجیره علیت** رو تأیید می‌کنه.

**محدودیت اصلی:** اگه **Event ID 5140** یا **Sysmon EID 10** روی Endpointها فعال نباشه، نمی‌تونم این مراحل رو تأیید کنم. در این صورت، فقط به **Network Flow** (SMB به Port 445) و **Alertهای IDS** محدود می‌شم .

**اقدام بعدی:** پس از تأیید، **Account** مربوطه رو Disable می‌کنم، **Sessionها** رو Revoke می‌کنم، و روی **Hostهای Target** بررسی می‌کنم که آیا **Persistence** (Scheduled Task، WMI Subscription) ایجاد شده یا نه.
