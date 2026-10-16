از Alert تا Incident Closure
فقط این اطلاعات را داری: یک Alert مشکوک روی Windows Endpoint.
از Validation تا Investigation، Scoping، Severity، Containment، Escalation، Evidence Preservation و Closure را مرحله‌به‌مرحله توضیح بده.

این چرخه کامل مدیریت Incident از یک Alert مشکوک تا بستن پرونده است. در هر مرحله، تمرکز اصلی بر **جمع‌آوری شواهد** و **تصمیم‌گیری مبتنی بر داده** است، نه اقدامات شتاب‌زده.

### 🛡️ مرحله ۱: Validation (اعتبارسنجی)

هدف: تفکیک **False Positive** از **True Positive** و تعیین اینکه آیا Alert ارزش Investigation دارد یا خیر.

**اقدامات:**
- **بررسی Detection Source:** Alert از کدام قابلیت آمده؟ EDR، Antivirus، ASR Rule، یا Custom Threat Intel؟ اگر از ASR Rule باشد، احتمال False Positive بالاست.
- **بررسی Context اولیه:** روی همان Endpoint، چه Processهایی در حال اجرا هستند؟ آیا Parent Process قانونی است؟ اگر Parent یک Agent شناخته‌شده باشد (`CcmExec.exe`، `IntuneManagementExtension.exe`)، احتمال False Positive بالاست.
- **Baseline مقایسه:** آیا این رفتار قبلاً روی این Host یا Hostهای مشابه دیده شده؟ اگر بله و در Allowlist سازمان ثبت شده، احتمال False Positive بالاست.

**معیار خروج:** اگر شواهد به‌اندازه کافی برای **Likely True Positive** وجود دارد، وارد Investigation می‌شویم. در غیر این صورت، Alert را Classify و Suppress می‌کنیم.

### 🔍 مرحله ۲: Investigation (تحقیق)

هدف: بازسازی **زنجیره علیت** و تعیین اینکه مهاجم **چه کاری انجام داده است**.

**اقدامات:**
- **Process Ancestry:** از Sysmon Event ID 1 یا Security Event 4688، Parent Process Chain را استخراج کن. آیا `cmd.exe` یا `powershell.exe` توسط یک Process غیرعادی spawn شده است؟ 
- **Command Line Analysis:** به دنبال الگوهای مشکوک بگرد: `-enc`، `IEX`، `DownloadString`، `bitsadmin`، `certutil`، مسیر `C:\Users\Public\` به‌عنوان Parent Process. 
- **Network Activity:** از Sysmon Event ID 3 و 22، اتصالات خروجی و DNS Queryهای Process مشکوک را بررسی کن. آیا به IP یا Domain ناشناخته متصل شده است؟ 
- **Credential Access Check:** از Sysmon Event ID 10، دسترسی به `lsass.exe` با `GrantedAccess` مشکوک (مثل `0x1010` یا `0x1410`) را بررسی کن. 
- **Persistence Check:** از Security Event 4698 (Scheduled Task) و System Event 7045 (Service Installation)، مکانیزم‌های ماندگاری ایجادشده را شناسایی کن. 

**معیار خروج:** اگر زنجیره علیت تأیید شد و Techniqueها Map شدند، وارد Scoping می‌شویم.

### 🌐 مرحله ۳: Scoping (تعیین دامنه)

هدف: تعیین **وسعت Incident** — کدام Hostها، Accountها، و سیستم‌ها تحت تأثیر قرار گرفته‌اند.

**اقدامات:**
- **Hostهای درگیر:** از Network Logs (SMB/RDP/WinRM)، لیست Hostهایی که از Endpoint آلوده Access شده‌اند را استخراج کن. از Security Event 4624 با Logon Type 3 (Network) برای تأیید Loginهای موفق استفاده کن. 
- **Accountهای درگیر:** از Event 4624 و 4672، Accountهایی که Login کرده‌اند و Privileges بالا گرفته‌اند را شناسایی کن.
- **زمان‌بندی:** یک **Unified Timeline** از اولین شواهد Compromise تا آخرین فعالیت مشکوک بساز.
- **Patient Zero:** با استفاده از Prefetch و Amcache، **قدیمی‌ترین Execution Time** فایل مخرب را پیدا کن — این Host واقعی Patient Zero است، نه Hostی که اول Alert داده.

**معیار خروج:** لیست کامل Hostها و Accountهای درگیر آماده است.

### ⚖️ مرحله ۴: Severity (تعیین شدت)

هدف: تعیین **اولویت** و **فوریت** Incident بر اساس **Criticality** دارایی‌ها و **وسعت** نفوذ.

**معیارها:**
- **Critical (P1):** Domain Controller، Database، File Server آلوده شده. حساب ممتاز (Domain Admin) Compromise شده. Ransomware یا Exfiltration در حال وقوع است.
- **High (P2):** Endpoint معمولی آلوده شده، اما مهاجم در حال **Lateral Movement** است.
- **Medium (P3):** Endpoint آلوده شده، اما شواهد **Execution** تأیید نشده یا محدود است.

### 🚧 مرحله ۵: Containment (مهار)

هدف: **توقف گسترش** بدون از بین بردن شواهد.

**اقدامات:**
- **Isolate Endpoint:** از طریق EDR، Endpoint را از شبکه Isolate کن. **توجه:** Isolate کامل (Network Containment) ممکن است Communication با EDR Console را قطع کند. اگر Process مشکوک هنوز در حال اجراست و نیاز به Memory Dump داری، اول Dump بگیر بعد Isolate کن.
- **Revoke Sessions:** تمام Sessionهای فعال Accountهای درگیر را Revoke کن (Kerberos Tickets، RDP Sessions).
- **Block C2:** IP/Domain مقصد C2 را در Firewall و Proxy Block کن.
- **Account Disable:** Accountهای Compromised را Disable کن.

**هشدار:** **Restart نکن** — Volatile Data (Memory، Decryption Keys) از بین می‌رود.

### 📢 مرحله ۶: Escalation (ارتقا)

هدف: **اطلاع‌رسانی** به ذی‌نفعان مناسب بر اساس **Severity** و **Policy سازمان**.

**معیارهای Escalation:**
- **به Incident Response Team:** اگر Severity **Critical** یا **High** است، فوراً Escalate کن.
- **به Management:** اگر داده حساس در خطر است، یا اگر Incident نیاز به **Legal/Compliance** دارد.
- **به تیم‌های دیگر:** اگر Incident شامل **Third-Party** یا **Cloud Service** است، تیم مربوطه را مطلع کن.

### 📦 مرحله ۷: Evidence Preservation (حفظ شواهد)

هدف: **حفظ شواهد** برای Forensic Analysis و **Legal Proceedings** (در صورت نیاز).

**اقدامات:**
- **Memory Dump:** از Endpoint و (اگر درگیر است) Domain Controller.
- **Disk Image:** از Endpoint آلوده (اگر حجم و زمان اجازه می‌دهد).
- **Export Event Logs:** Security، Sysmon، PowerShell Operational، Defender for Identity.
- **جمع‌آوری Artifactها:** Prefetch، Amcache، $MFT، USN Journal.
- **Snapshot:** از VMها و Cloud Volumes.

### ✅ مرحله ۸: Closure (بستن پرونده)

هدف: **مستندسازی**، **تحلیل**، و **بهبود** برای جلوگیری از تکرار.

**اقدامات:**
- **Incident Report:** خلاصه Timeline، Techniques Map‌شده، Root Cause، Impact، Actions Taken.
- **Lessons Learned:** چه چیزی کار کرد؟ چه چیزی نشد؟ چه Telemetry کم بود؟
- **Detection Improvement:** Ruleهای جدید برای Techniqueهای مشاهده‌شده (مثلاً قانون برای `C:\Users\Public\` به‌عنوان Parent Process). 
- **Telemetry Gap:** اگر Sysmon یا Auditing غیرفعال بود، فعال‌سازی و ثبت Gap.

### 💎 جمع‌بندی برای مصاحبه

**Validation:** اول Detection Source رو چک می‌کنم. اگر از ASR یا Custom Intel باشه، احتمال FP بالاست. Parent Process رو بررسی می‌کنم.

**Investigation:** Process Ancestry، Command Line، Network Activity، و Credential Access (Sysmon EID 10 برای LSASS) رو بررسی می‌کنم.

**Scoping:** Hostهای درگیر از Network Logs و Event 4624، Accountهای درگیر از 4672، و Patient Zero از Prefetch/Amcache.

**Severity:** Critical اگر DC یا Domain Admin درگیره. High اگر Lateral Movement در حال وقوعه.

**Containment:** Isolate Endpoint، Revoke Sessions، Block C2. **Restart نکن.**

**Escalation:** اگر Critical/High، فوراً به IR Team.

**Evidence Preservation:** Memory Dump، Event Logs، Prefetch/Amcache.

**Closure:** Incident Report، Detection Improvement (قانون برای `C:\Users\Public\` به‌عنوان Parent)، و فعال‌سازی Telemetry Gapها.
