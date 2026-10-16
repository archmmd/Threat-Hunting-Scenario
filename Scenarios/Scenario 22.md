PsExec و ایجاد سرویس
روی یک Server، ایجاد سرویس جدید و اجرای Process مشکوک هم‌زمان با اتصال SMB از یک Workstation دیده می‌شود.
چه شواهدی برای تأیید یا رد Lateral Movement لازم داری؟

برای تأیید یا رد Lateral Movement در این سناریو، باید یک **زنجیره شواهد** از Source (Workstation) تا Destination (Server) بسازیم. صرفاً دیدن همزمانی (Time Proximity) بین SMB Connection و Service Creation **کافی نیست**؛ باید **علیت (Causation)** را از طریق **Process Execution** و **Artifacts** تأیید کنیم.

### 1. شواهد ضروری برای تأیید (Confirmation)

اگر این سه دسته شواهد را داشته باشیم، اطمینان ما **بالا** می‌شود:

**الف) Artifacts اختصاصی PsExec روی Server (Destination)**
ابزار PsExec (و مشتقات آن) ردپای مشخصی از خود باقی می‌گذارند که High-Fidelity هستند:
- **Service Creation (Event ID 7045):** بررسی `ServiceFileName` برای مسیر `%SystemRoot%\PSEXESVC.exe` یا نام‌های مشابه. حتی اگر مهاجم نام سرویس را تغییر دهد (`-r` option)، فایل اجرایی معمولاً در `C:\Windows\` کپی می‌شود و سرویس در **User Mode** (نه Kernel Mode) و با اکانت **LocalSystem** اجرا می‌شود .
- **Named Pipe (Sysmon EID 17):** ایجاد Pipe با نام `\PSEXESVC`. این یکی از **قطعی‌ترین شواهد** است و معمولاً حتی وقتی نام سرویس تغییر می‌کند، باقی می‌ماند .
- **File Artifact:** ایجاد فایل‌های موقت با الگوی `C:\Windows\PSEXEC-*.key` روی سرور .

**ب) شواهد روی Source (Workstation)**
- **Process Creation (Sysmon EID 1 یا Event 4688):** اجرای `psexec.exe` یا `PsExec64.exe` با آرگومان `\\TargetServer`. اگر Command Line فعال باشد، می‌توانیم دقیقاً ببینیم چه دستوری اجرا شده است .
- **Network Connection (Sysmon EID 3):** اتصال خروجی از `psexec.exe` به پورت 445 روی سرور Target.

**ج) Correlate کردن دو طرف (Source و Destination)**
- **Event 4624 (Logon Type 3):** روی Server (Destination) باید یک Network Logon از **IP همان Workstation** و با **همان User** ثبت شده باشد. زمان آن باید **کمتر از ۱ دقیقه** قبل از ایجاد سرویس (7045) باشد .
- **Event 5145 (Detailed File Share):** اگر Auditing فعال باشد، باید نوشتن فایل اجرایی (مثلاً PSEXESVC.exe) در Shareهای `ADMIN$` یا `C$` را ببینیم. این نشان می‌دهد که فایل **قبل از** اجرای سرویس روی سرور کپی شده است .

### 2. شواهدی که باید رد کنیم (False Positive)

اگر شواهد زیر را ببینیم، احتمال اینکه یک **ابزار مدیریتی قانونی** (مثل SCCM، Tanium، یا IT Admin از Jump Server) باشد، بالا می‌رود:
- **Source IP:** اگر IP مبدأ در محدوده **Management VLAN** یا **Jump Server** باشد.
- **Process روی Source:** اگر Process ایجادکننده اتصال `explorer.exe`، `mmc.exe` یا یک Agent شناخته‌شده باشد (نه `cmd.exe` یا `powershell.exe`).
- **Target Selection:** اگر اتصال به **همه** Hostها (نه فقط ۱۵ سیستم) باشد (رفتار اسکنر).
- **Time Window:** اگر Activity در **ساعات کاری** و همزمان با **Patch Window** یا **Backup Schedule** باشد .

### 3. محدودیت‌ها و وابستگی‌ها (Limitations)

تشخیص قطعی به این موارد بستگی دارد:
- **Audit Policy:** باید **Audit Process Creation** (Event 4688) و **Include command line** فعال باشد .
- **Sysmon Config:** باید **Named Pipe Events (EID 17/18)** در Sysmon فعال شده باشد .
- **Detailed File Share Auditing:** برای دیدن **Event 5145** باید این Policy فعال باشد .
- **Time Sync:** اختلاف ساعت بین Source و Destination (بیش از ۵ دقیقه) می‌تواند Correlation را خراب کند .

### 4. پاسخ کوتاه برای شروع جواب در مصاحبه

برای تأیید Lateral Movement از طریق PsExec، اول روی **Server (Destination)** دنبال **Event ID 7045** با نام سرویس `PSEXESVC` یا مسیر فایل در `C:\Windows\` می‌گردم . این **قطعی‌ترین نشانه** است. بعد با **Sysmon Event ID 17** بررسی می‌کنم که آیا Named Pipe با نام `\PSEXESVC` ایجاد شده یا نه .

در قدم بعدی، **Event ID 4624 (Logon Type 3)** روی همون Server رو چک می‌کنم: اگه یک Network Logon از **IP همون Workstation** و با **همون User** ثبت شده باشه و زمانش **کمتر از ۱ دقیقه قبل** از 7045 باشه، این **زنجیره علیت** رو تأیید می‌کنه .

**محدودیت اصلی:** اگه **Named Pipe Logging** در Sysmon فعال نباشه، ممکنه 7045 رو ببینم ولی نتونم PsExec رو قطعی تأیید کنم. همچنین اگه Command Line Auditing فعال نباشه، نمی‌تونم ببینم چه دستوری روی Server اجرا شده .

**اقدام بعدی:** اگه تأیید شد، Source رو Isolate می‌کنم و روی Server بررسی می‌کنم که **Process Parent** اون سرویس چه بوده و آیا `cmd.exe` یا `powershell.exe` توسط `PSEXESVC.exe` اجرا شده یا نه.
