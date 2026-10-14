### 1. تعریف سناریو و هدف Hunt

**سناریو:** فرض بر این است که مهاجم پس از **Initial Access** مکانیزمی برای **Persistence** ایجاد کرده است، اما IOC مشخصی در دست نیست. هدف Hunt، شناسایی **مکانیزم‌های ماندگاری** از طریق بررسی **محل‌های Persistence**، **Logها** و **تغییرات سیستم** است.

**نکته حیاتی:** Persistence **حیاتی‌ترین مرحله** در یک کمپین APT است. ۶۹٪ گروه‌های APT حداقل از یک تکنیک Persistence استفاده کرده‌اند . مهاجمان معمولاً **چندین مکانیزم** را به‌صورت **Redundant** پیاده‌سازی می‌کنند تا با حذف یکی، دسترسی از دست نرود .

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده |
|---|---|---|
| **فرضیه اصلی (Multiple Persistence Mechanisms)** | مهاجم چندین مکانیزم Persistence از **خانواده‌های مختلف** (Registry، Scheduled Task، Service، WMI) ایجاد کرده است | Event ID 4698 (Task Created)، 7045 (Service Install)، Registry Run Keys، WMI Event Subscription  |
| **فرضیه جایگزین (Legitimate Software)** | نرم‌افزارهای قانونی (Backup، Monitoring، Update) مکانیزم‌های Persistence ایجاد کرده‌اند | TaskName مطابق Baseline، Signature معتبر، Parent Process شناخته‌شده |

### 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Sysmon EID 1** (Essential) | Process Creation | `schtasks.exe /create`، `sc.exe create`، `reg add` |
| **Sysmon EID 11/13** (Essential) | File/Registry Modification | فایل در `C:\Windows\System32\Tasks\`، Registry Run Keys |
| **Security EID 4698/4702** (Essential) | Task Created/Updated | نیاز به **Audit Other Object Access Events**  |
| **System EID 7045** (Essential) | Service Installation | `ServiceFileName` مشکوک |
| **WMI-Activity/Operational** (Supplementary) | WMI Persistence | EID 5861 (Subscription Created) |

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: بررسی Scheduled Tasks**

```kql
SecurityEvent
| where EventID == 4698
| extend TaskContent = tostring(EventData.TaskContent)
| where TaskContent has_any ("powershell", "-enc", "cmd", "rundll32", "mshta", 
    "\\AppData\\", "\\Temp\\", "\\Users\\Public\\", "http://", "https://")
| project TimeGenerated, Computer, TaskName, TaskContent
```

**مرحله B: بررسی Registry Run Keys**

```kql
DeviceRegistryEvents
| where RegistryKey has_any (
    "\\CurrentVersion\\Run", "\\CurrentVersion\\RunOnce",
    "\\Winlogon\\Shell", "\\Winlogon\\Userinit"
)
| where RegistryValueData !startswith "C:\\Program Files"
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
```

**مرحله C: بررسی Service Creation**

```kql
DeviceEvents
| where ActionType == "ServiceInstalled"
| where ServiceFileName !startswith "C:\\Windows\\System32"
| project Timestamp, DeviceName, ServiceName, ServiceFileName
```

### 5. Pivoting و Correlation شواهد

1. **از Process به Registry/File:** چه Processی Run Key یا Task را ایجاد کرده؟ (Sysmon EID 1 + EID 13)
2. **از Parent Process به Persistence:** آیا Parent Process در Baseline سازمان به‌عنوان Persistence Creator ثبت شده؟
3. **از Persistence به Execution:** آیا Payload اشاره‌شده در Run Key یا Task اجرا شده است؟

### 6. اعتبارسنجی و False Positive

**Baseline:** آیا TaskName یا Registry Value در Baseline سازمان وجود دارد؟
**False Positive:** Software Installers (Adobe، Google Update)، Management Agents (SCCM)، Backup Software.

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1547.001** | Registry Run Keys / Startup Folder | Run Key Created  |
| **T1053.005** | Scheduled Task | Event 4698  |
| **T1543.003** | Windows Service | Event 7045  |
| **T1546.003** | WMI Event Subscription | WMI-Activity EID 5861  |

### 8. نتیجه‌گیری

**Observed:** مکانیزم Persistence در سیستم ایجاد شده است.
**Likely:** این رفتار **مشکوک به Persistence مخرب** است اگر: TaskContent شامل `powershell -enc` یا مسیر `AppData`/`Temp` باشد، Run Key به باینری غیرسیستمی اشاره کند، Service از مسیر غیراستاندارد نصب شده باشد .

### 9. Response

1. **Disable Task / Remove Run Key / Delete Service.**
2. **Forensic Collection:** کپی XML Task، Registry Key، Service Binary.
3. **بررسی Persistenceهای دیگر:** Tarrask (حذف SD)، WMI Subscription.
4. **Detection Improvement:** قانون Sigma برای Task با مسیر `AppData` .

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

برای Hunt Persistence، اول **Scheduled Tasks** رو از **Event ID 4698** چک می‌کنم — اگه TaskContent شامل `powershell -enc`، `mshta`، یا مسیر `AppData`/`Temp` باشه، این Strong Indicator هست .

بعد **Registry Run Keys** رو با Sysmon EID 13 بررسی می‌کنم: اگه Value به باینری در `AppData` یا `Users\Public` اشاره کنه، مشکوکه .

**Service Creation** رو هم از **Event ID 7045** چک می‌کنم — ServiceFileName خارج از `System32` مشکوکه .

**محدودیت اصلی:** Event 4698 نیاز به **Audit Other Object Access Events** داره و به‌صورت پیش‌فرض فعال نیست .

**اقدام بعدی:** اگه تأیید شد، Persistence رو Disable می‌کنم و روی **Tarrask** (حذف SD) و **WMI Subscription** بررسی می‌کنم .
