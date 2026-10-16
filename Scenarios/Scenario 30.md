### 1. تعریف سناریو و هدف Hunt

یک **Threat Intelligence Report** اعلام کرده که یک **Threat Actor** از چند **Technique مشخص** (مثلاً T1059.001، T1053.005، T1021.002، T1003.001) استفاده می‌کند، اما **IOC قابل‌استفاده‌ای** (IP، Hash، Domain) در دسترس نیست. هدف Hunt، تبدیل **Techniqueهای انتزاعی** به **Hypothesis عملی**، **Data Requirement مشخص**، **Query قابل اجرا** و **Detection پایدار** است.

**نکته حیاتی:** Hunt مبتنی بر ATT&CK **IOC-Independent** است. به‌جای جستجو برای «چه چیزی»، به‌دنبال «**چگونه**» می‌گردیم. این رویکرد **Resilient** است، زیرا Techniqueها برخلاف IOCها **به‌سختی تغییر می‌کنند** .

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (Threat Actor Active)** | Threat Actor با Techniqueهای گزارش‌شده در سازمان فعال است | تطابق رفتار مشاهده‌شده با Techniqueها، Timeline مشکوک، Accountهای غیرعادی  | عدم تطابق با Baseline، Processهای قانونی |
| **فرضیه جایگزین (Legitimate Activity Mimics Technique)** | فعالیت قانونی سازمان **تصادفاً** شبیه به Techniqueهاست | Process Ancestry قانونی، Source IP از Management Network، Timing در ساعات کاری | Process Ancestry مشکوک، Source IP خارجی |
| **فرضیه جایگزین (False Positive Report)** | Report Threat Intel **دقت کافی** ندارد یا برای سازمان **مرتبط نیست** | Techniqueها در Baseline سازمان **قبلاً** دیده شده‌اند | Techniqueها با **Vertical** سازمان تطابق دارند |

### 3. Telemetry و Data Sources (بر اساس Technique)

| Technique | Data Source ضروری | چه چیزی را بررسی کنیم |
|---|---|---|
| **T1059.001 (PowerShell)** | PowerShell Operational Log (4103/4104)، Sysmon EID 1 | `ScriptBlockText`، `CommandLine`، `-enc`، `IEX`، `DownloadString`  |
| **T1053.005 (Scheduled Task)** | Security EID 4698، TaskScheduler Operational (106/200) | `TaskContent`، `Action`، `Principal`، `Trigger`  |
| **T1021.002 (SMB/Admin Shares)** | Security EID 5140/5145، Sysmon EID 3 | `ShareName` (ADMIN$، C$)، `SourceAddress`  |
| **T1003.001 (LSASS Memory)** | Sysmon EID 10، EDR Process Access | `TargetImage=lsass.exe`، `GrantedAccess`  |
| **T1071.001 (Web C2)** | Sysmon EID 3/22، Proxy Logs | `DestinationHostname`، `User-Agent`، `URI`  |

**محدودیت:** برای **هر Technique**، باید **Data Source مربوطه** فعال باشد. اگر PowerShell Script Block Logging (4104) فعال نباشد، T1059.001 **قابل Hunt نیست** .

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: تبدیل Technique به Hypothesis**

برای هر Technique، **سه سؤال** بپرسید:
1. **چه رفتاری** در Telemetry منعکس می‌شود؟
2. **چه Process/Account/Network Pattern** باید ببینم؟
3. **چه چیزی** این رفتار را از Baseline **متمایز** می‌کند؟

**مثال برای T1053.005:**
- **Hypothesis:** مهاجم یک Scheduled Task با دسترسی SYSTEM ایجاد کرده که یک Script را در فواصل زمانی اجرا می‌کند.
- **Behavior:** `schtasks.exe /create` یا `Register-ScheduledTask`، فایل XML در `C:\Windows\System32\Tasks\`.
- **Distinguisher:** TaskName شبیه Microsoft، Action شامل `powershell -enc`، Trigger غیرعادی.

**مرحله B: Query برای هر Technique**

**T1059.001 — PowerShell Suspicious:**

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "-enc", "-EncodedCommand", "IEX", "Invoke-Expression",
    "DownloadString", "DownloadFile", "FromBase64String",
    "Bypass", "Hidden", "Nop", "WindowStyle"
)
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, 
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**T1053.005 — Scheduled Task:**

```kql
SecurityEvent
| where EventID == 4698
| extend TaskContent = tostring(EventData.TaskContent)
| where TaskContent has_any ("powershell", "-enc", "cmd", "mshta", "rundll32")
| project TimeGenerated, Computer, TaskName, TaskContent
```

**T1003.001 — LSASS Access:**

```kql
DeviceEvents
| where ActionType == "ProcessAccess"
| where TargetProcessFileName =~ "lsass.exe"
| where GrantedAccess in ("0x1FFFFF", "0x1410", "0x1010")
| where InitiatingProcessFileName !in~ ("MsMpEng.exe", "svchost.exe", "csrss.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, 
          InitiatingProcessCommandLine, GrantedAccess
```

**مرحله C: ساخت Detection پایدار**

پس از Hunt، **الگوهای تأییدشده** را به **Detection Rule** تبدیل کنید:
- **Sigma Rule** برای هر Technique.
- **KQL Analytics Rule** در Sentinel.
- **Threshold** بر اساس Baseline سازمان.

### 5. Pivoting و Correlation شواهد

1. **از Technique به Technique:** اگر T1059.001 (PowerShell) تأیید شد، بررسی کنید آیا T1053.005 (Scheduled Task) نیز رخ داده (Persistence).
2. **از Process به Network:** اگر Process مشکوک به C2 متصل شده، Destination را بررسی کنید.
3. **از Account به Account:** اگر یک Account Compromised شده، Loginهای بعدی با همان Account را بررسی کنید.
4. **از Host به Host:** اگر یک Host آلوده شده، Lateral Movement به Hostهای دیگر را بررسی کنید.

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline:**
- آیا Technique در **Baseline سازمان** قبلاً دیده شده؟
- آیا **Process Ancestry** قانونی است؟
- آیا **Source IP** از Management Network است؟

**Scope:**
- روی **همه Hostها** Query بزنید: آیا همان Technique در Hostهای دیگر دیده می‌شود؟
- آیا **Accountهای دیگر** نیز رفتار مشابهی دارند؟

**False Positive:**
- **PowerShell:** Admin Scriptها، SCCM Deployment، DSC 
- **Scheduled Task:** Windows Update، Adobe Updater، Backup Software 
- **LSASS Access:** EDR، Antivirus، Task Manager، Process Explorer 

**معیار قطعی:** تطابق **Process Ancestry + Command Line + Timing + Source Context** = **High Confidence**.

### 7. MITRE ATT&CK Mapping (خود Techniqueها)

| Technique ID | Name | Data Source | Query Focus |
|---|---|---|---|
| **T1059.001** | PowerShell | PowerShell 4103/4104 | `ScriptBlockText`، `-enc`  |
| **T1053.005** | Scheduled Task | Security 4698 | `TaskContent`  |
| **T1021.002** | SMB/Admin Shares | Security 5140/5145 | `ShareName`  |
| **T1003.001** | LSASS Memory | Sysmon EID 10 | `GrantedAccess`  |
| **T1071.001** | Web C2 | Sysmon EID 3/22 | `DestinationHostname`  |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** Threat Intel Report چند Technique مشخص را گزارش کرده است.

**Likely:** Threat Actor در سازمان فعال است اگر:
1. **چندین Technique** به‌صورت **همزمان** یا **زنجیره‌ای** مشاهده شوند.
2. **Process Ancestry** و **Command Line** مطابق الگوهای گزارش‌شده باشند.
3. **Source Context** (IP، Account) در Baseline سازمان نباشد.

**Confidence: Medium** — برای **High** نیاز به **تأیید چند Technique** و **Correlation بین آن‌ها** داریم.

### 9. Response و بهبود Detection

**فوری:**
1. **Isolation** Hostهای درگیر.
2. **Account Containment** برای Accountهای Compromised.
3. **Forensic Collection** از Hostهای درگیر.

**Detection Improvement:**
1. **Sigma Rules** برای هر Technique.
2. **KQL Analytics Rules** در Sentinel.
3. **Baseline Tuning** برای کاهش False Positive.
4. **Data Source Activation:** اطمینان از فعال بودن PowerShell 4104، Sysmon EID 10، و Security 4698 .

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

اول **Techniqueها** رو به **Hypothesis** تبدیل می‌کنم: برای هر Technique، می‌پرسم «چه رفتاری در Telemetry منعکس می‌شه؟» و «چه چیزی این رفتار رو از Baseline متمایز می‌کنه؟»

بعد **Data Requirement** رو مشخص می‌کنم: برای **T1059.001** به **PowerShell 4104** نیاز دارم، برای **T1053.005** به **Security 4698**، برای **T1003.001** به **Sysmon EID 10** .

در قدم بعدی، **Query** می‌سازم: برای PowerShell، دنبال `-enc` و `IEX` می‌گردم. برای Scheduled Task، دنبال `TaskContent` مشکوک. برای LSASS، دنبال `GrantedAccess` غیرعادی .

**محدودیت اصلی:** اگه **Data Source** فعال نباشه (مثل PowerShell 4104)، نمی‌تونم اون Technique رو Hunt کنم .

**اقدام بعدی:** اگه چند Technique به‌صورت **زنجیره‌ای** تأیید شد، Hostها رو Isolate می‌کنم و **Sigma Rule** برای هر Technique می‌سازم .
