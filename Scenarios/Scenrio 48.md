Conflicting Evidence
EDR فعالیتی را Malicious می‌داند، اما تیم IT اعلام می‌کند Process متعلق به ابزار مدیریتی مجاز است.
چه شواهدی برای تأیید یا رد هر دو فرضیه می‌خواهی و چه زمانی Escalate می‌کنی؟


### 1. تعریف سناریو و هدف Hunt

**سناریو:** EDR یک فعالیت را **Malicious** می‌داند، اما تیم IT اعلام می‌کند که Process متعلق به یک **ابزار مدیریتی مجاز** است. این یک **Conflict** بین دو منبع معتبر است و هدف، **جمع‌آوری شواهد عینی** برای تأیید یا رد هر دو فرضیه، و **تعیین زمان Escalation** است.

**نکته حیاتی:** «ابزار مدیریتی مجاز» **به‌تنهایی** دلیل بر بی‌خطر بودن نیست. مهاجمان اغلب از **ابزارهای دوکاربردی (Dual-Use Tools)** مثل PsExec، WMIC، و PowerShell برای حرکت جانبی استفاده می‌کنند که همان ابزارهای IT هستند. بنابراین، تأیید IT **کافی نیست** — باید **Context عملیاتی** (Process Ancestry، Command Line، Destination، User) بررسی شود.

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (False Positive EDR)** | EDR به‌دلیل **Rule بیش‌ازحد حساس** یا **Detonation Behavior**، یک ابزار قانونی را Malicious تشخیص داده | Process Ancestry از Agent شناخته‌شده (`CcmExec.exe`، `IntuneManagementExtension.exe`)، Command Line مطابق Baseline، Hash در Allowlist سازمان  | Command Line غیرعادی، Parent Process مشکوک، Destination ناشناخته |
| **فرضیه جایگزین (True Positive / Malicious Abuse)** | مهاجم از **همان ابزار مدیریتی مجاز** برای حرکت جانبی یا Execution استفاده کرده | Process Ancestry غیرعادی (`cmd.exe` spawning `psexec.exe`)، Command Line شامل `-accepteula` یا `/node:`، Source IP از Workstation غیرمجاز  | Process Ancestry قانونی، Source IP از Management Server |

### 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **EDR Alert Details** (Essential) | Alert Context | `DetectionSource` (EDR vs AV vs ASR)، `AlertName`، `ProcessCommandLine`، `ParentProcess`، `FileHash`  |
| **Sysmon EID 1** (Essential) | Process Creation | `Image`، `CommandLine`، `ParentImage`، `ParentCommandLine`، `User`، `Hashes`  |
| **Sysmon EID 3** (Essential) | Network Connection | `DestinationIp`، `DestinationPort`، `ProcessGuid` — برای بررسی Lateral Movement |
| **Asset Inventory / Allowlist** (Essential) | Tool Context | آیا این ابزار در **Allowlist سازمان** ثبت شده؟ آیا Source IP در **Management VLAN** است؟  |

**محدودیت:** «ابزار مدیریتی مجاز» باید **مستند، دارای Owner، و در Allowlist** ثبت شده باشد. تأیید شفاهی IT **کافی نیست** .

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: شناسایی Detection Source (مهم‌ترین قدم)**

قبل از هر چیز، باید مشخص کنم که **کدام قابلیت** EDR این Alert را تولید کرده است :

| Detection Source | معنی | اقدام |
|---|---|---|
| **EDR** | رفتار مشکوک در سطح Process | بررسی Command Line و Process Ancestry |
| **Microsoft Defender Antivirus** | فایل به‌عنوان Malware شناسایی شده | بررسی Hash و Signature |
| **ASR Rule** | یک قانون Attack Surface Reduction | بررسی اینکه کدام ASR Rule فعال شده |
| **Custom Threat Intelligence** | Indicator سفارشی سازمان | بررسی Allowlist و Indicator Management |

**منطق:** اگر Alert از **ASR Rule** یا **Custom Indicator** باشد، احتمال **False Positive** بالاست (مثلاً ASR Rule برای Block کردن JavaScript از Downloaded Content) .

**مرحله B: بررسی Process Ancestry**

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName has "tool_name.exe"  // نام Process مشکوک
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, 
          InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

**منطق Query:** اگر Parent Process یک **Agent شناخته‌شده** باشد (`CcmExec.exe`، `IntuneManagementExtension.exe`)، احتمال **False Positive** بالاست. اگر Parent Process `cmd.exe`، `powershell.exe`، یا `explorer.exe` باشد، احتمال **Malicious Abuse** بالاست.

**مرحله C: بررسی Command Line در برابر Baseline**

```kql
// مقایسه با Baseline سازمان
DeviceProcessEvents
| where FileName has "tool_name.exe"
| summarize 
    TotalCount = count(),
    DistinctCommandLines = dcount(ProcessCommandLine),
    DistinctParents = dcount(InitiatingProcessFileName)
    by DeviceName
| where TotalCount > 5
```

**منطق Query:** اگر **همان Command Line** و **همان Parent** روی Hostهای متعدد تکرار شده باشد، این **Automated Deployment** است. اگر Command Line **منحصربه‌فرد** و **غیرعادی** باشد، این **Hands-on-Keyboard** است.

**مرحله D: بررسی Network Activity برای Lateral Movement**

```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName has "tool_name.exe"
| where RemoteIPType == "Private"
| where RemotePort in (445, 3389, 135, 5985)
| project Timestamp, DeviceName, RemoteIP, RemotePort, 
          InitiatingProcessCommandLine
| order by Timestamp desc
```

**منطق Query:** اگر ابزار مدیریتی به **Portهای Lateral Movement** روی Hostهای متعدد متصل شده باشد، این **Strong Indicator** برای Malicious Abuse است.

### 5. Pivoting و Correlation شواهد

1. **از EDR Alert به Detection Source:** Alert را در Defender Portal باز کنید و ببینید **کدام قابلیت** آن را تولید کرده .
2. **از Process به Parent Process:** از Sysmon EID 1، `ParentImage` و `ParentCommandLine` را استخراج کنید.
3. **از Hash به Allowlist:** Hash فایل را با **Allowlist سازمان** مقایسه کنید. اگر در Allowlist باشد، **False Positive** است.
4. **از Source IP به Management VLAN:** آیا Source IP در **Management VLAN** یا **Jump Server** است؟

**هشدار:** **Temporal Proximity ≠ Causation**. دیدن Process و Network Connection در یک بازه **کافی نیست** — باید **ProcessGuid یکسان** تأیید شود.

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**معیارهای False Positive (تأیید EDR اشتباه کرده):**
- **Process Ancestry:** Parent Process یک Agent شناخته‌شده است .
- **Hash در Allowlist:** فایل در **Allowlist سازمان** ثبت شده است.
- **Command Line مطابق Baseline:** همان Command Line در **Baseline سازمان** دیده شده.
- **Source IP از Management Network:** اتصال از **Jump Server** یا **Management VLAN** است.

**معیارهای True Positive (تأیید Malicious Abuse):**
- **Process Ancestry غیرعادی:** `cmd.exe` یا `powershell.exe` spawning ابزار مدیریتی.
- **Command Line غیرعادی:** شامل `-accepteula`، `/node:`، یا مسیر `Temp`/`AppData`.
- **Source IP از Workstation غیرمجاز:** نه از Management Network.
- **Lateral Movement:** اتصال به **Portهای SMB/RDP/WinRM** روی Hostهای متعدد.

**اقدامات در صورت False Positive:**
1. **Classify Alert** به‌عنوان **False Positive** در Defender Portal .
2. **Suppress Alert** با یک **Suppression Rule** .
3. **Create Indicator** برای فایل/Process در Defender for Endpoint .
4. **Submit File** به **Microsoft Security Intelligence** برای تحلیل .

**اقدامات در صورت True Positive:**
1. **Isolate Endpoint** فوراً.
2. **Investigate Lateral Movement** روی Hostهای Target.
3. **Revoke Sessions** و **Reset Credentials** در صورت نیاز.

### 7. MITRE ATT&CK Mapping

| رفتار | Technique ID | Name |
|---|---|---|
| استفاده از ابزار مدیریتی مجاز | **T1078** | Valid Accounts |
| حرکت جانبی از طریق SMB | **T1021.002** | Remote Services: SMB/Admin Shares |
| اجرای Process از طریق Management Tool | **T1047** | Windows Management Instrumentation |
| (احتمالی) | **T1218** | System Binary Proxy Execution |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** EDR یک فعالیت را Malicious می‌داند، IT اعلام می‌کند ابزار مجاز است.

**Likely (False Positive):** اگر **Parent Process قانونی**، **Hash در Allowlist**، و **Command Line مطابق Baseline** باشد.

**Likely (True Positive):** اگر **Parent Process غیرعادی**، **Command Line مشکوک**، و **Lateral Movement** مشاهده شود.

**Confidence: Medium** — برای **High** نیاز به **تأیید Detection Source** و **Allowlist** داریم.

### 9. Response و بهبود Detection

**اقدامات فوری (بسته به نتیجه):**

| نتیجه | اقدام |
|---|---|
| **False Positive** | Classify Alert، Suppress Rule، Create Indicator، Submit File to Microsoft  |
| **True Positive** | Isolate Endpoint، Investigate Lateral Movement، Revoke Sessions |

**Detection Improvement:**
1. **Allowlist Integration:** ثبت ابزارهای مجاز در **Defender Allowlist** .
2. **ASR Rule Review:** بررسی اینکه کدام ASR Rule باعث Alert شده .
3. **Detection Source Analysis:** تفکیک Alertهای EDR، AV، ASR، و Custom TI .

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

**اول** باید **Detection Source** رو مشخص کنم: آیا Alert از **EDR**، **Microsoft Defender Antivirus**، **ASR Rule**، یا **Custom Threat Intelligence** اومده؟ این تفکیک، **مهم‌ترین قدم** برای فهمیدن Root Cause هست .

**بعد** **Process Ancestry** رو بررسی می‌کنم: اگه **Parent Process** یک **Agent شناخته‌شده** باشه (مثل `CcmExec.exe`)، احتمال **False Positive** بالاست. اگه `cmd.exe` یا `powershell.exe` باشه، شک من به **Malicious Abuse** می‌ره .

**سوم** **Hash فایل** رو با **Allowlist سازمان** مقایسه می‌کنم و **Command Line** رو با **Baseline** چک می‌کنم.

**زمان Escalate:** اگه **Process Ancestry غیرعادی** باشه، **Command Line شامل مسیر Temp/AppData** باشه، یا **Lateral Movement** به Portهای SMB/RDP دیده بشه، **فوراً Escalate** می‌کنم. اگه **False Positive** تأیید شد، Alert رو **Classify** و **Suppress** می‌کنم و فایل رو به **Microsoft** می‌فرستم .

**محدودیت اصلی:** تأیید شفاهی IT **کافی نیست** — باید **Allowlist مستند** و **Process Ancestry** تأیید شود.
