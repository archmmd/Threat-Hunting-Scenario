### 1. تعریف سناریو و هدف Hunt

یک Rule مربوط به PowerShell روزانه **صدها Alert** تولید می‌کند، اما بیشتر آن‌ها **فعالیت مجاز** (SCCM Deployment، Agent داخلی، Admin Script) هستند. هدف، **افزایش Precision** بدون **کاهش Recall** (از دست دادن Detection واقعی) است.

**نکته حیاتی:** Rule فعلی احتمالاً یک **Substring Match Bug** دارد (مثل `-enc` که `-encoding` را هم Match می‌کند) یا **Context کافی** برای فیلتر کردن False Positive ندارد. Tuning درست یعنی **افزودن Context** نه **ضعیف کردن شرط اصلی** .

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده |
|---|---|---|
| **فرضیه اصلی (Rule Over-Broad)** | Rule فقط بر اساس `Image endswith powershell.exe` و `CommandLine contains -enc` است و **Context کافی** ندارد | تمام Processهای PowerShell با `-enc` Alert می‌دهند، حتی از `C:\Windows\CCM\` یا با Parent قانونی |
| **فرضیه جایگزین (Bug منطقی)** | `-enc` با `-encoding` Match می‌شود (Substring Bug) | `powershell.exe -encoding UTF8` هم Alert می‌دهد، در حالی که Encoded Command نیست  |
| **فرضیه جایگزین (Baseline ناقص)** | سازمان **Baseline** از PowerShell قانونی (SCCM، Monitoring Agent) ندارد | نمی‌توان «نرمال» را از «مشکوک» تفکیک کرد  |

### 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Sysmon EID 1** (Essential) | Process Creation | `CommandLine`، `ParentImage`، `ParentCommandLine`، `Image`، `User` |
| **PowerShell 4104** (Essential) | Script Block | `ScriptBlockText` (Deobfuscated) — برای دیدن Payload **پس از Decode**  |
| **Alert History** (Essential) | FP Analysis | کدام Alertها به‌عنوان False Positive بسته شده‌اند؟ توسط چه Analystی؟  |

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: شناسایی Bug منطقی (Substring Match)**

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine contains "-encoding"
| where ProcessCommandLine !contains "-encodedcommand"
| project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessFileName
```

**منطق Query:** اگر این Query نتایج برگرداند، Rule فعلی **Bug** دارد: `-encoding` (تنظیم Encoding خروجی) با `-enc` (Encoded Command) اشتباه گرفته می‌شود .

**مرحله B: استخراج Context برای Tuning**

```kql
DeviceProcessEvents
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-enc", "-EncodedCommand")
| summarize AlertCount = count() by 
    InitiatingProcessFileName, 
    InitiatingProcessFolderPath,
    AccountName,
    bin(Timestamp, 1d)
| order by AlertCount desc
```

**منطق Query:** این Query نشان می‌دهد **کدام Processها** بیشترین Alert را تولید می‌کنند. اگر `CcmExec.exe` (SCCM) یا `AcmeAgent.exe` در صدر باشند، این‌ها **کاندیدای فیلتر** هستند .

**مرحله C: Rule Tuning شده (مثال Sigma)**

```yaml
title: Suspicious PowerShell Encoded Command
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: 
      - '\powershell.exe'
      - '\pwsh.exe'  # PowerShell 7 را پوشش می‌دهد 
    CommandLine|contains: '-EncodedCommand'  # به جای '-enc'، دقیق‌تر
  filter_sccm:
    ParentImage|startswith: 'C:\Windows\CCM\'
  filter_agent:
    ParentImage|endswith: '\AcmeAgent.exe'
  condition: selection and not filter_sccm and not filter_agent
level: high
```

**منطق Rule:**
- `-EncodedCommand` به جای `-enc` = رفع Bug منطقی 
- `pwsh.exe` = پوشش PowerShell 7 
- `filter_sccm` و `filter_agent` = فیلتر بر اساس **Parent Process شناخته‌شده** 

### 5. Pivoting و Correlation شواهد

1. **از Alert به Parent Process:** اگر Parent یک Agent شناخته‌شده باشد (SCCM، Monitoring)، آن را به‌عنوان **Filter** ثبت کنید، نه **Suppression کلی** .
2. **از CommandLine به ScriptBlock (4104):** اگر Platform قابلیت Decode دارد، `ScriptBlockText` را بررسی کنید که آیا `IEX` یا `DownloadString` دارد .
3. **از User به Service Account:** اگر Alert از یک Service Account باشد که **قبلاً** این رفتار را داشته، آن را Classify کنید .

**هشدار:** فیلتر کردن بر اساس **Path** یا **Parent Process** یک **Trade-off** است. مهاجم می‌تواند فایل خود را در `C:\Windows\CCM\` قرار دهد و از فیلتر عبور کند . بنابراین فیلترها باید **باریک** و **مستند** باشند .

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline:**
- آیا این Parent Process **قبلاً** در Baseline سازمان ثبت شده؟
- آیا این Service Account **مستند** است؟

**Scope:**
- پس از Tuning، Rule را روی **Historical Data (14 روز)** اجرا کنید .
- **Precision جدید** را محاسبه کنید: `TP / (TP + FP)` .
- **Recall** را تأیید کنید: آیا **همه TPهای قبلی** هنوز Alert می‌دهند؟ .

**معیار قطعی:** Precision بالای **80%** بدون کاهش Recall .

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1059.001** | PowerShell | Encoded Command برای Obfuscation  |
| **T1027** | Obfuscated Files or Information | Base64 Encoding |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** Rule روزانه صدها Alert تولید می‌کند که بیشتر آن‌ها FP هستند.

**Likely:** Root Cause شامل **Substring Bug** (`-enc` → `-encoding`) و **عدم Context** (Parent Process) است.

**Confidence: High** — با Tuning بر اساس **Parent Process** و **دقیق‌سازی Match**، Precision به بالای 80% می‌رسد.

### 9. Response و بهبود Detection

**اقدامات فوری:**
1. **رفع Bug منطقی:** `-enc` → `-EncodedCommand` .
2. **افزودن Filter:** `ParentImage` برای SCCM و Agentهای شناخته‌شده .
3. **افزودن `pwsh.exe`:** پوشش PowerShell 7 .

**Detection Improvement:**
1. **Pivot به ScriptBlock (4104):** به جای Alert روی **CommandLine خام**، روی **ScriptBlockText پس از Decode** Alert بدهید .
2. **Shadow Mode:** Rule جدید را **14 روز** در حالت Shadow اجرا کنید و Precision را اندازه بگیرید .
3. **Automation Rule:** در Sentinel، از **Automation Rule** برای **موقتاً** Suppress کردن Entityهای شناخته‌شده استفاده کنید (نه حذف دائمی) .

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

اول **Root Cause** رو پیدا می‌کنم: آیا Rule یک **Substring Bug** داره؟ مثلاً `-enc` با `-encoding` Match می‌شه؟ اگه بله، این یک **Bug منطقی** هست و باید به `-EncodedCommand` تغییر کنه .

بعد **Alert History** رو تحلیل می‌کنم: کدوم Processها بیشترین FP رو تولید می‌کنن؟ اگه `CcmExec.exe` (SCCM) یا یک Agent شناخته‌شده باشه، بر اساس **ParentImage** فیلتر می‌کنم .

**محدودیت اصلی:** فیلتر کردن بر اساس **Parent Process** یک **Trade-off** است — مهاجم می‌تونه فایلش رو در `C:\Windows\CCM\` بذاره و از فیلتر عبور کنه . بنابراین فیلتر باید **باریک** باشه و **مستند** .

**اقدام بعدی:** Rule رو روی **14 روز Historical Data** تست می‌کنم، **Precision** رو اندازه می‌گیرم، و مطمئن می‌شم **Recall** کاهش پیدا نکرده .
