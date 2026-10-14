### 1. تعریف سناریو و هدف Hunt

چندین سیستم آلوده شناسایی شده و زمان **شناسایی (Detection)** آن‌ها متفاوت است. هدف، یافتن **قدیمی‌ترین شواهد قابل‌اعتماد از Compromise** (Patient Zero واقعی) و اجتناب از اشتباه گرفتن **اولین Detection** با **اولین Compromise** است.

**نکته حیاتی:** در بسیاری از حملات، EDR یا AV **اولین Detection** را روی سیستمی ثبت می‌کند که **لزوماً Patient Zero نیست** . مهاجم ممکن است هفته‌ها یا ماه‌ها قبل از Detection، در سیستم حضور داشته باشد. برای یافتن Patient Zero واقعی، باید از **Artifactهای Forensic** استفاده کنیم که مستقل از Detection Time هستند و تاریخ **اجرای واقعی** یا **ورود واقعی** را ثبت می‌کنند.

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده |
|---|---|---|
| **فرضیه اصلی (Patient Zero ≠ First Detection)** | قدیمی‌ترین Compromise روی سیستمی رخ داده که **اولین Alert را تولید نکرده** است | Artifactهای Forensic (Prefetch، Amcache، MFT) تاریخ قدیمی‌تری از First Detection نشان می‌دهند |
| **فرضیه جایگزین (First Detection = Patient Zero)** | سیستمی که اول Detection شده، واقعاً Patient Zero است | تمام Artifactها تأیید می‌کنند که Compromise روی همین سیستم اول رخ داده |

### 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **$MFT** (Essential) | File System Timeline | `$SI` (Standard Information) و `$FN` (File Name) timestamps — زمان ایجاد فایل مهاجم  |
| **USN Journal** (Essential) | File Change Log | `$UsnJrnl` — تاریخ ایجاد، تغییر، حذف فایل‌های مهاجم (حتی پس از حذف)  |
| **Prefetch** (Essential) | Execution Proof | فایل `.pf` — تاریخ **اولین و آخرین اجرا** + Run Count  |
| **Amcache.hve** (Essential) | Execution Proof | تاریخ **اولین اجرا** + SHA1 Hash — حتی اگر فایل حذف شده باشد  |
| **ShimCache** (Supplementary) | Execution Indicator | `AppCompatCache` — آخرین Modified Time فایل‌های اجراشده  |
| **EDR/SIEM Alerts** (Supplementary) | Detection Timeline | Alert Time — **فقط برای Cross-Reference**، نه به‌عنوان First Compromise  |

**محدودیت:** Prefetch و Amcache **فقط روی Windows** کار می‌کنند. اگر Retention Logs کوتاه باشد (مثلاً 30 روز)، ممکن است نتوانیم به شواهد قدیمی‌تر دسترسی داشته باشیم.

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: استخراج Execution Timeline از Prefetch**

```powershell
# Parse Prefetch with PECmd
PECmd.exe -d "C:\Windows\Prefetch" --csv "C:\output" --csvf prefetch_timeline.csv

# Filter for suspicious executables
Import-Csv "C:\output\prefetch_timeline.csv" | 
Where-Object { $_.ExecutableName -match "mimikatz|psexec|rundll32|powershell" } |
Select-Object SourceFilename, ExecutableName, RunCount, LastRun, PreviousRun0 |
Sort-Object LastRun -Descending
```

**منطق Query:** Prefetch تاریخ **اولین و آخرین اجرا** را ثبت می‌کند. اگر فایل مهاجم روی یک سیستم **زودتر** اجرا شده باشد، آن سیستم **Patient Zero** است .

**مرحله B: استخراج First Execution از Amcache**

```powershell
# Parse Amcache with AmcacheParser
AmcacheParser.exe -f "C:\Windows\AppCompat\Programs\Amcache.hve" --csv "C:\output"

# Filter for suspicious hash or filename
Import-Csv "C:\output\Amcache_UnassociatedFileEntries.csv" | 
Where-Object { $_.Name -match "malware|payload|svchost" -or $_.SHA1 -eq "SUSPICIOUS_HASH" } |
Select-Object Name, Path, SHA1, LinkDate, FileKeyLastWriteTimestamp |
Sort-Object FileKeyLastWriteTimestamp
```

**منطق Query:** Amcache تاریخ **First Execution** را ثبت می‌کند — حتی اگر فایل حذف شده باشد. این **قطعی‌ترین شاهد** برای Execution است .

**مرحله C: File System Timeline از $MFT و USN Journal**

```powershell
# Parse $MFT with MFTECmd
MFTECmd.exe -f "C:\$MFT" --csv "C:\output" --csvf mft_timeline.csv

# Filter for suspicious paths
Import-Csv "C:\output\mft_timeline.csv" | 
Where-Object { $_.ParentPath -match "Temp|Public|AppData" -and $_.FileName -match "\.exe|\.dll" } |
Select-Object FileName, ParentPath, Created0x10, Created0x30, Modified0x10 |
Sort-Object Created0x10
```

**منطق Query:** `$SI` (Created0x10) و `$FN` (Created0x30) باید با هم مقایسه شوند. اگر `Created0x10 < Created0x30` باشد، **Timestomping** رخ داده .

**مرحله D: Cross-Reference با EDR Detection Timeline**

```kql
// Defender XDR — Alert Timeline
SecurityAlert
| where TimeGenerated > ago(90d)
| where AlertName has "malware" or AlertName has "ransomware"
| project TimeGenerated, CompromisedEntity, AlertName, AlertSeverity
| order by TimeGenerated asc
```

**منطق Query:** این Query **Detection Timeline** را نشان می‌دهد، نه **Compromise Timeline**. باید با Artifactهای Forensic مقایسه شود تا مشخص شود آیا Detection روی Patient Zero رخ داده یا سیستم دیگری .

### 5. Pivoting و Correlation شواهد

1. **از EDR Alert به Artifactهای Forensic:** روی سیستمی که Alert شده، Prefetch و Amcache را بررسی کنید. آیا **تاریخ اجرای فایل مهاجم** قدیمی‌تر از Alert Time است؟
2. **از Alert به Lateral Movement:** اگر Alert روی یک **Member Server** رخ داده، بررسی کنید که آیا **DC** یا **File Server** زودتر Compromise شده .
3. **از DNS Query به Patient Zero:** اگر IOC شامل **DNS Query به C2 Domain** باشد، اولین Hostی که این Query را انجام داده، **Patient Zero** است .
4. **از SMB Connection به Patient Zero:** اولین Hostی که به **Hostهای دیگر** SMB Connection برقرار کرده، احتمالاً Patient Zero است.

**هشدار:** **First Detection** ممکن است روی سیستمی رخ دهد که **مهاجم آن را قربانی کرده** تا Detection واقعی را پنهان کند. این یک **Decoy Strategy** است.

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline:**
- آیا فایل مشکوک **قبلاً** روی سیستم‌های دیگر اجرا شده؟ (Historical Prefetch)
- آیا **Software قانونی** با همین نام وجود دارد؟

**Scope:**
- روی **همه Endpointها** Prefetch و Amcache را Parse کنید.
- **قدیمی‌ترین Execution Time** را پیدا کنید.

**False Positive:**
- **Software Update:** ممکن است فایل‌های موقت با نام مشابه ایجاد کند.
- **Backup Software:** ممکن است فایل‌های سیستمی را کپی کند.
- **EDR Quarantine:** اگر EDR فایل را **قبل از اجرا** Block کرده باشد، Amcache ثبت نمی‌شود.

**معیار قطعی:** اگر **Amcache First Execution** روی یک سیستم **قدیمی‌تر** از First Detection روی سیستم دیگر باشد، آن سیستم **Patient Zero** است.

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1070.006** | Indicator Removal: Timestomping | اگر `$SI` و `$FN` timestamps مغایر باشند  |
| **T1204.002** | User Execution: Malicious File | اگر Amcache Execution ثبت شده باشد |
| **T1059.001** | PowerShell | اگر Prefetch نشان دهد PowerShell زودتر اجرا شده |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** چندین سیستم آلوده با زمان Detection متفاوت.

**Likely (Patient Zero ≠ First Detection):** اگر **Artifactهای Forensic** (Amcache، Prefetch) تاریخ **قدیمی‌تری** از First Detection نشان دهند.

**Confidence: Medium-High** — برای **High** نیاز به **تأیید چند Artifact** (Amcache + Prefetch + MFT) داریم.

### 9. Response و بهبود Detection

**اقدامات فوری:**
1. **Isolate Patient Zero** قبل از هر چیز — این سیستم **منبع گسترش** است .
2. **Investigate Patient Zero:** چه Credentialهایی استفاده شده؟ چه Persistence ایجاد شده؟
3. **Trace Lateral Movement:** از Patient Zero به Hostهای دیگر.

**Detection Improvement:**
1. **Forensic Artifact Collection:** اطمینان از فعال بودن Prefetch، Amcache، و USN Journal.
2. **DNS-Based Patient Zero:** قانون برای **اولین DNS Query به C2 Domain** .
3. **Cross-Host Timeline:** ساخت **Unified Timeline** از همه Hostها با Artifactهای Forensic.

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

اول **EDR Alert Timeline** رو استخراج می‌کنم، اما **به‌عنوان First Compromise بهش نگاه نمی‌کنم** — این فقط **Detection Time** هست .

بعد **Artifactهای Forensic** رو بررسی می‌کنم: از **Amcache** تاریخ **First Execution** فایل مهاجم رو استخراج می‌کنم، از **Prefetch** تاریخ **اولین اجرا** رو می‌گیرم، و از **$MFT** زمان **ایجاد فایل** رو چک می‌کنم .

**معیار قطعی:** سیستمی که **قدیمی‌ترین Execution Time** رو داشته باشه، **Patient Zero** واقعی هست — نه سیستمی که اول Alert داده .

**محدودیت اصلی:** اگه **Prefetch** یا **Amcache** غیرفعال باشه، نمی‌تونم Execution Time رو تأیید کنم. همچنین اگه مهاجم **Timestomping** کرده باشه، باید `$SI` و `$FN` رو مقایسه کنم .

**اقدام بعدی:** Patient Zero رو **اول** Isolate می‌کنم، چون منبع گسترش هست، بعد از اون Hostهای دیگه رو بررسی می‌کنم .
