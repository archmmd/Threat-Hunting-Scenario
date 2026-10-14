### 1. تعریف سناریو و هدف Hunt

یک فایل مشکوک توسط EDR روی یک Endpoint شناسایی شده است. سؤال کلیدی این است: **آیا این فایل فقط دانلود شده، یا واقعاً اجرا شده است؟** و اگر اجرا شده، **چه اثراتی داشته است؟**

**نکته حیاتی:** صرفاً وجود یک فایل مشکوک روی دیسک **به‌تنهایی** نشان‌دهنده Compromise نیست. EDR ممکن است فایل را حین **Download**، **Copy**، یا **Execution** شناسایی کرده باشد. تفکیک این حالت‌ها نیازمند **Correlation چندلایه** است.

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (Execution Confirmed)** | فایل دانلود **و اجرا** شده است | Sysmon EID 1 (Process Creation)، Prefetch File، Amcache Entry، Network Connection از همان Process  | عدم وجود Process Creation، عدم وجود Prefetch |
| **فرضیه جایگزین (Download Only)** | فایل فقط دانلود شده و **هرگز اجرا نشده** | Sysmon EID 11 (File Create) وجود دارد اما **EID 1** ندارد  | وجود Prefetch یا Amcache |
| **فرضیه جایگزین (Quarantined by EDR)** | EDR فایل را قبل از اجرا **قرنطینه** کرده است | EDR Quarantine Log، عدم وجود Process Creation پس از Download  | EDR Action = Blocked/Quarantined  |

### 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Sysmon EID 1** (Essential) | Process Creation | آیا Process با **Hash** فایل مشکوک ایجاد شده؟ `Image`، `CommandLine`، `ParentImage`  |
| **Sysmon EID 11** (Essential) | File Create | **TargetFilename** = مسیر فایل مشکوک. **Image** = Process ایجادکننده فایل (Downloader)  |
| **Sysmon EID 3** (Essential) | Network Connection | آیا Process مشکوک به IP/Domain خارجی متصل شده؟  |
| **Sysmon EID 22** (Essential) | DNS Query | آیا Process مشکوک DNS Query انجام داده؟ `QueryName`، `Image`  |
| **Prefetch** (Supplementary) | Execution Proof | وجود فایل `.pf` با نام فایل مشکوک = **اجرا شده**  |
| **Amcache** (Supplementary) | Execution Proof | رکورد با Hash فایل مشکوک = **اجرا شده** (حتی اگر فایل حذف شود)  |

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: تأیید Execution از Sysmon EID 1**

```kql
// Defender XDR — جستجو بر اساس Hash فایل مشکوک
let SuspiciousHash = "SHA256_HASH_HERE";
DeviceProcessEvents
| where SHA256 == SuspiciousHash
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, 
          ProcessCommandLine, InitiatingProcessFileName, 
          InitiatingProcessCommandLine, SHA256
| order by Timestamp desc
```

**منطق Query:** اگر **نتیجه‌ای برگردد**، فایل **اجرا شده** است. `ProcessCommandLine` نشان می‌دهد **چگونه** اجرا شده و `InitiatingProcessFileName` نشان می‌دهد **چه کسی** آن را اجرا کرده .

**مرحله B: تأیید Download (نه Execution)**

```kql
// Sysmon EID 11 — File Create
DeviceFileEvents
| where ActionType == "FileCreated"
| where FileName has "suspicious_file.exe"  // یا بر اساس Hash
| project Timestamp, DeviceName, FileName, FolderPath, 
          InitiatingProcessFileName, InitiatingProcessCommandLine,
          SHA256
| order by Timestamp desc
```

**منطق Query:** اگر **EID 11 وجود دارد** اما **EID 1 ندارد**، فایل فقط **دانلود** شده و اجرا نشده .

**مرحله C: بررسی Network Activity از Process مشکوک**

```kql
// Sysmon EID 3 — Network Connection
let ProcessGuid = "PROCESS_GUID_FROM_EID_1";
DeviceNetworkEvents
| where InitiatingProcessGuid == ProcessGuid
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp asc
```

**منطق Query:** از `ProcessGuid` در Sysmon EID 1 برای Pivot به EID 3 استفاده کنید. اگر Process مشکوک به C2 متصل شده باشد، این **Network Activity** است .

**مرحله D: بررسی DNS Query**

```kql
// Sysmon EID 22 — DNS Query
DeviceEvents
| where ActionType == "DnsQueryResponse"
| where InitiatingProcessGuid == ProcessGuid
| project Timestamp, DeviceName, QueryName, InitiatingProcessFileName
```

**منطق Query:** Sysmon EID 22 فیلد `Image` را دارد که Process انجام‌دهنده DNS Query را نشان می‌دهد .

### 5. Pivoting و Correlation شواهد

1. **از EDR Alert به Hash:** Hash فایل را از EDR Alert استخراج کنید.
2. **از Hash به Sysmon EID 1:** آیا Process با این Hash ایجاد شده؟ (تأیید Execution)
3. **از Hash به Sysmon EID 11:** آیا فایل با این Hash ایجاد شده؟ (تأیید Download)
4. **از ProcessGuid به EID 3:** آیا Process به Network متصل شده؟ (تأیید C2)
5. **از ProcessGuid به EID 22:** آیا Process DNS Query انجام داده؟
6. **از Hash به Prefetch/Amcache:** تأیید ثانویه Execution .

**هشدار:** همزمانی زمانی به‌تنهایی Causation را اثبات نمی‌کند. برای انتساب Network Connection به Process، باید **ProcessGuid یکسان** تأیید شود.

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline:**
- آیا این Hash در **Baseline سازمان** قبلاً دیده شده؟
- آیا این فایل بخشی از **Software قانونی** است؟ (Signature، Company Name)

**Scope:**
- آیا این Hash روی **Endpointهای دیگر** دیده می‌شود؟
- آیا **Process Ancestry** مشابه روی Hostهای دیگر وجود دارد؟

**False Positive:**
- **EDR Quarantine:** اگر EDR فایل را قبل از اجرا **Block** کرده باشد، Execution رخ نداده .
- **Signed Binary:** اگر فایل با Certificate معتبر امضا شده باشد، احتمال FP بالاست.
- **Software Update:** برخی Updaterها فایل‌های موقت ایجاد می‌کنند که ممکن است به‌عنوان مشکوک شناسایی شوند.

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1204.002** | User Execution: Malicious File | اگر Execution تأیید شود |
| **T1105** | Ingress Tool Transfer | اگر Download از طریق Network تأیید شود |
| **T1071** | Application Layer Protocol | اگر Process به C2 متصل شده باشد |
| **T1547** (احتمالی) | Boot or Logon Autostart Execution | اگر Persistence ایجاد شده باشد |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** یک فایل مشکوک روی Endpoint شناسایی شده است.

**Likely (Execution Confirmed):** اگر **Sysmon EID 1** با Hash فایل مشکوک وجود داشته باشد.

**Likely (Download Only):** اگر **Sysmon EID 11** وجود داشته باشد اما **EID 1** نداشته باشد.

**Confidence: Medium-High** — برای **High** نیاز به تأیید **Prefetch/Amcache** و **Network Activity** داریم.

### 9. Response و بهبود Detection

**اقدامات فوری:**
1. **Isolate Endpoint** اگر Execution تأیید شود.
2. **Kill Process** و **Memory Dump** برای Forensic.
3. **Block Hash/IP/Domain** در EDR و Proxy.
4. **Investigate Persistence:** Scheduled Tasks، Registry Run Keys، Services .

**Detection Improvement:**
1. **Hash-based Alerting:** Alert روی **Sysmon EID 1** با Hash مشکوک.
2. **Correlation Rule:** Alert روی **EID 11 (Download) + EID 1 (Execution)** در بازه کوتاه.
3. **Network Pivot:** Alert روی **EID 3** از Process مشکوک به IP خارجی.

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

اول **Hash فایل** رو از EDR Alert استخراج می‌کنم و در **Sysmon EID 1** جستجو می‌کنم. اگه **Process Creation با اون Hash** پیدا بشه، Execution تأیید می‌شه .

اگه EID 1 نبود، **Sysmon EID 11** رو چک می‌کنم: اگه فایل **ایجاد شده** اما **Process Creation نداره**، فقط **دانلود** شده .

بعد از **ProcessGuid** برای Pivot به **Sysmon EID 3** استفاده می‌کنم: اگه Process به **IP خارجی** متصل شده باشه، این **C2 Communication** هست .

**محدودیت اصلی:** اگه **Sysmon نصب نباشه** یا **Event 3 غیرفعال** باشه، نمی‌تونم Network Activity رو تأیید کنم. همچنین اگه فایل **Quarantine** شده باشه، ممکنه Execution اصلاً رخ نداده باشه .

**اقدام بعدی:** اگه Execution تأیید شد، Endpoint رو Isolate می‌کنم و روی **Persistence** (Scheduled Tasks، Run Keys، Services) بررسی می‌کنم .
