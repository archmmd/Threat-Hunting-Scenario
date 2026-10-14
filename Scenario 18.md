## 1. تعریف سناریو و هدف Hunt

یک Account تعداد زیادی **Event ID 4625** (Failed Logon) و سپس یک **Event ID 4624** (Successful Logon) دارد. هدف Hunt، تعیین اینکه آیا این یک **Brute Force موفق** (T1110) بوده است، شناسایی **Source** حمله، و بررسی اینکه آیا **Accountهای دیگر** نیز تحت تأثیر قرار گرفته‌اند.

**نکته حیاتی:** صرفاً وجود 4625های متعدد و سپس یک 4624 **به‌تنهایی Brute Force موفق را اثبات نمی‌کند**. ممکن است کاربر رمز خود را اشتباه وارد کرده و در نهایت صحیح وارد شده باشد. تمایز اصلی در **Volume**، **Time Window**، **Source IP** و **Logon Type** است .

## 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (Brute Force موفق)** | مهاجم از یک Source مشخص، تعداد زیادی رمز را روی یک Account تست کرده و در نهایت موفق شده است | 4625های متعدد (بالای Threshold) از **یک IP**، سپس 4624 از **همان IP**، Logon Type 3 یا 10، SubStatus `0xC000006A` (Wrong Password)  | 4624 از IP متفاوت، Volume پایین، SubStatus مربوط به Account Locked یا Disabled |
| **فرضیه جایگزین (User Error)** | کاربر رمز خود را چند بار اشتباه وارد کرده و سپس صحیح وارد شده است | تعداد کم 4625 (مثلاً 3-5)، بازه زمانی کوتاه، 4624 از **همان Workstation** با Logon Type 2  | Volume بالا، Source IP خارجی، Logon Type 10 |
| **فرضیه جایگزین (Password Spray)** | مهاجم از یک رمز مشترک روی **چندین Account** استفاده کرده (نه یک Account) | 4625 از **یک IP** روی **چندین TargetUserName** مختلف، SubStatus متفاوت  | تمرکز روی یک Account، SubStatus یکسان |

## 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Windows Security Event ID 4625** (Essential) | Failed Logon | `TargetUserName`, `IpAddress`, `LogonType`, `SubStatus`, `WorkstationName`, `ProcessName`  |
| **Windows Security Event ID 4624** (Essential) | Successful Logon | `TargetUserName`, `IpAddress`, `LogonType`, `LogonProcessName`, `AuthenticationPackageName`  |
| **Windows Security Event ID 4776** (Supplementary) | Credential Validation | روی Domain Controller — تأیید اعتبار در سطح Domain  |
| **Windows Security Event ID 4740** (Supplementary) | Account Lockout | آیا Account قفل شده است؟  |
| **EDR / SIEM** (Essential) | Correlation | برای Pivot از IP به Processهای ایجادشده پس از Login |

**محدودیت مهم:** Event ID 4625 **به‌صورت پیش‌فرض Audited نیست** و باید از طریق Group Policy (Audit Logon — Failure) فعال شود . اگر Audit Policy فعال نباشد، **هیچ 4625 ثبت نمی‌شود** و ما فقط 4624 را می‌بینیم.

## 4. مراحل اجرایی Hunt و Queryهای عملی

### مرحله A: استخراج و گروه‌بندی 4625ها

**KQL (Sentinel / Defender XDR):**

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| where Account !endswith "$"  // Exclude computer accounts
| summarize 
    FailedCount = count(),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated),
    DistinctUsers = dcount(Account),
    SubStatuses = make_set(EventData.SubStatus)
    by IpAddress, Computer, LogonType
| where FailedCount >= 10  // Adjustable threshold
| order by FailedCount desc
```

**منطق Query:** گروه‌بندی بر اساس `IpAddress` + `Computer` + `LogonType` برای شناسایی Sourceهای پرتکرار. Threshold 10 قابل تنظیم بر اساس Baseline سازمان است .

### مرحله B: Correlate 4625 و 4624 از همان Source

**KQL (Sentinel):**

```kql
let FailedLogons = SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| project FailedTime = TimeGenerated, TargetUser = Account, 
          SourceIP = IpAddress, LogonType, SubStatus = EventData.SubStatus;
let SuccessfulLogons = SecurityEvent
| where EventID == 4624
| where TimeGenerated > ago(24h)
| project SuccessTime = TimeGenerated, TargetUser = Account, 
          SourceIP = IpAddress, LogonType, LogonProcessName;
FailedLogons
| join kind=inner SuccessfulLogons on TargetUser, SourceIP
| where SuccessTime between (FailedTime .. 10m)  // 10-minute correlation window
| project FailedTime, SuccessTime, TargetUser, SourceIP, LogonType, SubStatus
| order by FailedTime desc
```

**منطق Query:** Correlate 4625 و 4624 از **همان Account** و **همان Source IP** در بازه زمانی مشخص (مثلاً 10 دقیقه). این **Strong Indicator** برای Brute Force موفق است .

### مرحله C: بررسی Password Spray (چند Account از یک IP)

**KQL (Sentinel):**

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| summarize 
    FailedCount = count(),
    TargetUsers = make_set(Account),
    DistinctUserCount = dcount(Account)
    by IpAddress
| where FailedCount >= 20 and DistinctUserCount >= 3
| order by FailedCount desc
```

**منطق Query:** اگر یک IP روی **چندین Account** (بیش از 3) تلاش کرده باشد، این **Password Spray** است، نه Brute Force سنتی .

### مرحله D: بررسی Logon Type و SubStatus

**KQL (Sentinel):**

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(24h)
| extend SubStatus = tostring(EventData.SubStatus)
| extend LogonType = tostring(EventData.LogonType)
| summarize count() by SubStatus, LogonType, Account
| order by count_ desc
```

**منطق تفسیر:**
- `0xC000006A` (Wrong Password) → Brute Force یا User Error 
- `0xC0000064` (User Does Not Exist) → User Enumeration / Password Spray 
- `0xC0000234` (Account Locked) → Brute Force تشدیدشده 
- `LogonType 3` (Network) → SMB / Network Logon
- `LogonType 10` (RDP) → Remote Desktop — **رایج‌ترین هدف Brute Force** 

## 5. Pivoting و Correlation شواهد

از `IpAddress` و `TargetUserName` برای Pivot استفاده کنید:

1. **Process Creation پس از 4624:** از Sysmon Event ID 1 یا EDR Process Tree بررسی کنید که **بلافاصله پس از 4624** چه Processهایی ایجاد شده‌اند. آیا `cmd.exe`، `powershell.exe`، یا Process غیرعادی spawn شده؟ 
2. **همان Source IP در Hostهای دیگر:** آیا این IP روی Endpointهای دیگر نیز 4625 تولید کرده است؟ (Lateral Movement)
3. **Accountهای تحت تأثیر:** آیا 4625های همان IP شامل Accountهای دیگر نیز می‌شود؟ (Password Spray)
4. **Network Activity پس از Login:** آیا Processهای ایجادشده پس از 4624 اتصال شبکه‌ای برقرار کرده‌اند؟ (C2 Communication)
5. **WorkstationName:** آیا `WorkstationName` در 4625 و 4624 یکسان است؟ (تأیید اینکه Source یکسان است)

**هشدار:** همزمانی زمانی (Temporal Proximity) به‌تنهایی **Causation** را اثبات نمی‌کند. برای انتساب Brute Force به Login موفق، باید **Source IP یکسان** و **Target Account یکسان** تأیید شود.

## 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline مقایسه:**
- آیا `IpAddress` در Baseline سازمان وجود دارد؟ (Service Account، Scanner، Jump Box)
- آیا Volume 4625 در ساعات کاری رخ داده یا خارج از آن؟
- آیا `LogonType` با Baseline سازمان مطابقت دارد؟ (Logon Type 10 در سازمانی که RDP ندارد = مشکوک)

**Scope Determination:**
- روی **همه Domain Controllers** Query بزنید (نه فقط یک DC) .
- آیا همان IP روی Hostهای دیگر نیز 4625 تولید کرده؟
- آیا Accountهای دیگری نیز از همان IP تحت تأثیر قرار گرفته‌اند؟

**False Positive ممکن:**
- **Service Accounts:** رمز اشتباه در Service Account می‌تواند 4625های متعدد تولید کند.
- **Cache Credentials:** کاربر با Credential قدیمی به‌صورت خودکار Retry می‌کند.
- **Network Scanner:** Vulnerability Scanner ممکن است 4625 تولید کند (Credential Testing).
- **Account Lockout Policy:** اگر Policy خیلی سختگیرانه باشد، 4625های کم نیز منجر به Lockout می‌شوند.

**معیار قطعی:** اگر 4624 **از همان IP** و **در بازه زمانی کوتاه پس از 4625ها** باشد، و `LogonType` 3 یا 10 باشد، احتمال **False Positive پایین** است .

## 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1110.001** | Brute Force: Password Guessing | 4625های متعدد روی **یک Account** از یک Source، سپس 4624  |
| **T1110.003** | Brute Force: Password Spraying | 4625 روی **چندین Account** از یک Source  |
| **T1078** (احتمالی) | Valid Accounts | اگر 4624 با Account معتبر و از IP مشکوک رخ دهد  |
| **T1021.001** (اگر Logon Type 10) | Remote Services: RDP | اگر Brute Force از طریق RDP (Logon Type 10) انجام شده باشد |

**هشدار:** Mapping فقط بر اساس **شواهد مشاهده‌شده** انجام شده. اگر 4624 از IP متفاوت یا Workstation متفاوت باشد، T1110 **اعمال نمی‌شود**.

## 8. نتیجه‌گیری و سطح اطمینان

**وضعیت فعلی: Observed (مشاهده‌شده)**

- **آنچه مسلم است:** تعداد زیادی 4625 و سپس یک 4624 برای یک Account ثبت شده است.
- **آنچه Likely است:** این رفتار **مشکوک به Brute Force موفق** است، به‌ویژه اگر:
  1. 4625ها از **یک Source IP** باشند.
  2. 4624 از **همان Source IP** باشد.
  3. `LogonType` 3 یا 10 باشد.
  4. تعداد 4625ها بالای Threshold سازمان باشد.
- **آنچه هنوز اثبات نشده:** اینکه این Login واقعاً **مخرب** است. برای Confirmation نیاز به:
  1. بررسی Processهای ایجادشده پس از 4624.
  2. بررسی Network Activity پس از Login.
  3. تأیید اینکه Source IP در Baseline سازمان نیست.

**سطح اطمینان اولیه: Medium-High** که این یک **Anomaly امنیتی** است. اگر Source IP خارجی باشد و Logon Type 10، اطمینان به **High** ارتقا می‌یابد.

## 9. Response و بهبود Detection

**اقدامات فوری (اگر Brute Force موفق تأیید شد):**
1. **Account Containment:** Disable Account یا Reset Password فوری.
2. **Session Revocation:** بستن Sessionهای فعال (Kerberos Tickets، RDP Sessions).
3. **IP Blocking:** بلاک کردن Source IP در Firewall / Proxy.
4. **Forensic Investigation:** بررسی Processهای ایجادشده پس از Login، Persistence Mechanisms، Lateral Movement.

**اقدامات بلندمدت (Detection Improvement):**
1. **قانون Detection جدید:** هر 4624 که در بازه 10 دقیقه پس از 5+ 4625 از **همان IP** رخ دهد → Alert.
2. **قانون Password Spray:** هر IP که روی 3+ Account مختلف 4625 تولید کند → Alert.
3. **قانون Logon Type:** هر 4624 با Logon Type 10 از IP خارجی → Alert.
4. **Account Lockout Policy:** تنظیم Threshold مناسب (مثلاً 10 تلاش در 15 دقیقه).
5. **Audit Policy:** اطمینان از فعال بودن **Audit Logon — Success and Failure** .

## 10. پاسخ کوتاه برای شروع جواب در مصاحبه

برای تشخیص Brute Force موفق، اول **4625ها رو از 4624 جدا می‌کنم** و بر اساس **Source IP** گروه‌بندی می‌کنم. اگه یک IP تعداد زیادی 4625 تولید کرده باشه، این **Strong Indicator** برای Brute Force هست.

بعد **4624 رو با 4625 correlate می‌کنم**: اگه 4624 از **همون IP** و برای **همون Account** و در بازه زمانی کوتاه (مثلاً 10 دقیقه) رخ داده باشه، احتمال موفقیت حمله بالاست. **Logon Type** هم مهمه — Type 10 (RDP) رایج‌ترین هدفه.

برای **Password Spray**، بررسی می‌کنم که آیا همون IP روی **چندین Account** تلاش کرده یا فقط یکی. اگه 3+ Account تحت تأثیر باشن، این Password Spray هست نه Brute Force سنتی.

**محدودیت اصلی:** اگه Audit Policy برای Failure فعال نباشه، **هیچ 4625 ثبت نمی‌شه** و ما فقط 4624 رو می‌بینیم. همچنین، اگه Source IP در Baseline سازمان باشه (مثل Scanner یا Jump Box)، ممکنه False Positive باشه.

**اقدام بعدی:** اگه Brute Force موفق تأیید شد، اول Account رو Disable می‌کنم، Sessionها رو Revoke می‌کنم، و بعد Processهای ایجادشده پس از Login رو بررسی می‌کنم.
