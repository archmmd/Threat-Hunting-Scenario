## 1. تعریف سناریو و هدف Hunt

یک **Domain Admin** (حساب ممتاز Tier 0) خارج از ساعات کاری روی یک **Workstation معمولی** لاگین کرده است. هدف Hunt، تشخیص **Suspicious Privileged Access** و بررسی احتمال **Credential Theft** یا **Lateral Movement** از طریق حساب ممتاز است.

**نکته حیاتی:** Login یک Domain Admin روی Workstation معمولی **به‌تنهایی جرم نیست**، اما **ریسک امنیتی بالایی** دارد. طبق اصول **Tiered Administration**، حساب‌های Tier 0 (Domain Admins) **نباید** روی Workstationهای Tier 1 یا Tier 2 لاگین کنند، زیرا Credentialهای آن‌ها در حافظه Workstation باقی می‌ماند و در معرض **Mimikatz** یا **DCSync** قرار می‌گیرد .

## 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (Suspicious Privileged Access)** | مهاجم Credential یک Domain Admin را به دست آورده و از آن برای حرکت جانبی یا دسترسی به Workstation استفاده کرده | Login خارج از ساعات کاری، Logon Type 10 (RDP)، Source IP ناشناخته، Processهای مشکوک پس از Login، 4648 (Explicit Credential)  | Login در ساعات کاری، Source IP شناخته‌شده، Processهای قانونی |
| **فرضیه جایگزین (Legitimate Admin Activity)** | یک Domain Admin به‌دلیل Maintenance، Troubleshooting، یا نصب نرم‌افزار روی Workstation لاگین کرده است | Login در ساعات کاری، Ticket قبلی، Source IP از Jump Server، Processهای قانونی (مثل `msiexec.exe`) | عدم وجود مستندات، زمان غیرعادی، رفتار جانبی مشکوک |
| **فرضیه جایگزین (Service Account Misuse)** | یک Service Account با Privileges بالا (مثل Backup Account) به‌صورت خودکار روی Workstation لاگین کرده است | Account Name با `$` تمام می‌شود یا در Baseline به‌عنوان Service Account ثبت شده | Account یک کاربر واقعی است، Logon Type 2 (Interactive) |

## 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Windows Security Event ID 4624** (Essential) | Logon | `TargetUserName`, `LogonType`, `IpAddress`, `WorkstationName`, `ProcessName`, `LogonProcessName`  |
| **Windows Security Event ID 4672** (Essential) | Special Privileges | `SubjectUserName`, `PrivilegeList` — تأیید اعطای Privileges بالا به Session  |
| **Windows Security Event ID 4648** (Supplementary) | Explicit Credentials | `TargetUserName`, `ProcessName`, `IpAddress` — نشان‌دهنده RunAs یا Scheduled Task  |
| **Kerberos Events 4768/4769** (Supplementary) | TGT/TGS Request | روی Domain Controller — `TargetUserName`, `IpAddress`, `ServiceName`  |
| **Sysmon Event ID 1** (Essential) | Process Creation | Processهای ایجادشده پس از Login — `Image`, `CommandLine`, `ParentImage`  |
| **Sysmon Event ID 3** (Supplementary) | Network Connection | اتصالات خروجی از Workstation پس از Login  |

**محدودیت مهم:** Event ID 4672 **به‌صورت پیش‌فرض Audited نیست** و باید از طریق **Audit Sensitive Privilege Use** فعال شود . همچنین، برای RDP (Logon Type 10)، فیلد `WorkstationName` ممکن است **نام Host محلی** را نشان دهد نه Source واقعی .

## 4. مراحل اجرایی Hunt و Queryهای عملی

### مرحله A: استخراج Loginهای Domain Admin روی Workstation

**KQL (Sentinel / Defender XDR):**

```kql
SecurityEvent
| where EventID == 4624
| where LogonType in (2, 10)  // Interactive or RDP
| where Account has_any ("Domain Admins", "DA_", "Admin")
| where Computer !has "DC"  // Exclude Domain Controllers
| project TimeGenerated, Computer, Account, LogonType, IpAddress, WorkstationName, ProcessName
| order by TimeGenerated desc
```

**منطق Query:** فیلتر Loginهای Interactive/RDP از حساب‌های Admin روی Hostهایی که DC نیستند.

### مرحلB: بررسی Special Privileges

**KQL (Sentinel):**

```kql
SecurityEvent
| where EventID == 4672
| where TimeGenerated > ago(24h)
| where Account !has "$"  // Exclude computer accounts
| where Account !in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
| project TimeGenerated, Computer, Account, PrivilegeList
| order by TimeGenerated desc
```

**منطق Query:** Event ID 4672 نشان می‌دهد که Privileges بالا به Session اعطا شده است. اگر حساب یک Domain Admin باشد و روی Workstation معمولی لاگین کرده باشد، این **Strong Indicator** است .

### مرحله C: بررسی Explicit Credentials (4648)

**KQL (Sentinel):**

```kql
SecurityEvent
| where EventID == 4648
| where TimeGenerated > ago(24h)
| where TargetUserName has_any ("Domain Admins", "DA_", "Admin")
| project TimeGenerated, Computer, SubjectUserName, TargetUserName, ProcessName, IpAddress
| order by TimeGenerated desc
```

**منطق Query:** Event 4648 زمانی رخ می‌دهد که یک Process با **Explicit Credentials** لاگین می‌کند (مثل `RUNAS` یا Scheduled Task). اگر Target یک Domain Admin باشد، این **بسیار مشکوک** است .

### مرحله D: بررسی Processهای پس از Login

**KQL (Defender XDR):**

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where DeviceName has "WORKSTATION_NAME"  // Replace with actual hostname
| where InitiatingProcessFileName !in~ ("svchost.exe", "lsass.exe", "services.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, 
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

**منطق Query:** Processهای ایجادشده **پس از Login** Domain Admin را بررسی کنید. اگر Processهایی مثل `cmd.exe`، `powershell.exe`، `net.exe`، `whoami.exe` یا `mimikatz` ایجاد شده باشند، این **Strong Indicator** است.

## 5. Pivoting و Correlation شواهد

از `Account`، `Computer` و `IpAddress` برای Pivot استفاده کنید:

1. **Correlation 4624 و 4672:** از `LogonId` در 4624 برای پیدا کردن Event 4672 متناظر استفاده کنید. اگر همان `SubjectLogonId` در 4672 دیده شود، تأیید می‌شود که Privileges بالا به آن Session اعطا شده است.
2. **Process Tree پس از Login:** از Sysmon Event ID 1 استفاده کنید تا ببینید چه Processهایی **بلافاصله پس از 4624** ایجاد شده‌اند. Parent Process چه بوده؟
3. **Kerberos TGT (4768):** اگر Domain Admin از Workstation لاگین کرده، TGT آن در Domain Controller ثبت شده است. `IpAddress` در 4768 را با `IpAddress` در 4624 مقایسه کنید .
4. **Network Activity:** آیا Workstation پس از Login Domain Admin، اتصال شبکه‌ای به سرورهای حساس (مثل DC یا File Server) برقرار کرده است؟
5. **Accountهای دیگر:** آیا همان Source IP روی Workstationهای دیگر نیز Login کرده است؟

**هشدار:** همزمانی زمانی (Temporal Proximity) به‌تنهایی **Causation** را اثبات نمی‌کند. برای اتصال Events به یک زنجیره حمله، نیاز به **Shared LogonId** یا **Shared Process Tree** داریم.

## 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline مقایسه:**
- آیا این Domain Admin **قبلاً** روی این Workstation لاگین کرده است؟ (Historical Baseline)
- آیا Login در **ساعات کاری** است یا خارج از آن؟
- آیا Source IP در Baseline سازمان وجود دارد؟ (Jump Server، Management VLAN)
- آیا **Ticket** یا **Change Request** برای این Login وجود دارد؟

**Scope Determination:**
- روی **همه Workstationها** Query بزنید: آیا این Domain Admin روی Hostهای دیگر نیز لاگین کرده است؟
- آیا Domain Adminهای دیگر نیز رفتار مشابهی داشته‌اند؟
- آیا Source IP روی Hostهای دیگر نیز دیده شده است؟

**False Positive ممکن:**
- **Maintenance Window:** تیم IT برای نصب نرم‌افزار یا Troubleshooting لاگین کرده است.
- **Backup Account:** اگر Account با `$` تمام شود یا در Baseline به‌عنوان Service Account ثبت شده باشد.
- **Emergency Access:** در شرایط اضطراری، Domain Admin ممکن است مجبور به لاگین مستقیم شود.

**معیار قطعی:** اگر Login **خارج از ساعات کاری** باشد، **Source IP ناشناخته** باشد، و **Processهای مشکوک** پس از Login ایجاد شده باشند، احتمال **False Positive پایین** است.

## 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1078.002** | Valid Accounts: Domain Accounts | استفاده از Domain Admin Account معتبر برای Login روی Workstation  |
| **T1021.001** | Remote Services: RDP | اگر Logon Type 10 باشد، دسترسی از طریق RDP  |
| **T1550** (احتمالی) | Use Alternate Authentication Material | اگر 4648 (Explicit Credentials) مشاهده شود  |
| **T1003** (احتمالی) | OS Credential Dumping | اگر Processهای مشکوک پس از Login (مثل `mimikatz`) دیده شود |

**هشدار:** Mapping فقط بر اساس **شواهد مشاهده‌شده** انجام شده. اگر Login در ساعات کاری و از Jump Server باشد، T1078.002 ممکن است **اعمال نشود**.

## 8. نتیجه‌گیری و سطح اطمینان

**وضعیت فعلی: Observed (مشاهده‌شده)**

- **آنچه مسلم است:** یک Domain Admin خارج از ساعات کاری روی یک Workstation معمولی لاگین کرده است.
- **آنچه Likely است:** این رفتار **مشکوک به Privileged Access Misuse** است، به‌ویژه اگر:
  1. Login **خارج از ساعات کاری** باشد.
  2. **Logon Type 10** (RDP) باشد.
  3. **Source IP** در Baseline سازمان نباشد.
  4. Processهای مشکوک پس از Login ایجاد شده باشند.
- **آنچه هنوز اثبات نشده:** اینکه این Login **مخرب** است. برای Confirmation نیاز به:
  1. بررسی Processهای ایجادشده پس از Login.
  2. بررسی Network Activity پس از Login.
  3. تأیید اینکه Source IP در Baseline سازمان نیست.

**سطح اطمینان اولیه: Medium-High** که این یک **Anomaly امنیتی** است. اگر Source IP خارجی باشد و Processهای مشکوک دیده شوند، اطمینان به **High** ارتقا می‌یابد.

## 9. Response و بهبود Detection

**اقدامات فوری (اگر Suspicious Privileged Access تأیید شد):**
1. **Account Containment:** Reset Password فوری برای Domain Admin Account.
2. **Session Revocation:** بستن Sessionهای فعال (Kerberos Tickets، RDP Sessions).
3. **Forensic Investigation:** بررسی Processهای ایجادشده پس از Login، Persistence Mechanisms، Lateral Movement.
4. **IP Blocking:** بلاک کردن Source IP در Firewall.

**اقدامات بلندمدت (Detection Improvement):**
1. **قانون Detection جدید:** هر Login Domain Admin روی Workstation غیر DC → Alert.
2. **قانون Tiered Administration:** نظارت بر Login حساب‌های Tier 0 روی Hostهای Tier 1/2 .
3. **قانون Logon Type:** هر Logon Type 10 از IP خارجی به Workstation → Alert.
4. **Privileged Access Workstation (PAW):** اجرای PAW برای Domain Adminها.
5. **Audit Policy:** اطمینان از فعال بودن **Audit Sensitive Privilege Use** برای ثبت 4672 .

## 10. پاسخ کوتاه برای شروع جواب در مصاحبه

برای تشخیص سوءاستفاده از Domain Admin، اول **Event ID 4624** رو بررسی می‌کنم و **Logon Type** رو چک می‌کنم — اگه Type 10 (RDP) باشه و **خارج از ساعات کاری**، این **Strong Indicator** هست.

بعد **Event ID 4672** رو correlate می‌کنم: اگه همون `LogonId` در 4672 دیده بشه، تأیید می‌شه که Privileges بالا به اون Session اعطا شده . همچنین **Event ID 4648** رو چک می‌کنم که نشون‌دهنده **Explicit Credential Usage** هست .

**Source IP** و **WorkstationName** رو هم بررسی می‌کنم که آیا در Baseline سازمان هست یا نه. اگه از یک **Jump Server** شناخته‌شده نباشه، شک من قطعی‌تر می‌شه.

**محدودیت اصلی:** Event ID 4672 به‌صورت پیش‌فرض Audited نیست و باید Audit Policy فعال باشه . همچنین، برای RDP، `WorkstationName` ممکنه گمراه‌کننده باشه و باید `IpAddress` رو جداگانه بررسی کنم .

**اقدام بعدی:** اگه Login مشکوک تأیید شد، اول Password اون Domain Admin رو Reset می‌کنم، Sessionها رو Revoke می‌کنم، و بعد Processهای ایجادشده پس از Login رو برای **Lateral Movement** یا **Credential Dumping** بررسی می‌کنم.
