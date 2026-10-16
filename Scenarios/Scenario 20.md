## 1. تعریف سناریو و هدف Hunt

یک **Workstation** شروع به انجام **LDAP Queryهای غیرمعمول** علیه **Domain Controller** کرده است. هدف Hunt، تفکیک **AD Reconnaissance** (T1087.002 / T1069.002 / T1018) از **رفتار طبیعی ابزارهای مدیریتی** و **سرویس‌های سازمانی** است.

**نکته حیاتی:** LDAP یکی از پروتکل‌های **پرترافیک** در محیط Active Directory است. میلیون‌ها Query قانونی روزانه از Userها، Service Accountها و ابزارهای IT انجام می‌شود . صرفاً وجود LDAP Query **هیچ ارزش تشخیصی ندارد**. تمایز اصلی در **Volume**، **Source Context**، **Search Filter**، و **Query Scope** است .

## 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (Malicious Reconnaissance)** | مهاجم از یک Workstation Compromised برای انجام **AD Enumeration** (نقشه‌برداری از Domain) استفاده می‌کند | Volume بالا از یک Workstation، Search Filterهای خاص (مثل `adminCount=1`، `pKICertificateTemplate`)، Source Process غیرعادی، Query در ساعات غیرکاری  | Query از Source شناخته‌شده (Jump Server، IT Workstation)، Volume پایین، Filterهای عمومی |
| **فرضیه جایگزین (Legitimate IT Tools)** | ابزارهای Management (SCCM، Intune، Antivirus، Monitoring) به‌صورت قانونی Query انجام می‌دهند | Source Process شناخته‌شده (`svchost.exe`، `mmc.exe`، `lsass.exe`)، Volume مطابق Baseline، Query در ساعات کاری  | Process ناشناخته، Volume بالاتر از Baseline، Filterهای خاص مهاجم |
| **فرضیه جایگزین (User Application)** | یک Application قانونی (مثل Outlook، Teams) برای Directory Lookup از LDAP استفاده می‌کند | Source Process قابل توضیح، Volume پایین، Filterهای محدود (مثل Email Lookup) | Process غیرعادی روی Workstation، Filterهای گسترده |

## 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Microsoft-Windows-LDAP-Client/Debug ETW** (Essential) | LDAP Query Details | `EventID 30`، `SearchFilter`، `DistinguishedName`، `AttributeList`  |
| **Windows Security Event ID 4662** (Essential) | Directory Service Access | `ObjectName`، `AccessMask`، `Properties`، `SubjectUserName`  |
| **Windows Security Event ID 1644** (Supplementary) | Expensive LDAP Query | `VisitedEntries`، `ReturnedEntries`، `SearchFilter` — روی DC  |
| **Sysmon Event ID 3** (Essential) | Network Connection | اتصال به Port 389/636/3268/3269 از Processهای غیرعادی  |
| **Sysmon Event ID 1** (Essential) | Process Creation | `Image`، `CommandLine` — Source Process که LDAP Query را انجام می‌دهد |
| **Defender for Identity / MDI** (Supplementary) | LDAP Query Analytics | `IdentityQueryEvents` — Baseline و Anomaly Detection  |

**محدودیت مهم:** **Microsoft-Windows-LDAP-Client/Debug ETW** به‌صورت پیش‌فرض **فعال نیست** و باید صریحاً Enable شود . همچنین، **Directory Service Access Auditing** (Event 4662) باید روی DC فعال باشد و SACL روی Objectهای حساس تنظیم شود .

## 4. مراحل اجرایی Hunt و Queryهای عملی

### مرحله A: Baseline و تشخیص Anomaly در Volume

**KQL (Sentinel / Defender XDR — IdentityQueryEvents):**

```kql
let starttime = 30d;
let timeframe = 1h;
let Workstations = DeviceInfo
    | where DeviceType == "Workstation"
    | distinct DeviceName;
let TimeSeriesData = IdentityQueryEvents
    | where ActionType == "LDAP query"
    | where DeviceName in~ (Workstations)
    | make-series PerHourCount=count() on Timestamp from startofday(ago(starttime)) to startofday(ago(1d)) step timeframe by DeviceName;
TimeSeriesData
| extend (anomalies, score, baseline) = series_decompose_anomalies(PerHourCount, 1.5, -1, 'linefit')
| mv-expand anomalies to typeof(double), score to typeof(double), baseline to typeof(long)
| where anomalies > 0 and PerHourCount > 50  // Threshold قابل تنظیم
| project DeviceName, Timestamp, PerHourCount, baseline, score
| order by score desc
```

**منطق Query:** این Query یک **Baseline** از تعداد LDAP Query هر Workstation در هر ساعت ایجاد می‌کند و **Deviation** از Baseline را شناسایی می‌کند . Threshold 50 قابل تنظیم بر اساس محیط سازمان است.

### مرحله B: شناسایی Search Filterهای مشکوک

**KQL (Sentinel — SecurityEvent 4662 یا LDAP ETW):**

```kql
SecurityEvent
| where EventID == 4662
| where TimeGenerated > ago(24h)
| where ObjectName has_any ("CN=Certificate Templates", "CN=Domain Admins", "CN=Enterprise Admins")
| where Properties has_any (
    "pKICertificateTemplate",
    "msPKI-Certificate-Name-Flag",
    "nTSecurityDescriptor",
    "adminCount"
)
| project TimeGenerated, Computer, SubjectUserName, ObjectName, Properties, AccessMask
| order by TimeGenerated desc
```

**منطق Query:** این Query به‌دنبال **Certificate Template Enumeration** (T1649) و **Admin Group Enumeration** است. ابزارهایی مثل **Certipy**، **Certify**، **SharpHound** و **BloodHound** از این Filterها استفاده می‌کنند .

### مرحله C: شناسایی Sysmon Network Connection به LDAP Port

**KQL (Sentinel — Sysmon EID 3):**

```kql
SysmonEvent
| where EventID == 3
| where DestinationPort in (389, 636, 3268, 3269)
| where Image !has_any ("\\lsass.exe", "\\svchost.exe", "\\mmc.exe", "\\certsrv.exe")
| where Image has_any ("\\powershell.exe", "\\cmd.exe", "\\rundll32.exe", "\\Users\\Public\\", "\\Temp\\", "\\AppData\\")
| project TimeGenerated, Computer, Image, DestinationIp, DestinationPort, ProcessGuid
| order by TimeGenerated desc
```

**منطق Query:** Processهای غیرسیستمی که به LDAP Portها متصل می‌شوند، **Strong Indicator** برای Enumeration هستند. Processهای سیستمی (`lsass.exe`، `svchost.exe`) به‌صورت قانونی به LDAP متصل می‌شوند .

### مرحله D: شناسایی ADWS Enumeration (Port 9389)

**KQL (Sentinel — Sysmon EID 3):**

```kql
SysmonEvent
| where EventID == 3
| where DestinationPort == 9389  // ADWS
| where Image !has_any ("\\Microsoft.ActiveDirectory.WebServices.exe", "\\svchost.exe")
| project TimeGenerated, Computer, Image, DestinationIp, DestinationPort, ProcessGuid
```

**منطق Query:** مهاجمان مدرن ممکن است از **ADWS (Port 9389)** به‌جای LDAP سنتی استفاده کنند تا از Detection فرار کنند. ابزارهایی مثل **ADWSHound** از این روش استفاده می‌کنند .

## 5. Pivoting و Correlation شواهد

از `SubjectUserName`، `Computer` و `ProcessGuid` برای Pivot استفاده کنید:

1. **Correlation بین 4662 و Sysmon EID 3:** اگر Event 4662 از یک User روی DC ثبت شده، با Sysmon EID 3 روی همان Workstation correlate کنید تا **Source Process** را شناسایی کنید.
2. **Process Tree:** از Sysmon EID 1 بررسی کنید که چه Processی LDAP Query را ایجاد کرده. اگر Parent Process `powershell.exe`، `cmd.exe` یا `rundll32.exe` باشد → **مشکوک** .
3. **Search Filter Analysis:** Filterهای خاص مثل `adminCount=1`، `pKICertificateTemplate`، یا `userAccountControl:1.2.840.113556.1.4.803:=4194304` را جستجو کنید .
4. **Network Timeline:** آیا Queryها در **Burst** کوتاه رخ داده‌اند؟ (Enumeration Tool Behavior) یا در **فواصل منظم**؟ (Service Behavior)
5. **همان User روی Hostهای دیگر:** آیا این User روی Workstationهای دیگر نیز LDAP Query غیرمعمول انجام داده؟

**هشدار:** همزمانی زمانی (Temporal Proximity) به‌تنهایی **Causation** را اثبات نمی‌کند. برای انتساب Enumeration به Source، باید **ProcessGuid** و **SearchFilter** یکسان تأیید شود.

## 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline مقایسه:**
- آیا این Workstation **قبلاً** LDAP Query انجام می‌داده است؟ (Historical Baseline)
- آیا **Source Process** (`powershell.exe`، `cmd.exe`) در Baseline سازمان به‌عنوان LDAP Client ثبت شده؟
- آیا Query در **ساعات کاری** است یا خارج از آن؟ (Enumeration اغلب در ساعات غیرکاری رخ می‌دهد)

**Scope Determination:**
- روی **همه Workstationها** Query بزنید: آیا همان Search Filter یا همان Source Process در Hostهای دیگر دیده می‌شود؟
- آیا همان User روی Endpointهای دیگر نیز رفتار مشابهی داشته؟
- آیا DCهای دیگر نیز Event 4662 مشابهی ثبت کرده‌اند؟

**False Positive ممکن:**
- **IT Tools:** SCCM، Intune، Antivirus، و Monitoring Agentها به‌صورت قانونی LDAP Query انجام می‌دهند .
- **CA Management Tools:** `certlm.msc`، `pkiview.msc` و ابزارهای PKI ممکن است Certificate Templateها را Enumeration کنند .
- **Third-Party PAM:** ابزارهای Privileged Access Management ممکن است LDAP Query گسترده انجام دهند.

**معیار قطعی:** اگر **Search Filter** شامل `pKICertificateTemplate`، `adminCount=1`، یا `msDS-AllowedToActOnBehalfOfOtherIdentity` باشد، و **Source Process** یک Process غیرسیستمی باشد، احتمال **False Positive پایین** است .

## 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1087.002** | Account Discovery: Domain Account | LDAP Query برای Enumeration کاربران Domain  |
| **T1069.002** | Permission Groups Discovery: Domain Groups | LDAP Query برای Enumeration Groupهای Domain  |
| **T1482** | Domain Trust Discovery | LDAP Query برای Trust Relationships  |
| **T1649** | Steal or Forge Authentication Certificates | LDAP Query برای Certificate Template Enumeration (AD CS)  |
| **T1018** | Remote System Discovery | LDAP Query برای Enumeration کامپیوترها |

**هشدار:** Mapping فقط بر اساس **شواهد مشاهده‌شده** انجام شده. اگر Source Process یک ابزار Management شناخته‌شده باشد و Filterها عمومی باشند، ممکن است T1087.002 **اعمال نشود**.

## 8. نتیجه‌گیری و سطح اطمینان

**وضعیت فعلی: Observed (مشاهده‌شده)**

- **آنچه مسلم است:** یک Workstation LDAP Queryهای غیرمعمول علیه DC انجام داده است.
- **آنچه Likely است:** این رفتار **مشکوک به Reconnaissance** است، به‌ویژه اگر:
  1. Volume بالاتر از Baseline باشد.
  2. Search Filterها شامل `pKICertificateTemplate` یا `adminCount=1` باشد.
  3. Source Process غیرسیستمی باشد (`powershell.exe`، `cmd.exe`).
  4. Query خارج از ساعات کاری رخ داده باشد.
- **آنچه هنوز اثبات نشده:** اینکه این Queryها **مخرب** هستند. برای Confirmation نیاز به:
  1. تأیید اینکه Source Process یک Enumeration Tool است (مثل SharpHound، AdFind).
  2. بررسی Processهای ایجادشده **پس از** Enumeration.
  3. بررسی Network Activity به مقصدهای مشکوک.

**سطح اطمینان اولیه: Medium** که این یک **Anomaly امنیتی** است. اگر **Search Filter** خاص و **Source Process** غیرسیستمی باشد، اطمینان به **High** ارتقا می‌یابد.

## 9. Response و بهبود Detection

**اقدامات فوری (اگر Reconnaissance تأیید شد):**
1. **Endpoint Isolation** از طریق EDR.
2. **Forensic Investigation:** بررسی Process Tree، Persistence Mechanisms، Lateral Movement.
3. **Account Containment:** اگر حساب Compromised شده، Password Reset و Session Revocation.
4. **Network Blocking:** بلاک کردن اتصالات LDAP از Workstation به DC در Firewall (اگر امکان‌پذیر باشد).

**اقدامات بلندمدت (Detection Improvement):**
1. **فعال‌سازی LDAP Client ETW Logging:** `Microsoft-Windows-LDAP-Client/Debug` برای ثبت Event ID 30 .
2. **فعال‌سازی Directory Service Access Auditing:** Event 4662 روی DC با SACL روی Objectهای حساس .
3. **قانون Detection جدید:** هر Workstation که Volume LDAP Query آن بیش از **2x Baseline** باشد → Alert .
4. **قانون Search Filter:** هر Query شامل `pKICertificateTemplate`، `adminCount=1`، یا `msDS-AllowedToActOnBehalfOfOtherIdentity` → Alert .
5. **قانون ADWS:** هر اتصال به Port 9389 از Process غیرسیستمی → Alert .
6. **Canary Objects:** ایجاد Objectهای تله در AD برای تشخیص Enumeration غیرمجاز .

## 10. پاسخ کوتاه برای شروع جواب در مصاحبه

برای تفکیک Reconnaissance از رفتار طبیعی، اول **Volume** رو بررسی می‌کنم: اگه یک Workstation **بالاتر از Baseline** خودش LDAP Query بزنه، این **Strong Indicator** هست. از `IdentityQueryEvents` و `series_decompose_anomalies` برای Baseline استفاده می‌کنم .

بعد **Search Filter** رو تحلیل می‌کنم: اگه شامل `pKICertificateTemplate`، `adminCount=1`، یا `msDS-AllowedToActOnBehalfOfOtherIdentity` باشه، این **High-Confidence Indicator** برای Enumeration هست . ابزارهایی مثل Certipy، SharpHound و AdFind از این Filterها استفاده می‌کنند.

**Source Process** رو هم از Sysmon EID 1 و EID 3 چک می‌کنم: اگه `powershell.exe` یا `cmd.exe` از یک Workstation به LDAP Port متصل شده باشه، شک من قطعی‌تر می‌شه. Processهای سیستمی مثل `lsass.exe` و `svchost.exe` قانونی هستند .

**محدودیت اصلی:** LDAP Client ETW Logging به‌صورت پیش‌فرض فعال نیست و باید صریحاً Enable بشه . همچنین، ابزارهای IT مثل SCCM و Intune ممکنه False Positive ایجاد کنند.

**اقدام بعدی:** اگه Enumeration تأیید شد، اول Endpoint رو Isolate می‌کنم، بعد Process Tree رو برای **Lateral Movement** و **Credential Dumping** بررسی می‌کنم.
