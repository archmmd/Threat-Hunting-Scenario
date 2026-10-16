### 1. تعریف سناریو و هدف Hunt

یک Host به‌طور **دوره‌ای** DNS Queryهایی با **Subdomainهای طولانی و غیرمعمول** تولید می‌کند. هدف Hunt، تشخیص **DNS Tunneling** (T1071.004) از طریق تحلیل **NXDOMAIN، طول نام‌ها، Entropy، حجم Query و رفتار Resolver** است.

**نکته حیاتی:** DNS Tunneling داده را در **Subdomain Labels** کد می‌کند (Egress) و در **TXT/CNAME/NULL Responses** دریافت می‌کند (Ingress) . صرفاً دیدن Subdomain طولانی **کافی نیست** — باید **Entropy بالا**، **حجم Query متمرکز روی یک Domain**، و **Process غیرعادی** را با هم ببینیم .

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده |
|---|---|---|
| **فرضیه اصلی (DNS Tunneling)** | مهاجم از DNS برای Exfiltration یا C2 استفاده می‌کند | Subdomain Length > 50، Shannon Entropy > 4.0، Unique Subdomains > 100 در یک Domain، TXT/NULL Record، NXDOMAIN Rate بالا  |
| **فرضیه جایگزین (Legitimate CDN/Telemetry)** | یک سرویس قانونی از Subdomainهای Random استفاده می‌کند | Domain در Allowlist، Process Browser، Entropy پایین‌تر، Volume متعادل |

### 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **Sysmon EID 22** (Essential) | DNS Query | `QueryName`, `Image` (Process), `QueryStatus`  |
| **Sysmon EID 3** (Supplementary) | Network Connection | Connection به DNS Server (Port 53)  |
| **DNS Server Logs / Zeek** (Essential) | Query Analytics | `qtype_name`, `rcode_name` (NXDOMAIN), `answers`  |
| **Proxy Logs** (Supplementary) | Context | آیا HTTP/S Traffic به همان Domain وجود دارد؟ |

**محدودیت:** اگر DNS Encryption (DoH/DoT) فعال باشد، **Network Sensor** نمی‌تواند محتوای Query را ببیند . در این حالت، فقط **Endpoint Telemetry** (Sysmon EID 22) قابل استفاده است.

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: تحلیل NXDOMAIN Rate**

```kql
DeviceEvents
| where ActionType == "DnsQueryResponse"
| where Timestamp > ago(24h)
| summarize 
    TotalQueries = count(),
    NXDOMAINCount = countif(AdditionalFields.responseCode == "NXDOMAIN"),
    NXDOMAINRate = (countif(AdditionalFields.responseCode == "NXDOMAIN") * 100.0) / count()
    by DeviceName, tostring(split(QueryName, ".")[-2]) + "." + tostring(split(QueryName, ".")[-1])
| where NXDOMAINRate > 40 and TotalQueries > 50
| order by NXDOMAINRate desc
```

**منطق Query:** DNS Tunneling اغلب با **NXDOMAIN** همراه است (چون Subdomainها وجود ندارند). نرخ بالای **40%** با Volume بالا = **Strong Indicator** .

**مرحله B: تحلیل طول Subdomain**

```kql
DeviceEvents
| where ActionType == "DnsQueryResponse"
| where Timestamp > ago(24h)
| extend FirstLabel = tostring(split(QueryName, ".")[0])
| extend LabelLength = strlen(FirstLabel)
| where LabelLength > 50
| summarize 
    LongLabelCount = count(),
    AvgLength = avg(LabelLength),
    UniqueLabels = dcount(FirstLabel)
    by DeviceName, InitiatingProcessFileName
| where LongLabelCount > 20
| order by AvgLength desc
```

**منطق Query:** Label طولانی (نزدیک به **63 کاراکتر** حد مجاز) نشانه **Data Encoding** است .

**مرحله C: محاسبه Entropy**

Entropy Shannon برای Subdomain مشکوک:

```python
import math
from collections import Counter

def shannon_entropy(s):
    c = Counter(s)
    n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

# روی First Label هر Query اجرا شود
# > 4.0 = مشکوک برای رشته‌های کوتاه
# > 3.5 = مشکوک برای رشته‌های بلند
```

**منطق:** داده‌های Encoded (Base64، Hex) **Entropy بالاتری** از Subdomainهای معنادار دارند. Threshold **4.0** برای رشته‌های کوتاه، **3.5** برای رشته‌های بلند .

**مرحله D: تحلیل حجم Query متمرکز**

```kql
DeviceEvents
| where ActionType == "DnsQueryResponse"
| where Timestamp > ago(1h)
| summarize 
    QueryCount = count(),
    UniqueSubdomains = dcount(QueryName),
    AvgLength = avg(strlen(QueryName))
    by DeviceName, tostring(split(QueryName, ".")[-2]) + "." + tostring(split(QueryName, ".")[-1])
| where QueryCount > 500 and UniqueSubdomains > 100
| order by QueryCount desc
```

**منطق Query:** Tunneling حجم بالایی از Query را به **یک Domain** متمرکز می‌کند . **500+ Query در یک ساعت** با **100+ Unique Subdomain** = **Strong Indicator**.

### 5. Pivoting و Correlation شواهد

1. **از DNS Query به Process:** از Sysmon EID 22، `Image` (Process) را استخراج کنید. اگر **Browser** باشد، احتمال Legitimate. اگر `powershell.exe`، `rundll32.exe`، یا `cmd.exe` باشد، **مشکوک** .
2. **از Domain به Threat Intel:** Domain را در VirusTotal/AbuseIPDB بررسی کنید. **Registration Age < 30 روز** = **مشکوک** .
3. **از Query به Response:** آیا Response شامل **TXT Record** یا **NULL Record** است؟ این‌ها در Tunneling رایج‌اند .
4. **از Host به Host:** آیا Hostهای دیگر سازمان نیز به همان Domain Query می‌زنند؟

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline:**
- آیا Domain در **Allowlist** سازمان است؟ (CDN، Telemetry، Marketing)
- آیا Process انجام‌دهنده Query **Browser** است؟

**False Positive:**
- **CDN/DDoS Protection:** Cloudflare، Akamai از Subdomainهای Random استفاده می‌کنند.
- **Telemetry Agents:** Datadog، New Relic ممکن است Subdomainهای طولانی تولید کنند.
- **DNSSEC:** Validation Queries ممکن است Length بالاتری داشته باشند .

**معیار قطعی:** Entropy > 4.0 + Label Length > 50 + NXDOMAIN Rate > 40% + Process غیرBrowser = **High Confidence Tunneling** .

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1071.004** | Application Layer Protocol: DNS | Subdomain طولانی، Entropy بالا، NXDOMAIN بالا  |
| **T1048** | Exfiltration Over Alternative Protocol | Data Encoding در Subdomain  |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** Host به‌طور دوره‌ای DNS Query با Subdomain طولانی تولید می‌کند.

**Likely:** این رفتار **مشکوک به DNS Tunneling** است اگر:
1. **Entropy > 4.0** باشد.
2. **Label Length > 50** باشد.
3. **NXDOMAIN Rate > 40%** باشد.
4. **Process غیرBrowser** باشد .

**Confidence: Medium-High** — برای **High** نیاز به **TXT/NULL Record** و **Process Analysis** داریم.

### 9. Response و بهبود Detection

**فوری:**
1. **Block Domain** در DNS Firewall (اگر **اختصاصی** باشد).
2. **Isolate Endpoint** اگر Process مخرب تأیید شد.
3. **Forensic Collection:** DNS Logs، Process Tree، Network Capture.

**Detection Improvement:**
1. **Entropy-Based Rule:** هر Subdomain با **Entropy > 4.0** و **Length > 50** → Alert .
2. **NXDOMAIN Rule:** هر Domain با **NXDOMAIN Rate > 40%** و **Query Count > 100** → Alert .
3. **TXT/NULL Record Rule:** هر Query با **qtype_name = TXT** یا **NULL** از Internal Host → Alert .

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

اول **NXDOMAIN Rate** رو بررسی می‌کنم: اگه یک Domain **بیش از ۴۰٪ NXDOMAIN** داشته باشه و **Volume Query بالا** باشه، این **Strong Indicator** برای DNS Tunneling هست .

بعد **طول Subdomain** و **Entropy** رو چک می‌کنم: اگه Label **بیش از ۵۰ کاراکتر** باشه و **Shannon Entropy بالای ۴.۰** داشته باشه، این **Data Encoding** هست .

از **Sysmon EID 22**، **Process انجام‌دهنده Query** رو استخراج می‌کنم: اگه Browser باشه، احتمال Legitimate. اگه `powershell.exe` یا `rundll32.exe` باشه، شک من قطعی‌تر می‌شه .

**محدودیت اصلی:** اگه **DNS Encryption (DoH/DoT)** فعال باشه، Network Sensor نمی‌تونه محتوای Query رو ببینه و فقط **Endpoint Telemetry** قابل استفاده است .

**اقدام بعدی:** اگه تأیید شد، Domain رو در DNS Firewall بلاک می‌کنم و Endpoint رو Isolate می‌کنم.
