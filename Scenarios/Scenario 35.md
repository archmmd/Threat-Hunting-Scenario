### 1. تعریف سناریو و هدف Hunt

در بازه **۱۰ دقیقه**، **۲٬۰۰۰ Alert** تولید شده که بیشتر آن‌ها از **چند Host** مشخص می‌آیند. هدف، **گروه‌بندی (Clustering)**، **اولویت‌بندی (Prioritization)**، و تبدیل Alertها به **Incidentهای قابل‌بررسی** است، بدون اینکه Detection واقعی از دست برود.

**نکته حیاتی:** Alert Flood می‌تواند **دو معنا** داشته باشد: (۱) **True Positive Storm** — یک کمپین واقعی در حال اجراست و باید فوراً مهار شود؛ (۲) **False Positive Storm** — یک Rule معیوب یا تغییر محیطی باعث انفجار Alert شده. تفکیک این دو **اولویت اول** است .

### 2. فرضیه اصلی و فرضیه‌های جایگزین

| فرضیه | توضیح | شواهد تقویت‌کننده | شواهد تضعیف‌کننده |
|---|---|---|---|
| **فرضیه اصلی (True Positive Storm)** | یک کمپین فعال (مثل Ransomware Pre-encryption، Lateral Movement) در حال اجراست و Alertها **مرتبط** هستند | Hostهای محدود، Account مشترک، Process Ancestry پیوسته، Timeline صعودی  | Hostهای پراکنده، Accountهای متفاوت، Processهای قانونی |
| **فرضیه جایگزین (False Positive Storm)** | یک Rule معیوب، تغییر Baseline، یا Software Update باعث انفجار Alert شده | Alertها از **یک Rule**، Hostهای مشابه، Process قانونی، Time Correlation با Change Window  | Ruleهای متفاوت، Hostهای پراکنده |
| **فرضیه جایگزین (Alert Fatigue Exploitation)** | مهاجم عمداً Alert Flood تولید کرده تا Alert واقعی در میان آن‌ها گم شود | Alertهای پرحجم از یک Source، Alert واقعی **همزمان** در Host دیگر | عدم وجود Alert واقعی |

### 3. Telemetry و Data Sources

| منبع | نقش | چه چیزی را بررسی کنیم |
|---|---|---|
| **SIEM Alert Queue** (Essential) | Alert Metadata | `AlertName`، `Severity`، `Host`، `Account`، `Timestamp`، `RuleId`  |
| **EDR Alert Data** (Essential) | Endpoint Context | Process Tree، Command Line، File Hash  |
| **Asset Inventory** (Essential) | Host Context | آیا Host **Critical** است؟ (DC، File Server، Database)  |
| **Threat Intel** (Supplementary) | Reputation | آیا IP/Hash/Domain در Intel Malicious است؟ |

### 4. مراحل اجرایی Hunt و Queryهای عملی

**مرحله A: گروه‌بندی Alertها (Clustering)**

```kql
SecurityAlert
| where TimeGenerated > ago(10m)
| summarize 
    AlertCount = count(),
    AlertNames = make_set(AlertName),
    FirstAlert = min(TimeGenerated),
    LastAlert = max(TimeGenerated),
    Entities = make_set(Entities)
    by CompromisedEntity, AlertSeverity
| order by AlertCount desc
```

**منطق Query:** گروه‌بندی بر اساس **Host** و **Severity**. اگر ۱٬۵۰۰ Alert از **۳ Host** باشد، این **Clustering** واضح است .

**مرحله B: شناسایی Rule منفرد (Root Cause)**

```kql
SecurityAlert
| where TimeGenerated > ago(10m)
| summarize AlertCount = count() by AlertName, ProductName
| order by AlertCount desc
```

**منطق Query:** اگر **یک Rule** مسئول ۹۰٪ Alertها باشد، احتمال **False Positive Storm** بالاست. اگر **چند Rule** درگیر باشند، احتمال **True Positive Storm** بالاست .

**مرحله C: اولویت‌بندی بر اساس Risk**

```kql
SecurityAlert
| where TimeGenerated > ago(10m)
| extend HostCriticality = case(
    CompromisedEntity has_any ("DC", "SQL", "EXCHANGE"), "Critical",
    CompromisedEntity has_any ("FILE", "APP"), "High",
    "Medium")
| extend RiskScore = case(
    AlertSeverity == "High" and HostCriticality == "Critical", 100,
    AlertSeverity == "High" and HostCriticality == "High", 80,
    AlertSeverity == "Medium" and HostCriticality == "Critical", 70,
    50)
| summarize 
    AlertCount = count(),
    MaxRisk = max(RiskScore),
    AlertNames = make_set(AlertName)
    by CompromisedEntity, HostCriticality
| order by MaxRisk desc, AlertCount desc
```

**منطق Query:** اولویت‌بندی بر اساس **Host Criticality** + **Alert Severity** + **Volume**.

**مرحله D: تبدیل به Incident**

```kql
SecurityAlert
| where TimeGenerated > ago(10m)
| where AlertSeverity in ("High", "Medium")
| summarize 
    AlertCount = count(),
    AlertNames = make_set(AlertName),
    FirstAlert = min(TimeGenerated),
    LastAlert = max(TimeGenerated)
    by CompromisedEntity, Account = tostring(Entities)
| where AlertCount >= 10  // Threshold برای Incident
| project CompromisedEntity, Account, AlertCount, AlertNames, FirstAlert, LastAlert
```

**منطق Query:** Alertهایی که **Volume بالا** + **Host مشترک** + **Account مشترک** دارند، به **Incident** تبدیل می‌شوند .

### 5. Pivoting و Correlation شواهد

1. **از Host به Account:** آیا همان Account روی چند Host Alert تولید کرده؟ (Lateral Movement)
2. **از AlertName به Process:** آیا Alertها از **یک Process** خاص می‌آیند؟
3. **از Timeline به Sequence:** آیا Alertها **صعودی** هستند؟ (Ongoing Attack)
4. **از Host Criticality به Business Impact:** آیا Host در **Critical Asset List** است؟

**هشدار:** Alert Flood **ممکن است** عمداً برای **پنهان کردن** یک Alert واقعی تولید شده باشد. باید **Alert واقعی** را در میان **Noise** جستجو کنید .

### 6. اعتبارسنجی، تعیین Scope و بررسی False Positive

**Baseline:**
- آیا این Rule **قبلاً** Alert Flood تولید کرده؟ (Historical Alert Rate)
- آیا در **Change Window** هستیم؟ (Software Update، Patch)

**Scope:**
- اگر **True Positive Storm** باشد: همه Hostهای درگیر را Isolate کنید.
- اگر **False Positive Storm** باشد: Rule را **Tune** کنید.

**False Positive:**
- Software Update (Windows Update، Adobe)
- Vulnerability Scanner (Credential Testing)
- Misconfigured Agent (Log Loop)

**معیار قطعی:** اگر **Alertها از یک Rule** و **Process قانونی** باشند → **False Positive**. اگر **چند Rule** و **Hostهای Critical** باشند → **True Positive**.

### 7. MITRE ATT&CK Mapping

| Technique ID | Name | شواهد |
|---|---|---|
| **T1499** (احتمالی) | Endpoint Denial of Service | اگر Alert Flood عمدی باشد  |
| **T1078** (احتمالی) | Valid Accounts | اگر Account مشترک در Alertها باشد |

### 8. نتیجه‌گیری و سطح اطمینان

**Observed:** ۲٬۰۰۰ Alert در ۱۰ دقیقه از چند Host.

**Likely:** **Alert Storm** با **Clustering** مشخص. اگر **یک Rule** غالب باشد → **False Positive**. اگر **چند Rule** و **Hostهای Critical** باشند → **True Positive**.

**Confidence: Medium** — برای **High** نیاز به **Process Analysis** و **Host Criticality** داریم.

### 9. Response و بهبود Detection

**اقدامات فوری:**
1. **Suppress** Rule معیوب (اگر FP تأیید شد).
2. **Isolate** Hostهای Critical (اگر TP تأیید شد).
3. **Incident Creation** برای Hostهای High-Risk .

**Detection Improvement:**
1. **Rule Tuning:** کاهش Sensitivity یا افزودن Filter .
2. **Alert Grouping:** استفاده از **SIEM Incident Grouping** .
3. **Anomaly Detection:** استفاده از **UEBA** برای شناسایی Alert Flood غیرعادی .

### 10. پاسخ کوتاه برای شروع جواب در مصاحبه

اول Alertها رو **گروه‌بندی** می‌کنم: بر اساس **Host**، **AlertName** و **Severity**. اگه ۱٬۵۰۰ Alert از **۳ Host** باشه، این **Clustering** واضحه .

بعد **Root Cause** رو پیدا می‌کنم: اگه **یک Rule** مسئول ۹۰٪ Alertها باشه، احتمال **False Positive Storm** بالاست. اگه **چند Rule** درگیر باشن، احتمال **True Positive** بالاست .

**اولویت‌بندی** رو بر اساس **Host Criticality** انجام می‌دم: اگه Host یه **Domain Controller** باشه، Risk بالاتره .

**محدودیت اصلی:** Alert Flood ممکنه عمداً برای **پنهان کردن** یه Alert واقعی تولید شده باشه — پس باید **Alert واقعی** رو در میان Noise جستجو کنم .

**اقدام بعدی:** اگه **True Positive** تأیید شد، Hostهای Critical رو Isolate می‌کنم. اگه **False Positive** بود، Rule رو Tune می‌کنم .
