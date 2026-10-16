برای پاسخ به این سوال، باید سه لایه را به هم گره بزنیم: **چه داده‌ای**، **توسط کدام Process**، و **به کدام مقصد**. کلید حل این معما، **Correlation** بین Telemetry شبکه و Endpoint است، نه نگاه تک‌بعدی به یکی از آن‌ها.

### 📊 گام اول: تعیین حجم و مقصد از دید Network

اول باید بفهمیم **چه چیزی** و **به کجا** منتقل شده است. از **Zeek conn.log** یا **NetFlow** استفاده می‌کنیم و روی **Outbound Bytes** از Host داخلی به مقصد خارجی تمرکز می‌کنیم.

**Query نمونه (Zeek/Splunk):**
```splunk
index=zeek sourcetype=bro:conn:json
| where orig_bytes > 50000000  // Threshold: 50MB
| where id.resp_h NOT IN (Internal_Subnets)
| stats sum(orig_bytes) as TotalUpload by id.orig_h, id.resp_h
| sort -TotalUpload
```

این Query به ما می‌گوید **کدام Host داخلی (id.orig_h)** حجم زیادی داده را به **کدام مقصد خارجی (id.resp_h)** ارسال کرده است . در این مرحله، **نوع داده** هنوز مشخص نیست، اما **مقصد** و **حجم** روشن می‌شود.

### 🧩 گام دوم: شناسایی Process مسئول از دید Endpoint

حالا باید بفهمیم **کدام Process** این ترافیک را ایجاد کرده است. از **Sysmon Event ID 3 (Network Connect)** استفاده می‌کنیم که اتصالات را با **Process GUID** و **Image** (نام Process) ثبت می‌کند .

**Query نمونه (Sentinel/Defender XDR):**
```kql
DeviceNetworkEvents
| where Timestamp > ago(24h)
| where RemoteIPType == "Public"
| where DeviceName has "Internal-Host-Name"
| summarize TotalSent = sum(SentBytes) by InitiatingProcessFileName, RemoteIP, RemotePort
| where TotalSent > 50000000
| order by TotalSent desc
```

این Query مشخص می‌کند که مثلاً **`rclone.exe`** یا **`powershell.exe`** یا **`curl.exe`** مسئول ارسال داده بوده است .

### 🔍 گام سوم: استخراج مقصد دقیق (Domain/IP) از DNS

اگر ترافیک روی HTTPS باشد، فقط IP را می‌بینیم. برای فهمیدن **Domain** واقعی، از **Sysmon Event ID 22 (DNS Query)** استفاده می‌کنیم که QueryName را با Process GUID مرتبط می‌کند .

**Query نمونه:**
```kql
DeviceEvents
| where ActionType == "DnsQueryResponse"
| where InitiatingProcessGuid == "GUID_FROM_STEP_2"
| project Timestamp, QueryName, InitiatingProcessFileName
```

این Query نشان می‌دهد که Process مسئول، به کدام Domain متصل شده است. اگر Domain **ناشناخته** یا **DGA-style** باشد، شک ما به Exfiltration قطعی‌تر می‌شود.

### 🕵️ گام چهارم: تحلیل رفتار (مخصوص DNS Tunneling)

اگر ترافیک از **DNS** برای Exfiltration استفاده کرده باشد، باید الگوهای خاص را بررسی کنیم. علائم کلیدی شامل **Subdomainهای طولانی (بیش از 50 کاراکتر)**، **Entropy بالا (بالای 4.0)**، و **تعداد زیاد Subdomain یکتا تحت یک Domain** است .

**Query نمونه برای DNS Tunneling (Splunk):**
```splunk
index=dns
| rex field=query "^(?<subdomain>[^.]+)\.(?<domain>.+)$"
| eval sub_len = len(subdomain)
| where sub_len > 50
| stats dc(query) as UniqueSubdomains, count by src_ip, domain
| where UniqueSubdomains > 50
```

این Query نشان می‌دهد که یک Host داخلی، تعداد زیادی Subdomain طولانی و یکتا را به یک Domain خارجی ارسال کرده است که **الگوی کلاسیک DNS Tunneling** است .

### 🧠 گام پنجم: تعیین حساسیت داده (Context)

حالا باید بفهمیم **چه داده‌ای** منتقل شده است. اینجا نیاز به **Correlation** با **File Access Logs** داریم. اگر Process مسئول (مثلاً `rclone.exe`) بلافاصله قبل از ارسال، به **پوشه‌های حساس** (مثل Finance, HR, IP) دسترسی داشته، احتمال سرقت داده بالا می‌رود.

**Query نمونه (Event ID 4663 در Windows):**
```kql
SecurityEvent
| where EventID == 4663
| where ObjectName has_any ("Finance", "HR", "Confidential")
| where Account == "Compromised_Account"
| where TimeGenerated between (Time_Of_Transfer - 1h .. Time_Of_Transfer)
| project TimeGenerated, ObjectName, Account, ProcessName
```

اگر Process Exfiltration (مثل `rclone.exe`) با Process File Access یکی باشد، این **زنجیره علیت** را تأیید می‌کند.

### 📝 جمع‌بندی: پاسخ در مصاحبه

برای فهمیدن اینکه چه داده‌ای، از کدام Process و به کدام مقصد منتقل شده، **سه لایه** را به هم وصل می‌کنم:

**اول، از Network Flow** (Zeek/NetFlow) شروع می‌کنم و **مقصد** و **حجم Outbound** را پیدا می‌کنم. یک Query با `orig_bytes > 50MB` از Host داخلی به IP خارجی، کاندیداهای Exfiltration را مشخص می‌کند .

**دوم، از Sysmon Event ID 3** استفاده می‌کنم تا بفهمم **کدام Process** این ترافیک را ایجاد کرده. فیلد `Image` و `ProcessGuid` را استخراج می‌کنم .

**سوم، از Sysmon Event ID 22** برای دیدن **DNS Query** همان Process استفاده می‌کنم تا **Domain مقصد** را بفهمم .

اگر Domain **مشکوک** یا **DGA-style** باشد، الگوهای **DNS Tunneling** را بررسی می‌کنم: **طول Subdomain بالای 50**، **Entropy بالای 4.0**، و **تعداد Subdomain یکتا بالای 50** .

**محدودیت اصلی:** اگر ترافیک **HTTPS Encrypted** باشد، فقط IP را می‌بینیم و برای فهمیدن Domain باید به **Sysmon EID 22** تکیه کنیم. اگر **DoH** فعال باشد، حتی DNS Query هم قابل مشاهده نیست .
