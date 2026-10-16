تحلیل Zeek یا Suricata
چند Alert شبکه‌ای داری، اما هیچ‌کدام به‌تنهایی برای اثبات Incident کافی نیستند.
چطور DNS، HTTP، TLS، Flow و Alertهای IDS را Correlate می‌کنی و شواهد را به Endpoint نسبت می‌دهی؟

برای پاسخ به این سوال، باید از یک رویکرد **لایه‌ای و مبتنی بر Pivot** استفاده کنی. چند Alert شبکه‌ای به‌تنهایی کافی نیستند چون هر کدام فقط یک تکه از پازل را نشان می‌دهند. راه‌حل، اتصال این تکه‌ها از طریق **شناسه‌های 
مشترک** و در نهایت **نسبت دادن آن‌ها به یک Process روی Endpoint** است.

### 🧩 گام اول: استفاده از Community ID به‌عنوان کلید اتصال

مهم‌ترین ابزار برای Correlate کردن داده‌های شبکه با Endpoint، **Community ID** است. این یک **هش استاندارد و یکتا** برای هر Connection است که از روی Source IP/Port، Destination IP/Port و Protocol محاسبه می‌شود .

نکته کلیدی این است که **Zeek و Suricata به‌صورت بومی Community ID را در لاگ‌های خود دارند**. از طرف دیگر، **Sysmon (Event ID 3)** این فیلد را ندارد، اما می‌توان آن را **از روی فیلدهای موجود در رویداد Sysmon (SourceIp, SourcePort, DestinationIp, DestinationPort, Protocol) به‌صورت Retroactive محاسبه کرد** . این کار باعث می‌شود یک **Join Key** مشترک بین داده‌های شبکه و Endpoint داشته باشی.

### 🔍 گام دوم: Pivot درون لاگ‌های شبکه (Zeek/Suricata)

اول باید Alertهای Suricata را با لاگ‌های Zeek گره بزنی. Zeek لاگ‌های غنی‌تری از لایه‌های مختلف (DNS, HTTP, TLS, Conn) تولید می‌کند .

**سناریو:** یک Alert از Suricata داری که به یک IP مقصد خارجی اشاره می‌کند. اما نمی‌دانی این IP برای چه Domain یا چه سرویسی است.

**راه‌حل:** از **UID** موجود در لاگ‌های Zeek استفاده کن. یک Connection در `conn.log` یک UID منحصربه‌فرد دارد. همین UID در لاگ‌های دیگر مثل `dns.log`، `http.log` و `ssl.log` هم تکرار می‌شود . با این UID می‌توانی مسیر کامل را بازسازی کنی:

1.  **از conn.log به dns.log:** ببین این Connection از چه **DNS Query**ای ناشی شده است. آیا Domain مشکوک است؟ آیا TTL غیرعادی دارد؟ 
2.  **از conn.log به ssl.log:** اگر ترافیک HTTPS است، فیلد **`server_name` (SNI)** را ببین. این فیلد حتی در TLS Encrypted هم به‌صورت Plaintext ارسال می‌شود و نام واقعی سرور را فاش می‌کند .
3.  **از ssl.log به تحلیل JA3:** در `ssl.log`، فیلد **`ja3`** را استخراج کن. این یک Fingerprint از ClientHello است. یک JA3 غیرعادی که شبیه مرورگرهای معمول نیست، نشانه‌ای قوی از یک **ابزار خودکار یا Malware** است .

### 🧠 گام سوم: نسبت دادن شواهد به Process روی Endpoint

حالا که یک Connection مشکوک را در سطح شبکه شناسایی کردی، باید بفهمی **کدام Process** روی Host مسئول آن است.

**راه‌حل:** از **Community ID** استفاده کن.

1.  در لاگ Zeek (مثلاً `ssl.log`)، مقدار Community ID را بردار.
2.  در Sysmon (Event ID 3)، همان مقدار Community ID را محاسبه کن .
3.  حالا می‌توانی رویداد Sysmon را با **Process GUID** آن Join کنی و به Sysmon (Event ID 1) بروی تا **Command Line**، **Parent Process** و **User** را ببینی.

**نتیجه نهایی:** یک زنجیره علیت کامل داری:
`Suricata Alert` -> `Zeek UID` -> `Community ID` -> `Sysmon Event ID 3` -> `Sysmon Event ID 1 (Process Creation)`

### 🛡️ گام چهارم: مدیریت False Positive و Correlation تصادفی

**مشکل:** ممکن است یک IP یا Domain به‌دلیل **Shared Infrastructure** (مثل CDN یا Cloud Provider) در Alertهای متعدد ظاهر شود.

**راه‌حل:**
*   **مقایسه با Baseline:** از روش‌هایی مثل **PEAK** استفاده کن که ابتدا رفتار نرمال را Baseline می‌گیرد و سپس انحرافات آماری را شناسایی می‌کند. اگر این Connection در Baseline قبلی وجود نداشته، مشکوک‌تر است .
*   **تحلیل JA3 در طول زمان:** به‌جای اعتماد به یک JA3 مشکوک، تغییرات JA3 یک Source IP را در طول زمان رصد کن. اگر یک Endpoint ناگهان JA3 خود را تغییر دهد، ممکن است نشانه **Tooling Change** باشد .
*   **ترکیب شواهد:** هرگز به یک Alert تنها اتکا نکن. ترکیب **JA3 غیرعادی + SNI مشکوک + Self-Signed Certificate + Beaconing Pattern** شواهد بسیار قوی‌تری از یک Connection قانونی است .

### 💎 جمع‌بندی

برای Correlate کردن Alertهای شبکه و نسبت دادن آن‌ها به Endpoint، **Community ID** را به‌عنوان ستون فقرات کارت استفاده کن . در سطح شبکه، از **UID** در Zeek برای Pivot بین پروتکل‌ها (DNS, TLS, HTTP) استفاده کن . در سطح Endpoint، **Community ID** را به Sysmon (Event ID 3) متصل کن تا به **Process Creator** برسی . و برای کاهش False Positive، همیشه **Baseline** و **ترکیب چند شواهد** (مثل JA3 + SNI + Timing) را در نظر بگیر .

**محدودیت اصلی:** اگر **Sysmon (Event ID 3)** روی Endpoint فعال نباشد، نمی‌توانی Connection را به Process نسبت دهی. همچنین اگر **TLS 1.3 با ECH** استفاده شود، JA3/SNI کارایی خود را از دست می‌دهند .
