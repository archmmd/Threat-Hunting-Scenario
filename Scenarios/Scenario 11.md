# سناریوی Threat Hunting: Kerberos Authentication مشکوک دیده‌ای

در این سناریو، هدف من فقط پیدا کردن یک رویداد Kerberos غیرعادی نیست؛ می‌خواهم مشخص کنم آیا با سوءاستفاده از Ticket، سرقت اعتبارنامه، جعل Ticket یا فعالیت عادی احراز هویت در Active Directory مواجه هستم.

نکته‌ی کلیدی برای مصاحبه‌ی SOC T2: دیدن یک Event ID مثل `4769` به‌تنهایی نشانه‌ی حمله نیست. باید نوع Ticket، حساب درخواست‌کننده، سرویس مقصد، الگوی زمانی و شواهد Endpoint را بررسی کنم.

## 1. Hunt Objective & Hypothesis — هدف و فرضیه

فرضیه‌های اولیه‌ی من عبارت‌اند از:

- H1 — Kerberos Ticket Abuse: استفاده‌ی غیرعادی از TGT یا TGS، یا احتمال سوءاستفاده از Ticket سرقت‌شده.
- H2 — Kerberoasting: درخواست غیرعادی Service Ticket برای حساب‌های سرویس با هدف آفلاین‌کردن حدس رمز عبور.
- H3 — Golden Ticket / Silver Ticket: احتمال جعل TGT یا Service Ticket.
- H4 — Legitimate Authentication: رفتار عادی سرویس‌ها، کاربران، Scheduled Tasks یا تغییرات عملیاتی.

باید ابتدا بفهمم دقیقاً چه چیزی مشکوک بوده است: تعداد زیاد درخواست‌های Ticket، حساب سرویس غیرمعمول، نوع Encryption، مبدأ جدید یا الگوی دسترسی غیرعادی به سرویس‌ها.

## 2. Telemetry & Data Sources — چه Logهایی را بررسی می‌کنم؟

[Trimarc Research: Detecting Kerberoasting Activity](https://images.openai.com/static-rsc-4/thVUHrqQcLS9P_z7G-gwdhPuOvQnMxFGjPek6ZdBBl5PkrQJNE8C9UN-X_anWoOYEPmwWg4ooFYL0lPrV3bLhKCCerLpblgV5pbtbKCGw9Kw9eLmPej-B-Q8e7DQuZVQ6JMW6GveuOwuskTkb78wEfeZyHQNnICv1iryKyXasyE?purpose=inline)

۱. Domain Controller — Windows Security Logs

- `4768`: درخواست TGT از Kerberos Authentication Service.
- `4769`: درخواست Service Ticket یا TGS.
- `4770`: تمدید Service Ticket.
- `4771`: شکست Pre-Authentication در Kerberos.
- `4624` و `4625`: ورود موفق یا ناموفق روی سیستم‌هایی که رویدادهای مربوط را ثبت کرده‌اند.

این رویدادها کمک می‌کنند بفهمم چه حسابی، چه زمانی و برای کدام سرویس درخواست احراز هویت داشته است.

[Microsoft Defender para Ponto de Extremidade linha do tempo de dispositivos - Microsoft Defender for Endpoint | Microsoft Learn](https://images.openai.com/static-rsc-4/7bMHuIbI4bCIGOg2yzB73rw17escjvX-t2pPUchEpjYhy_pmCXGyHgpZlGzi-qU9N1S9ZV3fNo4x6CUJq_nO5CxWvXtXZeS-KxhwQcOcKN1TrXDykCnFgoJ_Z-20xCvzZ_FJzmNHmu_pYpauf6npoP6mqPYNVqytnp-E0Rm1274?purpose=inline)

۲. Endpoint / EDR

- Process Creation، Command Line و Process Tree.
- هشدارهای مربوط به ابزارهای دست‌کاری یا استخراج Kerberos Ticket.
- فعالیت‌های مشکوک روی LSASS و دسترسی‌های غیرعادی به حافظه.
- ارتباطات شبکه و دسترسی به سرویس‌های حساس.

هدفم یافتن شواهدی است که درخواست Kerberos را به رفتار مشخصی روی Endpoint مرتبط کند.

[KRBTGT Password Reset  - Daniel Donda](https://images.openai.com/static-rsc-4/mjEg640kNuQPf1RAr8h5qqCDBvcrAROA82BqjnIyF5xZmnHqHS2hikcIQlggm4kz_1XZjyf8nFzyKI2uL3Z63sn0d6o_Whg8atDufqc_AQ4j7rKN0DvWEN_TZedl6SSckAAzpJ7npvXocdRlgxJmcztjvdu9RcWFqaMjcYoNyUM?purpose=inline)

۳. Active Directory و اطلاعات حساب‌ها

- نوع حساب و عضویت در گروه‌های حساس.
- Service Principal Name یا `SPN` حساب‌های سرویس.
- تغییرات رمز عبور، مجوزها و تنظیمات حساب.
- مالک سرویس و الگوی معمول استفاده از آن.

این اطلاعات برای تشخیص تفاوت رفتار عادی از فعالیت مشکوک ضروری است.

### چهار Event ID مهم را از هم تفکیک کن

| Event ID | مفهوم                            | نشانه‌ای که بررسی می‌کنم                         |
| -------- | -------------------------------- | ------------------------------------------------ |
| `4768`   | درخواست TGT                      | درخواست‌های غیرمعمول برای دریافت Ticket اولیه    |
| `4769`   | درخواست TGS                      | تعداد یا نوع غیرعادی درخواست‌ها برای سرویس‌ها    |
| `4770`   | تمدید TGS                        | الگوی تمدید غیرمنتظره یا ناسازگار با Baseline    |
| `4771`   | شکست Kerberos Pre-Authentication | تلاش‌های ناموفق مکرر یا الگوی غیرعادی احراز هویت |

توجه: `4771` شکست Pre-Authentication را ثبت می‌کند؛ لزوماً به معنی شکست تمام مراحل Kerberos یا اثبات حمله نیست. همچنین فیلدهای موجود در این رویدادها به نسخه‌ی ویندوز و تنظیمات Audit بستگی دارند.

## 3. Hunt Execution & Queries — اجرای Hunt

### گام اول: بررسی درخواست‌های غیرعادی Service Ticket

در Microsoft Sentinel، با Event ID `4769` شروع می‌کنم و درخواست‌های هر حساب و مبدأ را در بازه‌های زمانی مقایسه می‌کنم.

```
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4769
| summarize
    RequestCount = count(),
    ServiceCount = dcount(ServiceName),
    Services = make_set(ServiceName, 30),
    FirstSeen = min(TimeGenerated),
    LastSeen = max(TimeGenerated)
    by TargetAccount, IpAddress, bin(TimeGenerated, 15m)
| where RequestCount > 20 or ServiceCount > 10
| order by RequestCount desc
```

آستانه‌های `20` و `10` صرفاً نمونه‌اند و باید با حجم واقعی احراز هویت در سازمان تنظیم شوند.

چه چیزی را از نتیجه استخراج می‌کنم؟

- یک حساب در مدت کوتاه برای سرویس‌های متعدد Ticket درخواست کرده است؟
- آیا درخواست‌ها از مبدأیی آمده‌اند که معمولاً این حساب از آن استفاده نمی‌کند؟
- آیا حساب کاربری معمولی برای تعداد زیادی سرویس درخواست فرستاده است؟
- آیا رفتار با وظیفه‌ی حساب، ساعات کاری و الگوی معمول سیستم سازگار است؟

تعداد زیاد درخواست‌ها می‌تواند ناشی از یک برنامه‌ی عادی یا تغییر عملیاتی باشد؛ برای تشخیص Kerberoasting به بررسی دقیق‌تر نیاز دارم.

### گام دوم: بررسی Encryption Type و احتمال Kerberoasting

Kerberoasting معمولاً با درخواست Service Ticket برای حساب‌های دارای SPN مرتبط است؛ مهاجم ممکن است Ticketها را برای تلاش آفلاین جهت حدس‌زدن رمز عبور جمع‌آوری کند.

```
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4769
| extend EncType = tostring(TicketEncryptionType)
| summarize
    Requests = count(),
    Accounts = make_set(TargetAccount, 30),
    Sources = make_set(IpAddress, 20),
    EncryptionTypes = make_set(EncType, 10)
    by ServiceName, bin(TimeGenerated, 1h)
| order by Requests desc
```

در این مرحله به موارد زیر توجه می‌کنم:

- درخواست‌های پرتعداد برای Service Ticketهای حساب‌های دارای SPN.
- درخواست از حساب یا Host غیرمعمول.
- استفاده از Encryption Type ضعیف‌تر، مثل RC4، در شرایطی که با Baseline سازمان تفاوت دارد.
- تعداد سرویس‌ها و سرعت درخواست‌ها نسبت به رفتار معمول.

نکته‌ی مهم: استفاده از RC4 یا افزایش درخواست‌های `4769` به‌تنهایی اثبات Kerberoasting نیست. باید SPN، نوع حساب سرویس، مبدأ، الگوی درخواست و در صورت امکان شواهد Endpoint را هم بررسی کنم. همچنین مقادیر Encryption Type در بعضی Schemaها به صورت Hexadecimal و در برخی به شکل دیگری نمایش داده می‌شوند؛ قبل از فیلترکردن باید قالب واقعی داده را بررسی کرد.

### گام سوم: بررسی Golden Ticket، Silver Ticket و Pass-the-Ticket

این تکنیک‌ها را با یک Query ساده از هم تفکیک نمی‌کنم؛ هر کدام الگوی شواهد متفاوتی دارند.

- Golden Ticket: به دنبال نشانه‌های جعل TGT، فعالیت غیرعادی Kerberos و استفاده‌ی غیرمنتظره از دسترسی‌های سطح بالا هستم. نبودن یک رویداد `4768` متناظر، به‌تنهایی دلیل جعل نیست؛ ممکن است Ticket از قبل صادر شده باشد یا لاگ‌ها کامل نباشند.
- Silver Ticket: چون جعل Service Ticket ممکن است بدون درخواست متناظر از Domain Controller استفاده شود، علاوه بر لاگ‌های DC، رویدادهای احراز هویت روی سرور مقصد و شواهد EDR را بررسی می‌کنم.
- Pass-the-Ticket: به دنبال نشانه‌های دسترسی یا استفاده‌ی غیرعادی از Ticketهای Kerberos روی Endpoint و سپس دسترسی به سرویس‌های دیگر می‌گردم.

اگر رویدادهای `4768`، `4769` یا `4770` با فعالیت مشکوک روی Endpoint، حساب‌های ممتاز یا دسترسی‌های غیرمعمول به سرورها هم‌زمان شوند، فرضیه را دقیق‌تر بررسی می‌کنم؛ ولی صرف هم‌زمانی، رابطه‌ی علّی را ثابت نمی‌کند.

## 4. Pivoting & Evidence Correlation — همبستگی شواهد

پس از پیدا کردن درخواست Kerberos مشکوک، این مسیر را دنبال می‌کنم:

Kerberos Event مشکوک روی DC

4768 / 4769 / 4771

Account + Source IP + Service SPN

مقایسه با Baseline و نوع حساب

Endpoint و Destination Server

Process، Ticket Activity، ورود و دسترسی به سرویس

تعیین دامنه و اعتبارسنجی فرضیه

مثلاً اگر یک Workstation معمولی در مدت کوتاهی برای تعداد زیادی SPN درخواست Ticket بفرستد، سپس روی یک سرور حساس دسترسی غیرعادی دیده شود، احتمال فعالیت مخرب بیشتر می‌شود.

در این مرحله بررسی می‌کنم:

- آیا حساب درخواست‌کننده، حساب انسانی است یا Service Account؟
- آیا SPNها به سرویس‌های واقعی و مورد انتظار مربوط‌اند؟
- آیا مقصدهای بعدی با وظیفه‌ی کاربر تطابق دارند؟
- آیا EDR شواهدی از ابزارهای غیرعادی، دست‌کاری Ticket یا دسترسی به حافظه ثبت کرده است؟
- آیا فعالیت مشابه از سایر Hostها یا حساب‌ها دیده می‌شود؟

## 5. Validation & Scope — اعتبارسنجی و دامنه‌ی حمله

پیش از اعلام Incident، موارد زیر را بررسی می‌کنم:

1. Baseline: آیا این حجم و نوع درخواست Kerberos در گذشته هم دیده شده است؟
2. Account Context: آیا حساب مجوز استفاده از سرویس موردنظر را دارد؟
3. Encryption: آیا نوع رمزنگاری با تنظیمات Domain و سرویس سازگار است؟
4. DC Coverage: آیا تمام Domain Controllerهای مرتبط را بررسی کرده‌ام؟ نبود رویداد در یک DC به معنای نبود فعالیت در کل Domain نیست.
5. Endpoint Evidence: آیا نشانه‌ی مستقلی از استخراج یا دست‌کاری Ticket وجود دارد؟
6. Impact: آیا حساب به منابع حساس دسترسی پیدا کرده یا فعالیت به میزبان‌های دیگری گسترش یافته است؟

نتیجه را در سه سطح گزارش می‌کنم:

- Anomaly: الگوی Kerberos با رفتار عادی تفاوت دارد.
- Suspicious Activity: شواهد چندگانه با یک تکنیک سوءاستفاده از Kerberos سازگارند.
- Confirmed Compromise: شواهد معتبر، سوءاستفاده یا دسترسی غیرمجاز را تأیید می‌کنند.

## 6. MITRE ATT&CK Mapping

| تکنیک                         | کاربرد                                                                        |
| ----------------------------- | ----------------------------------------------------------------------------- |
| `T1558.003` — Kerberoasting   | درخواست و جمع‌آوری مشکوک Service Ticket برای تلاش آفلاین جهت حدس رمز عبور     |
| `T1558.001` — Golden Ticket   | جعل TGT با شواهد پشتیبان                                                      |
| `T1558.002` — Silver Ticket   | جعل Service Ticket با شواهد پشتیبان                                           |
| `T1550.003` — Pass the Ticket | استفاده‌ی غیرمجاز از Kerberos Ticket                                          |
| `T1558.004` — AS-REP Roasting | سوءاستفاده از حساب‌هایی که Kerberos Pre-Authentication برای آن‌ها غیرفعال است |

این نگاشت‌ها فقط زمانی در گزارش نهایی ثبت می‌شوند که شواهد با تکنیک موردنظر سازگار باشند.

## 7. Response & Detection Improvement

اگر سوءاستفاده تأیید شود یا ریسک فوری وجود داشته باشد:

- Endpoint مشکوک را طبق رویه‌ی Incident Response ایزوله می‌کنم.
- حساب‌ها و Sessionهای در معرض خطر را متناسب با نوع حمله مهار می‌کنم.
- در صورت احتمال جعل یا سرقت Ticket، صرفاً تغییر رمز عبور را راهکار کافی فرض نمی‌کنم؛ اقدام مناسب به نوع Ticket و کلید یا حساب در معرض خطر بستگی دارد.
- حساب‌های سرویس، مجوزها، SPNها و سیستم‌های مقصد را بررسی می‌کنم.
- Detection را بر پایه‌ی ترکیب رفتار حساب، مبدأ، SPN، Encryption Type، نرخ درخواست و فعالیت Endpoint بهبود می‌دهم.

هدف این است که Detection به یک Event ID یا یک Encryption Type محدود نشود و رفتارهای مشروع سرویس‌ها نیز به‌اشتباه Incident تلقی نشوند.

## پاسخ کوتاه برای شروع جواب در مصاحبه

اگر Kerberos Authentication مشکوک ببینم، ابتدا لاگ‌های Domain Controller را بررسی می‌کنم؛ به‌ویژه Event IDهای 4768 برای درخواست TGT، 4769 برای درخواست Service Ticket و 4771 برای شکست Pre-Authentication.

سپس حساب درخواست‌کننده، Source IP، سرویس مقصد یا SPN، Encryption Type و تعداد درخواست‌ها را با Baseline مقایسه می‌کنم. اگر درخواست‌های غیرمعمول برای سرویس‌های متعدد مشاهده شود، احتمال Kerberoasting را بررسی می‌کنم؛ و اگر نشانه‌هایی از استفاده‌ی غیرعادی از Ticket یا دسترسی به سرورهای حساس وجود داشته باشد، فرضیه‌های Golden Ticket، Silver Ticket یا Pass-the-Ticket را متناسب با شواهد بررسی می‌کنم.

در مرحله‌ی بعد، لاگ‌های Endpoint و سرور مقصد را با رویدادهای Domain Controller هم‌بسته می‌کنم تا مشخص شود آیا رفتار مشکوک به دسترسی غیرمجاز یا Lateral Movement منجر شده است.

نکته‌ی مهم این است که یک Event ID یا Encryption Type به‌تنهایی حمله را اثبات نمی‌کند. نتیجه‌گیری باید بر اساس Baseline، همبستگی شواهد و اعتبارسنجی فعالیت مجاز باشد.
