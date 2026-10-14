# سناریوی Threat Hunting: احتمال Credential Theft وجود دارد؛ چه Logهایی را بررسی می‌کنی؟

در این سناریو، صرفاً دنبال Login مشکوک نیستم؛ می‌خواهم مشخص کنم اعتبارنامه چگونه ممکن است سرقت شده باشد، آیا مهاجم از آن استفاده کرده و آیا به سیستم‌های دیگری هم دسترسی پیدا کرده است.

یک نکته‌ی مهم برای مصاحبه‌ی SOC T2: هیچ Event ID واحدی وجود ندارد که به‌تنهایی Credential Theft را ثابت کند. باید شواهد Endpoint، احراز هویت، شبکه و هویت سازمانی را به هم مرتبط کنم.

## 1. Hunt Objective & Hypothesis

فرضیه‌ها را به چهار مسیر تقسیم می‌کنم:

- Credential Dumping: استخراج اعتبارنامه یا مواد احراز هویت از حافظه یا سیستم.
- Credential Phishing / Theft: سرقت رمز عبور یا Token از طریق فیشینگ، بدافزار یا سرقت Session.
- Credential Misuse: استفاده از اعتبارنامه‌ی سرقت‌شده برای ورود به سیستم.
- Lateral Movement: استفاده از دسترسی اولیه برای ورود به سرورها یا حساب‌های دیگر.

این مسیرها ممکن است با هم رخ دهند؛ مثلاً مهاجم ابتدا روی یک Workstation به اعتبارنامه دست پیدا کند و بعد با حساب Admin به سرور دیگری وارد شود.

## 2. Telemetry & Data Sources — کدام Logها را بررسی می‌کنم؟

[100SECURITY](https://images.openai.com/static-rsc-4/m0a4xq0T9kDXjMSgwpxpOBwZMQBhbIGTu0fFNZ2OxXY1gyi0ctFs37r7T5Fz-_0Q9xa994hvxCJuUoNnvWHNd5kQ1XzbgUncMuv9jZswdzC7IqNaipl2SiZaPhFqEv7AT42h7GdF0cpZZA9qJzqnBlyr9N0zCOCCqdyw0bv4QlA?purpose=inline)

۱. Windows Security Logs — احراز هویت

مهم‌ترین Eventها:

- `4624`: ورود موفق؛ مبدأ، Logon Type و حساب مقصد.
- `4625`: ورود ناموفق؛ بررسی الگوهای تلاش مکرر.
- `4648`: استفاده از Explicit Credentials.
- `4672`: اختصاص Privilegeهای حساس به Session.
- `4768` و `4769`: درخواست Kerberos TGT و Service Ticket در Domain Controller.
- `4776`: اعتبارسنجی NTLM، در صورت استفاده از این روش.

دنبال چه چیزی هستم؟ ورود از مبدأ جدید، استفاده‌ی غیرمعمول از حساب Admin، الگوی احراز هویت متفاوت و دسترسی به سرویس‌های غیرمنتظره.

[Here’s Why Process Explorer Is Still the Best For Task Management on Windows - Make Tech Easier](https://images.openai.com/static-rsc-4/rdIThJKh7rKLWBPFj2Fd1wMRb8YuMis5-KLUtjROtrMLLv6UP4rfnuvaW3djzJtCwcFpWH9kaxqRgd708h2ygSgTlIO1pYaaBKlheQAbtiVVWmDgw4SegL8BUe5s5R6QQGlw70kuzRYJX8kUObqcwQAFBCrdvZRWgmQs2wLWm6k?purpose=inline)

۲. Endpoint / EDR — احتمال سرقت اعتبارنامه روی میزبان

- `4688`: ایجاد Process در Windows Security Log.
- Sysmon Event ID `1`: ایجاد Process و اطلاعات Parent Process.
- Sysmon Event ID `10`: دسترسی یک Process به Process دیگر؛ در صورت فعال بودن پیکربندی مربوطه.
- Sysmon Event ID `7`: بارگذاری Image یا DLL، در صورت فعال بودن.
- لاگ‌های EDR درباره‌ی دسترسی به حافظه، رفتارهای Credential Dumping و هشدارهای مربوط به LSASS.

دنبال چه چیزی هستم؟ Process غیرمعمولی که به LSASS دسترسی پیدا کرده، ابزارهای مشکوک استخراج اعتبارنامه، اجرای فرمان غیرمنتظره یا زنجیره‌ی Processهایی که با رفتار سرقت اعتبارنامه سازگارند.

[🔍 Day 1: Introduction to Log Analysis Getting Started Like a SOC Analyst! | by Rishav kumar Thapa | Medium](https://images.openai.com/static-rsc-4/0pgOmQyRuFfxtBzjRpeVFTDzPHucUHwIZuPhe7pIMq8hKJXofJizWsx_FO91aFgAfBJ3Ml1JVKtqZlDXoUy9B_sSEjaPzIgb4mTFjdQ4Yj350M8fQNHcGGA8YL_saNT6GFd9y182m-jne9k1OCwk-7D6eiFVvDACuJ-NP9T5DiA?purpose=inline)

۳. PowerShell و ابزارهای اجرایی

- PowerShell Operational `4104`: Script Block Logging، در صورت فعال بودن.
- PowerShell Operational `4103`: Module Logging، در صورت فعال بودن.
- `4688` و Sysmon `1`: بررسی Command Line و Parent Process، اگر جمع‌آوری شده باشد.

دنبال چه چیزی هستم؟ اجرای اسکریپت یا ابزار غیرمعمول، اجرای دستورات مرتبط با جمع‌آوری اطلاعات امنیتی و فعالیت‌هایی که با EDR Alert یا رویدادهای احراز هویت هم‌زمان شده‌اند.

[Beheben von Anmeldeproblemen bei bedingtem Zugriff - Microsoft Entra ID | Microsoft Learn](https://images.openai.com/static-rsc-4/tY5Ub2xqrI3Svs-Vp4XkbKt1wLnaUc0JecqURSbshRikjx7vHJBp8DROqqxWtPaSUGMnHY4sI7CcexiL4AcNRTe9l5QDMB_En7z5f8kmExnk935T2nFfy8S3jOiZv-jHS7UeRcPSsZ_2Vmb2gRYSWB1Z0zt19WAibZ7xNyPFbxg?purpose=inline)

۴. Identity Provider و Cloud Identity

اگر سازمان از Microsoft Entra ID یا سرویس هویت مشابه استفاده کند، این موارد را بررسی می‌کنم:

- Sign-in Logs و لاگ‌های احراز هویت ناموفق یا پرریسک.
- MFA Challenge، نتیجه‌ی MFA و تغییرات روش‌های احراز هویت.
- تغییر رمز عبور، ثبت روش MFA جدید و تغییرات مجوزها.
- Audit Logs مربوط به تغییرات حساب و دسترسی.

دنبال چه چیزی هستم؟ ورود از موقعیت یا دستگاه جدید، تغییرات غیرمنتظره‌ی هویت، MFA غیرعادی یا استفاده از Session و Token مشکوک. موفقیت MFA به‌تنهایی اصالت کاربر را تضمین نمی‌کند.

[Microsoft Windows Firewall Observability | Splunkbase](https://images.openai.com/static-rsc-4/ts305lBF-q457sPo20B1WSc4yFJ93LjHjWrQq06J6usf7ne9-16D8tEiCKwRboY3GAI3vH1Tok06aKnjunjyh6ArXxMiHk0WrdvCjkwswaaiyxpTn_cPozkLfxep_wEjXrOttmA9arm3xSuzunyms5mvOEwfoZYasUJUhuIJ1u4?purpose=inline)

۵. Network Logs — بررسی مسیر و گسترش دسترسی

- Firewall، VPN، Proxy و DNS.
- Sysmon Event ID `3` یا Network Telemetry در EDR.
- لاگ‌های RDP، SMB و WinRM در صورت وجود.

دنبال چه چیزی هستم؟ اتصال از Host مشکوک به سرورهای حساس، دسترسی راه دور پس از فعالیت مشکوک روی Endpoint و ارتباط با مقصدهای غیرمنتظره. ارتباط شبکه به‌تنهایی اثبات‌کننده‌ی سرقت اعتبارنامه نیست.

## 3. Hunt Execution — از کجا شروع می‌کنم؟

من معمولاً از Endpoint مشکوک و بازه‌ی زمانی قبل از اولین Login غیرعادی شروع می‌کنم؛ چون اگر فقط لاگ سرور مقصد را ببینم، ممکن است نشانه‌های اولیه‌ی سرقت اعتبارنامه را از دست بدهم.

### نمونه Query برای Microsoft Sentinel

ابتدا ورودهای موفق و ناموفق حساب مشکوک را بررسی می‌کنم:

```
let Account = @"CONTOSO\admin.user";
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4624, 4625, 4648, 4672)
| where TargetAccount =~ Account
| project
    TimeGenerated,
    Computer,
    EventID,
    TargetAccount,
    LogonType,
    IpAddress,
    WorkstationName,
    TargetLogonId,
    Activity
| order by TimeGenerated desc
```

این Query به Schema محیط بستگی دارد؛ ممکن است بعضی فیلدها در Connector شما وجود نداشته باشند یا `4648` با فیلدهای حساب متفاوت ثبت شده باشد. در آن صورت باید فیلتر را بر اساس فیلدهای واقعی تنظیم کنم.

بعد از پیدا کردن رویداد مشکوک، سه Pivot مهم دارم:

1. از حساب به مبدأ: این حساب پیش از Login مشکوک روی کدام Hostها استفاده شده است؟
2. از مبدأ به Process: پیش از Login، چه Process یا فعالیتی روی Endpoint مبدأ دیده شده است؟
3. از Login به مقصدهای بعدی: آیا همان حساب یا سایر حساب‌های حساس پس از آن روی سیستم‌های دیگری استفاده شده‌اند؟

### یک نکته‌ی فنی مهم درباره‌ی LSASS

اگر احتمال Credential Dumping وجود داشته باشد، به دنبال شواهد دسترسی غیرمعمول به حافظه‌ی `lsass.exe` می‌گردم؛ برای مثال Sysmon Event ID `10` یا هشدارهای EDR.

اما نبودن این رویداد، سرقت اعتبارنامه را رد نمی‌کند؛ چون ممکن است Sysmon پیکربندی نشده باشد، رویداد ثبت نشده باشد یا سرقت از روش دیگری انجام شده باشد.

همچنین دسترسی یک Process به LSASS به‌تنهایی اثبات استخراج اعتبارنامه نیست. باید Process، کاربر اجراکننده، زمان، رفتارهای مرتبط و شواهد تکمیلی را بررسی کنم.

## 4. Pivoting & Evidence Correlation — چطور شواهد را به هم وصل می‌کنم؟

فرض کنیم سه نشانه داریم:

- روی Workstation یک Process مشکوک دیده شده که به LSASS دسترسی پیدا کرده است.
- کمی بعد همان حساب Admin از آن Workstation به یک سرور حساس Login کرده است.
- پس از Login، دسترسی به سرور دیگری نیز ثبت شده است.

این زنجیره، فرضیه‌ی سرقت اعتبارنامه و استفاده از آن برای حرکت جانبی را تقویت می‌کند. با این حال، باید بررسی کنم که آیا رویدادهای Endpoint واقعاً به همان حساب و Session مربوط‌اند و آیا فعالیت مدیریتی مجازی در کار بوده است.

برای این کار زمان‌ها، نام حساب، Source IP، `TargetLogonId`، شناسه‌های Process در EDR و رویدادهای Domain Controller را هم‌بسته می‌کنم. شناسه‌های Logon در همه‌ی میزبان‌ها یکسان نیستند؛ بنابراین نباید صرفاً بر اساس یک `LogonId` مشترک در سیستم‌های مختلف نتیجه‌گیری کنم.

## 5. Validation & Scope — اعتبارسنجی و تعیین دامنه

برای اینکه مطمئن شوم فقط یک Login غیرمعمول نیست، این موارد را بررسی می‌کنم:

- آیا شواهدی از دسترسی به حافظه، ابزار Credential Dumping یا رفتار مشکوک روی Endpoint وجود دارد؟
- آیا Login با فعالیت تأییدشده‌ی ادمین یا تغییرات مجاز سازمان تطابق دارد؟
- آیا حساب‌های دیگری از همان مبدأ استفاده شده‌اند؟
- آیا پس از فعالیت مشکوک، دسترسی به سرورهای حساس، تغییر مجوزها یا ایجاد Persistence رخ داده است؟
- آیا لاگ‌ها کامل‌اند یا محدودیت Retention، تنظیمات Audit یا خاموش بودن Telemetry وجود دارد؟

در گزارش نهایی، میان نشانه‌ی سرقت اعتبارنامه، استفاده‌ی مشکوک از حساب و سرقت تأییدشده‌ی اعتبارنامه تمایز می‌گذارم.

## 6. MITRE ATT&CK Mapping

| تکنیک                                      | کاربرد در این سناریو                                                    |
| ------------------------------------------ | ----------------------------------------------------------------------- |
| `T1003.001` — LSASS Memory                 | شواهد از استخراج اعتبارنامه از حافظه‌ی LSASS پشتیبانی کنند.             |
| `T1078` — Valid Accounts                   | استفاده‌ی غیرمجاز از حساب معتبر تأیید یا به‌خوبی پشتیبانی شود.          |
| `T1550.002` — Pass the Hash                | شواهد مشخص از استفاده از Hash به‌جای اعتبارنامه‌ی عادی وجود داشته باشد. |
| `T1550.003` — Pass the Ticket              | شواهد از استفاده‌ی غیرمجاز از Kerberos Ticket پشتیبانی کنند.            |
| `T1555` — Credentials from Password Stores | شواهد استخراج اعتبارنامه از Password Store را نشان دهند.                |
| `T1021` — Remote Services                  | استفاده از سرویس راه دور برای دسترسی یا حرکت جانبی تأیید شود.           |

این تکنیک‌ها گزینه‌های بررسی هستند؛ صرف مشاهده‌ی Login مشکوک مجوز انتساب همه‌ی آن‌ها را نمی‌دهد.

## 7. Conclusion & Response — نتیجه‌گیری و واکنش

اگر شواهد سرقت اعتبارنامه قوی باشد، باید هم منشأ سرقت و هم استفاده‌های بعدی از اعتبارنامه را مهار کنم:

- Endpoint مشکوک را مطابق رویه‌ی Incident Response ایزوله می‌کنم.
- حساب یا Session در معرض خطر را متناسب با سطح ریسک محدود می‌کنم.
- رمز عبور و سایر روش‌های احراز هویت در معرض خطر را امن‌سازی می‌کنم؛ در صورت احتمال سرقت Token یا Ticket، صرفاً تغییر رمز عبور را کافی فرض نمی‌کنم.
- لاگ‌ها و شواهد EDR را حفظ می‌کنم و دامنه‌ی دسترسی مهاجم را روی سایر میزبان‌ها بررسی می‌کنم.
- Detectionها را برای ترکیب رفتار مشکوک Endpoint، رویدادهای احراز هویت و دسترسی به سیستم‌های حساس بهبود می‌دهم.

## پاسخ کوتاه برای شروع جواب در مصاحبه

اگر احتمال Credential Theft وجود داشته باشد، بررسی را از سه دسته‌ی اصلی شروع می‌کنم: Endpoint Logs، Authentication Logs و Network Logs.

در Windows Security Logs، رویدادهای 4624، 4625، 4648 و 4672 را برای بررسی الگوی ورود و استفاده از حساب بررسی می‌کنم. روی Domain Controller نیز Event IDهای 4768، 4769 و 4776 را، متناسب با روش احراز هویت، بررسی می‌کنم.

در Endpoint، به دنبال شواهد دسترسی غیرمعمول به LSASS، اجرای Processهای مشکوک، PowerShell و هشدارهای EDR مرتبط با Credential Dumping می‌گردم. سپس با لاگ‌های VPN، Firewall و Telemetry شبکه بررسی می‌کنم آیا از همان مبدأ برای دسترسی به سرورهای دیگر استفاده شده است.

در نهایت، رویدادها را بر اساس زمان، حساب، مبدأ، مقصد و شواهد Process به هم مرتبط می‌کنم و Hunt را برای شناسایی استفاده‌های بعدی از اعتبارنامه گسترش می‌دهم.

نکته‌ی مهم این است که هیچ Event ID واحدی سرقت اعتبارنامه را اثبات نمی‌کند. نتیجه‌گیری باید بر اساس همبستگی شواهد باشد و در صورت تأیید تهدید، هم منشأ سرقت و هم دسترسی‌های بعدی را مهار کنم.
