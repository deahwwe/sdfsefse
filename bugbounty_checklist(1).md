
# Bug Bounty Checklist 🛡️

## 1. Recon 🔍

- [Subdomain Finder](https://subdomainfinder.c99.nl/)
- `subfinder -d ucartz.com`
- `assetfinder --subs-only ucartz.com`
- `subzy run --targets all.txt`  # Subdomain takeover tool
- [Dedupelist - حذف التكرار](https://dedupelist.com/)
- `cat domains.txt | httpx`

## 2. إدارة الجلسات (اختبار المستخدمين) 🛡️

- اختبار تجاوز المصادقة
- اختبار الحماية من هجمات القوة الغاشمة
- اختبار قواعد جودة كلمة المرور
- اختبار وظيفة "تذكرني"
- اختبار الإكمال التلقائي لنماذج/إدخال كلمات المرور
- اختبار إعادة تعيين كلمة المرور و/أو استعادتها
- اختبار عملية تغيير كلمة المرور
- اختبار CAPTCHA
- اختبار المصادقة متعددة العوامل
- اختبار وجود وظيفة تسجيل الخروج
- اختبار عمليات تسجيل الدخول الافتراضية
- اختبار سجل المصادقة الذي يمكن للمستخدم الوصول إليه
- التحقق من إنهاء الجلسة بعد تسجيل الخروج
- اختبار مشاكل التحكم في الوصول العمودي (تصعيد الامتيازات)
- اختبار مشاكل التحكم في الوصول الأفقي (بين مستخدمين بنفس مستوى الامتياز)

## 3. استخراج الروابط 🔗

### Arjun

- `arjun -u https://example.com`
- `arjun -u https://example.com -o params.json`
- `arjun -i urls.txt`
- `arjun -u https://example.com -q -oJ params.json`

### FUZZ

- `ffuf -w common.txt -u https://dev.ucartz.com/FUZZ`
- `ffuf -w ~/wordlists/parameters.txt -u http://ffuf.me/cd/param/data?FUZZ=1 -mc 200`
- `ffuf -w common.txt -recursion -u https://dev.ucartz.com/FUZZ -mc 200`

### Waybackurls

- `cat domains.txt | waybackurls > urls`

## 4. Google Dorks 🔎

- [Dorks by Faisal Ahmed](https://dorks.faisalahmed.me/)
- GitHub Backups
- robots.txt, sitemap.xml, .DS_Store

## 5. Burp Suite Scan 🛠️

- تنفيذ فحص شامل باستخدام Burp Suite.

## 6. تجاوز المصادقة الثنائية (Bypass 2FA) 🔐

- التخمين عبر Burp Suite ([رابط الشرح](https://youtu.be/LYDTnkCurU0?t=347))
- تخطي المصادقة بالانتقال المباشر ([رابط الشرح](https://youtu.be/LYDTnkCurU0?t=620))
- استخدام أداة JSFScan.sh
- تغيير القيم داخل Burp ([رابط الشرح](https://youtu.be/LYDTnkCurU0?t=174))
  - `false ==> true`
  - `1 ==> 0`
  - `0 ==> 1`
- تسريب كود المصادقة ([رابط الشرح](https://youtu.be/LYDTnkCurU0?t=279))
- تغيير الكوكيز بعد نجاح تحقق.

> **ملاحظة:** هذه القائمة قابلة للتوسيع حسب التطبيق أو البنية التحتية. 🎯
