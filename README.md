# Phishing Detector by ApexSec

منصة عربية لكشف التصيد الإلكتروني: فحص الروابط والرسائل والملفات، ومساعد ذكي (CyberBot)، مع حسابات مستخدمين وخطة مجانية وخطة Pro مدفوعة.
مشروع فريق ApexSec، جامعة تكريت، كلية علوم الحاسوب والرياضيات، قسم الأمن السيبراني.

> الفحص يعتمد على قواعد وخوارزميات (Heuristics) وقوائم تهديدات عامة وعمر النطاق. هو ليس مضاد فيروسات، وغياب المؤشرات لا يثبت أن الهدف آمن.

## ما الذي يقدّمه الموقع

| | المجانية | Pro (2$ شهرياً) |
|---|---|---|
| الفحوصات اليومية (روابط + رسائل + ملفات) | 20 | حتى 1000 |
| رسائل CyberBot اليومية | 10 | حتى 200 |
| قوائم التهديدات (OpenPhish و URLhaus) | ✓ | ✓ |
| فحص عمر النطاق (RDAP) | | ✓ |
| الفحص الجماعي (50 رابطاً) + CSV | | ✓ |
| سجل الفحوصات بالحساب | | ✓ |
| مفتاح API | | ✓ |

- **كل حساب جديد يحصل على أول شهر Pro مجاناً** (مرة واحدة لكل حساب).
- أول صفحة يراها الزائر هي **تسجيل الدخول**. الدخول بالبريد وكلمة السر، أو عبر **Google** و**Microsoft** و**Apple** (كل زر يظهر فقط إذا ضبطت متغيراته).
- **الدفع بالماستر كارد (Qi Card) فقط:** Paddle و Lemon Squeezy و Stripe لا تقبل بائعين من العراق، لذلك المشترك يحوّل إلى بطاقتك ويكتب رقم العملية من صفحة «حسابي واشتراكي». أنت توافق من لوحة الأدمن فيتفعّل اشتراكه تلقائياً.

## هيكل المشروع

```
server.js              نقطة التشغيل وربط الوحدات وبوابة الدخول
server/
  config.js              كل الإعدادات من متغيرات البيئة
  db.js                  القاعدة: Upstash Redis (إنتاج) أو ذاكرة (تجربة محلية)
  users.js               الحسابات، كلمات السر (scrypt)، الجلسات، الحصص، طلبات الدفع، مفاتيح API
  oauth.js               الدخول عبر Google / Microsoft / Apple (OIDC + PKCE + state + nonce)
  auth.js                مسارات الدخول والحساب والاشتراك
  plans.js               الخطط والأسعار والحدود (عدّلها هنا)
  scan.js                واجهات الفحص على الخادم + API لمشتركي Pro
  intel.js               قوائم التهديدات و RDAP (عمر النطاق)
  chat.js                CyberBot (أي مزوّد متوافق مع OpenAI)
  admin.js + admin/      لوحة الأدمن: المستخدمون، طلبات الدفع، الإيرادات، الصحة، سجل الأحداث
  http.js, rate-limit.js, stats.js, health.js, visitors.js, static.js, totp.js, upstash.js
public/
  login.html             صفحة الدخول
  index.html             التطبيق (للمسجّلين فقط)
  js/ detection-engine.js (المحرك، يعمل بالخادم والمتصفح)، app.js، account.js، login.js، error-guard.js
  css/ style.css (المظاهر)، auth.css (الدخول والحساب)
tools/make-admin.js      إنشاء حساب أدمن
tests/                   الاختبارات (npm test)
```

## التشغيل محلياً

```bash
npm start      # http://localhost:8080  (الحسابات بالذاكرة، تضيع عند الإيقاف)
npm test       # كل الاختبارات
```

يحتاج Node.js 20 أو أحدث. لا توجد أي مكتبات خارجية.

## الإعداد على Render (مرة واحدة)

### 1. قاعدة البيانات (إلزامية)
بدونها الحسابات والاشتراكات **تضيع عند كل نشر**.
1. أنشئ حساباً مجانياً على upstash.com ثم **Create Database** (Redis)، واختر منطقة قريبة من Render (Oregon).
2. من تبويب REST API انسخ `UPSTASH_REDIS_REST_URL` و `UPSTASH_REDIS_REST_TOKEN` وضعهما بمتغيرات Render.

### 2. عنوان الموقع
`APP_URL=https://اسم-خدمتك.onrender.com` (بدون / بالنهاية). يُستخدم لروابط الدخول عبر Google/Microsoft/Apple.

### 3. الأدمن
```bash
npm run make-admin -- musab
```
ضع سطر `ADMINS=...` الناتج بمتغيرات Render، وأضف السر لتطبيق المصادقة، ثم افتح `/admin`.

### 4. CyberBot (الذكاء الاصطناعي)
أي مزوّد متوافق مع OpenAI. أسهل خيار مجاني: Gemini.
- **Gemini:** أنشئ مفتاحاً من Google AI Studio ثم `GEMINI_API_KEY=...` فقط (النموذج الافتراضي `gemini-2.5-flash`، وتقدر تغيّره بـ `AI_MODEL`).
- **OpenAI:** `AI_API_KEY=sk-...` و `AI_MODEL=...`
- **غيرهم (Groq, OpenRouter...):** `AI_API_KEY`, `AI_MODEL`, `AI_BASE_URL`

إذا تعطّل المزوّد يرد البوت بإجابة محلية (ويفحص الروابط دائماً)، وسبب العطل الدقيق يظهر بلوحة الأدمن ضمن «آخر عطل بمزوّد CyberBot».

### 5. الدفع
| المتغير | مثال |
|---|---|
| `PAY_QICARD` | رقم بطاقة الماستر كارد (Qi Card) لاستلام الدفع |
| `CONTACT_WHATSAPP` | 9647xxxxxxxxx (بدون +) |
| `CONTACT_TELEGRAM` | اسم المستخدم |
| `PAYMENT_NOTE` | تعليمات إضافية تظهر للمشترك |
| `PRICE_USD` / `PRICE_IQD` / `TRIAL_DAYS` | 2 / 3000 / 30 (الافتراضي) |

**طريقة العمل:** المشترك يحوّل ويرسل رقم العملية ← يظهر الطلب بلوحة الأدمن ← تتأكد أن المبلغ وصل فعلاً ← «موافقة وتفعيل» ← يتمدد اشتراكه تلقائياً. تقدر أيضاً تمنح Pro يدوياً أو توقف أي حساب.

### 5.5 تأكيد البريد (موصى به بشدة)
بدونه أي شخص يقدر يسجّل ببريد وهمي. معه: لا دخول قبل الضغط على رابط التأكيد، والشهر المجاني يبدأ عند التأكيد، ويُرفض البريد المؤقت (mailinator وأمثاله)، ويُعدّ `a.b@gmail.com` و`ab+x@gmail.com` نفس الصندوق، والشهر المجاني مرة واحدة لكل صندوق حتى لو حُذف الحساب. ويفعّل أيضاً «نسيت كلمة السر» بالبريد.
1. أنشئ حساباً مجانياً في brevo.com ← Senders & IP ← Senders ← أضف بريدك ووثّقه (رابط يصلك).
2. من SMTP & API ← API Keys أنشئ مفتاحاً (v3).
3. في Render: `BREVO_API_KEY` (المفتاح) و`MAIL_FROM` (البريد الموثَّق) و`MAIL_FROM_NAME` اختياري.
لوحة الأدمن تعرض حالة البريد وآخر عطل. بدون هذه المتغيرات يبقى التسجيل يعمل بدون تأكيد.
(بديل: `RESEND_API_KEY` لكنه يلزمه نطاق خاص موثّق.)

### 6. الدخول عبر Google / Microsoft / Apple (اختياري)
عنوان الرجوع (Redirect URI) لكل مزوّد: `APP_URL/auth/<google|microsoft|apple>/callback`

- **Google** (مجاني): Google Cloud Console ← APIs & Services ← Credentials ← OAuth client ID (Web application). أضف عنوان الرجوع، ثم `GOOGLE_CLIENT_ID` و `GOOGLE_CLIENT_SECRET`. اضبط شاشة الموافقة (OAuth consent screen) واجعلها In production.
- **Microsoft** (مجاني): Azure Portal ← App registrations ← New registration ← «Accounts in any organizational directory and personal Microsoft accounts». أضف عنوان الرجوع (Web)، وأنشئ Client secret، ثم `MICROSOFT_CLIENT_ID` و `MICROSOFT_CLIENT_SECRET`.
- **Apple** (يحتاج Apple Developer بـ 99$ سنوياً): أنشئ Services ID وفعّل Sign in with Apple وأضف النطاق وعنوان الرجوع، وأنشئ Key من نوع Sign in with Apple. ثم `APPLE_CLIENT_ID` (الـ Services ID)، `APPLE_TEAM_ID`، `APPLE_KEY_ID`، `APPLE_PRIVATE_KEY` (محتوى ملف .p8 كاملاً).

### 7. Render
- النوع: Docker. Health Check Path: `/healthz`.
- الخطة المجانية تنام بعد الخمول (أول طلب قد يتأخر نحو 30 ثانية).

## نسيان كلمة السر
مع تفعيل البريد (القسم 5.5) يضغط المستخدم «أرسل لي رابطاً على بريدي» في صفحة الدخول. بدونه: من لوحة الأدمن تضغط «رابط كلمة سر» بجانب حسابه وترسله له. الرابط صالح ساعة ولمرة واحدة في الحالتين.

## واجهة API (Pro)
المشترك ينشئ مفتاحاً من صفحة حسابه:
```bash
curl -X POST https://موقعك/api/v1/scan-url -H "Authorization: Bearer pd_..." -H "Content-Type: application/json" -d '{"url":"https://fasebook.com"}'
curl -X POST https://موقعك/api/v1/scan-url -H "Authorization: Bearer pd_..." -H "Content-Type: application/json" -d '{"urls":["https://a.com","https://b.com"]}'
curl -X POST https://موقعك/api/v1/scan-text -H "Authorization: Bearer pd_..." -H "Content-Type: application/json" -d '{"text":"..."}'
```

## الأمان
- كلمات السر مشفّرة بـ scrypt، ولا تُخزَّن الرموز السرية (الجلسات، مفاتيح API، روابط إعادة التعيين) إلا كبصمة SHA-256.
- جلسات بكوكي HttpOnly + SameSite=Lax (+ Secure و __Host- على HTTPS)، وحماية CSRF بفحص المصدر ونوع المحتوى.
- حظر مؤقت بعد محاولات دخول خاطئة (لكل عنوان ولكل بريد)، وحد يومي لإنشاء الحسابات من نفس العنوان.
- الدخول الخارجي: state لمرة واحدة مربوط بالمتصفح، PKCE، nonce، والتحقق من المُصدر والجمهور والصلاحية. البريد غير الموثّق لا يُربط بحساب موجود.
- الحصص تُفرض على الخادم، فلا يمكن تجاوزها بتعديل الصفحة.
- CSP صارم، ورؤوس أمان كاملة، والأدمن بتحقق ثنائي TOTP.
- لا يوجد نظام آمن 100%. فعّل 2FA على GitHub و Render و Upstash، ولا تضع أي مفتاح داخل الكود.

## الخصوصية
- الملفات تُحلَّل داخل متصفح المستخدم ولا تُرفع.
- الروابط والرسائل تُفحص على الخادم ولا تُحفظ، إلا بسجل حساب مشترك Pro (ويقدر يوقفه أو يمسحه).
- فحص عمر النطاق يرسل اسم النطاق فقط إلى rdap.org. قوائم التهديدات تُحمَّل للخادم ولا نرسل روابط المستخدمين لأي جهة.
- رسائل CyberBot تُرسل لمزوّد الذكاء الاصطناعي لتوليد الرد.
