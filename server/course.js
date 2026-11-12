"use strict";

/*
  الدورة التوعوية بالمستويات، والاختبارات، والشهادات.

  - 3 مستويات (مبتدئ، متوسط، متقدم)، لكل مستوى دروس قصيرة وبنك 10 أسئلة.
  - الاختبار 5 أسئلة عشوائية بترتيب خيارات عشوائي. التصحيح على الخادم فقط (المتصفح ما يستلم الإجابات الصحيحة).
  - النجاح 4 من 5. كل مستوى يفتح اللي بعده. محاولة الاختبار تنتهي بعد 30 دقيقة وتنقبل مرة وحدة.
  - بعد المستويات الثلاثة: شهادة إتمام برقم تحقق فريد، وصفحة /verify/<رقم> تبين إذا الشهادة صحيحة.
  - الشهادة تقول بوضوح إنها إتمام دورة على المنصة، وليست معتمدة من جهة رسمية أو أكاديمية.
*/

const crypto = require("node:crypto");

const LEVELS = [
    {
        id: "beginner", title: "المستوى الأول: الأساسيات", points: 100,
        lessons: [
            { title: "شنو هو التصيد؟", body: "التصيد (Phishing) رسالة أو رابط أو اتصال يتظاهر إنه من جهة تثق بيها (مصرف، شركة اتصالات، صديق) حتى ياخذ منك كلمة سر أو رمز تحقق أو فلوس." },
            { title: "علامات الرسالة المشبوهة", body: "الاستعجال («خلال 24 ساعة»)، التهديد («راح ينقفل حسابك»)، الجوائز اللي ما شاركت بيها، طلب رمز التحقق أو كلمة السر، والروابط الغريبة." },
            { title: "القاعدة الذهبية", body: "لا ترسل رمز التحقق (OTP) لأي أحد، حتى لو قال إنه من المصرف أو الدعم الفني. والجهة الحقيقية تتصل بيك من رقمها الرسمي، وإنت تتأكد بالاتصال بيها بنفسك." }
        ],
        bank: [
            { q: "وصلتك رسالة: «تم تجميد حسابك، حدّث بياناتك خلال 24 ساعة عبر الرابط». شنو أفضل تصرف؟", options: ["أفتح الرابط بسرعة قبل ما ينقفل الحساب", "أتجاهل الرابط وأتواصل ويّا المصرف من رقمه أو تطبيقه الرسمي", "أرسل بياناتي برد على الرسالة", "أحول الرسالة لأصدقائي حتى يفتحون الرابط"], answer: 1, explain: "الاستعجال والتهديد أسلوب حتى تتصرف بدون تفكير. تأكد دائماً من القناة الرسمية." },
            { q: "شخص يتصل ويكول إنه من الدعم الفني ويطلب الرمز اللي وصلك برسالة. شنو تسوي؟", options: ["أعطيه الرمز لأنه من الدعم", "أعطيه نص الرمز بس", "ما أعطيه الرمز أبداً وأسكر الخط", "أطلب منه يتصل بعدين"], answer: 2, explain: "الرمز هو مفتاح حسابك. ولا جهة حقيقية تطلبه منك." },
            { q: "أي من هاي علامة شائعة للتصيد؟", options: ["رسالة تذكر اسمك الكامل", "وعد بجائزة بمسابقة ما شاركت بيها", "رسالة من رقم محفوظ عندك تسأل عن حالك", "إشعار من التطبيق الرسمي"], answer: 1, explain: "الجوائز الوهمية من أشهر الطُعم." },
            { q: "القفل (HTTPS) بجانب عنوان الموقع يعني:", options: ["الموقع رسمي وموثوق أكيد", "الاتصال مشفر، بس ما يثبت إن صاحب الموقع موثوق", "الموقع ما بيه فيروسات", "الموقع تابع للحكومة"], answer: 1, explain: "أغلب مواقع التصيد اليوم تستخدم HTTPS هي هم." },
            { q: "صديقك راسلك من رقم جديد: «غيرت رقمي، دزلي 50 ألف ضروري». شنو تسوي؟", options: ["أحول فوراً لأنه صديقي", "أتصل بيه على رقمه القديم أو صوتياً وأتأكد", "أطلب منه صورة هويته", "أحول نص المبلغ"], answer: 1, explain: "انتحال الأقارب والأصدقاء برقم جديد شائع. تأكد بصوته." },
            { q: "شنو أفضل طريقة تفتح بيها موقع مصرفك؟", options: ["من رابط بالرسائل", "من نتيجة إعلان ممول بالبحث", "من التطبيق الرسمي أو بكتابة العنوان بنفسك", "من رابط بالكروب"], answer: 2, explain: "الوصول المباشر يحميك من الروابط المزيفة والإعلانات المنتحلة." },
            { q: "وصلتك رسالة من «إدارة فيسبوك» تكول إن صفحتك راح تنحذف إلا إذا دخلت بياناتك. هاي غالباً:", options: ["تنبيه حقيقي لازم أتبعه", "محاولة تصيد", "تحديث عادي", "رسالة ترحيب"], answer: 1, explain: "التهديد بحذف الحساب وطلب الدخول عبر رابط هو أسلوب تصيد كلاسيكي." },
            { q: "ضغطت رابط مشبوه بس ما كتبت شي. شنو أول خطوة؟", options: ["أسكّر الصفحة وما أكمل، وأراجع إذا أعطيت أذونات", "أكتب بياناتي حتى أعرف شنو يصير", "أبلغ الكل إن جهازي اخترق", "أمسح الموبايل فوراً"], answer: 0, explain: "فتح الرابط وحده غالباً ما يضر إذا ما كتبت أو نزلت شي." },
            { q: "أي رسالة غالباً حقيقية؟", options: ["«رمز التحقق الخاص بك 482913. لا تشاركه مع أي شخص»، وإنت طلبته هسه", "«ارسل الرمز اللي وصلك حتى نفعّل الجائزة»", "«حسابك موقوف، أرسل كلمة السر للتفعيل»", "«ربحت آيفون، ادفع رسوم التوصيل»"], answer: 0, explain: "رسالة الرمز الحقيقية تحذرك ما تشاركه، وتوصل بعد ما تطلبه إنت." },
            { q: "شنو تسوي برسالة احتيال وصلتك؟", options: ["أرد عليها وأسب المحتال", "أحذفها وأبلغ عنها وأحذر أهلي", "أفتح الرابط حتى أفحصه", "أحولها لكل الكروبات بدون تعليق"], answer: 1, explain: "البلاغ والتحذير يحمي غيرك، والرد يأكد للمحتال إن رقمك فعال." }
        ]
    },
    {
        id: "intermediate", title: "المستوى الثاني: كشف الروابط والملفات", points: 150,
        lessons: [
            { title: "اقرأ الرابط صح", body: "النطاق الحقيقي هو الجزء اللي قبل أول «/» مباشرة: بالرابط paypal.com.verify-login.xyz/account النطاق هو verify-login.xyz مو paypal.com." },
            { title: "خدع الأسماء", body: "استبدال حروف بأرقام (g00gle)، حروف من لغات ثانية تشبه الإنكليزية، إضافة كلمات (paypal-secure-login)، والروابط المختصرة اللي تخفي الوجهة." },
            { title: "الملفات المتنكرة", body: "invoice.pdf.exe ملف برنامج متنكر بشكل PDF. ملفات APK من خارج المتجر، والماكرو بمستندات Office، والملفات المضغوطة اللي بيها برامج أو اختصارات: كلها طرق نشر برمجيات خبيثة." }
        ],
        bank: [
            { q: "بالرابط https://paypal.com.secure-check.top/login النطاق الحقيقي هو:", options: ["paypal.com", "secure-check.top", "login", "https"], answer: 1, explain: "النطاق هو آخر جزء قبل أول «/» بعد الاسم: secure-check.top." },
            { q: "أي رابط يستخدم استبدال حروف بأرقام؟", options: ["https://google.com", "https://g00gle.com", "https://mail.google.com", "https://accounts.google.com"], answer: 1, explain: "حرف o صار صفر (0)." },
            { q: "وصلك ملف اسمه «كشف_الرواتب.pdf.exe». شنو هو؟", options: ["ملف PDF عادي", "برنامج متنكر كـ PDF، لا تفتحه", "صورة", "ملف نصي"], answer: 1, explain: "الامتداد الحقيقي هو الأخير (.exe)، يعني برنامج." },
            { q: "مستند Word يكول لك «فعّل المحتوى (Enable Content) حتى تشوف النص». هذا:", options: ["طبيعي بكل المستندات", "أسلوب لتشغيل ماكرو خبيث، لا تفعّله", "تحديث من مايكروسوفت", "حماية من الفيروسات"], answer: 1, explain: "الماكرو من أشهر طرق نشر البرمجيات الخبيثة." },
            { q: "الرابط المختصر (bit.ly/xxxx) مشكلته إنه:", options: ["بطيء", "يخفي الوجهة الحقيقية", "دائماً خبيث", "ما يشتغل بالموبايل"], answer: 1, explain: "مو دائماً خبيث، بس يخفي الوجهة. افحصه قبل ما تفتحه." },
            { q: "شنو المشكلة بتطبيق APK من رابط بالواتساب؟", options: ["حجمه كبير", "ممكن يسرق رسائلك وحساباتك المصرفية لأنه من خارج المتجر", "ما يشتغل", "يحتاج إنترنت"], answer: 1, explain: "أغلب تطبيقات سرقة الحسابات توصل هيج." },
            { q: "ملف مضغوط (ZIP) بيه «صورة.jpg.lnk». هذا:", options: ["صورة عادية", "اختصار يشغّل أوامر على الجهاز متنكر كصورة", "ملف نصي", "ملف صوت"], answer: 1, explain: "ملفات الاختصار (.lnk) تقدر تشغل أي أمر." },
            { q: "أي امتداد نطاق يستعمله المحتالين بكثرة لأنه رخيص؟", options: [".gov.iq", ".edu.iq", ".xyz و .top", ".com.iq"], answer: 2, explain: "الامتدادات الرخيصة يرمونها بعد أيام." },
            { q: "باركود QR بملصق على طاولة مطعم يطلب منك تدفع عبر رابط. شنو تسوي؟", options: ["أدفع فوراً", "أفحص الرابط قبل ما أفتحه، وأتأكد من الموظفين إن الملصق حقيقي", "أتجاهل كل الباركودات للأبد", "أصوره وأنشره"], answer: 1, explain: "المحتالين يلصقون باركود فوق الأصلي (Quishing)." },
            { q: "موقع جديد عمره 3 أيام ويطلب بيانات بطاقتك. هذا:", options: ["طبيعي", "مؤشر خطر قوي", "علامة إنه موقع رسمي", "ما يأثر"], answer: 1, explain: "أغلب مواقع التصيد تنعمل وتستخدم خلال أيام." }
        ]
    },
    {
        id: "advanced", title: "المستوى الثالث: الحماية والاستجابة", points: 250,
        lessons: [
            { title: "التحقق بخطوتين", body: "حتى لو انسرقت كلمة سرك، التحقق بخطوتين يمنع الدخول. تطبيقات المصادقة أقوى من SMS. فعّله بالبريد أولاً لأن منه تسترجع كلشي." },
            { title: "انتحال المرسل بالإيميل", body: "الاسم الظاهر يكدر يكون أي شي. شوف العنوان الحقيقي، وReply-To، ونتائج SPF وDKIM وDMARC. فشل DMARC من أقوى مؤشرات الانتحال." },
            { title: "إذا وقعت بالفخ", body: "غيّر كلمة السر من جهاز نظيف، فعّل التحقق بخطوتين، سجّل خروج من كل الأجهزة، واتصل بمصرفك فوراً إذا الموضوع بيه فلوس، واحتفظ بالأدلة، وبلّغ." }
        ],
        bank: [
            { q: "ليش تفعيل التحقق بخطوتين بالبريد أهم من غيره؟", options: ["لأن البريد أسرع", "لأن من البريد تسترجع كلمات سر حساباتك الثانية", "لأنه مجاني", "ما مهم"], answer: 1, explain: "اللي يسيطر على بريدك يكدر يسترجع أغلب حساباتك." },
            { q: "إيميل يبين من «PayPal Security» بس Reply-To لعنوان على نطاق ثاني. هذا:", options: ["طبيعي", "مؤشر انتحال: ردك يروح للمحتال", "تحديث أمني", "خطأ تقني بسيط"], answer: 1, explain: "اختلاف عنوان الرد عن المرسل خدعة شائعة." },
            { q: "نتيجة DMARC=fail بترويسة الإيميل تعني:", options: ["الإيميل وصل متأخر", "الرسالة ما تثبت إنها من نطاق المرسل الظاهر", "الإيميل بيه مرفق", "المرسل غير متصل"], answer: 1, explain: "من أقوى مؤشرات انتحال المرسل." },
            { q: "دخلت كلمة سرك بصفحة مزيفة. أول خطوة:", options: ["أنتظر أشوف شنو يصير", "أغيّر كلمة السر فوراً من الموقع الرسمي وأفعّل التحقق بخطوتين", "أحذف الموبايل", "أسوي حساب جديد"], answer: 1, explain: "السرعة مهمة: غيّرها قبل ما يستعملها المحتال." },
            { q: "حوّلت فلوس لمحتال. شنو تسوي أولاً؟", options: ["أحول مبلغ ثاني حتى يرجعون الأول", "أتصل بالمصرف أو المحفظة فوراً من الرقم الرسمي وأطلب إيقاف العملية", "أنتظر يوم", "أرد على المحتال وأهدده"], answer: 1, explain: "بعض التحويلات تنوقف إذا بلّغت بسرعة." },
            { q: "أي كلمة سر أقوى؟", options: ["Baghdad2024", "12345678", "جملة طويلة من 4 كلمات ما بينها علاقة", "اسمك وتاريخ ميلادك"], answer: 2, explain: "الطول والعشوائية أهم من الرموز المعقدة." },
            { q: "ليش ما تستخدم نفس كلمة السر بأكثر من موقع؟", options: ["لأنها تنسى", "لأن تسريبها من موقع واحد يفتح كل حساباتك", "لأن المواقع تمنعها", "ما اكو مشكلة"], answer: 1, explain: "المحتالين يجربون كلمات السر المسربة على كل المواقع." },
            { q: "شنو الفرق بين SMS وتطبيق المصادقة بالتحقق بخطوتين؟", options: ["ما اكو فرق", "تطبيق المصادقة أقوى لأن الرسائل ممكن تنسرق بتحويل الشريحة أو التصيد", "SMS أقوى دائماً", "التطبيق يحتاج إنترنت دائماً"], answer: 1, explain: "رسائل SMS معرضة لسرقة الشريحة (SIM swap)." },
            { q: "نزّلت تطبيق مشبوه. شنو تسوي؟", options: ["أتركه", "أفصل الإنترنت، أحذفه وأشيل صلاحياته، وأغيّر كلمات السر من جهاز ثاني", "أحدّثه", "أنصبه مرة ثانية"], answer: 1, explain: "التطبيق ممكن يسجل اللي تكتبه، فغيّر كلمات السر من جهاز نظيف." },
            { q: "شنو أهم شي تحتفظ بيه بعد ما تتعرض لاحتيال؟", options: ["ولا شي", "الأدلة: صور المحادثة والرابط والأرقام وإشعارات التحويل", "رقم المحتال بالمفضلة", "كلمة السر القديمة"], answer: 1, explain: "الأدلة ضرورية للمصرف والبلاغ الرسمي." }
        ]
    }
];

const QUIZ_SIZE = 5, PASS = 4, ATTEMPT_TTL = 1800;

class CourseError extends Error {
    constructor(message, status = 400) {
        super(message);
        this.status = status;
    }
}

const shuffle = list => {
    const a = list.slice();
    for (let i = a.length - 1; i > 0; i--) {
        const j = crypto.randomInt(0, i + 1);
        [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
};
const cleanName = v => String(v || "").replace(/<[^>]{0,200}>/g, "").replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩<>]/g, "").replace(/\s+/g, " ").trim().slice(0, 60);

function createCourse({ db, users, now = () => Date.now() }) {
    const k = (...p) => db.key(...p);
    const progressOf = user => (user.course && typeof user.course === "object" ? user.course : { levels: {}, points: 0 });

    function overview(user) {
        const progress = progressOf(user);
        let unlocked = true;
        return {
            levels: LEVELS.map(level => {
                const done = progress.levels[level.id] || null;
                const entry = { id: level.id, title: level.title, points: level.points, lessons: level.lessons, passed: Boolean(done), score: done ? done.score : null, unlocked };
                unlocked = unlocked && Boolean(done);
                return entry;
            }),
            points: progress.points || 0,
            certificateId: progress.certificateId || null,
            complete: LEVELS.every(l => progress.levels[l.id])
        };
    }

    async function startQuiz(user, levelId) {
        const view = overview(user);
        const level = LEVELS.find(l => l.id === levelId);
        if (!level) throw new CourseError("مستوى غير موجود.");
        if (!view.levels.find(l => l.id === levelId).unlocked) throw new CourseError("اجتاز المستوى اللي قبله أولاً.", 403);
        const picks = shuffle(level.bank.map((q, i) => i)).slice(0, QUIZ_SIZE);
        const items = picks.map(qi => ({ qi, order: shuffle([0, 1, 2, 3]) }));
        const id = crypto.randomBytes(12).toString("base64url");
        await db.cmd(["SET", k("quiz", id), JSON.stringify({ uid: user.id, level: levelId, items }), "EX", String(ATTEMPT_TTL)]);
        return { attemptId: id, questions: items.map(({ qi, order }) => ({ q: level.bank[qi].q, options: order.map(o => level.bank[qi].options[o]) })) };
    }

    async function submitQuiz(user, attemptId, answers) {
        if (typeof attemptId !== "string" || attemptId.length > 40) throw new CourseError("محاولة غير صالحة.");
        const key = k("quiz", attemptId);
        const [raw] = await db.pipe([["GET", key], ["DEL", key]]);   // المحاولة تنقبل مرة وحدة
        if (!raw) throw new CourseError("انتهت صلاحية الاختبار. ابدي من جديد.", 410);
        const attempt = JSON.parse(raw);
        if (attempt.uid !== user.id) throw new CourseError("محاولة غير صالحة.", 403);
        const level = LEVELS.find(l => l.id === attempt.level);
        const given = Array.isArray(answers) ? answers : [];
        const results = attempt.items.map(({ qi, order }, i) => {
            const q = level.bank[qi];
            const chosen = Number.isInteger(given[i]) ? given[i] : -1;
            const correctShown = order.indexOf(q.answer);
            return { correct: chosen === correctShown, correctIndex: correctShown, explain: q.explain };
        });
        const score = results.filter(r => r.correct).length;
        const passed = score >= PASS;
        let updated = user;
        if (passed) {
            updated = await users.update(user.id, u => {
                const progress = progressOf(u);
                const before = progress.levels[level.id];
                progress.levels = { ...progress.levels, [level.id]: { score: Math.max(score, before ? before.score : 0), passedAt: before ? before.passedAt : now() } };
                if (!before) progress.points = (progress.points || 0) + level.points;
                u.course = progress;
            });
        }
        return { score, total: QUIZ_SIZE, passed, results, overview: overview(updated) };
    }

    async function issueCertificate(user, rawName) {
        const view = overview(user);
        if (!view.complete) throw new CourseError("أكمل المستويات الثلاثة أولاً.", 403);
        if (view.certificateId) return getCertificate(view.certificateId);
        const name = cleanName(rawName) || cleanName(user.name);
        if (name.length < 3) throw new CourseError("اكتب اسمك كما تريده على الشهادة.");
        const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        const id = Array.from(crypto.randomBytes(10), b => alphabet[b % alphabet.length]).join("");
        const progress = progressOf(user);
        const cert = { id, name, issuedAt: now(), levels: LEVELS.map(l => ({ title: l.title, score: progress.levels[l.id].score })), points: progress.points };
        await db.cmd(["SET", k("cert", id), JSON.stringify(cert)]);
        await users.update(user.id, u => { u.course = { ...progressOf(u), certificateId: id }; });
        return cert;
    }

    async function getCertificate(id) {
        if (typeof id !== "string" || !/^[A-Z2-9]{10}$/.test(id)) return null;
        const raw = await db.cmd(["GET", k("cert", id)]);
        try { return raw ? JSON.parse(raw) : null; } catch { return null; }
    }

    return { overview, startQuiz, submitQuiz, issueCertificate, getCertificate, LEVELS };
}

module.exports = { createCourse, CourseError, LEVELS };
