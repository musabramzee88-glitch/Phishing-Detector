"use strict";

/*
  الحسابات والجلسات والاستهلاك وطلبات الدفع. منطق فقط (بدون HTTP)، فيسهل اختباره.

  مفاتيح القاعدة (كلها تبدأ ببادئة STORE_PREFIX، الافتراضي pd):
    u:<id>                 بيانات المستخدم (JSON)
    email:<email>          -> id
    oauth:<provider>:<sub> -> id
    users                  ZSET بكل المستخدمين (الدرجة = وقت الإنشاء)
    sess:<sha256(token)>   جلسة (JSON) تنتهي تلقائياً
    use:<id>:<yyyymmdd>    عدّاد الاستهلاك اليومي (HASH: scan / chat)
    hist:<id>              سجل الفحوصات (ZSET، لمشتركي Pro فقط)
    apikey:<sha256(key)>   -> id
    pay:<id>               طلب دفع (JSON)،  pays (ZSET الكل)،  pays:pending (SET)،  upays:<uid> (ZSET)
    reset:<sha256(token)>  رابط إعادة تعيين كلمة السر ينتهي بعد ساعة
    verify:<sha256(token)> رابط تأكيد البريد (24 ساعة)،  canon:<email موحّد> -> id،  trial:<email موحّد> (الشهر المجاني استُهلك)
    mailn:<نوع>:<sha>      عدّاد رسائل البريد بالساعة
  الرموز السرية (الجلسات، مفاتيح API، روابط إعادة التعيين) لا تُخزَّن أبداً كما هي، بل بصمتها SHA-256.
*/

const crypto = require("node:crypto");
const { promisify } = require("node:util");
const { planOf, LIMITS, DAY_MS, PAYMENT_MONTHS } = require("./plans");

const scrypt = promisify(crypto.scrypt);
const SCRYPT = { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 };
const SESSION_DAYS = 30;
const MAX_HISTORY = 100;
const USER_CACHE_MS = 60_000;
const COMMON_PASSWORDS = new Set([
    "12345678", "123456789", "1234567890", "password", "password1", "qwertyui", "qwerty123", "11111111",
    "00000000", "iloveyou", "abcd1234", "abc12345", "admin123", "welcome1", "87654321", "12341234",
    "11223344", "1q2w3e4r", "q1w2e3r4", "asdfghjk", "zxcvbnm1", "baghdad1", "iraq1234"
]);
// كلمات أساسية شائعة: نكشفها حتى لو أُضيفت لها أرقام أو استُبدلت حروفها برموز (p@ssw0rd, letmein1)
const COMMON_BASES = new Set([
    "password", "passw0rd", "passcode", "letmein", "welcome", "iloveyou", "admin", "administrator", "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl",
    "zxcvbn", "monkey", "dragon", "football", "baseball", "master", "login", "princess", "sunshine", "shadow", "superman", "trustno", "freedom",
    "whatever", "starwars", "hello", "abc", "abcd", "abcdef", "secret", "iraq", "baghdad", "basra", "mosul", "tikrit", "apexsec", "phishing", "changeme", "test", "user"
]);
const LEET = { "@": "a", "4": "a", "0": "o", "1": "l", "!": "i", "3": "e", "$": "s", "5": "s", "7": "t" };

// تسلسل أرقام صاعد أو نازل أو متكرر بالكامل: 12345678910, 98765432, 123123123
function isDigitPattern(value) {
    if (!/^\d+$/.test(value)) return false;
    let asc = true, desc = true;
    for (let i = 1; i < value.length; i++) {
        const d = Number(value[i]) - Number(value[i - 1]);
        if (d !== 1 && !(Number(value[i - 1]) === 9 && Number(value[i]) === 0)) asc = false;
        if (d !== -1 && !(Number(value[i - 1]) === 0 && Number(value[i]) === 9)) desc = false;
    }
    if (asc || desc) return true;
    for (let size = 1; size <= 4; size++) if (value.length % size === 0 && value.slice(0, size).repeat(value.length / size) === value) return true;
    return /^12345678910\d*$/.test(value);
}

// مزوّدو بريد مؤقت شائعون: يُرفضون عند التسجيل بالبريد (لا يؤثر على الدخول عبر Google/Microsoft/Apple)
const DISPOSABLE_DOMAINS = new Set([
    "mailinator.com", "guerrillamail.com", "guerrillamail.net", "guerrillamail.org", "sharklasers.com", "grr.la", "10minutemail.com", "10minutemail.net",
    "tempmail.com", "temp-mail.org", "temp-mail.io", "tempmail.net", "tempmailo.com", "throwawaymail.com", "yopmail.com", "yopmail.net", "yopmail.fr",
    "trashmail.com", "trashmail.net", "trashmail.de", "getnada.com", "nada.email", "maildrop.cc", "dispostable.com", "fakeinbox.com", "mailnesia.com",
    "mintemail.com", "mohmal.com", "emailondeck.com", "burnermail.io", "spamgourmet.com", "mytemp.email", "tempinbox.com", "moakt.com", "mail.tm",
    "inboxkitten.com", "tmpmail.org", "tmpmail.net", "dropmail.me", "discard.email", "anonbox.net", "33mail.com", "emailfake.com", "fakemail.net",
    "harakirimail.com", "mailcatch.com", "mailforspam.com", "spambox.us", "spam4.me", "tempr.email", "tempail.com", "email-fake.com", "luxusmail.org",
    "1secmail.com", "1secmail.net", "1secmail.org", "wwjmp.com", "esiix.com", "xojxe.com", "yoggm.com", "vjuum.com", "laafd.com", "txcct.com",
    "gufum.com", "cuvox.de", "armyspy.com", "dayrep.com", "einrot.com", "fleckens.hu", "gustr.com", "jourrapide.com", "rhyta.com", "superrito.com", "teleworm.us",
    "crazymailing.com", "linshiyouxiang.net", "mailpoof.com", "mvrht.net", "tmail.ws", "zetmail.com", "tempm.com", "temporary-mail.net", "guerrillamailblock.com"
]);

// يوحّد عناوين الصندوق نفسه: Gmail يتجاهل النقاط و +tag، وبقية المزوّدين نحذف +tag. نستخدمه لمنع تكرار الشهر المجاني.
function canonicalEmail(email) {
    const at = email.lastIndexOf("@");
    let local = email.slice(0, at);
    let domain = email.slice(at + 1);
    if (domain === "googlemail.com") domain = "gmail.com";
    const base = local.split("+")[0];
    if (base) local = base;
    if (domain === "gmail.com") local = local.replace(/\./g, "") || local;
    return local + "@" + domain;
}

const isDisposableEmail = email => DISPOSABLE_DOMAINS.has(email.slice(email.lastIndexOf("@") + 1));

class UserError extends Error {
    constructor(code, message, status = 400) {
        super(message);
        this.code = code;
        this.status = status;
    }
}

const sha256 = value => crypto.createHash("sha256").update(value).digest("hex");
const randomId = (bytes = 8) => crypto.randomBytes(bytes).toString("hex");
const token = () => crypto.randomBytes(32).toString("base64url");
const dayKey = (now = Date.now()) => new Date(now).toISOString().slice(0, 10).replace(/-/g, "");

// يمنع محارف التحكم واتجاه النص المخفية (تُستخدم لتزوير الأسماء بالعرض)
function cleanName(value, max = 60) {
    return String(value || "").replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩<>]/g, "").replace(/\s+/g, " ").trim().slice(0, max);
}

function normalizeEmail(value) {
    const email = String(value || "").trim().toLowerCase();
    if (email.length > 254 || !/^[^\s@"<>()[\],;:]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/.test(email)) return "";
    return email;
}

function passwordProblem(password, email) {
    if (typeof password !== "string" || password.length < 8) return "كلمة السر يجب أن تكون 8 أحرف على الأقل.";
    if (password.length > 200) return "كلمة السر طويلة جداً.";
    const lower = password.toLowerCase();
    const unleet = lower.replace(/[@4013!$57]/g, c => LEET[c]);
    // نزيل الأرقام والرموز من الأطراف لنصل للكلمة الأساسية
    const trim = value => value.replace(/^[^a-z\u0600-\u06ff]+|[^a-z\u0600-\u06ff]+$/g, "");
    const base = trim(lower);
    if (COMMON_PASSWORDS.has(lower) || /^(.)\1+$/.test(password) || isDigitPattern(password) || COMMON_BASES.has(base) || COMMON_BASES.has(trim(unleet)) || COMMON_BASES.has(unleet.replace(/[^a-z]/g, ""))) {
        return "كلمة السر هذه شائعة جداً وسهلة التخمين. اختر غيرها.";
    }
    if (email && lower === email.split("@")[0]) return "لا تستخدم اسم بريدك ككلمة سر.";
    return "";
}

async function hashPassword(password) {
    const salt = crypto.randomBytes(16);
    const hash = await scrypt(password, salt, 32, SCRYPT);
    return `s1$${salt.toString("hex")}$${hash.toString("hex")}`;
}

const DUMMY_HASH = "s1$" + "00".repeat(16) + "$" + "00".repeat(32);
async function verifyPassword(password, stored) {
    const [version, saltHex, hashHex] = String(stored || DUMMY_HASH).split("$");
    if (version !== "s1" || !saltHex || !hashHex) return false;
    const expected = Buffer.from(hashHex, "hex");
    const actual = await scrypt(String(password).slice(0, 200), Buffer.from(saltHex, "hex"), expected.length, SCRYPT);
    return crypto.timingSafeEqual(actual, expected);
}

// ما يُرسل للمتصفح عن المستخدم (بدون أي سر)
function publicUser(user, now = Date.now()) {
    const plan = planOf(user, now);
    return {
        id: user.id,
        email: user.email,
        name: user.name,
        emailVerified: Boolean(user.emailVerified),
        hasPassword: Boolean(user.pw),
        providers: Object.keys(user.providers || {}),
        createdAt: new Date(user.createdAt).toISOString(),
        plan: plan.id,
        planSource: plan.source,
        planUntil: plan.until ? new Date(plan.until).toISOString() : null,
        trialUsed: Boolean(user.trialEndsAt),
        apiKeyHint: user.apiKeyHint || "",
        historyEnabled: !user.historyOff,
        limits: LIMITS[plan.id]
    };
}

function createUsers({ db, config, now: clock = () => Date.now() }) {
    const k = (...parts) => db.key(...parts);
    const cache = new Map();          // id -> { user, at }
    const sessionCache = new Map();   // sha -> { uid, exp, at }
    const trialMs = config.plans.trialDays * DAY_MS;
    // عند ضبط مزوّد البريد: حسابات البريد/كلمة السر لا تعمل قبل تأكيد البريد، ويبدأ الشهر المجاني عند التأكيد.
    const verifyRequired = Boolean(config.mail && config.mail.enabled);

    // الشهر المجاني مرة واحدة لكل صندوق بريد (حتى لو حُذف الحساب وأُعيد إنشاؤه)
    async function claimTrial(email) {
        if (trialMs <= 0) return 0;
        const won = await db.cmd(["SET", k("trial", canonicalEmail(email)), "1", "NX"]);
        return won === "OK" ? clock() + trialMs : 0;
    }

    function remember(user) {
        if (cache.size > 5000) cache.delete(cache.keys().next().value);
        cache.set(user.id, { user, at: clock() });
        return user;
    }

    async function get(id) {
        if (typeof id !== "string" || !/^[0-9a-f]{16}$/.test(id)) return null;
        const hit = cache.get(id);
        if (hit && clock() - hit.at < USER_CACHE_MS) return hit.user;
        const raw = await db.cmd(["GET", k("u", id)]);
        if (!raw) { cache.delete(id); return null; }
        try { return remember(JSON.parse(raw)); } catch { return null; }
    }

    async function save(user) {
        await db.cmd(["SET", k("u", user.id), JSON.stringify(user)]);
        return remember(user);
    }

    async function update(id, change) {
        const user = await get(id);
        if (!user) throw new UserError("not_found", "الحساب غير موجود.", 404);
        const next = { ...user };
        change(next);
        return save(next);
    }

    async function findByEmail(email) {
        const id = await db.cmd(["GET", k("email", email)]);
        return id ? get(id) : null;
    }

    // إنشاء حساب. البريد يُحجز أولاً بـ SET NX فلا ينشأ حسابان بنفس البريد حتى لو وصل طلبان معاً.
    async function create({ email, name, password, provider, sub, emailVerified }) {
        const id = randomId();
        const reserved = await db.cmd(["SET", k("email", email), id, "NX"]);
        if (reserved !== "OK") throw new UserError("email_taken", "هذا البريد مسجّل مسبقاً. سجّل الدخول بدلاً من ذلك.", 409);
        // نفس الصندوق بشكل آخر (نقاط Gmail أو +tag) يُعامل كحساب مكرر
        const canonOwner = await db.cmd(["SET", k("canon", canonicalEmail(email)), id, "NX"]);
        if (canonOwner !== "OK") {
            await db.cmd(["DEL", k("email", email)]);
            throw new UserError("email_taken", "هذا البريد مسجّل مسبقاً. سجّل الدخول بدلاً من ذلك.", 409);
        }
        const now = clock();
        const trialEndsAt = (emailVerified || !verifyRequired) ? await claimTrial(email) : 0;
        const user = {
            id, email, name: cleanName(name) || email.split("@")[0],
            emailVerified: Boolean(emailVerified),
            pw: password ? await hashPassword(password) : "",
            providers: provider ? { [provider]: sub } : {},
            createdAt: now,
            // أول شهر مجاني (مرة واحدة لكل صندوق بريد). حسابات البريد تبدأ الشهر عند تأكيد البريد إن كان التأكيد مفعّلاً.
            trialEndsAt,
            paidUntil: 0,
            disabled: false,
            lastLoginAt: now
        };
        const commands = [["SET", k("u", id), JSON.stringify(user)], ["ZADD", k("users"), String(now), id]];
        if (provider) commands.push(["SET", k("oauth", provider, sub), id]);
        await db.pipe(commands);
        return remember(user);
    }

    async function register({ email: rawEmail, password, name }) {
        const email = normalizeEmail(rawEmail);
        if (!email) throw new UserError("bad_email", "اكتب بريداً إلكترونياً صحيحاً.");
        const problem = passwordProblem(password, email);
        if (problem) throw new UserError("weak_password", problem);
        if (isDisposableEmail(email)) throw new UserError("disposable_email", "لا نقبل البريد المؤقت. استخدم بريدك الحقيقي (Gmail أو Outlook أو بريد جامعتك).");
        return create({ email, name, password, emailVerified: false });
    }

    // ---------- تأكيد البريد ----------
    const needsVerification = user => verifyRequired && !user.emailVerified;

    // يحدّ عدد رسائل البريد لكل صندوق (يمنع استعمال الموقع لإغراق بريد أحد)
    async function mailAllowed(email, kind, max = 3) {
        const key = k("mailn", kind, sha256(canonicalEmail(email)));
        const [n] = await db.pipe([["INCR", key], ["EXPIRE", key, "3600"]]);
        return Number(n) <= max;
    }

    async function createVerifyToken(userId) {
        const raw = token();
        await db.cmd(["SET", k("verify", sha256(raw)), userId, "EX", String(24 * 3600)]);
        return raw;
    }

    // كود تحقق من 6 أرقام (صالح 15 دقيقة، 5 محاولات خاطئة كحد أقصى ثم يُلغى)
    async function createVerifyCode(userId) {
        const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
        await db.pipe([
            ["SET", k("vcode", userId), sha256(userId + ":" + code), "EX", "900"],
            ["DEL", k("vtry", userId)]
        ]);
        return code;
    }

    async function verifyCode(rawEmail, rawCode) {
        const bad = () => new UserError("bad_code", "الكود غير صحيح أو منتهي. اطلب كوداً جديداً.", 400);
        const code = String(rawCode || "").replace(/\s/g, "");
        if (!/^\d{6}$/.test(code)) throw bad();
        const user = await findByEmail(String(rawEmail || "").trim().toLowerCase());
        if (!user || user.disabled) throw bad();
        const stored = await db.cmd(["GET", k("vcode", user.id)]);
        if (!stored) throw bad();
        const [tries] = await db.pipe([["INCR", k("vtry", user.id)], ["EXPIRE", k("vtry", user.id), "900"]]);
        if (Number(tries) > 5) {
            await db.cmd(["DEL", k("vcode", user.id)]);
            throw bad();
        }
        const a = Buffer.from(stored, "hex");
        const b = Buffer.from(sha256(user.id + ":" + code), "hex");
        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw bad();
        await db.pipe([["DEL", k("vcode", user.id)], ["DEL", k("vtry", user.id)]]);
        if (user.emailVerified) return user;
        const trialEndsAt = user.trialEndsAt || await claimTrial(user.email);
        return update(user.id, u => { u.emailVerified = true; u.trialEndsAt = trialEndsAt; });
    }

    // ---------- التحقق الثنائي بالبريد (MFA) ----------
    // بعد العامل الأول (كلمة السر أو Google/Microsoft/Apple) ننشئ «تحدياً» مؤقتاً: رمز عشوائي للمتصفح (كوكي) + كود 6 أرقام للبريد.
    // الكود يُخزَّن مُجزّأً، صالح 10 دقائق، 5 محاولات خاطئة تلغيه، و3 إعادات إرسال كحد أقصى.
    const MFA_TTL = 600;
    const newCode = () => String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");

    async function createLoginChallenge(userId, via = "password") {
        const raw = token();
        const code = newCode();
        const sha = sha256(raw);
        await db.pipe([
            ["SET", k("mfa", sha), JSON.stringify({ uid: userId, code: sha256(sha + ":" + code), via: String(via).slice(0, 20), resends: 0 }), "EX", String(MFA_TTL)],
            ["DEL", k("mfatry", sha)]
        ]);
        return { token: raw, code };
    }

    async function loadChallenge(raw) {
        if (typeof raw !== "string" || raw.length < 20 || raw.length > 100) return null;
        const sha = sha256(raw);
        const stored = await db.cmd(["GET", k("mfa", sha)]);
        if (!stored) return null;
        try { return { sha, data: JSON.parse(stored) }; } catch { return null; }
    }

    async function resendLoginChallenge(raw) {
        const found = await loadChallenge(raw);
        if (!found) throw new UserError("mfa_expired", "انتهت صلاحية رمز الدخول. سجّل الدخول من جديد.", 400);
        if (found.data.resends >= 3) throw new UserError("mfa_resend_limit", "طلبت رموزاً كثيرة. سجّل الدخول من جديد بعد قليل.", 429);
        const user = await get(found.data.uid);
        if (!user || user.disabled) throw new UserError("mfa_expired", "انتهت صلاحية رمز الدخول. سجّل الدخول من جديد.", 400);
        const code = newCode();
        await db.pipe([
            ["SET", k("mfa", found.sha), JSON.stringify({ ...found.data, code: sha256(found.sha + ":" + code), resends: found.data.resends + 1 }), "EX", String(MFA_TTL)],
            ["DEL", k("mfatry", found.sha)]
        ]);
        return { user, code };
    }

    async function verifyLoginChallenge(raw, rawCode) {
        const bad = () => new UserError("bad_code", "رمز الدخول غير صحيح أو منتهي.", 400);
        const code = String(rawCode || "").replace(/\s/g, "");
        if (!/^\d{6}$/.test(code)) throw bad();
        const found = await loadChallenge(raw);
        if (!found) throw new UserError("mfa_expired", "انتهت صلاحية رمز الدخول. سجّل الدخول من جديد.", 400);
        const [tries] = await db.pipe([["INCR", k("mfatry", found.sha)], ["EXPIRE", k("mfatry", found.sha), String(MFA_TTL)]]);
        if (Number(tries) > 5) {
            await db.pipe([["DEL", k("mfa", found.sha)], ["DEL", k("mfatry", found.sha)]]);
            throw new UserError("mfa_expired", "محاولات خاطئة كثيرة. سجّل الدخول من جديد.", 400);
        }
        const a = Buffer.from(found.data.code, "hex");
        const b = Buffer.from(sha256(found.sha + ":" + code), "hex");
        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw bad();
        await db.pipe([["DEL", k("mfa", found.sha)], ["DEL", k("mfatry", found.sha)]]);
        const user = await get(found.data.uid);
        if (!user) throw new UserError("mfa_expired", "انتهت صلاحية رمز الدخول. سجّل الدخول من جديد.", 400);
        if (user.disabled) throw new UserError("disabled", "هذا الحساب موقوف. تواصل مع الدعم.", 403);
        return { user: await update(user.id, u => { u.lastLoginAt = clock(); }), via: found.data.via };
    }

    async function verifyEmail(raw) {
        if (typeof raw !== "string" || raw.length > 100) throw new UserError("bad_link", "رابط التأكيد غير صالح أو منتهي.", 400);
        const key = k("verify", sha256(raw));
        const id = await db.cmd(["GET", key]);
        const user = id ? await get(id) : null;
        if (!user) throw new UserError("bad_link", "رابط التأكيد غير صالح أو منتهي.", 400);
        await db.cmd(["DEL", key]);
        if (user.emailVerified) return user;
        const trialEndsAt = user.trialEndsAt || await claimTrial(user.email);
        return update(user.id, u => { u.emailVerified = true; u.trialEndsAt = trialEndsAt; });
    }

    // كلمة السر الخاطئة والحساب غير الموجود يرجعان نفس الخطأ وبنفس الزمن تقريباً
    async function login({ email: rawEmail, password }) {
        const email = normalizeEmail(rawEmail);
        const user = email ? await findByEmail(email) : null;
        const ok = await verifyPassword(String(password || ""), user && user.pw ? user.pw : DUMMY_HASH);
        if (!user || !user.pw || !ok) throw new UserError("bad_login", "البريد أو كلمة السر غير صحيحة.", 401);
        if (user.disabled) throw new UserError("disabled", "هذا الحساب موقوف. تواصل مع الدعم.", 403);
        if (needsVerification(user)) throw new UserError("email_unverified", "أكّد بريدك الإلكتروني أولاً: أرسلنا لك كود تحقق من 6 أرقام. إذا ما وصلك اطلب كوداً جديداً.", 403);
        return update(user.id, u => { u.lastLoginAt = clock(); });
    }

    /*
      الدخول عبر Google / Microsoft / Apple.
      - إن كان هذا الحساب الخارجي مربوطاً سابقاً: ندخل مباشرة.
      - إن كان البريد مسجّلاً بحساب آخر: نربط فقط إذا أكّد المزوّد أن البريد موثّق (emailVerified)،
        وإلا نرفض (يمنع الاستيلاء على حساب عبر مزوّد يسمح ببريد غير موثّق).
      - غير ذلك: حساب جديد.
    */
    async function loginWithProvider({ provider, sub, email: rawEmail, emailVerified, name }, { allowCreate = true } = {}) {
        const linkedId = await db.cmd(["GET", k("oauth", provider, sub)]);
        if (linkedId) {
            const user = await get(linkedId);
            if (user) {
                if (user.disabled) throw new UserError("disabled", "هذا الحساب موقوف. تواصل مع الدعم.", 403);
                return { user: await update(user.id, u => { u.lastLoginAt = clock(); }), created: false };
            }
        }
        const email = normalizeEmail(rawEmail);
        if (!email) throw new UserError("no_email", "لم يرسل المزوّد بريداً إلكترونياً. اسمح بمشاركة البريد وحاول مرة أخرى.");
        const existing = await findByEmail(email);
        if (existing) {
            if (!emailVerified) throw new UserError("link_unverified", "هذا البريد مسجّل مسبقاً. سجّل الدخول بطريقتك المعتادة.", 409);
            if (existing.disabled) throw new UserError("disabled", "هذا الحساب موقوف. تواصل مع الدعم.", 403);
            await db.cmd(["SET", k("oauth", provider, sub), existing.id]);
            const trialEndsAt = existing.trialEndsAt || await claimTrial(existing.email);
            const user = await update(existing.id, u => {
                u.providers = { ...(u.providers || {}), [provider]: sub };
                u.emailVerified = true;
                u.trialEndsAt = trialEndsAt;
                u.lastLoginAt = clock();
            });
            return { user, created: false };
        }
        if (!allowCreate) throw new UserError("registration_closed", "إنشاء الحسابات الجديدة متوقف حالياً.", 403);
        const user = await create({ email, name, provider, sub, emailVerified });
        return { user, created: true };
    }

    // ---------- الجلسات ----------
    async function createSession(userId, meta = {}) {
        const raw = token();
        const sha = sha256(raw);
        const exp = clock() + SESSION_DAYS * DAY_MS;
        await db.cmd(["SET", k("sess", sha), JSON.stringify({ uid: userId, exp, iat: clock(), ua: String(meta.ua || "").slice(0, 120) }), "EX", String(SESSION_DAYS * 86400)]);
        sessionCache.set(sha, { uid: userId, exp, iat: clock(), at: clock() });
        return { token: raw, maxAge: SESSION_DAYS * 86400 };
    }

    async function userFromSession(raw) {
        if (typeof raw !== "string" || raw.length < 20 || raw.length > 100) return null;
        const sha = sha256(raw);
        let entry = sessionCache.get(sha);
        if (!entry || clock() - entry.at > USER_CACHE_MS) {
            const stored = await db.cmd(["GET", k("sess", sha)]);
            if (!stored) { sessionCache.delete(sha); return null; }
            try {
                const parsed = JSON.parse(stored);
                entry = { uid: parsed.uid, exp: parsed.exp, iat: Number(parsed.iat) || 0, at: clock() };
            } catch { return null; }
            if (sessionCache.size > 20000) sessionCache.delete(sessionCache.keys().next().value);
            sessionCache.set(sha, entry);
        }
        if (entry.exp <= clock()) return null;
        const user = await get(entry.uid);
        if (!user || user.disabled) return null;
        // تغيير كلمة السر أو «خروج من كل الأجهزة» يُسقط كل الجلسات الأقدم منه (حتى لو سُرقت جلسة قديمة)
        const cutoff = Math.max(Number(user.pwAt) || 0, Number(user.revokedAt) || 0);
        if (cutoff && (entry.iat || 0) < cutoff) {
            sessionCache.delete(sha);
            return null;
        }
        return user;
    }

    async function destroySession(raw) {
        if (typeof raw !== "string" || raw.length > 100) return;
        const sha = sha256(raw);
        sessionCache.delete(sha);
        await db.cmd(["DEL", k("sess", sha)]);
    }

    // ---------- الاستهلاك اليومي ----------
    // يحجز وحدة (أو أكثر) من حصة اليوم. يرجع { ok, used, limit }
    async function consume(user, kind, amount = 1) {
        const limits = LIMITS[planOf(user, clock()).id];
        const limit = kind === "chat" ? limits.chatPerDay : limits.scansPerDay;
        const key = k("use", user.id, dayKey(clock()));
        const [used] = await db.pipe([["HINCRBY", key, kind, String(amount)], ["EXPIRE", key, String(3 * 86400)]]);
        if (Number(used) > limit) {
            await db.cmd(["HINCRBY", key, kind, String(-amount)]);
            return { ok: false, used: Number(used) - amount, limit };
        }
        return { ok: true, used: Number(used), limit };
    }

    async function usage(user) {
        const raw = await db.cmd(["HGETALL", k("use", user.id, dayKey(clock()))]);
        const out = { scan: 0, chat: 0 };
        const list = Array.isArray(raw) ? raw : Object.entries(raw || {}).flat();
        for (let i = 0; i + 1 < list.length; i += 2) if (list[i] in out) out[list[i]] = Number(list[i + 1]) || 0;
        const limits = LIMITS[planOf(user, clock()).id];
        return { scan: out.scan, chat: out.chat, scanLimit: limits.scansPerDay, chatLimit: limits.chatPerDay };
    }

    // ---------- سجل الفحوصات (Pro) ----------
    async function addHistory(user, item) {
        if (!LIMITS[planOf(user, clock()).id].history || user.historyOff) return;
        const key = k("hist", user.id);
        const entry = JSON.stringify({ ...item, at: clock(), r: randomId(3) });
        await db.pipe([["ZADD", key, String(clock()), entry], ["ZREMRANGEBYRANK", key, "0", String(-(MAX_HISTORY + 1))]]);
    }

    async function history(user) {
        const raw = await db.cmd(["ZREVRANGE", k("hist", user.id), "0", String(MAX_HISTORY - 1)]);
        return (Array.isArray(raw) ? raw : []).map(r => { try { const v = JSON.parse(r); delete v.r; return v; } catch { return null; } }).filter(Boolean);
    }

    async function clearHistory(user) {
        await db.cmd(["DEL", k("hist", user.id)]);
    }

    // ---------- مفتاح API (Pro) ----------
    async function rotateApiKey(user) {
        if (!LIMITS[planOf(user, clock()).id].api) throw new UserError("pro_only", "مفتاح API متاح لمشتركي Pro فقط.", 403);
        const raw = "pd_" + crypto.randomBytes(24).toString("base64url");
        const commands = [["SET", k("apikey", sha256(raw)), user.id]];
        if (user.apiKeySha) commands.push(["DEL", k("apikey", user.apiKeySha)]);
        await db.pipe(commands);
        await update(user.id, u => { u.apiKeySha = sha256(raw); u.apiKeyHint = raw.slice(0, 7) + "…" + raw.slice(-4); });
        return raw;
    }

    async function userFromApiKey(raw) {
        if (typeof raw !== "string" || !/^pd_[A-Za-z0-9_-]{32}$/.test(raw)) return null;
        const id = await db.cmd(["GET", k("apikey", sha256(raw))]);
        const user = id ? await get(id) : null;
        if (!user || user.disabled || user.apiKeySha !== sha256(raw)) return null;
        return user;
    }

    // ---------- الملف الشخصي ----------
    async function rename(user, name) {
        const clean = cleanName(name);
        if (!clean) throw new UserError("bad_name", "اكتب اسماً صحيحاً.");
        return update(user.id, u => { u.name = clean; });
    }

    async function changePassword(user, { current, next }) {
        if (user.pw && !(await verifyPassword(String(current || ""), user.pw))) throw new UserError("bad_password", "كلمة السر الحالية غير صحيحة.", 401);
        const problem = passwordProblem(next, user.email);
        if (problem) throw new UserError("weak_password", problem);
        const pw = await hashPassword(next);
        return update(user.id, u => { u.pw = pw; u.pwAt = clock(); });
    }

    async function setHistoryEnabled(user, enabled) {
        if (!enabled) await clearHistory(user);
        return update(user.id, u => { u.historyOff = !enabled; });
    }

    // حذف الحساب نهائياً (طلبات الدفع تبقى بسجل الإيرادات بدون اسم)
    async function remove(user) {
        const commands = [
            ["DEL", k("u", user.id)], ["DEL", k("email", user.email)], ["DEL", k("canon", canonicalEmail(user.email))], ["ZREM", k("users"), user.id],
            ["DEL", k("hist", user.id)], ["DEL", k("upays", user.id)]
        ];
        for (const [provider, sub] of Object.entries(user.providers || {})) commands.push(["DEL", k("oauth", provider, sub)]);
        if (user.apiKeySha) commands.push(["DEL", k("apikey", user.apiKeySha)]);
        await db.pipe(commands);
        cache.delete(user.id);
        for (const [sha, entry] of sessionCache) if (entry.uid === user.id) sessionCache.delete(sha);
    }

    // ---------- إعادة تعيين كلمة السر (رابط يصدره الأدمن، صالح ساعة ولمرة واحدة) ----------
    async function createResetLink(userId) {
        const user = await get(userId);
        if (!user) throw new UserError("not_found", "الحساب غير موجود.", 404);
        const raw = token();
        await db.cmd(["SET", k("reset", sha256(raw)), user.id, "EX", "3600"]);
        return raw;
    }

    async function useResetLink(raw, password) {
        if (typeof raw !== "string" || raw.length > 100) throw new UserError("bad_link", "الرابط غير صالح أو منتهي.", 400);
        const key = k("reset", sha256(raw));
        const id = await db.cmd(["GET", key]);
        const user = id ? await get(id) : null;
        if (!user) throw new UserError("bad_link", "الرابط غير صالح أو منتهي.", 400);
        const problem = passwordProblem(password, user.email);
        if (problem) throw new UserError("weak_password", problem);
        await db.cmd(["DEL", key]);
        const pw = await hashPassword(password);
        return update(user.id, u => { u.pw = pw; u.pwAt = clock(); });
    }

    // ---------- طلبات الدفع ----------
    async function createPayment(user, { method, months, reference, note }) {
        const methods = config.payment.methods.map(m => m.id);
        if (!methods.includes(method)) throw new UserError("bad_method", "اختر طريقة دفع من القائمة.");
        const m = Number(months);
        if (!PAYMENT_MONTHS.includes(m)) throw new UserError("bad_months", "اختر مدة صحيحة.");
        const ref = cleanName(reference, 80);
        if (ref.length < 4) throw new UserError("bad_reference", "اكتب رقم العملية أو الحوالة كما يظهر بإشعار الدفع.");
        const pending = await paymentsOf(user);
        if (pending.filter(p => p.status === "pending").length >= 3) throw new UserError("too_many", "عندك طلبات قيد المراجعة. انتظر حتى نراجعها.", 429);
        const payment = {
            id: randomId(6), uid: user.id, email: user.email, method, months: m, reference: ref,
            note: cleanName(note, 300),
            amountUsd: m * config.plans.priceUsd, amountIqd: m * config.plans.priceIqd,
            status: "pending", createdAt: clock(), decidedAt: 0, decidedBy: "", reason: ""
        };
        await db.pipe([
            ["SET", k("pay", payment.id), JSON.stringify(payment)],
            ["ZADD", k("pays"), String(payment.createdAt), payment.id],
            ["ZADD", k("upays", user.id), String(payment.createdAt), payment.id],
            ["SADD", k("pays", "pending"), payment.id]
        ]);
        return payment;
    }

    async function loadPayments(ids) {
        if (!ids.length) return [];
        const raw = await db.pipe(ids.map(id => ["GET", k("pay", id)]));
        return raw.map(r => { try { return JSON.parse(r); } catch { return null; } }).filter(Boolean);
    }

    async function paymentsOf(user) {
        const ids = await db.cmd(["ZREVRANGE", k("upays", user.id), "0", "49"]);
        return loadPayments(Array.isArray(ids) ? ids : []);
    }

    async function listPayments({ status, limit = 200 } = {}) {
        const ids = status === "pending"
            ? await db.cmd(["SMEMBERS", k("pays", "pending")])
            : await db.cmd(["ZREVRANGE", k("pays"), "0", String(limit - 1)]);
        const list = await loadPayments(Array.isArray(ids) ? ids : []);
        return list.sort((a, b) => b.createdAt - a.createdAt);
    }

    // الموافقة تمدد الاشتراك من تاريخ انتهائه الحالي (أو من الآن إن كان منتهياً)
    async function decidePayment(id, { approve, admin, reason }) {
        const raw = await db.cmd(["GET", k("pay", id)]);
        if (!raw) throw new UserError("not_found", "الطلب غير موجود.", 404);
        const payment = JSON.parse(raw);
        if (payment.status !== "pending") throw new UserError("decided", "تمت مراجعة هذا الطلب مسبقاً.", 409);
        // SREM ذرّي: أول طلب فقط يحذف الطلب من قائمة المعلّقة. يمنع تمديد الاشتراك مرتين لو ضُغط «موافقة» مرتين بنفس اللحظة
        const claimed = await db.cmd(["SREM", k("pays", "pending"), id]);
        if (Number(claimed) !== 1) throw new UserError("decided", "تمت مراجعة هذا الطلب مسبقاً.", 409);
        payment.status = approve ? "approved" : "rejected";
        payment.decidedAt = clock();
        payment.decidedBy = cleanName(admin, 40);
        payment.reason = cleanName(reason, 200);
        await db.cmd(["SET", k("pay", id), JSON.stringify(payment)]);
        let user = null;
        if (approve) user = await extend(payment.uid, payment.months).catch(() => null);
        return { payment, user };
    }

    async function extend(userId, months) {
        return update(userId, u => {
            const base = Math.max(Number(u.paidUntil || 0), clock());
            u.paidUntil = base + months * 30 * DAY_MS;
        });
    }

    // ---------- للأدمن ----------
    async function listUsers({ offset = 0, limit = 50, query = "" } = {}) {
        const total = Number(await db.cmd(["ZCARD", k("users")])) || 0;
        const q = String(query || "").trim().toLowerCase();
        if (q) {
            // تطابق تام بالبريد أولاً (سريع)، وإلا بحث جزئي بالبريد أو الاسم في أحدث 5000 حساب
            const exact = q.includes("@") ? await findByEmail(q) : null;
            if (exact) return { total, users: [exact] };
            const found = [];
            for (let start = 0; start < Math.min(total, 5000) && found.length < limit; start += 500) {
                const ids = await db.cmd(["ZREVRANGE", k("users"), String(start), String(start + 499)]);
                if (!Array.isArray(ids) || !ids.length) break;
                const raw = await db.pipe(ids.map(id => ["GET", k("u", id)]));
                for (const r of raw) {
                    let u;
                    try { u = JSON.parse(r); } catch { continue; }
                    if (u && (String(u.email).includes(q) || String(u.name || "").toLowerCase().includes(q))) found.push(u);
                    if (found.length >= limit) break;
                }
            }
            return { total, users: found };
        }
        const ids = await db.cmd(["ZREVRANGE", k("users"), String(offset), String(offset + limit - 1)]);
        const raw = (Array.isArray(ids) && ids.length) ? await db.pipe(ids.map(id => ["GET", k("u", id)])) : [];
        const users = raw.map(r => { try { return JSON.parse(r); } catch { return null; } }).filter(Boolean);
        return { total, users };
    }

    async function count() {
        return Number(await db.cmd(["ZCARD", k("users")])) || 0;
    }

    // ينهي كل جلسات المستخدم الحالية (بأي جهاز) بدون تغيير كلمة السر
    async function revokeSessions(userId) {
        const user = await update(userId, u => { u.revokedAt = clock(); });
        for (const [sha, entry] of sessionCache) if (entry.uid === userId) sessionCache.delete(sha);
        return user;
    }

    async function setDisabled(userId, disabled) {
        const user = await update(userId, u => { u.disabled = Boolean(disabled); });
        if (disabled) for (const [sha, entry] of sessionCache) if (entry.uid === userId) sessionCache.delete(sha);
        return user;
    }

    async function revenue() {
        const all = await listPayments({ limit: 5000 });
        const approved = all.filter(p => p.status === "approved");
        const now = clock();
        const monthStart = new Date(new Date(now).getFullYear(), new Date(now).getMonth(), 1).getTime();
        const sum = (list, field) => list.reduce((s, p) => s + (Number(p[field]) || 0), 0);
        const thisMonth = approved.filter(p => p.decidedAt >= monthStart);
        const last30 = approved.filter(p => now - p.decidedAt <= 30 * DAY_MS);
        return {
            approvedCount: approved.length,
            pendingCount: all.filter(p => p.status === "pending").length,
            totalUsd: sum(approved, "amountUsd"), totalIqd: sum(approved, "amountIqd"),
            monthUsd: sum(thisMonth, "amountUsd"), monthIqd: sum(thisMonth, "amountIqd"),
            last30Usd: sum(last30, "amountUsd"), last30Iqd: sum(last30, "amountIqd")
        };
    }

    return {
        get, register, login, loginWithProvider, findByEmail, needsVerification, mailAllowed, createVerifyToken, createVerifyCode, verifyCode, verifyEmail, createLoginChallenge, resendLoginChallenge, verifyLoginChallenge, createSession, userFromSession, destroySession,
        consume, usage, addHistory, history, clearHistory, rotateApiKey, userFromApiKey,
        rename, changePassword, setHistoryEnabled, remove, createResetLink, useResetLink,
        createPayment, paymentsOf, listPayments, decidePayment, extend, listUsers, count, setDisabled, revokeSessions, revenue,
        publicUser: user => publicUser(user, clock())
    };
}

module.exports = { createUsers, UserError, normalizeEmail, passwordProblem, hashPassword, verifyPassword, cleanName, publicUser };
