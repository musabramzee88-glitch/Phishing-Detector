"use strict";

/*
  إعدادات الخادم. كل شيء يُقرأ من متغيرات البيئة، ولا يوجد أي سر داخل الكود.
  القائمة الكاملة مع الشرح: README.md (قسم المتغيرات).

  الأساسية:
    APP_URL                          عنوان الموقع العام (مثل https://phishing-detector.onrender.com) لروابط الدخول عبر Google/Microsoft/Apple
    UPSTASH_REDIS_REST_URL/TOKEN     قاعدة البيانات (الحسابات والاشتراكات). إلزامية بالإنتاج.
    ADMIN_EMAILS                     بريد الأدمن (واحد أو أكثر بفواصل): الدخول بكود يصل للبريد. يحتاج مزوّد بريد مفعّل
    ADMINS                           حسابات الأدمن: اسم مستخدم + بريد + كلمة سر ثم كود للبريد (npm run make-admin -- <user> <email>)
  الذكاء الاصطناعي (CyberBot):
    AI_API_KEY, AI_MODEL, AI_BASE_URL   أي مزوّد متوافق مع OpenAI (OpenAI, Gemini, Groq, OpenRouter...)
    OPENAI_API_KEY, OPENAI_MODEL     (الأسماء القديمة ما زالت مدعومة)
    GEMINI_API_KEY                   اختصار: يفعّل Gemini مباشرة
  تسجيل الدخول الخارجي (كل مزوّد يظهر زره فقط إذا ضُبطت متغيراته):
    GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET
    MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET
    APPLE_CLIENT_ID, APPLE_TEAM_ID, APPLE_KEY_ID, APPLE_PRIVATE_KEY
  الخطط والدفع:
    PRICE_USD (2), PRICE_IQD (3000), TRIAL_DAYS (30)
    BREVO_API_KEY أو RESEND_API_KEY أو (MAILJET_API_KEY + MAILJET_SECRET_KEY) + MAIL_FROM (+ MAIL_FROM_NAME)   تفعيل التحقق من البريد وإرسال روابط كلمة السر
    PAY_QICARD                       رقم بطاقة الماستر كارد (Qi Card) لاستلام الدفع، يظهر للمشترك (الطريقة الوحيدة)
    CONTACT_WHATSAPP, CONTACT_TELEGRAM, PAYMENT_NOTE
  أخرى:
    THREAT_FEEDS=0                   تعطيل قوائم التهديدات و RDAP
    TRUST_PROXY=1, HOST, PORT, CYBERBOT_GLOBAL_LIMIT, STORE_PREFIX
*/

const path = require("node:path");

const HEX_32_BYTES = /^[0-9a-f]{64}$/i;

const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g;
const cleanEnv = (value, max) => String(value || "").replace(CONTROL_CHARS, " ").trim().slice(0, max);
const numberEnv = (value, fallback, min, max) => {
    const n = Number(value);
    return Number.isFinite(n) && n >= min && n <= max ? n : fallback;
};

// عنوان الموقع العام: يلزم https بالإنتاج (http مسموح للجهاز المحلي فقط)
function parseAppUrl(env, port) {
    const fallback = env.RENDER_EXTERNAL_URL || `http://localhost:${port}`;
    try {
        const u = new URL(String(env.APP_URL || fallback).trim());
        const local = ["localhost", "127.0.0.1"].includes(u.hostname);
        if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) throw new Error("insecure");
        return u.origin;
    } catch {
        return `http://localhost:${port}`;
    }
}

function parseOAuth(env) {
    const pair = (id, secret) => (env[id] && env[secret] ? { clientId: String(env[id]).trim(), clientSecret: String(env[secret]).trim() } : null);
    let apple = null;
    if (env.APPLE_CLIENT_ID && env.APPLE_TEAM_ID && env.APPLE_KEY_ID && env.APPLE_PRIVATE_KEY) {
        // المفتاح يُلصق بـ Render كما هو، أو بسطر واحد مع \n بدل الأسطر الجديدة
        const pem = String(env.APPLE_PRIVATE_KEY).replace(/\\n/g, "\n").trim();
        try {
            const privateKey = require("node:crypto").createPrivateKey(pem);
            apple = { clientId: env.APPLE_CLIENT_ID.trim(), teamId: env.APPLE_TEAM_ID.trim(), keyId: env.APPLE_KEY_ID.trim(), privateKey };
        } catch {
            apple = null;
        }
    }
    return {
        google: pair("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"),
        microsoft: pair("MICROSOFT_CLIENT_ID", "MICROSOFT_CLIENT_SECRET"),
        apple
    };
}

// مزوّد الذكاء الاصطناعي. أي خدمة متوافقة مع OpenAI تعمل؛ Responses API لـ OpenAI و Chat Completions للبقية.
function parseAi(env) {
    let apiKey = env.AI_API_KEY || env.OPENAI_API_KEY || "";
    let model = env.AI_MODEL || env.OPENAI_MODEL || "";
    let baseUrl = env.AI_BASE_URL || env.OPENAI_BASE_URL || "";
    if (!apiKey && env.GEMINI_API_KEY) {
        apiKey = env.GEMINI_API_KEY;
        model = model || env.GEMINI_MODEL || "gemini-2.5-flash";
    }
    apiKey = String(apiKey).trim();
    model = String(model).trim();
    let style = String(env.AI_API_STYLE || "").toLowerCase();
    let host = "";
    try { host = new URL(baseUrl).hostname; } catch { /* افتراضي أدناه */ }
    // Gemini: نستخدم الواجهة الأصلية (generateContent). مفاتيح Google الجديدة (AQ.) لا تعمل على واجهة OpenAI-compat.
    const geminiKey = Boolean(env.GEMINI_API_KEY && apiKey === String(env.GEMINI_API_KEY).trim());
    if (style === "gemini" || (style !== "chat" && (host === "generativelanguage.googleapis.com" || (!baseUrl && geminiKey)))) {
        return { apiKey, model: model || "gemini-2.5-flash", baseUrl: "https://generativelanguage.googleapis.com/v1beta", style: "gemini", webSearch: false };
    }
    baseUrl = (baseUrl || "https://api.openai.com/v1").replace(/\/+$/, "");
    if (!["responses", "chat"].includes(style)) style = host === "api.openai.com" || !host ? "responses" : "chat";
    return { apiKey, model, baseUrl, style, webSearch: env.OPENAI_WEB_SEARCH === "1" || env.AI_WEB_SEARCH === "1" };
}

// البريد (التحقق من الإيميل وروابط كلمة السر). يعمل فقط إذا ضُبط المفتاح وعنوان المرسل.
function parseMail(env) {
    const mailjet = env.MAILJET_API_KEY && env.MAILJET_SECRET_KEY;
    const provider = env.BREVO_API_KEY ? "brevo" : env.RESEND_API_KEY ? "resend" : mailjet ? "mailjet" : "";
    // Mailjet يستخدم مفتاحاً عاماً وسرياً (Basic auth): نخزّنهما معاً بصيغة key:secret
    const apiKey = provider === "mailjet"
        ? `${String(env.MAILJET_API_KEY).trim()}:${String(env.MAILJET_SECRET_KEY).trim()}`
        : String(env.BREVO_API_KEY || env.RESEND_API_KEY || "").trim();
    const from = /^[^\s@"<>]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(String(env.MAIL_FROM || "").trim()) ? String(env.MAIL_FROM).trim() : "";
    let apiBase = provider === "brevo" ? "https://api.brevo.com" : provider === "mailjet" ? "https://api.mailjet.com" : "https://api.resend.com";
    if (env.MAIL_API_BASE) {
        try {
            const u = new URL(env.MAIL_API_BASE);
            if (u.protocol === "https:" || ["localhost", "127.0.0.1"].includes(u.hostname)) apiBase = u.origin;
        } catch { /* نبقي الافتراضي */ }
    }
    return { provider, apiKey, from, fromName: cleanEnv(env.MAIL_FROM_NAME || "Phishing Detector", 60), apiBase, enabled: Boolean(provider && apiKey && from) };
}

function parsePayment(env) {
    const methods = [];
    const add = (id, label, value) => { const v = cleanEnv(value, 80); if (v) methods.push({ id, label, account: v }); };
    // الدفع بالماستر كارد فقط: بطاقة كي كارد (Qi Card) الماستر كارد. لا توجد طرق أخرى.
    add("qicard", "ماستر كارد (Qi Card)", env.PAY_QICARD);
    // بدون أي طريقة مضبوطة نعرض "تواصل معنا" فقط، ويبقى طلب التفعيل ممكناً
    if (!methods.length) methods.push({ id: "contact", label: "تواصل معنا لترتيب الدفع", account: "" });
    return {
        methods,
        whatsapp: /^\d{7,15}$/.test(env.CONTACT_WHATSAPP || "") ? env.CONTACT_WHATSAPP : "",
        telegram: /^[A-Za-z0-9_]{5,32}$/.test(env.CONTACT_TELEGRAM || "") ? env.CONTACT_TELEGRAM : "",
        note: cleanEnv(env.PAYMENT_NOTE, 400)
    };
}

// قاعدة Upstash: عنوان REST والرمز من لوحة Upstash. نقبل https فقط (وhttp للجهاز المحلي بالاختبارات).
function parseUpstash(env) {
    const url = String(env.UPSTASH_REDIS_REST_URL || "").trim();
    const token = String(env.UPSTASH_REDIS_REST_TOKEN || "").trim();
    if (!url && !token) return { upstash: null, error: "" };
    try {
        const parsed = new URL(url);
        const local = ["127.0.0.1", "localhost"].includes(parsed.hostname);
        if (!token || !(parsed.protocol === "https:" || (parsed.protocol === "http:" && local))) throw new Error("invalid");
        const prefix = /^[A-Za-z0-9_-]{1,32}$/.test(env.STORE_PREFIX || "") ? env.STORE_PREFIX : "pd";
        return { upstash: { url: parsed.origin, token, prefix }, error: "" };
    } catch {
        return { upstash: null, error: "UPSTASH_REDIS_REST_URL أو UPSTASH_REDIS_REST_TOKEN غير صالح (يلزم عنوان https ورمز). الحسابات ستعمل بالذاكرة فقط." };
    }
}

// صيغة كل حساب:
//   username:email:saltHex:hashHex   الدخول: اسم المستخدم ← البريد ← كلمة السر ← كود يصل للبريد (الموصى به)
//   username:saltHex:hashHex[:totp]  الصيغة القديمة: اسم مستخدم + كلمة سر (+ تطبيق مصادقة)
function parseAdmins(value) {
    const admins = new Map();
    for (const entry of String(value || "").split(",")) {
        const fields = entry.trim().split(":");
        const email = fields[1] && fields[1].includes("@") ? fields.splice(1, 1)[0].trim().toLowerCase() : "";
        const [user, salt, hash, totpSecret] = fields;
        if (!user || !salt || !HEX_32_BYTES.test(hash || "")) continue;
        if (email && parseAdminEmails(email).size !== 1) continue;   // بريد تالف: نتجاهل الحساب بدل ما نقفل صاحبه
        admins.set(user.toLowerCase(), {
            email,
            salt,
            hash: Buffer.from(hash, "hex"),
            totpSecret: email ? "" : totpSecret || "",
            lastTotpCounter: -1
        });
    }
    return admins;
}

// بريد الأدمن: قائمة مفصولة بفواصل، تُوحَّد بحروف صغيرة ويُتجاهل أي عنوان غير صالح
function parseAdminEmails(value) {
    const emails = new Set();
    for (const raw of String(value || "").split(/[,;\s]+/)) {
        const email = raw.trim().toLowerCase();
        if (email.length <= 254 && /^[^\s@"<>()[\],;:]+@[a-z0-9-]+(\.[a-z0-9-]+)*\.[a-z]{2,}$/.test(email)) emails.add(email);
    }
    return emails;
}

function loadConfig(env = process.env) {
    const onRender = Boolean(env.RENDER);
    const root = path.resolve(__dirname, "..");
    const upstash = parseUpstash(env);
    return {
        onRender,
        root,
        publicDir: path.join(root, "public"),
        adminDir: path.join(__dirname, "admin"),
        host: env.HOST || (onRender ? "0.0.0.0" : "127.0.0.1"),
        port: Number(env.PORT || 8080),
        trustProxy: env.TRUST_PROXY === "1" || onRender,
        // الترويسة التي يضعها الوسيط بعنوان الزائر الحقيقي ولا يستطيع الزائر تزويرها.
        // تأكد منها بـ /api/admin/ipcheck. مثال: cf-connecting-ip إذا كان Cloudflare الخاص بك أمام الموقع.
        clientIpHeader: /^[a-z0-9-]{1,40}$/i.test(env.CLIENT_IP_HEADER || "") ? env.CLIENT_IP_HEADER.toLowerCase() : "true-client-ip",
        allowedOrigin: env.CYBERBOT_ORIGIN || "",
        appUrl: parseAppUrl(env, Number(env.PORT || 8080)),
        openai: parseAi(env),
        oauth: parseOAuth(env),
        intel: { enabled: env.THREAT_FEEDS !== "0" },
        plans: {
            priceUsd: numberEnv(env.PRICE_USD, 2, 0, 1000),
            priceIqd: numberEnv(env.PRICE_IQD, 3000, 0, 10_000_000),
            trialDays: numberEnv(env.TRIAL_DAYS, 30, 0, 365)
        },
        payment: parsePayment(env),
        mail: parseMail(env),
        admins: parseAdmins(env.ADMINS),
        adminEmails: parseAdminEmails(env.ADMIN_EMAILS),
        // سجل التدقيق كسطور JSON في سجلات الاستضافة (تلقائي على Render، يُعطَّل بـ AUDIT_STDOUT=0)
        auditStdout: env.AUDIT_STDOUT === "1" || (onRender && env.AUDIT_STDOUT !== "0"),
        health: {},   // عتبات مراقب الصحة (انظر server/health.js)، تُعدَّل بالاختبارات فقط
        billing: {
            // قاعدة البيانات الخارجية (الحسابات والاشتراكات). بدونها: ذاكرة فقط (للتجربة المحلية).
            upstash: upstash.upstash,
            upstashError: upstash.error
        },
        limits: {
            chatPerMinute: 20,
            globalChatPerMinute: Number(env.CYBERBOT_GLOBAL_LIMIT || 120),
            eventPerMinute: 120,
            clientErrorPerMinute: 10,
            globalClientErrorPerMinute: 100,
            loginFailuresPerWindow: 5,
            loginWindowMs: 15 * 60_000,
            loginAttemptsPerMinute: 30,
            badApiKeysPerWindow: 20,
            registrationsPerDay: 5,
            userLoginFailures: 8,
            authPerMinute: 30,
            scanPerMinute: 30,
            maxBodyBytes: 128 * 1024
        },
        session: {
            idleMs: 20 * 60_000,
            absoluteMs: 8 * 60 * 60_000,
            maxSessions: 20
        }
    };
}

module.exports = { loadConfig, parseAdmins };
