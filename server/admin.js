"use strict";

/*
  صفحة الأدمن. القواعد:
  - مغلقة تماماً (404) إذا لم يُضبط ADMIN_EMAILS ولا ADMINS.
  - الدخول الموصى به (ADMINS بصيغة username:email:salt:hash): اسم المستخدم ← البريد ← كلمة السر، تُفحص الثلاثة
    معاً (scrypt دائماً، ورسالة خطأ واحدة) ← كود من 6 أرقام يصل لبريد الحساب ← الجلسة. هذه الحسابات لا تقبل الدخول بكلمة السر وحدها.
  - الدخول بالبريد فقط (ADMIN_EMAILS): بريد الأدمن ← كود من 6 أرقام يصل للبريد (صالح 10 دقائق، لمرة واحدة،
    5 محاولات كحد أقصى) ← الجلسة. الرد واحد لأي بريد، والإرسال لا يُنتظر، فلا يُعرف هل البريد للأدمن أم لا.
  - الدخول القديم (ADMINS، اختياري): اسم مستخدم + كلمة سر (scrypt) + رمز TOTP إذا كان مفعّلاً للحساب.
  - بعد 5 محاولات فاشلة من نفس العنوان يُحظر 15 دقيقة، وسقف عام لمحاولات الدخول بالدقيقة.
  - الجلسة: رمز عشوائي طويل في كوكي HttpOnly + SameSite=Strict (+ Secure على HTTPS)، تنتهي بعد 20 دقيقة خمول أو 8 ساعات.
  - كل ما يغيّر الحالة يتطلب طلب JSON قادماً من الموقع نفسه (حماية CSRF).
  - رسالة الخطأ دائماً واحدة، فلا يُعرف هل الخطأ بالاسم أم الكلمة أم الرمز.
*/

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const { promisify } = require("node:util");
const totp = require("./totp");
const { createRateLimiter, createFailureLimiter } = require("./rate-limit");
const http = require("./http");
const { planOf } = require("./plans");
const { UserError } = require("./users");
const { versionAssets } = require("./static");

const scrypt = promisify(crypto.scrypt);
const DUMMY_SALT = crypto.randomBytes(16).toString("hex");
const GENERIC_LOGIN_ERROR = "بيانات الدخول غير صحيحة.";
const CODE_TTL_MS = 10 * 60_000;
const CODE_MAX_TRIES = 5;
const CODE_RESEND_MS = 60_000;
const CODE_STARTS_PER_WINDOW = 8;
const maskEmail = email => String(email).replace(/^(.)[^@]*@(.)[^.]*(\..+)$/, "$1***@$2***$3");

const ASSETS = {
    "admin.css": { type: "text/css; charset=utf-8", publicAsset: true },
    "login.js": { type: "text/javascript; charset=utf-8", publicAsset: true },
    "dashboard.js": { type: "text/javascript; charset=utf-8", publicAsset: false },
    "manage.js": { type: "text/javascript; charset=utf-8", publicAsset: false },
    "settings.js": { type: "text/javascript; charset=utf-8", publicAsset: false },
    "community.js": { type: "text/javascript; charset=utf-8", publicAsset: false }
};

function sha256(value) {
    return crypto.createHash("sha256").update(value).digest("hex");
}

// extras: { visitors, health, users, db, intel, chat } لإظهارها وإدارتها بلوحة الأدمن (اختياري)
function createAdmin(config, stats, extras = {}) {
    const adminEmails = config.adminEmails || new Set();
    const enabled = config.admins.size > 0 || adminEmails.size > 0;
    const mailer = extras.mailer || null;
    const mailReady = () => Boolean(mailer && mailer.enabled);
    const emailLogin = () => adminEmails.size > 0 && mailReady();
    const fullAccounts = [...config.admins.values()].some(a => a.email);
    const passwordOnly = [...config.admins.values()].some(a => !a.email);
    const tickets = new Map();     // sha256(ticket) -> { email|null, user?, codeHash, exp, tries }
    const lastSent = new Map();    // email -> وقت آخر كود (منع الإغراق)
    const starts = createFailureLimiter({ windowMs: config.limits.loginWindowMs, max: CODE_STARTS_PER_WINDOW });
    const sessions = new Map();   // sha256(sid) -> { user, created, last }
    const failures = createFailureLimiter({ windowMs: config.limits.loginWindowMs, max: config.limits.loginFailuresPerWindow });
    const attempts = createRateLimiter({ windowMs: 60_000, max: Infinity, globalMax: config.limits.loginAttemptsPerMinute });

    const files = {};
    if (enabled) {
        for (const name of ["login.html", "dashboard.html", ...Object.keys(ASSETS)]) {
            const raw = fs.readFileSync(path.join(config.adminDir, name));
            // روابط /vendor بصفحات الإدارة تحمل بصمة المحتوى مثل بقية الموقع
            files[name] = name.endsWith(".html") ? Buffer.from(versionAssets(raw.toString("utf8"), config.publicDir)) : raw;
        }
    }

    const pruneTimer = setInterval(() => {
        const now = Date.now();
        for (const [key, record] of sessions) {
            if (now - record.last > config.session.idleMs || now - record.created > config.session.absoluteMs) sessions.delete(key);
        }
        for (const [key, t] of tickets) if (t.exp <= now) tickets.delete(key);
        for (const [email, at] of lastSent) if (now - at > CODE_RESEND_MS) lastSent.delete(email);
    }, 60_000);
    pruneTimer.unref();

    // ---------- الجلسات ----------
    const cookieName = req => (http.isHttps(req, config) ? "__Host-sid" : "sid");

    function cookieHeader(req, value, maxAgeSeconds) {
        const parts = [`${cookieName(req)}=${value}`, "Path=/", "HttpOnly", "SameSite=Strict", `Max-Age=${maxAgeSeconds}`];
        if (http.isHttps(req, config)) parts.push("Secure");
        return parts.join("; ");
    }

    function createSession(user) {
        if (sessions.size >= config.session.maxSessions) sessions.delete(sessions.keys().next().value);
        const sid = crypto.randomBytes(32).toString("base64url");
        const now = Date.now();
        sessions.set(sha256(sid), { user, created: now, last: now });
        return sid;
    }

    function currentSession(req) {
        const sid = http.parseCookies(req.headers.cookie)[cookieName(req)];
        if (!sid || sid.length > 100) return null;
        const key = sha256(sid);
        const record = sessions.get(key);
        if (!record) return null;
        const now = Date.now();
        if (now - record.last > config.session.idleMs || now - record.created > config.session.absoluteMs) {
            sessions.delete(key);
            return null;
        }
        record.last = now;
        return { key, user: record.user };
    }

    // ---------- الردود ----------
    function sendFile(req, res, name, contentType) {
        const body = files[name];
        res.writeHead(200, {
            "Content-Type": contentType,
            "Content-Length": body.length,
            "Cache-Control": "no-store",
            "X-Robots-Tag": "noindex, nofollow, noarchive"
        });
        res.end(req.method === "HEAD" ? undefined : body);
    }

    function methodNotAllowed(res, allow) {
        http.sendJson(res, 405, { error: "Method not allowed" }, { Allow: allow });
    }

    // ---------- تسجيل الدخول ----------
    async function login(req, res) {
        const ip = http.getClientIp(req, config);
        if (!http.isSameOrigin(req)) {
            stats.count("blockedRequests");
            stats.event("blocked_origin", "محاولة دخول من موقع غير مسموح", ip);
            http.sendJson(res, 403, { error: "Forbidden" });
            return;
        }
        if (!http.isJsonRequest(req)) {
            http.sendJson(res, 415, { error: "Content-Type must be application/json" });
            return;
        }
        if (!attempts.take("login")) {
            stats.event("login_throttled", "تجاوز السقف العام لمحاولات الدخول", ip);
            http.sendJson(res, 429, { error: "محاولات كثيرة. حاول بعد قليل." }, { "Retry-After": "60" });
            return;
        }
        if (failures.isBlocked(ip)) {
            http.sendJson(res, 429, { error: "تم حظر المحاولات مؤقتاً. حاول لاحقاً." }, { "Retry-After": String(failures.retryAfterSeconds(ip)) });
            return;
        }

        let body;
        try {
            body = await http.readJsonBody(req, 2048);
            if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("bad body");
        } catch {
            http.sendJson(res, 400, { error: "Bad request" });
            return;
        }

        // نقصّ الأطوال حتى لا تُستخدم مدخلات ضخمة لإبطاء الخادم
        const username = typeof body.username === "string" ? body.username.trim().toLowerCase().slice(0, 64) : "";
        const password = typeof body.password === "string" ? body.password.slice(0, 256) : "";
        const code = typeof body.code === "string" ? body.code.replace(/\s/g, "").slice(0, 10) : "";

        const admin = config.admins.get(username);
        // نشغّل scrypt حتى لو الحساب غير موجود، حتى لا يكشف زمن الرد وجود الحساب
        const derived = await scrypt(password, admin ? admin.salt : DUMMY_SALT, 32);
        let passwordOk = Boolean(admin) && crypto.timingSafeEqual(derived, admin.hash);

        let reason = "";
        if (passwordOk && admin.email) {
            passwordOk = false;   // حساب مربوط ببريد: يلزمه كود البريد، فلا يكفي هذا المسار
            reason = "محاولة دخول بكلمة السر وحدها لحساب يتطلب كود البريد";
        }
        let codeOk = true;
        if (passwordOk && admin.totpSecret) {
            const counter = totp.verify(admin.totpSecret, code, { lastCounter: admin.lastTotpCounter });
            codeOk = counter >= 0;
            if (codeOk) admin.lastTotpCounter = counter;   // نمنع إعادة استخدام نفس الرمز
            else reason = "رمز التحقق الثنائي خاطئ";
        } else if (!passwordOk && !reason) {
            reason = admin ? "كلمة سر خاطئة" : "اسم مستخدم غير معروف";
        }

        if (!passwordOk || !codeOk) {
            failures.fail(ip);
            stats.count("loginFailed");
            stats.event("login_failed", reason, ip);
            http.sendJson(res, 401, { error: GENERIC_LOGIN_ERROR });
            return;
        }

        failures.clear(ip);
        stats.count("loginOk");
        stats.event("login_ok", "تسجيل دخول ناجح للأدمن", ip);
        // جلسة جديدة دائماً بعد الدخول (تمنع تثبيت الجلسة)
        const sid = createSession(username);
        http.sendJson(res, 200, { ok: true }, { "Set-Cookie": cookieHeader(req, sid, Math.floor(config.session.absoluteMs / 1000)) });
    }

    // ---------- الدخول بكود البريد ----------
    // فحوصات مشتركة: نفس الموقع، JSON، السقف العام، والحظر المؤقت للعنوان. يرجع الجسم أو undefined
    async function guardedBody(req, res, ip) {
        if (!http.isSameOrigin(req)) {
            stats.count("blockedRequests");
            stats.event("blocked_origin", "محاولة دخول من موقع غير مسموح", ip);
            http.sendJson(res, 403, { error: "Forbidden" });
            return undefined;
        }
        if (!http.isJsonRequest(req)) return http.sendJson(res, 415, { error: "Content-Type must be application/json" }), undefined;
        if (!attempts.take("login")) {
            stats.event("login_throttled", "تجاوز السقف العام لمحاولات الدخول", ip);
            return http.sendJson(res, 429, { error: "محاولات كثيرة. حاول بعد قليل." }, { "Retry-After": "60" }), undefined;
        }
        if (failures.isBlocked(ip)) {
            return http.sendJson(res, 429, { error: "تم حظر المحاولات مؤقتاً. حاول لاحقاً." }, { "Retry-After": String(failures.retryAfterSeconds(ip)) }), undefined;
        }
        try {
            const body = await http.readJsonBody(req, 1024);
            if (body && typeof body === "object" && !Array.isArray(body)) return body;
        } catch { /* نكمل للرد بالخطأ */ }
        http.sendJson(res, 400, { error: "Bad request" });
        return undefined;
    }

    async function startEmailLogin(req, res) {
        const ip = http.getClientIp(req, config);
        if (!emailLogin()) return http.sendJson(res, 503, { error: "الدخول بالبريد غير مفعّل على الخادم.", code: "email_login_disabled" });
        const body = await guardedBody(req, res, ip);
        if (body === undefined) return;
        if (starts.isBlocked(ip)) {
            return http.sendJson(res, 429, { error: "طلبت رموزاً كثيرة. انتظر قليلاً ثم حاول." }, { "Retry-After": String(starts.retryAfterSeconds(ip)) });
        }
        const email = typeof body.email === "string" ? body.email.trim().toLowerCase().slice(0, 254) : "";
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return http.sendJson(res, 400, { error: "اكتب بريداً إلكترونياً صحيحاً." });
        starts.fail(ip);

        const now = Date.now();
        const isAdmin = adminEmails.has(email);
        const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
        const ticket = crypto.randomBytes(24).toString("base64url");
        if (tickets.size >= 500) tickets.delete(tickets.keys().next().value);
        tickets.set(sha256(ticket), { email: isAdmin ? email : null, codeHash: sha256(ticket + ":" + code), exp: now + CODE_TTL_MS, tries: 0 });

        // الرد واحد ومباشر لأي بريد؛ الإرسال يكمل بالخلفية حتى لا يكشف زمن الرد بريد الأدمن
        if (isAdmin && !(lastSent.has(email) && now - lastSent.get(email) < CODE_RESEND_MS)) {
            lastSent.set(email, now);
            mailer.adminCode(email, code).then(
                () => stats.event("admin_code_sent", `أُرسل رمز دخول الإدارة إلى ${maskEmail(email)}`, ip),
                () => stats.event("admin_code_failed", "تعذر إرسال رمز دخول الإدارة. راجع إعدادات مزوّد البريد.", ip)
            );
        } else if (!isAdmin) {
            stats.event("admin_code_unknown", "طلب رمز دخول الإدارة لبريد غير مسجّل كأدمن", ip);
        }
        http.sendJson(res, 200, { ok: true, ticket, expiresIn: CODE_TTL_MS / 1000, resendAfter: CODE_RESEND_MS / 1000 });
    }

    // اسم المستخدم + البريد + كلمة السر ← كود للبريد. الثلاثة تُفحص معاً حتى لا تكشف أي خطوة شيئاً
    async function startAccountLogin(req, res) {
        const ip = http.getClientIp(req, config);
        if (!fullAccounts) return http.sendJson(res, 404, { error: "Not found" });
        if (!mailReady()) return http.sendJson(res, 503, { error: "إرسال كود التحقق غير متاح: مزوّد البريد غير مضبوط على الخادم.", code: "email_login_disabled" });
        const body = await guardedBody(req, res, ip);
        if (body === undefined) return;
        if (starts.isBlocked(ip)) {
            return http.sendJson(res, 429, { error: "طلبت رموزاً كثيرة. انتظر قليلاً ثم حاول." }, { "Retry-After": String(starts.retryAfterSeconds(ip)) });
        }
        const username = typeof body.username === "string" ? body.username.trim().toLowerCase().slice(0, 64) : "";
        const email = typeof body.email === "string" ? body.email.trim().toLowerCase().slice(0, 254) : "";
        const password = typeof body.password === "string" ? body.password.slice(0, 256) : "";

        const admin = config.admins.get(username);
        const derived = await scrypt(password, admin ? admin.salt : DUMMY_SALT, 32);
        const passwordOk = Boolean(admin) && crypto.timingSafeEqual(derived, admin.hash);
        const emailOk = Boolean(admin && admin.email) && admin.email === email;
        if (!passwordOk || !emailOk) {
            failures.fail(ip);
            stats.count("loginFailed");
            const reason = !admin ? "اسم مستخدم غير معروف" : !admin.email ? "الحساب لا يستخدم الدخول بالبريد" : !emailOk ? "بريد لا يطابق الحساب" : "كلمة سر خاطئة";
            stats.event("login_failed", reason, ip);
            return http.sendJson(res, 401, { error: GENERIC_LOGIN_ERROR });
        }

        // البيانات صحيحة: الآن فقط نرسل الكود (ومسموح نقول للمستخدم إنه انتظر، لأن البيانات صحيحة)
        const now = Date.now();
        const last = lastSent.get(email);
        if (last && now - last < CODE_RESEND_MS) {
            const wait = Math.ceil((CODE_RESEND_MS - (now - last)) / 1000);
            return http.sendJson(res, 429, { error: `انتظر ${wait} ثانية قبل طلب رمز جديد.`, retryAfter: wait }, { "Retry-After": String(wait) });
        }
        starts.fail(ip);
        const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
        try {
            await mailer.adminCode(email, code);
        } catch {
            stats.event("admin_code_failed", "تعذر إرسال رمز دخول الإدارة. راجع إعدادات مزوّد البريد.", ip);
            return http.sendJson(res, 502, { error: "تعذر إرسال كود التحقق إلى بريدك. حاول بعد قليل." });
        }
        lastSent.set(email, now);
        for (const [key, t] of tickets) if (t.user === username) tickets.delete(key);   // الكود الجديد يلغي القديم
        const ticket = crypto.randomBytes(24).toString("base64url");
        if (tickets.size >= 500) tickets.delete(tickets.keys().next().value);
        tickets.set(sha256(ticket), { email, user: username, codeHash: sha256(ticket + ":" + code), exp: now + CODE_TTL_MS, tries: 0 });
        failures.clear(ip);
        stats.event("admin_code_sent", `أُرسل رمز دخول الإدارة إلى ${maskEmail(email)} (الحساب ${username})`, ip);
        http.sendJson(res, 200, { ok: true, ticket, sentTo: maskEmail(email), expiresIn: CODE_TTL_MS / 1000, resendAfter: CODE_RESEND_MS / 1000 });
    }

    async function verifyEmailLogin(req, res) {
        const ip = http.getClientIp(req, config);
        if (!emailLogin() && !(fullAccounts && mailReady())) return http.sendJson(res, 503, { error: "الدخول بالبريد غير مفعّل على الخادم.", code: "email_login_disabled" });
        const body = await guardedBody(req, res, ip);
        if (body === undefined) return;
        const ticket = typeof body.ticket === "string" ? body.ticket.slice(0, 100) : "";
        const code = typeof body.code === "string" ? body.code.replace(/\D/g, "").slice(0, 6) : "";
        const key = ticket ? sha256(ticket) : "";
        const record = key ? tickets.get(key) : null;

        const reject = (message, reason, extra = {}) => {
            failures.fail(ip);
            stats.count("loginFailed");
            stats.event("login_failed", reason, ip);
            http.sendJson(res, 401, { error: message, ...extra });
        };
        if (!record || record.exp <= Date.now()) {
            if (record) tickets.delete(key);
            return reject("انتهت صلاحية الرمز. اطلب رمزاً جديداً.", "رمز إدارة منتهي أو غير موجود", { code: "expired" });
        }
        record.tries += 1;
        const expected = Buffer.from(record.codeHash, "hex");
        const actual = Buffer.from(sha256(ticket + ":" + code), "hex");
        const ok = code.length === 6 && Boolean(record.email) && crypto.timingSafeEqual(expected, actual);
        if (!ok) {
            const left = CODE_MAX_TRIES - record.tries;
            if (left <= 0) tickets.delete(key);
            return reject(left > 0 ? `الرمز غير صحيح. باقي ${left} محاولات.` : "تجاوزت عدد المحاولات. اطلب رمزاً جديداً.", "رمز دخول إدارة خاطئ",
                { code: left > 0 ? "wrong_code" : "expired", triesLeft: Math.max(0, left) });
        }

        tickets.delete(key);
        lastSent.delete(record.email);
        failures.clear(ip);
        starts.clear(ip);
        stats.count("loginOk");
        stats.event("login_ok", record.user ? `دخول للإدارة: ${record.user} (كلمة سر + كود البريد)` : `دخول للإدارة بكود البريد (${maskEmail(record.email)})`, ip);
        const sid = createSession(record.user || record.email);
        http.sendJson(res, 200, { ok: true }, { "Set-Cookie": cookieHeader(req, sid, Math.floor(config.session.absoluteMs / 1000)) });
    }

    function logout(req, res) {
        if (!http.isSameOrigin(req)) {
            http.sendJson(res, 403, { error: "Forbidden" });
            return;
        }
        const session = currentSession(req);
        if (session) {
            sessions.delete(session.key);
            stats.event("logout", "تسجيل خروج", http.getClientIp(req, config));
        }
        http.sendJson(res, 200, { ok: true }, { "Set-Cookie": cookieHeader(req, "", 0) });
    }

    function statsPayload(req, session) {
        const memory = process.memoryUsage();
        const admin = config.admins.get(session.user);
        return {
            user: session.user,
            server: {
                node: process.version,
                memoryMb: Math.round(memory.rss / 1048576),
                platform: process.env.RENDER ? "Render" : "محلي",
                https: http.isHttps(req, config)
            },
            config: {
                chatConfigured: Boolean(config.openai.apiKey && config.openai.model),
                chat: extras.chat ? extras.chat() : null,
                mail: extras.mail ? extras.mail() : null,
                sms: extras.sms ? extras.sms() : null,
                database: extras.db ? { backend: extras.db.backend, persistent: extras.db.persistent, warning: extras.db.persistent ? "" : (config.onRender ? "الحسابات محفوظة بالذاكرة فقط وستضيع عند أي نشر أو إعادة تشغيل! أضف UPSTASH_REDIS_REST_URL و UPSTASH_REDIS_REST_TOKEN." : "ذاكرة فقط (تشغيل محلي).") } : null,
                intel: extras.intel ? extras.intel.status() : null,
                oauth: Object.keys(config.oauth).filter(k => config.oauth[k]),
                appUrl: config.appUrl,
                plans: config.plans,
                webSearch: config.openai.webSearch,
                chatPerMinute: config.limits.chatPerMinute,
                globalChatPerMinute: config.limits.globalChatPerMinute,
                adminCount: config.admins.size + adminEmails.size,
                loginMethod: admin ? (admin.email ? "كلمة سر + كود البريد" : admin.totpSecret ? "كلمة سر + تطبيق مصادقة" : "كلمة سر فقط") : "كود البريد",
                emailLogin: emailLogin() || (fullAccounts && mailReady()),
                totpEnabled: Boolean(admin && admin.totpSecret),
                activeSessions: sessions.size
            },
            visitors: extras.visitors ? extras.visitors.snapshot() : null,
            health: extras.health ? extras.health() : null,
            ...stats.snapshot(100)
        };
    }

    // ---------- الموجّه ----------
    // يرجع true إذا عالج الطلب (أي أن المسار يخص الأدمن)
    async function handle(req, res, url) {
        const p = url.pathname.replace(/\/+$/, "") || "/";
        const isAdminPath = p === "/admin" || p.startsWith("/admin/") || p.startsWith("/api/admin/");
        if (!isAdminPath) return false;

        // بدون حسابات مضبوطة، الصفحة غير موجودة أصلاً
        if (!enabled) {
            http.sendJson(res, 404, { error: "Not found" });
            return true;
        }

        if (p === "/admin") {
            if (req.method !== "GET" && req.method !== "HEAD") return methodNotAllowed(res, "GET, HEAD"), true;
            sendFile(req, res, currentSession(req) ? "dashboard.html" : "login.html", "text/html; charset=utf-8");
            return true;
        }

        if (p.startsWith("/admin/assets/")) {
            const name = p.slice("/admin/assets/".length);
            const asset = Object.prototype.hasOwnProperty.call(ASSETS, name) ? ASSETS[name] : null;
            if (req.method !== "GET" && req.method !== "HEAD") return methodNotAllowed(res, "GET, HEAD"), true;
            if (!asset || (!asset.publicAsset && !currentSession(req))) {
                http.sendJson(res, 404, { error: "Not found" });
                return true;
            }
            sendFile(req, res, name, asset.type);
            return true;
        }

        // طرق الدخول المتاحة (عامة: تكفي لعرض النموذج الصحيح ولا تكشف أي بريد)
        if (p === "/api/admin/methods") {
            if (req.method !== "GET") return methodNotAllowed(res, "GET"), true;
            http.sendJson(res, 200, { account: fullAccounts, email: adminEmails.size > 0, emailReady: mailReady(), password: passwordOnly });
            return true;
        }
        if (p === "/api/admin/account/start") {
            if (req.method !== "POST") return methodNotAllowed(res, "POST"), true;
            await startAccountLogin(req, res);
            return true;
        }
        if (p === "/api/admin/email/start" || p === "/api/admin/email/verify") {
            if (req.method !== "POST") return methodNotAllowed(res, "POST"), true;
            await (p.endsWith("start") ? startEmailLogin(req, res) : verifyEmailLogin(req, res));
            return true;
        }
        if (p === "/api/admin/login") {
            if (req.method !== "POST") return methodNotAllowed(res, "POST"), true;
            await login(req, res);
            return true;
        }
        if (p === "/api/admin/logout") {
            if (req.method !== "POST") return methodNotAllowed(res, "POST"), true;
            logout(req, res);
            return true;
        }
        if (p === "/api/admin/stats") {
            if (req.method !== "GET") return methodNotAllowed(res, "GET"), true;
            const session = currentSession(req);
            if (!session) {
                http.sendJson(res, 401, { error: "Unauthorized" });
                return true;
            }
            const payload = statsPayload(req, session);
            try { payload.usersTotal = extras.users && extras.users.count ? await extras.users.count() : null; } catch { payload.usersTotal = null; }
            try { payload.openReports = extras.community ? await extras.community.openCount() : 0; } catch { payload.openReports = 0; }
            http.sendJson(res, 200, payload);
            return true;
        }

        // تشخيص عنوان الزائر: يعرض ما يراه الخادم فعلاً، حتى تتأكد أن الزائر لا يستطيع تزوير عنوانه بترويسة
        // (curl -H "True-Client-IP: 1.2.3.4" ... ثم قارن). للأدمن فقط.
        if (p === "/api/admin/ipcheck") {
            if (req.method !== "GET") return methodNotAllowed(res, "GET"), true;
            if (!currentSession(req)) return http.sendJson(res, 401, { error: "Unauthorized" }), true;
            http.sendJson(res, 200, {
                usedIp: http.getClientIp(req, config),
                trustProxy: Boolean(config.trustProxy),
                trueClientIp: String(req.headers["true-client-ip"] || ""),
                cfConnectingIp: String(req.headers["cf-connecting-ip"] || ""),
                xForwardedFor: String(req.headers["x-forwarded-for"] || ""),
                socket: (req.socket && req.socket.remoteAddress) || ""
            });
            return true;
        }

        // إعدادات الموقع: قراءة وتعديل وإرجاع للافتراضي
        if (p === "/api/admin/settings" || p === "/api/admin/settings/reset") {
            const session = currentSession(req);
            if (!session) return http.sendJson(res, 401, { error: "Unauthorized" }), true;
            if (!extras.settings) return http.sendJson(res, 404, { error: "Not found" }), true;
            if (p === "/api/admin/settings" && req.method === "GET") return http.sendJson(res, 200, extras.settings.adminView()), true;
            if (req.method !== "POST") return methodNotAllowed(res, p.endsWith("reset") ? "POST" : "GET, POST"), true;
            const ip = http.getClientIp(req, config);
            // جسم أكبر قليلاً من بقية الطلبات (نصوص وتعليمات)
            if (!http.isSameOrigin(req)) return http.sendJson(res, 403, { error: "Forbidden" }), true;
            if (!http.isJsonRequest(req)) return http.sendJson(res, 415, { error: "Content-Type must be application/json" }), true;
            let body;
            try {
                body = await http.readJsonBody(req, 16 * 1024);
                if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("bad");
            } catch {
                return http.sendJson(res, 400, { error: "طلب غير صالح." }), true;
            }
            try {
                if (p.endsWith("reset")) {
                    const result = await extras.settings.reset(session.user);
                    stats.event("admin_settings", "إرجاع إعدادات الموقع للافتراضي", ip);
                    return http.sendJson(res, 200, result), true;
                }
                const result = await extras.settings.update(body.values, session.user);
                if (!result.ok) return http.sendJson(res, 400, { error: "قيم غير صالحة: " + result.errors.join("، "), fields: result.errors }), true;
                if (result.changed.length) stats.event("admin_settings", `تعديل إعدادات الموقع: ${result.changed.slice(0, 6).join("، ")}${result.changed.length > 6 ? " ..." : ""}`, ip);
                return http.sendJson(res, 200, result), true;
            } catch (error) {
                if (error && error.name === "UpstashError") return http.sendJson(res, 503, { error: "تعذر الحفظ بقاعدة البيانات." }), true;
                throw error;
            }
        }

        if (p === "/api/admin/ai-test") {
            if (req.method !== "POST") return methodNotAllowed(res, "POST"), true;
            const session = currentSession(req);
            if (!session) return http.sendJson(res, 401, { error: "Unauthorized" }), true;
            const body = await adminPostBody(req, res);
            if (body === undefined) return true;
            const result = extras.chatTest ? await extras.chatTest() : { ok: false, error: "غير متاح." };
            stats.event("admin_ai_test", result.ok ? `اختبار الذكاء الاصطناعي ناجح (${result.model}، ${result.ms}ms)` : `فشل اختبار الذكاء الاصطناعي: ${result.error}`, http.getClientIp(req, config));
            http.sendJson(res, 200, result);
            return true;
        }

        // ---------- المستخدمون والمدفوعات والإيرادات (تتطلب جلسة أدمن) ----------
        if (p === "/api/admin/identifiers" || p.startsWith("/api/admin/identifiers/")) {
            const session = currentSession(req);
            if (!session) return http.sendJson(res, 401, { error: "Unauthorized" }), true;
            const ids = extras.identifiers;
            if (!ids) return http.sendJson(res, 404, { error: "Not found" }), true;
            try {
                if (p === "/api/admin/identifiers" && req.method === "GET") return http.sendJson(res, 200, await ids.adminView()), true;
                if (req.method !== "POST") return methodNotAllowed(res, "POST"), true;
                const body = await adminPostBody(req, res);
                if (body === undefined) return true;
                const ip = http.getClientIp(req, config);
                if (p === "/api/admin/identifiers/dispute") {
                    const item = await ids.decideDispute(String(body.id || ""), { remove: body.remove === true, admin: session.user });
                    stats.event("identifier_dispute", `${item.status === "removed" ? "قبول اعتراض وحذف بلاغات" : "رفض اعتراض"} (${item.masked})`, ip);
                    return http.sendJson(res, 200, { item }), true;
                }
                if (p === "/api/admin/identifiers/remove") {
                    await ids.removeByHash(String(body.h || ""));
                    stats.event("identifier_dispute", "حذف بلاغات معرّف يدوياً", ip);
                    return http.sendJson(res, 200, { ok: true }), true;
                }
                return http.sendJson(res, 404, { error: "Not found" }), true;
            } catch (error) {
                if (error && typeof error.status === "number" && error.name !== "UpstashError") return http.sendJson(res, error.status, { error: error.message }), true;
                if (error && error.name === "UpstashError") return http.sendJson(res, 503, { error: "تعذر الوصول لقاعدة البيانات." }), true;
                throw error;
            }
        }
        if (p === "/api/admin/community" || p.startsWith("/api/admin/community/")) {
            return await communityRoutes(req, res, p, url), true;
        }
        if (p.startsWith("/api/admin/users") || p.startsWith("/api/admin/payments") || p === "/api/admin/revenue" || p.startsWith("/api/admin/export/")) {
            return await manageRoutes(req, res, p, url), true;
        }

        http.sendJson(res, 404, { error: "Not found" });
        return true;
    }

    // POST من الصفحة نفسها فقط، بجسم JSON صغير
    async function adminPostBody(req, res) {
        if (!http.isSameOrigin(req)) return http.sendJson(res, 403, { error: "Forbidden" }), undefined;
        if (!http.isJsonRequest(req)) return http.sendJson(res, 415, { error: "Content-Type must be application/json" }), undefined;
        try {
            const body = await http.readJsonBody(req, 4096);
            if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("bad body");
            return body;
        } catch {
            return http.sendJson(res, 400, { error: "طلب غير صالح." }), undefined;
        }
    }

    function sendDownload(res, contentType, filename, body) {
        res.writeHead(200, {
            "Content-Type": contentType,
            "Content-Disposition": `attachment; filename="${filename}"`,
            "Content-Length": Buffer.byteLength(body),
            "Cache-Control": "no-store"
        });
        res.end(body);
    }

    function adminUserView(u) {
        const plan = planOf(u);
        return {
            id: u.id, email: u.email || "", phone: u.phone || "", name: u.name, providers: Object.keys(u.providers || {}), hasPassword: Boolean(u.pw),
            emailVerified: Boolean(u.emailVerified), disabled: Boolean(u.disabled),
            createdAt: new Date(u.createdAt).toISOString(), lastLoginAt: u.lastLoginAt ? new Date(u.lastLoginAt).toISOString() : null,
            plan: plan.id, planSource: plan.source, planUntil: plan.until ? new Date(plan.until).toISOString() : null,
            paidUntil: u.paidUntil ? new Date(u.paidUntil).toISOString() : null
        };
    }

    const csvCell = value => {
        let text = String(value === undefined || value === null ? "" : value);
        // يمنع حقن الصيغ عند فتح الملف بـ Excel
        if (/^[=+\-@\t\r]/.test(text)) text = "'" + text;
        return '"' + text.replace(/"/g, '""') + '"';
    };
    const toCsv = (header, rows) => "\ufeff" + [header, ...rows].map(r => r.map(csvCell).join(",")).join("\r\n");

    // البلاغات والتنبيهات والقائمة المؤكدة
    async function communityRoutes(req, res, p, url) {
        const community = extras.community;
        const session = currentSession(req);
        if (!community) return http.sendJson(res, 404, { error: "Not found" });
        if (!session) return http.sendJson(res, 401, { error: "Unauthorized" });
        const ip = http.getClientIp(req, config);
        try {
            if (p === "/api/admin/community" && req.method === "GET") {
                const status = url.searchParams.get("reports") === "all" ? "all" : "open";
                const [reports, blocklist] = await Promise.all([community.listReports({ status, limit: 300 }), community.listBlocked()]);
                return http.sendJson(res, 200, { alerts: community.alerts(), reports, blocklist });
            }
            if (req.method !== "POST") return methodNotAllowed(res, "POST");
            const body = await adminPostBody(req, res);
            if (body === undefined) return;
            if (p === "/api/admin/community/alert") {
                const alert = await community.addAlert({ title: body.title, body: body.body, severity: body.severity }, session.user);
                stats.event("admin_alert", `نشر تنبيه احتيال: ${alert.title.slice(0, 60)}`, ip);
                return http.sendJson(res, 201, { alert });
            }
            if (p === "/api/admin/community/alert/delete") {
                await community.deleteAlert(String(body.id || ""));
                stats.event("admin_alert", "حذف تنبيه احتيال", ip);
                return http.sendJson(res, 200, { ok: true });
            }
            if (p === "/api/admin/community/report") {
                const report = await community.decideReport(String(body.id || ""), { confirm: body.confirm === true, admin: session.user });
                stats.event("report_decision", `${report.status === "confirmed" ? "تأكيد" : "رفض"} بلاغ${report.domain ? " (" + report.domain + ")" : ""}`, ip);
                return http.sendJson(res, 200, { report });
            }
            if (p === "/api/admin/community/unblock") {
                await community.unblock(String(body.domain || ""));
                stats.event("report_decision", `إزالة ${String(body.domain || "").slice(0, 80)} من قائمة الاحتيال المؤكدة`, ip);
                return http.sendJson(res, 200, { ok: true });
            }
            return http.sendJson(res, 404, { error: "Not found" });
        } catch (error) {
            if (error && typeof error.status === "number" && error.name !== "UpstashError") return http.sendJson(res, error.status, { error: error.message });
            if (error && error.name === "UpstashError") return http.sendJson(res, 503, { error: "تعذر الوصول لقاعدة البيانات." });
            throw error;
        }
    }

    async function manageRoutes(req, res, p, url) {
        const users = extras.users;
        const session = currentSession(req);
        if (!users) return http.sendJson(res, 404, { error: "Not found" });
        if (!session) return http.sendJson(res, 401, { error: "Unauthorized" });
        const ip = http.getClientIp(req, config);
        try {
            if (p === "/api/admin/users" && req.method === "GET") {
                const offset = Math.max(0, Math.min(1e6, Number(url.searchParams.get("offset")) || 0));
                const result = await users.listUsers({ offset, limit: 50, query: String(url.searchParams.get("q") || "").slice(0, 254) });
                return http.sendJson(res, 200, { total: result.total, offset, users: result.users.map(adminUserView) });
            }
            if (p === "/api/admin/users/action") {
                if (req.method !== "POST") return methodNotAllowed(res, "POST");
                const body = await adminPostBody(req, res);
                if (body === undefined) return;
                const id = String(body.id || "");
                if (body.action === "disable" || body.action === "enable") {
                    const user = await users.setDisabled(id, body.action === "disable");
                    stats.event("admin_user", `${body.action === "disable" ? "إيقاف" : "تفعيل"} حساب`, ip);
                    return http.sendJson(res, 200, { user: adminUserView(user) });
                }
                if (body.action === "grant") {
                    const months = Number(body.months);
                    if (![1, 3, 6, 12].includes(months)) return http.sendJson(res, 400, { error: "مدة غير صالحة." });
                    const user = await users.extend(id, months);
                    stats.event("admin_user", `منح اشتراك Pro يدوياً (${months} شهر)`, ip);
                    return http.sendJson(res, 200, { user: adminUserView(user) });
                }
                if (body.action === "revoke-sessions") {
                    const user = await users.revokeSessions(id);
                    stats.event("admin_user", "إنهاء كل جلسات مستخدم (خروج من كل الأجهزة)", ip);
                    return http.sendJson(res, 200, { user: adminUserView(user) });
                }
                if (body.action === "reset-link") {
                    const token = await users.createResetLink(id);
                    stats.event("admin_user", "إصدار رابط إعادة تعيين كلمة السر", ip);
                    return http.sendJson(res, 200, { link: `${config.appUrl}/login?reset=${token}`, expiresInMinutes: 60 });
                }
                return http.sendJson(res, 400, { error: "إجراء غير معروف." });
            }
            if (p === "/api/admin/payments" && req.method === "GET") {
                const status = url.searchParams.get("status") === "pending" ? "pending" : "all";
                return http.sendJson(res, 200, { payments: await users.listPayments({ status, limit: 300 }), methods: config.payment.methods });
            }
            if (p === "/api/admin/payments/decide") {
                if (req.method !== "POST") return methodNotAllowed(res, "POST");
                const body = await adminPostBody(req, res);
                if (body === undefined) return;
                const result = await users.decidePayment(String(body.id || ""), { approve: body.approve === true, admin: session.user, reason: body.reason });
                stats.event("payment_decision", `${result.payment.status === "approved" ? "موافقة" : "رفض"} طلب دفع (${result.payment.months} شهر)`, ip);
                return http.sendJson(res, 200, { payment: result.payment, user: result.user ? adminUserView(result.user) : null });
            }
            if (p === "/api/admin/revenue" && req.method === "GET") {
                return http.sendJson(res, 200, await users.revenue());
            }
            if (p === "/api/admin/export/users.csv" && req.method === "GET") {
                const all = [];
                for (let offset = 0; offset < 20000; offset += 500) {
                    const page = await users.listUsers({ offset, limit: 500 });
                    all.push(...page.users);
                    if (page.users.length < 500) break;
                }
                stats.event("export", "تصدير المستخدمين CSV", ip);
                const rows = all.map(adminUserView).map(u => [u.email || (u.phone ? "+" + u.phone : ""), u.name, u.plan, u.planSource, u.planUntil || "", u.providers.join(" "), u.createdAt, u.lastLoginAt || "", u.disabled ? "yes" : ""]);
                return sendDownload(res, "text/csv; charset=utf-8", "users.csv", toCsv(["email", "name", "plan", "source", "until", "providers", "created", "last_login", "disabled"], rows));
            }
            if (p === "/api/admin/export/payments.csv" && req.method === "GET") {
                const list = await users.listPayments({ limit: 5000 });
                stats.event("export", "تصدير المدفوعات CSV", ip);
                const rows = list.map(x => [x.id, x.email, x.method, x.months, x.amountUsd, x.amountIqd, x.reference, x.status, new Date(x.createdAt).toISOString(), x.decidedAt ? new Date(x.decidedAt).toISOString() : "", x.decidedBy, x.reason]);
                return sendDownload(res, "text/csv; charset=utf-8", "payments.csv", toCsv(["id", "email", "method", "months", "usd", "iqd", "reference", "status", "created", "decided", "by", "reason"], rows));
            }
            return http.sendJson(res, 404, { error: "Not found" });
        } catch (error) {
            if (error instanceof UserError) return http.sendJson(res, error.status, { error: error.message });
            if (error && error.name === "UpstashError") return http.sendJson(res, 503, { error: "تعذر الوصول لقاعدة البيانات." });
            throw error;
        }
    }

    return { handle, enabled };
}

module.exports = { createAdmin };
