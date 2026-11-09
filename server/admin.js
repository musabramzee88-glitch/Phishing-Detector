"use strict";

/*
  صفحة الأدمن. القواعد:
  - مغلقة تماماً (404) إذا لم يُضبط متغير ADMINS.
  - الدخول: اسم مستخدم + كلمة سر (مشفّرة بـ scrypt) + رمز تحقق ثنائي TOTP إذا كان مفعّلاً للحساب.
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

const scrypt = promisify(crypto.scrypt);
const DUMMY_SALT = crypto.randomBytes(16).toString("hex");
const GENERIC_LOGIN_ERROR = "بيانات الدخول غير صحيحة.";

const ASSETS = {
    "admin.css": { type: "text/css; charset=utf-8", publicAsset: true },
    "login.js": { type: "text/javascript; charset=utf-8", publicAsset: true },
    "dashboard.js": { type: "text/javascript; charset=utf-8", publicAsset: false }
};

function sha256(value) {
    return crypto.createHash("sha256").update(value).digest("hex");
}

// extras: { visitors, health } لإظهارها بلوحة الأدمن (اختياري)
function createAdmin(config, stats, extras = {}) {
    const enabled = config.admins.size > 0;
    const sessions = new Map();   // sha256(sid) -> { user, created, last }
    const failures = createFailureLimiter({ windowMs: config.limits.loginWindowMs, max: config.limits.loginFailuresPerWindow });
    const attempts = createRateLimiter({ windowMs: 60_000, max: Infinity, globalMax: config.limits.loginAttemptsPerMinute });

    const files = {};
    if (enabled) {
        for (const name of ["login.html", "dashboard.html", ...Object.keys(ASSETS)]) {
            files[name] = fs.readFileSync(path.join(config.adminDir, name));
        }
    }

    const pruneTimer = setInterval(() => {
        const now = Date.now();
        for (const [key, record] of sessions) {
            if (now - record.last > config.session.idleMs || now - record.created > config.session.absoluteMs) sessions.delete(key);
        }
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
        const passwordOk = Boolean(admin) && crypto.timingSafeEqual(derived, admin.hash);

        let reason = "";
        let codeOk = true;
        if (passwordOk && admin.totpSecret) {
            const counter = totp.verify(admin.totpSecret, code, { lastCounter: admin.lastTotpCounter });
            codeOk = counter >= 0;
            if (codeOk) admin.lastTotpCounter = counter;   // نمنع إعادة استخدام نفس الرمز
            else reason = "رمز التحقق الثنائي خاطئ";
        } else if (!passwordOk) {
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
                webSearch: config.openai.webSearch,
                chatPerMinute: config.limits.chatPerMinute,
                globalChatPerMinute: config.limits.globalChatPerMinute,
                adminCount: config.admins.size,
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
            http.sendJson(res, 200, statsPayload(req, session));
            return true;
        }

        http.sendJson(res, 404, { error: "Not found" });
        return true;
    }

    return { handle, enabled };
}

module.exports = { createAdmin };
