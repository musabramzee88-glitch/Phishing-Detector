"use strict";

/*
  مسارات الحسابات والدخول والاشتراك (HTTP). المنطق نفسه في users.js و oauth.js.

  الدخول:
    GET  /api/auth/config            المزوّدات المفعّلة وبيانات الخطة (عام)
    POST /api/auth/register          إنشاء حساب بالبريد وكلمة السر
    POST /api/auth/login             دخول بالبريد وكلمة السر
    POST /api/auth/logout
    GET  /api/auth/me                المستخدم الحالي واستهلاك اليوم
    POST /api/auth/reset             كلمة سر جديدة برابط يصدره الأدمن
    GET  /auth/<provider>/start      بدء الدخول عبر Google / Microsoft / Apple
    GET|POST /auth/<provider>/callback
  الحساب:
    POST /api/account/name | /password | /history-setting | /api-key | /delete
    GET  /api/account/history,  POST /api/account/history/clear
  الاشتراك:
    GET  /api/billing                الأسعار وطرق الدفع وطلباتي
    POST /api/billing/request        طلب تفعيل بعد التحويل (يراجعه الأدمن)

  الجلسة: رمز عشوائي بكوكي HttpOnly + SameSite=Lax (+ Secure و __Host- على HTTPS)، 30 يوماً.
  كل طلب يغيّر الحالة يجب أن يكون JSON ومن الموقع نفسه (حماية CSRF).
*/

const h = require("./http");
const { UserError } = require("./users");
const { createRateLimiter, createFailureLimiter } = require("./rate-limit");
const { pricingInfo } = require("./plans");

const PROVIDER_IDS = new Set(["google", "microsoft", "apple"]);

function createAuth({ config, users, oauth, stats, mailer }) {
    const authLimiter = createRateLimiter({ windowMs: 60_000, max: config.limits.authPerMinute });
    const registrations = createRateLimiter({ windowMs: 24 * 60 * 60_000, max: config.limits.registrationsPerDay });
    const ipFailures = createFailureLimiter({ windowMs: config.limits.loginWindowMs, max: config.limits.userLoginFailures * 2 });
    const emailFailures = createFailureLimiter({ windowMs: config.limits.loginWindowMs, max: config.limits.userLoginFailures });

    const secure = req => h.isHttps(req, config);
    const sessionCookieName = req => (secure(req) ? "__Host-pd_s" : "pd_s");

    function sessionCookie(req, value, maxAge) {
        const parts = [`${sessionCookieName(req)}=${value}`, "Path=/", "HttpOnly", "SameSite=Lax", `Max-Age=${maxAge}`];
        if (secure(req)) parts.push("Secure");
        return parts.join("; ");
    }

    // كوكي ربط المتصفح بعملية الدخول الخارجي. Apple ترجع بـ POST من نطاقها، فيلزم SameSite=None على HTTPS.
    function bindCookie(req, value, maxAge) {
        const parts = [`pd_oauth=${value}`, "Path=/auth/", "HttpOnly", `Max-Age=${maxAge}`];
        parts.push(secure(req) ? "SameSite=None; Secure" : "SameSite=Lax");
        return parts.join("; ");
    }

    function sessionToken(req) {
        return h.parseCookies(req.headers.cookie)[sessionCookieName(req)] || "";
    }

    async function currentUser(req) {
        const token = sessionToken(req);
        if (!token) return null;
        try {
            return await users.userFromSession(token);
        } catch {
            return null;    // القاعدة غير متاحة: نعامله كغير مسجّل بدل أن نوقع الطلب
        }
    }

    async function startSession(req, res, user, status, payload) {
        const session = await users.createSession(user.id, { ua: req.headers["user-agent"] });
        h.sendJson(res, status, payload, { "Set-Cookie": sessionCookie(req, session.token, session.maxAge) });
    }

    // يقرأ JSON من صفحاتنا فقط. يرجع الجسم أو undefined بعد الرد بالخطأ.
    async function jsonBody(req, res, maxBytes = 4096) {
        if (req.method !== "POST") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "POST" }), undefined;
        if (!h.isSameOrigin(req)) {
            stats.count("blockedRequests");
            return h.sendJson(res, 403, { error: "Forbidden" }), undefined;
        }
        if (!h.isJsonRequest(req)) return h.sendJson(res, 415, { error: "Content-Type must be application/json" }), undefined;
        try {
            const body = await h.readJsonBody(req, maxBytes);
            if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("bad");
            return body;
        } catch {
            return h.sendJson(res, 400, { error: "طلب غير صالح." }), undefined;
        }
    }

    function sendError(res, error) {
        if (error instanceof UserError) return h.sendJson(res, error.status, { error: error.message, code: error.code });
        if (error && error.name === "UpstashError") {
            stats.event("db_error", "تعذر الوصول لقاعدة البيانات", "");
            return h.sendJson(res, 503, { error: "الخدمة غير متاحة مؤقتاً. حاول بعد قليل." });
        }
        throw error;
    }

    async function me(user) {
        return { user: users.publicUser(user), usage: await users.usage(user) };
    }

    // ---------------------------------------------------------------- الدخول بالبريد

    async function register(req, res) {
        const ip = h.getClientIp(req, config);
        if (!authLimiter.take(ip)) return h.sendJson(res, 429, { error: "محاولات كثيرة. حاول بعد دقيقة." }, { "Retry-After": "60" });
        const body = await jsonBody(req, res);
        if (body === undefined) return;
        if (!registrations.take(ip)) {
            stats.event("register_throttled", "تجاوز حد إنشاء الحسابات اليومي", ip);
            return h.sendJson(res, 429, { error: "تم إنشاء حسابات كثيرة من هذا الاتصال اليوم. حاول غداً." });
        }
        try {
            const user = await users.register({ email: body.email, password: body.password, name: body.name });
            stats.count("registrations");
            stats.event("register", "حساب جديد (بريد)", ip);
            if (users.needsVerification(user)) {
                // لا جلسة قبل تأكيد البريد: نرسل الرابط ونطلب من المستخدم فتح بريده
                const sent = await sendVerification(user);
                return h.sendJson(res, 201, { needsVerification: true, email: user.email, sent });
            }
            await startSession(req, res, user, 201, await me(user));
        } catch (error) {
            sendError(res, error);
        }
    }

    // يرسل رابط التأكيد. يرجع true/false ولا يرمي: فشل البريد لا يكشف شيئاً ولا يوقف التسجيل (يقدر المستخدم يطلب إعادة الإرسال).
    async function sendVerification(user) {
        try {
            if (!(await users.mailAllowed(user.email, "verify"))) return false;
            const raw = await users.createVerifyToken(user.id);
            await mailer.verifyEmail(user.email, `${config.appUrl}/auth/verify?token=${encodeURIComponent(raw)}`);
            return true;
        } catch (error) {
            stats.event("mail_error", "تعذر إرسال رسالة التأكيد", "");
            return false;
        }
    }

    // إعادة إرسال رابط التأكيد. الرد نفسه دائماً (لا نكشف هل البريد مسجّل).
    async function resendVerification(req, res) {
        const ip = h.getClientIp(req, config);
        if (!authLimiter.take(ip)) return h.sendJson(res, 429, { error: "محاولات كثيرة. حاول بعد دقيقة." }, { "Retry-After": "60" });
        const body = await jsonBody(req, res);
        if (body === undefined) return;
        if (!mailer.enabled) return h.sendJson(res, 503, { error: "إرسال البريد غير مفعّل على الخادم." });
        try {
            const user = await users.findByEmail(String(body.email || "").trim().toLowerCase());
            if (user && users.needsVerification(user) && !user.disabled) await sendVerification(user);
            h.sendJson(res, 200, { ok: true, message: "إذا كان البريد مسجّلاً وغير مؤكَّد أرسلنا لك رابطاً جديداً. افحص صندوق الوارد والرسائل غير المرغوبة." });
        } catch (error) {
            sendError(res, error);
        }
    }

    // نسيت كلمة السر: رابط يصل للبريد (صالح ساعة ولمرة واحدة). الرد نفسه دائماً.
    async function forgotPassword(req, res) {
        const ip = h.getClientIp(req, config);
        if (!authLimiter.take(ip)) return h.sendJson(res, 429, { error: "محاولات كثيرة. حاول بعد دقيقة." }, { "Retry-After": "60" });
        const body = await jsonBody(req, res);
        if (body === undefined) return;
        if (!mailer.enabled) return h.sendJson(res, 503, { error: "إرسال البريد غير مفعّل. تواصل مع الدعم ليرسل لك رابط إعادة التعيين." });
        try {
            const email = String(body.email || "").trim().toLowerCase();
            const user = email ? await users.findByEmail(email) : null;
            if (user && !user.disabled && await users.mailAllowed(user.email, "reset")) {
                try {
                    const raw = await users.createResetLink(user.id);
                    await mailer.resetEmail(user.email, `${config.appUrl}/login.html?reset=${encodeURIComponent(raw)}`);
                    stats.event("password_reset_requested", "طلب رابط كلمة سر بالبريد", ip);
                } catch {
                    stats.event("mail_error", "تعذر إرسال رابط كلمة السر", ip);
                }
            }
            h.sendJson(res, 200, { ok: true, message: "إذا كان البريد مسجّلاً أرسلنا لك رابط إعادة التعيين. الرابط صالح ساعة واحدة." });
        } catch (error) {
            sendError(res, error);
        }
    }

    // رابط التأكيد من البريد
    async function verifyLink(req, res, url) {
        const ip = h.getClientIp(req, config);
        if (!authLimiter.take(ip)) return redirect(res, "/login.html?error=rate");
        try {
            await users.verifyEmail(url.searchParams.get("token") || "");
            stats.event("email_verified", "تأكيد بريد", ip);
            redirect(res, "/login.html?verified=1");
        } catch (error) {
            if (error instanceof UserError) return redirect(res, "/login.html?error=bad_verify");
            if (error && error.name === "UpstashError") return redirect(res, "/login.html?error=unavailable");
            throw error;
        }
    }

    async function login(req, res) {
        const ip = h.getClientIp(req, config);
        if (!authLimiter.take(ip)) return h.sendJson(res, 429, { error: "محاولات كثيرة. حاول بعد دقيقة." }, { "Retry-After": "60" });
        const body = await jsonBody(req, res);
        if (body === undefined) return;
        const emailKey = String(body.email || "").trim().toLowerCase().slice(0, 254);
        if (ipFailures.isBlocked(ip) || emailFailures.isBlocked(emailKey)) {
            const wait = Math.max(ipFailures.retryAfterSeconds(ip), emailFailures.retryAfterSeconds(emailKey));
            return h.sendJson(res, 429, { error: "محاولات خاطئة كثيرة. انتظر قليلاً ثم حاول." }, { "Retry-After": String(wait) });
        }
        try {
            const user = await users.login({ email: body.email, password: body.password });
            ipFailures.clear(ip);
            emailFailures.clear(emailKey);
            stats.count("userLogins");
            await startSession(req, res, user, 200, await me(user));
        } catch (error) {
            if (error instanceof UserError && error.code === "bad_login") {
                ipFailures.fail(ip);
                emailFailures.fail(emailKey);
                stats.count("userLoginFailed");
            }
            sendError(res, error);
        }
    }

    async function logout(req, res) {
        if (req.method !== "POST") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "POST" });
        if (!h.isSameOrigin(req)) return h.sendJson(res, 403, { error: "Forbidden" });
        await users.destroySession(sessionToken(req)).catch(() => {});
        h.sendJson(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(req, "", 0) });
    }

    async function resetPassword(req, res) {
        const ip = h.getClientIp(req, config);
        if (!authLimiter.take(ip)) return h.sendJson(res, 429, { error: "محاولات كثيرة." }, { "Retry-After": "60" });
        const body = await jsonBody(req, res);
        if (body === undefined) return;
        try {
            const user = await users.useResetLink(body.token, body.password);
            stats.event("password_reset", "تغيير كلمة السر برابط إعادة التعيين", ip);
            await startSession(req, res, user, 200, await me(user));
        } catch (error) {
            sendError(res, error);
        }
    }

    // ---------------------------------------------------------------- الدخول الخارجي

    function redirect(res, location, cookies = []) {
        res.writeHead(302, { Location: location, "Cache-Control": "no-store", ...(cookies.length ? { "Set-Cookie": cookies } : {}) });
        res.end();
    }

    async function oauthStart(req, res, provider) {
        if (req.method !== "GET") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET" });
        const ip = h.getClientIp(req, config);
        if (!authLimiter.take(ip)) return redirect(res, "/login?error=rate");
        try {
            const started = await oauth.start(provider);
            if (!started) return redirect(res, "/login?error=provider");
            redirect(res, started.url, [bindCookie(req, started.bind, 600)]);
        } catch {
            redirect(res, "/login?error=unavailable");
        }
    }

    async function oauthCallback(req, res, provider) {
        const ip = h.getClientIp(req, config);
        const url = new URL(req.url, "http://localhost");
        let params = url.searchParams;
        let extra = {};
        if (req.method === "POST") {
            // Apple: form_post (application/x-www-form-urlencoded)
            let raw = "";
            try {
                for await (const chunk of req) {
                    raw += chunk;
                    if (raw.length > 16_384) throw new Error("too large");
                }
            } catch {
                return redirect(res, "/login?error=failed");
            }
            params = new URLSearchParams(raw);
            extra = { user: params.get("user") || "" };
        } else if (req.method !== "GET") {
            return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET, POST" });
        }
        const clear = bindCookie(req, "", 0);
        if (params.get("error")) return redirect(res, "/login?error=cancelled", [clear]);
        try {
            const identity = await oauth.finish(provider, {
                code: params.get("code"), state: params.get("state"),
                bind: h.parseCookies(req.headers.cookie).pd_oauth, extra
            });
            const { user, created } = await users.loginWithProvider(identity);
            if (created) {
                stats.count("registrations");
                stats.event("register", `حساب جديد (${provider})`, ip);
            }
            stats.count("userLogins");
            const session = await users.createSession(user.id, { ua: req.headers["user-agent"] });
            redirect(res, "/", [clear, sessionCookie(req, session.token, session.maxAge)]);
        } catch (error) {
            const code = error instanceof UserError ? error.code : "failed";
            if (!(error instanceof UserError)) stats.event("oauth_failed", `${provider}: ${String(error && error.message).slice(0, 80)}`, ip);
            redirect(res, "/login?error=" + encodeURIComponent(code), [clear]);
        }
    }

    // ---------------------------------------------------------------- الحساب والاشتراك

    async function requireUser(req, res) {
        const user = await currentUser(req);
        if (!user) h.sendJson(res, 401, { error: "سجّل الدخول أولاً.", code: "login_required" });
        return user;
    }

    async function account(req, res, p) {
        const user = await requireUser(req, res);
        if (!user) return;
        try {
            if (p === "/api/account/history" && req.method === "GET") return h.sendJson(res, 200, { history: await users.history(user) });
            const body = await jsonBody(req, res);
            if (body === undefined) return;
            let updated = user;
            if (p === "/api/account/name") updated = await users.rename(user, body.name);
            else if (p === "/api/account/password") {
                updated = await users.changePassword(user, { current: body.current, next: body.next });
                stats.event("password_change", "تغيير كلمة سر مستخدم", h.getClientIp(req, config));
            } else if (p === "/api/account/history-setting") updated = await users.setHistoryEnabled(user, Boolean(body.enabled));
            else if (p === "/api/account/history/clear") await users.clearHistory(user);
            else if (p === "/api/account/api-key") {
                const key = await users.rotateApiKey(user);
                return h.sendJson(res, 200, { key, ...(await me(await users.get(user.id))) });
            } else if (p === "/api/account/delete") {
                if (String(body.confirm || "").trim().toLowerCase() !== user.email) {
                    return h.sendJson(res, 400, { error: "اكتب بريدك الإلكتروني بالضبط لتأكيد الحذف." });
                }
                await users.remove(user);
                await users.destroySession(sessionToken(req)).catch(() => {});
                stats.event("account_deleted", "حذف حساب مستخدم", h.getClientIp(req, config));
                return h.sendJson(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(req, "", 0) });
            } else return h.sendJson(res, 404, { error: "Not found" });
            h.sendJson(res, 200, await me(updated));
        } catch (error) {
            sendError(res, error);
        }
    }

    async function billing(req, res, p) {
        if (p === "/api/billing" && req.method === "GET") {
            const user = await requireUser(req, res);
            if (!user) return;
            try {
                const payments = (await users.paymentsOf(user)).map(({ uid, email, decidedBy, ...rest }) => rest);
                return h.sendJson(res, 200, { pricing: pricingInfo(config), payments });
            } catch (error) {
                return sendError(res, error);
            }
        }
        if (p === "/api/billing/request") {
            const user = await requireUser(req, res);
            if (!user) return;
            const body = await jsonBody(req, res);
            if (body === undefined) return;
            try {
                const payment = await users.createPayment(user, body);
                stats.count("paymentRequests");
                stats.event("payment_request", `طلب تفعيل ${payment.months} شهر (${payment.method})`, h.getClientIp(req, config));
                const { uid, email, decidedBy, ...visible } = payment;
                return h.sendJson(res, 201, { payment: visible });
            } catch (error) {
                return sendError(res, error);
            }
        }
        h.sendJson(res, 404, { error: "Not found" });
    }

    // ---------------------------------------------------------------- الموجّه

    async function handle(req, res, url) {
        const p = url.pathname;
        if (p === "/api/auth/config") {
            if (req.method !== "GET") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET" }), true;
            h.sendJson(res, 200, { providers: oauth.providers, emailVerification: mailer.enabled, trialDays: config.plans.trialDays, priceUsd: config.plans.priceUsd });
            return true;
        }
        if (p === "/api/auth/register") return await register(req, res), true;
        if (p === "/api/auth/login") return await login(req, res), true;
        if (p === "/api/auth/logout") return await logout(req, res), true;
        if (p === "/api/auth/reset") return await resetPassword(req, res), true;
        if (p === "/api/auth/resend") return await resendVerification(req, res), true;
        if (p === "/api/auth/forgot") return await forgotPassword(req, res), true;
        if (p === "/auth/verify") {
            if (req.method !== "GET") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET" }), true;
            return await verifyLink(req, res, url), true;
        }
        if (p === "/api/auth/me") {
            if (req.method !== "GET") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET" }), true;
            const user = await requireUser(req, res);
            if (user) {
                try { h.sendJson(res, 200, await me(user)); } catch (error) { sendError(res, error); }
            }
            return true;
        }
        const match = /^\/auth\/([a-z]+)\/(start|callback)$/.exec(p);
        if (match) {
            if (!PROVIDER_IDS.has(match[1])) return h.sendJson(res, 404, { error: "Not found" }), true;
            if (match[2] === "start") await oauthStart(req, res, match[1]);
            else await oauthCallback(req, res, match[1]);
            return true;
        }
        if (p.startsWith("/api/account/")) return await account(req, res, p), true;
        if (p === "/api/billing" || p.startsWith("/api/billing/")) return await billing(req, res, p), true;
        return false;
    }

    return { handle, currentUser, requireUser, jsonBody, sendError };
}

module.exports = { createAuth };
