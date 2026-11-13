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
    POST /api/auth/mfa               الخطوة الثانية: رمز الدخول المرسل للبريد (MFA)
    POST /api/auth/mfa/resend        إعادة إرسال رمز الدخول
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
const { PhoneError, maskPhone, normalizeIraqiMobile } = require("./phone-auth");

const PROVIDER_IDS = new Set(["google", "microsoft", "apple"]);

function maskEmail(email) {
    const [name, domain] = String(email).split("@");
    if (!domain) return "";
    const shown = name.length <= 2 ? name.slice(0, 1) : name.slice(0, 2);
    return `${shown}${"•".repeat(Math.max(2, Math.min(6, name.length - shown.length)))}@${domain}`;
}

function createAuth({ config, users, oauth, stats, mailer, settings, sms = null, phoneAuth = null }) {
    const feature = name => !settings || settings.get().features[name] !== false;
    // التحقق الثنائي بالبريد: يعمل عند ضبط مزوّد البريد، ويقدر الأدمن يطفيه من لوحة الإدارة
    const mfaActive = () => Boolean(mailer.enabled && (!settings || settings.get().security.mfaEmail));
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

    // كوكي التحدي بين الخطوتين (لا يفتح جلسة بحد ذاته)
    function mfaCookie(req, value, maxAge) {
        const parts = [`pd_mfa=${value}`, "Path=/api/auth/", "HttpOnly", "SameSite=Lax", `Max-Age=${maxAge}`];
        if (secure(req)) parts.push("Secure");
        return parts.join("; ");
    }

    // ينشئ التحدي ويرسل الرمز. يرمي UserError إذا تعذر الإرسال (لا نتجاوز الخطوة الثانية أبداً)
    async function beginMfa(user, via, ip) {
        const { token, code } = await users.createLoginChallenge(user.id, via);
        try {
            await mailer.loginCode(user.email, code);
        } catch {
            stats.event("mail_error", "تعذر إرسال رمز الدخول (MFA)", ip);
            throw new UserError("mfa_mail", "تعذر إرسال رمز الدخول إلى بريدك الآن. حاول بعد قليل.", 503);
        }
        stats.event("mfa_sent", `إرسال رمز دخول (${via})`, ip);
        return token;
    }

    // وضع الضيف: كوكي للمشاهدة فقط. لا يفتح أي صلاحية؛ كل الواجهات تبقى تطلب حساباً حقيقياً
    function guestCookie(req, on) {
        const parts = [`pd_guest=${on ? "1" : ""}`, "Path=/", "HttpOnly", "SameSite=Lax", `Max-Age=${on ? 86400 : 0}`];
        if (secure(req)) parts.push("Secure");
        return parts.join("; ");
    }
    const isGuest = req => h.parseCookies(req.headers.cookie).pd_guest === "1";

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
        if (error instanceof PhoneError) {
            return h.sendJson(res, error.status, { error: error.message, code: error.code }, error.retryAfter ? { "Retry-After": String(error.retryAfter) } : {});
        }
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
        if (!feature("registration")) return h.sendJson(res, 403, { error: "إنشاء الحسابات الجديدة متوقف حالياً.", code: "registration_closed" });
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
            const code = await users.createVerifyCode(user.id);
            await mailer.verifyCode(user.email, code);
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
            h.sendJson(res, 200, { ok: true, message: "إذا كان البريد مسجّلاً وغير مؤكَّد أرسلنا لك كوداً جديداً. افحص صندوق الوارد والرسائل غير المرغوبة." });
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

    // إدخال كود التحقق: عند النجاح يُفعَّل الحساب وتبدأ الجلسة
    async function verifyCodeRoute(req, res) {
        const ip = h.getClientIp(req, config);
        if (!authLimiter.take(ip)) return h.sendJson(res, 429, { error: "محاولات كثيرة. حاول بعد دقيقة." }, { "Retry-After": "60" });
        if (ipFailures.isBlocked(ip)) return h.sendJson(res, 429, { error: "محاولات خاطئة كثيرة. حاول لاحقاً." }, { "Retry-After": String(ipFailures.retryAfterSeconds(ip)) });
        const body = await jsonBody(req, res);
        if (body === undefined) return;
        try {
            const user = await users.verifyCode(body.email, body.code);
            ipFailures.clear(ip);
            stats.event("email_verified", "تأكيد بريد بالكود", ip);
            await startSession(req, res, user, 200, await me(user));
        } catch (error) {
            if (error instanceof UserError) ipFailures.fail(ip);
            sendError(res, error);
        }
    }

    // رابط التأكيد من البريد (قديم، يبقى للرسائل المرسلة سابقاً)
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
            if (mfaActive()) {
                const challenge = await beginMfa(user, "password", ip);
                return h.sendJson(res, 200, { mfa: true, email: maskEmail(user.email) }, { "Set-Cookie": mfaCookie(req, challenge, 600) });
            }
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

    // الخطوة الثانية: الرمز المرسل للبريد
    async function mfaVerify(req, res) {
        const ip = h.getClientIp(req, config);
        if (!authLimiter.take(ip)) return h.sendJson(res, 429, { error: "محاولات كثيرة. حاول بعد دقيقة." }, { "Retry-After": "60" });
        if (ipFailures.isBlocked(ip)) return h.sendJson(res, 429, { error: "محاولات خاطئة كثيرة. حاول لاحقاً." }, { "Retry-After": String(ipFailures.retryAfterSeconds(ip)) });
        const body = await jsonBody(req, res);
        if (body === undefined) return;
        const challenge = h.parseCookies(req.headers.cookie).pd_mfa || "";
        try {
            const { user, via } = await users.verifyLoginChallenge(challenge, body.code);
            ipFailures.clear(ip);
            stats.count("userLogins");
            stats.event("mfa_ok", `دخول بتحقق ثنائي (${via})`, ip);
            const session = await users.createSession(user.id, { ua: req.headers["user-agent"] });
            h.sendJson(res, 200, await me(user), { "Set-Cookie": [sessionCookie(req, session.token, session.maxAge), mfaCookie(req, "", 0)] });
        } catch (error) {
            if (error instanceof UserError) {
                ipFailures.fail(ip);
                stats.event("mfa_failed", "رمز دخول خاطئ أو منتهي", ip);
            }
            sendError(res, error);
        }
    }

    async function mfaResend(req, res) {
        const ip = h.getClientIp(req, config);
        if (!authLimiter.take(ip)) return h.sendJson(res, 429, { error: "محاولات كثيرة. حاول بعد دقيقة." }, { "Retry-After": "60" });
        const body = await jsonBody(req, res);
        if (body === undefined) return;
        try {
            const { user, code } = await users.resendLoginChallenge(h.parseCookies(req.headers.cookie).pd_mfa || "");
            try {
                await mailer.loginCode(user.email, code);
            } catch {
                return h.sendJson(res, 503, { error: "تعذر إرسال الرمز الآن. حاول بعد قليل." });
            }
            h.sendJson(res, 200, { ok: true, message: "أرسلنا رمزاً جديداً إلى بريدك." });
        } catch (error) {
            sendError(res, error);
        }
    }

    async function logout(req, res) {
        if (req.method !== "POST") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "POST" });
        if (!h.isSameOrigin(req)) return h.sendJson(res, 403, { error: "Forbidden" });
        await users.destroySession(sessionToken(req)).catch(() => {});
        h.sendJson(res, 200, { ok: true }, { "Set-Cookie": [sessionCookie(req, "", 0), guestCookie(req, false)] });
    }

    async function startGuest(req, res) {
        const body = await jsonBody(req, res, 256);
        if (body === undefined) return;
        if (!feature("guest")) return h.sendJson(res, 403, { error: "وضع الضيف متوقف حالياً." });
        stats.count("guestEntries");
        h.sendJson(res, 200, { ok: true }, { "Set-Cookie": guestCookie(req, true) });
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

    // ---------------------------------------------------------------- الدخول برقم الهاتف
    const phoneOn = () => Boolean(sms && sms.enabled && phoneAuth && feature("phoneLogin"));

    async function phoneStart(req, res) {
        const ip = h.getClientIp(req, config);
        if (!authLimiter.take(ip)) return h.sendJson(res, 429, { error: "محاولات كثيرة. حاول بعد دقيقة." }, { "Retry-After": "60" });
        const body = await jsonBody(req, res, 512);
        if (body === undefined) return;
        if (!phoneOn()) return h.sendJson(res, 503, { error: "الدخول برقم الهاتف غير متاح حالياً.", code: "sms_off" });
        try {
            const r = await phoneAuth.start({ phone: body.phone, ip, purpose: "login" });
            stats.event("phone_code", `إرسال رمز دخول لرقم ${r.masked}`, ip);
            h.sendJson(res, 200, { challenge: r.challenge, masked: r.masked, expiresIn: r.expiresIn, resendIn: r.resendIn });
        } catch (error) {
            if (error instanceof PhoneError && error.code === "send_failed") stats.event("sms_error", "تعذر إرسال رمز SMS", ip);
            sendError(res, error);
        }
    }

    async function phoneVerify(req, res) {
        const ip = h.getClientIp(req, config);
        if (!authLimiter.take(ip)) return h.sendJson(res, 429, { error: "محاولات كثيرة. حاول بعد دقيقة." }, { "Retry-After": "60" });
        if (ipFailures.isBlocked(ip)) return h.sendJson(res, 429, { error: "محاولات خاطئة كثيرة. حاول لاحقاً." }, { "Retry-After": String(ipFailures.retryAfterSeconds(ip)) });
        const body = await jsonBody(req, res, 512);
        if (body === undefined) return;
        if (!phoneOn()) return h.sendJson(res, 503, { error: "الدخول برقم الهاتف غير متاح حالياً.", code: "sms_off" });
        try {
            const { phone } = await phoneAuth.verify({ challenge: body.challenge, code: body.code, purpose: "login" });
            ipFailures.clear(ip);
            let user = await users.findByPhone(phone);
            let created = false;
            if (!user) {
                if (!feature("registration")) return h.sendJson(res, 403, { error: "إنشاء الحسابات الجديدة متوقف حالياً.", code: "registration_closed" });
                ({ user, created } = await users.createPhoneUser(phone, body.name));
            }
            user = await users.loginPhoneUser(user);
            if (created) {
                stats.count("registrations");
                stats.event("register", "حساب جديد (رقم هاتف)", ip);
            }
            stats.count("userLogins");
            await startSession(req, res, user, created ? 201 : 200, { ...(await me(user)), created });
        } catch (error) {
            if (error instanceof PhoneError && (error.code === "bad_code" || error.code === "too_many")) {
                ipFailures.fail(ip);
                stats.event("phone_failed", "رمز هاتف خاطئ", ip);
            }
            sendError(res, error);
        }
    }

    // ربط رقم بحساب موجود / إزالته (من صفحة الحساب)
    async function accountPhone(req, res, p, user) {
        const body = await jsonBody(req, res, 512);
        if (body === undefined) return;
        const ip = h.getClientIp(req, config);
        if (p === "/api/account/phone/remove") {
            const updated = await users.unlinkPhone(user);
            return h.sendJson(res, 200, await me(updated));
        }
        if (!phoneOn()) return h.sendJson(res, 503, { error: "خدمة رسائل التحقق غير متاحة حالياً.", code: "sms_off" });
        if (p === "/api/account/phone/start") {
            const phone = normalizeIraqiMobile(body.phone);
            const owner = phone ? await users.findByPhone(phone) : null;
            if (owner && owner.id !== user.id) return h.sendJson(res, 409, { error: "هذا الرقم مربوط بحساب ثاني.", code: "phone_taken" });
            const r = await phoneAuth.start({ phone: body.phone, ip, purpose: "link", uid: user.id });
            return h.sendJson(res, 200, { challenge: r.challenge, masked: r.masked, expiresIn: r.expiresIn, resendIn: r.resendIn });
        }
        if (p === "/api/account/phone/verify") {
            const { phone } = await phoneAuth.verify({ challenge: body.challenge, code: body.code, purpose: "link", uid: user.id });
            const updated = await users.linkPhone(user, phone);
            stats.event("phone_linked", `ربط رقم ${maskPhone(phone)} بحساب`, ip);
            return h.sendJson(res, 200, await me(updated));
        }
        h.sendJson(res, 404, { error: "Not found" });
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
            const { user, created } = await users.loginWithProvider(identity, { allowCreate: feature("registration") });
            if (created) {
                stats.count("registrations");
                stats.event("register", `حساب جديد (${provider})`, ip);
            }
            if (mfaActive()) {
                const challenge = await beginMfa(user, provider, ip);
                return redirect(res, "/login?mfa=1", [clear, mfaCookie(req, challenge, 600)]);
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
        if (!user && isGuest(req)) h.sendJson(res, 401, { error: "أنت بوضع الضيف (مشاهدة فقط). أنشئ حساباً مجانياً أو سجّل دخولك حتى تفحص وتستخدم الخدمات.", code: "guest" });
        else if (!user) h.sendJson(res, 401, { error: "سجّل الدخول أولاً.", code: "login_required" });
        return user;
    }

    async function account(req, res, p) {
        const user = await requireUser(req, res);
        if (!user) return;
        try {
            if (p === "/api/account/history" && req.method === "GET") return h.sendJson(res, 200, { history: await users.history(user) });
            if (p.startsWith("/api/account/phone/")) return await accountPhone(req, res, p, user);
            const body = await jsonBody(req, res);
            if (body === undefined) return;
            let updated = user;
            if (p === "/api/account/name") updated = await users.rename(user, body.name);
            else if (p === "/api/account/password") {
                updated = await users.changePassword(user, { current: body.current, next: body.next });
                stats.event("password_change", "تغيير كلمة سر مستخدم", h.getClientIp(req, config));
                // الجلسات القديمة سقطت بتغيير كلمة السر: نصدر جلسة جديدة لهذا المتصفح ونحذف القديمة
                await users.destroySession(sessionToken(req)).catch(() => {});
                return await startSession(req, res, updated, 200, await me(updated));
            } else if (p === "/api/account/checkup") {
                updated = await users.saveCheckup(user, body.score);
                return h.sendJson(res, 200, { ok: true, checkups: users.publicUser(updated).checkups });
            } else if (p === "/api/account/history-setting") updated = await users.setHistoryEnabled(user, Boolean(body.enabled));
            else if (p === "/api/account/history/clear") await users.clearHistory(user);
            else if (p === "/api/account/api-key") {
                const key = await users.rotateApiKey(user);
                return h.sendJson(res, 200, { key, ...(await me(await users.get(user.id))) });
            } else if (p === "/api/account/delete") {
                const typed = String(body.confirm || "").trim().toLowerCase();
                const confirmed = user.email ? typed === user.email : Boolean(user.phone) && normalizeIraqiMobile(typed) === user.phone;
                if (!confirmed) {
                    return h.sendJson(res, 400, { error: user.email ? "اكتب بريدك الإلكتروني بالضبط لتأكيد الحذف." : "اكتب رقم هاتفك بالضبط لتأكيد الحذف." });
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
            h.sendJson(res, 200, {
                providers: oauth.providers, emailVerification: mailer.enabled, mfa: mfaActive(), registration: feature("registration"), guest: feature("guest"), phone: phoneOn(),
                trialDays: config.plans.trialDays, priceUsd: config.plans.priceUsd
            });
            return true;
        }
        if (p === "/api/auth/register") return await register(req, res), true;
        if (p === "/api/auth/login") return await login(req, res), true;
        if (p === "/api/auth/logout") return await logout(req, res), true;
        if (p === "/api/auth/guest") return await startGuest(req, res), true;
        if (p === "/api/auth/phone/start") return await phoneStart(req, res), true;
        if (p === "/api/auth/phone/verify") return await phoneVerify(req, res), true;
        if (p === "/api/auth/mfa") return await mfaVerify(req, res), true;
        if (p === "/api/auth/mfa/resend") return await mfaResend(req, res), true;
        if (p === "/api/auth/reset") return await resetPassword(req, res), true;
        if (p === "/api/auth/resend") return await resendVerification(req, res), true;
        if (p === "/api/auth/verify-code") return await verifyCodeRoute(req, res), true;
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

    return { handle, currentUser, requireUser, jsonBody, sendError, isGuest };
}

module.exports = { createAuth, maskEmail };
