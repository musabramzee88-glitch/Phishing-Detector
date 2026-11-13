"use strict";

/*
  الدخول برقم الهاتف + رمز تحقق من 6 أرقام.

  الحماية:
  - أرقام الموبايل العراقية فقط (07XXXXXXXXX). هذا يمنع «هجمات ضخ الرسائل» (SMS pumping) اللي يستعملون بيها
    مواقع حتى يرسلون رسائل لأرقام دولية غالية ويخلصون رصيد صاحب الموقع.
  - رسالة وحدة كل 60 ثانية لنفس الرقم، و5 رسائل باليوم كحد أعلى لكل رقم، و20 بالساعة لكل عنوان IP،
    وحد يومي لكل الموقع (SMS_DAILY_CAP).
  - الرمز يُخزَّن مشفّراً (SHA-256 مع معرّف التحدي)، صالح 5 دقائق، و5 محاولات خاطئة كحد أعلى ثم ينلغي.
  - نفس الرد سواء الرقم مسجّل أو لا، فما ينكشف منو عنده حساب.
*/

const crypto = require("crypto");

const CODE_TTL = 300;
const MAX_TRIES = 5;
const RESEND_SECONDS = 60;
const PER_PHONE_DAY = 5;
// العراق: شبكات الموبايل تشارك عنوان IP وحد بين آلاف المشتركين (CGNAT)، فالحد لكل IP لازم ما يكون صغير جداً
const PER_IP_HOUR = 20;

class PhoneError extends Error {
    constructor(code, message, status = 400, extra = {}) {
        super(message);
        this.code = code;
        this.status = status;
        Object.assign(this, extra);
    }
}

const sha256 = v => crypto.createHash("sha256").update(String(v)).digest("hex");

// يرجع الرقم بصيغة 9647XXXXXXXXX أو "" إذا مو رقم موبايل عراقي
function normalizeIraqiMobile(raw) {
    let v = String(raw || "").trim().slice(0, 40)
        .replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 0x0660))
        .replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 0x06f0))
        .replace(/[\s\-().]/g, "").replace(/^\+/, "").replace(/^00/, "");
    if (/^07\d{9}$/.test(v)) v = "964" + v.slice(1);
    else if (/^7\d{9}$/.test(v)) v = "964" + v;
    return /^9647[3-9]\d{8}$/.test(v) ? v : "";
}

// للعرض: 0770 ••• 4567
function maskPhone(phone) {
    if (!phone) return "";
    const local = "0" + phone.slice(3);
    return `${local.slice(0, 4)} ••• ${local.slice(-4)}`;
}

function createPhoneAuth({ db, sms, now = () => Date.now() }) {
    const k = (...p) => db.key(...p);
    const day = () => new Date(now()).toISOString().slice(0, 10);

    async function counter(key, ttl) {
        const [n] = await db.pipe([["INCR", key], ["EXPIRE", key, String(ttl)]]);
        return Number(n) || 0;
    }

    async function start({ phone: raw, ip = "", purpose = "login", uid = "" }) {
        if (!sms || !sms.enabled) throw new PhoneError("sms_off", "الدخول برقم الهاتف غير متاح حالياً.", 503);
        const phone = normalizeIraqiMobile(raw);
        if (!phone) throw new PhoneError("bad_phone", "اكتب رقم موبايل عراقي صحيح، مثل 07701234567.");
        const ipKey = sha256("ip:" + ip).slice(0, 24);
        // حدود متعددة. نفحص فترة الانتظار أولاً حتى ما نحسب محاولة على الحدود الثانية بلا داعي
        const cooled = await db.cmd(["SET", k("otpwait", phone), "1", "NX", "EX", String(RESEND_SECONDS)]);
        if (cooled !== "OK") throw new PhoneError("wait", "أرسلنا رمز لهذا الرقم قبل شوية. انتظر دقيقة وجرّب مرة ثانية.", 429, { retryAfter: RESEND_SECONDS });
        if (await counter(k("otpip", ipKey), 3600) > PER_IP_HOUR) throw new PhoneError("ip_limit", "طلبت رموز كثيرة. جرّب بعد ساعة.", 429, { retryAfter: 3600 });
        if (await counter(k("otpday", phone, day()), 86400) > PER_PHONE_DAY) throw new PhoneError("phone_limit", "وصلت للحد اليومي لرسائل هذا الرقم. جرّب باچر.", 429, { retryAfter: 3600 });
        if (await counter(k("smsday", day()), 86400) > sms.dailyCap) throw new PhoneError("global_limit", "خدمة الرسائل مضغوطة اليوم. جرّب بعد شوية أو سجّل بالبريد.", 503);

        const challenge = crypto.randomBytes(24).toString("base64url");
        const code = String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");
        const id = sha256(challenge);
        await db.pipe([
            ["SET", k("otp", id), JSON.stringify({ phone, purpose: purpose === "link" ? "link" : "login", uid: String(uid || "").slice(0, 32), code: sha256(id + ":" + code) }), "EX", String(CODE_TTL)],
            ["DEL", k("otptry", id)]
        ]);
        try {
            await sms.sendCode(phone, code);
        } catch {
            await db.pipe([["DEL", k("otp", id)], ["DEL", k("otpwait", phone)]]);
            throw new PhoneError("send_failed", "تعذر إرسال الرمز هسه. تأكد من الرقم وجرّب بعد شوية.", 503);
        }
        return { challenge, phone, masked: maskPhone(phone), expiresIn: CODE_TTL, resendIn: RESEND_SECONDS };
    }

    async function verify({ challenge, code: rawCode, purpose = "login", uid = "" }) {
        const expired = () => new PhoneError("expired", "انتهت صلاحية الرمز. اطلب رمز جديد.", 400);
        if (typeof challenge !== "string" || !/^[A-Za-z0-9_-]{32}$/.test(challenge)) throw expired();
        const code = String(rawCode || "").replace(/\s/g, "")
            .replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 0x0660)).replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 0x06f0));
        if (!/^\d{6}$/.test(code)) throw new PhoneError("bad_code", "الرمز لازم يكون 6 أرقام.");
        const id = sha256(challenge);
        const stored = await db.cmd(["GET", k("otp", id)]);
        let data;
        try { data = stored ? JSON.parse(stored) : null; } catch { data = null; }
        if (!data) throw expired();
        if (data.purpose !== purpose || (purpose === "link" && data.uid !== String(uid))) throw expired();
        const tries = await counter(k("otptry", id), CODE_TTL);
        if (tries > MAX_TRIES) {
            await db.pipe([["DEL", k("otp", id)], ["DEL", k("otptry", id)]]);
            throw new PhoneError("too_many", "محاولات خاطئة كثيرة. اطلب رمز جديد.", 429);
        }
        const a = Buffer.from(data.code, "hex");
        const b = Buffer.from(sha256(id + ":" + code), "hex");
        if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
            throw new PhoneError("bad_code", `الرمز غلط. باقيلك ${MAX_TRIES - tries} محاولات.`);
        }
        await db.pipe([["DEL", k("otp", id)], ["DEL", k("otptry", id)]]);
        return { phone: data.phone };
    }

    return { start, verify };
}

module.exports = { createPhoneAuth, normalizeIraqiMobile, maskPhone, PhoneError };
