"use strict";

/*
  إرسال رمز التحقق للهاتف (بدون مكتبات). يكفي ضبط مزوّد واحد بمتغيرات البيئة:

    TELEGRAM_GATEWAY_TOKEN                  Telegram Gateway: يوصل الرمز كرسالة رسمية داخل تيليگرام (رخيص جداً، ويرجع
                                            المبلغ إذا ما وصلت). مناسب للعراق لأن أغلب الناس عدهم تيليگرام.
    TWILIO_ACCOUNT_SID + TWILIO_AUTH_TOKEN  Twilio: SMS عادي لأي هاتف.
      + TWILIO_FROM (رقم المرسل) أو TWILIO_MESSAGING_SERVICE_SID
    SMS_WEBHOOK_URL (+ SMS_WEBHOOK_TOKEN)   أي بوابة SMS محلية: نرسل POST JSON { to, message, code }
                                            و Authorization: Bearer <token>. مفيد لشركات SMS العراقية.

  SMS_DAILY_CAP   حد أعلى لعدد الرسائل باليوم لكل الموقع (افتراضي 300) حتى ما تنصرف فلوس الرصيد لو صار هجوم.

  بدون أي مزوّد: الدخول بالهاتف يختفي من صفحة الدخول، والموقع يشتغل طبيعي.
  المفاتيح ما تظهر بأي رسالة خطأ أو سجل.
*/

const TIMEOUT_MS = 10_000;

const clean = (v, max = 300) => String(v || "").trim().slice(0, max);

function parseSms(env = process.env) {
    const cap = Math.max(1, Math.min(100_000, Number(env.SMS_DAILY_CAP) || 300));
    if (clean(env.TELEGRAM_GATEWAY_TOKEN)) {
        return { provider: "telegram", token: clean(env.TELEGRAM_GATEWAY_TOKEN, 500), sender: clean(env.TELEGRAM_GATEWAY_SENDER, 64), dailyCap: cap, enabled: true };
    }
    const sid = clean(env.TWILIO_ACCOUNT_SID, 64);
    const auth = clean(env.TWILIO_AUTH_TOKEN, 128);
    const from = clean(env.TWILIO_FROM, 32);
    const service = clean(env.TWILIO_MESSAGING_SERVICE_SID, 64);
    if (sid && auth && (from || service)) {
        return { provider: "twilio", sid, auth, from, service, dailyCap: cap, enabled: /^AC[0-9a-f]{32}$/i.test(sid) };
    }
    const hook = clean(env.SMS_WEBHOOK_URL, 500);
    if (hook) {
        let ok = false;
        try { ok = new URL(hook).protocol === "https:"; } catch { ok = false; }
        return { provider: "webhook", url: hook, token: clean(env.SMS_WEBHOOK_TOKEN, 500), dailyCap: cap, enabled: ok };
    }
    return { provider: "", dailyCap: cap, enabled: false };
}

const PROVIDER_LABEL = { telegram: "Telegram Gateway", twilio: "Twilio SMS", webhook: "بوابة SMS خاصة" };

function createSms(conf, { fetchImpl = fetch } = {}) {
    const c = conf || { enabled: false };
    let lastError = "";
    let sent = 0;

    async function post(url, headers, body) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
        try {
            const res = await fetchImpl(url, { method: "POST", headers, body, signal: controller.signal });
            const text = await res.text().catch(() => "");
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            return text;
        } finally {
            clearTimeout(timer);
        }
    }

    // phone: أرقام فقط بالصيغة الدولية بدون + (مثل 9647701234567)
    async function sendCode(phone, code) {
        if (!c.enabled) throw new Error("sms_disabled");
        const message = `رمز الدخول إلى Phishing Detector: ${code}\nلا تعطي هذا الرمز لأي أحد، حتى لو كال إنه من الموقع.`;
        try {
            if (c.provider === "telegram") {
                const body = { phone_number: "+" + phone, code, ttl: 300 };
                if (c.sender) body.sender_username = c.sender;
                const text = await post("https://gatewayapi.telegram.org/sendVerificationMessage",
                    { Authorization: "Bearer " + c.token, "Content-Type": "application/json" }, JSON.stringify(body));
                let parsed = {};
                try { parsed = JSON.parse(text); } catch { parsed = {}; }
                if (parsed.ok !== true) throw new Error("telegram: " + clean(parsed.error, 60));
            } else if (c.provider === "twilio") {
                const form = new URLSearchParams({ To: "+" + phone, Body: message });
                if (c.service) form.set("MessagingServiceSid", c.service); else form.set("From", c.from);
                await post(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(c.sid)}/Messages.json`,
                    { Authorization: "Basic " + Buffer.from(`${c.sid}:${c.auth}`).toString("base64"), "Content-Type": "application/x-www-form-urlencoded" }, form.toString());
            } else {
                const headers = { "Content-Type": "application/json" };
                if (c.token) headers.Authorization = "Bearer " + c.token;
                await post(c.url, headers, JSON.stringify({ to: "+" + phone, message, code }));
            }
            sent++;
            lastError = "";
        } catch (error) {
            // نخزن وصفاً قصيراً بدون أي مفتاح
            lastError = clean(error && error.name === "AbortError" ? "timeout" : error && error.message, 80);
            throw new Error("sms_failed");
        }
    }

    const status = () => ({ enabled: Boolean(c.enabled), provider: PROVIDER_LABEL[c.provider] || "", dailyCap: c.dailyCap, sent, lastError });
    return { enabled: Boolean(c.enabled), dailyCap: c.dailyCap || 300, sendCode, status };
}

module.exports = { parseSms, createSms };
