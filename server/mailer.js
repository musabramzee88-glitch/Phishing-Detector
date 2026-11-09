"use strict";

/*
  إرسال البريد عبر واجهة HTTPS لمزوّد جاهز (بدون مكتبات):
    BREVO_API_KEY   (Brevo: مجاني 300 رسالة يومياً، يكفي توثيق عنوان مرسل واحد بدون نطاق خاص)
    RESEND_API_KEY  (Resend: يحتاج نطاقاً موثّقاً للإرسال لأي مستخدم)
    MAIL_FROM       عنوان المرسل (يجب أن يكون موثّقاً عند المزوّد)،  MAIL_FROM_NAME اختياري
  بدون هذه المتغيرات: التحقق من البريد وإرسال روابط كلمة السر معطّلان، ويبقى الموقع يعمل كما كان.
  المفتاح لا يظهر بأي رسالة خطأ أو سجل.
*/

const TIMEOUT_MS = 10_000;

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function createMailer(config) {
    const m = config.mail || {};
    const enabled = Boolean(m.enabled);
    let lastError = "";

    async function send({ to, subject, text, html }) {
        if (!enabled) throw new Error("mail_disabled");
        const url = m.provider === "brevo" ? `${m.apiBase}/v3/smtp/email` : `${m.apiBase}/emails`;
        const headers = { "Content-Type": "application/json", Accept: "application/json" };
        let body;
        if (m.provider === "brevo") {
            headers["api-key"] = m.apiKey;
            body = { sender: { name: m.fromName, email: m.from }, to: [{ email: to }], subject, textContent: text, htmlContent: html };
        } else {
            headers.Authorization = "Bearer " + m.apiKey;
            body = { from: `${m.fromName} <${m.from}>`, to: [to], subject, text, html };
        }
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
        try {
            const response = await fetch(url, { method: "POST", headers, body: JSON.stringify(body), signal: controller.signal });
            if (!response.ok) {
                lastError = `المزوّد رفض الإرسال (${response.status}). تأكد من المفتاح ومن توثيق عنوان المرسل MAIL_FROM.`;
                throw new Error("mail_failed_" + response.status);
            }
            lastError = "";
        } catch (error) {
            if (!lastError) lastError = error.name === "AbortError" ? "انتهت مهلة مزوّد البريد." : "تعذر الاتصال بمزوّد البريد.";
            throw new Error(error.message && error.message.startsWith("mail_failed_") ? error.message : "mail_unreachable");
        } finally {
            clearTimeout(timer);
        }
    }

    function layout(title, intro, buttonText, link, footer) {
        const safeLink = escapeHtml(link);
        const html = `<!doctype html><html lang="ar" dir="rtl"><body style="font-family:Tahoma,Arial,sans-serif;background:#f4f6f8;padding:24px">
<div style="max-width:480px;margin:auto;background:#fff;border-radius:12px;padding:28px;text-align:right">
<h2 style="margin-top:0;color:#111">${escapeHtml(title)}</h2>
<p style="color:#333;line-height:1.8">${escapeHtml(intro)}</p>
<p style="text-align:center;margin:28px 0"><a href="${safeLink}" style="background:#0a84ff;color:#fff;text-decoration:none;padding:12px 28px;border-radius:8px;display:inline-block">${escapeHtml(buttonText)}</a></p>
<p style="color:#666;font-size:13px;line-height:1.7">إذا ما ينفتح الزر انسخ هذا الرابط:<br><span dir="ltr" style="word-break:break-all">${safeLink}</span></p>
<p style="color:#888;font-size:12px">${escapeHtml(footer)}</p></div></body></html>`;
        const plain = `${title}\n\n${intro}\n\n${link}\n\n${footer}`;
        return { html, text: plain };
    }

    const verifyEmail = (to, link) => send({
        to, subject: "فعّل حسابك في Phishing Detector",
        ...layout("تأكيد البريد الإلكتروني", "اضغط الزر لتأكيد بريدك وتفعيل حسابك. الرابط صالح 24 ساعة ولمرة واحدة.", "تأكيد البريد", link, "إذا لم تنشئ حساباً بهذا البريد تجاهل الرسالة.")
    });
    const resetEmail = (to, link) => send({
        to, subject: "إعادة تعيين كلمة السر - Phishing Detector",
        ...layout("إعادة تعيين كلمة السر", "وصلنا طلب لتغيير كلمة سر حسابك. الرابط صالح ساعة واحدة ولمرة واحدة.", "تعيين كلمة سر جديدة", link, "إذا لم تطلب هذا تجاهل الرسالة؛ كلمة سرك ما تغيّرت.")
    });

    return { enabled, provider: m.provider || "", send, verifyEmail, resetEmail, status: () => ({ enabled, provider: m.provider || "", lastError }) };
}

module.exports = { createMailer };
