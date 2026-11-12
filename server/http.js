"use strict";

/* أدوات HTTP المشتركة: ترويسات الأمان، الردود، قراءة الجسم، عنوان الزائر، فحص الأصل. */

// سياسة أمان المحتوى (CSP): تمنع تشغيل أي سكربت لا يأتي من موقعنا نفسه.
// هذا أقوى دفاع ضد حقن الأكواد (XSS): حتى لو تسلل HTML خبيث للصفحة، المتصفح لن ينفّذه.
const CSP = [
    "default-src 'none'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com",
    "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com",
    "img-src 'self' data: blob:",
    "media-src 'self' blob:",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "object-src 'none'"
].join("; ");

function isHttps(req, config) {
    if (req.socket && req.socket.encrypted) return true;
    if (!config.trustProxy) return false;
    return String(req.headers["x-forwarded-proto"] || "").split(",")[0].trim() === "https";
}

function applySecurityHeaders(req, res, config) {
    res.setHeader("Content-Security-Policy", CSP);
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    res.setHeader("X-Permitted-Cross-Domain-Policies", "none");
    if (isHttps(req, config)) res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
}

function sendJson(res, status, payload, extraHeaders = {}) {
    const body = JSON.stringify(payload);
    res.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": Buffer.byteLength(body),
        "Cache-Control": "no-store",
        ...extraHeaders
    });
    res.end(body);
}

function sendText(res, status, text, extraHeaders = {}) {
    res.writeHead(status, {
        "Content-Type": "text/plain; charset=utf-8",
        "Content-Length": Buffer.byteLength(text),
        "Cache-Control": "no-store",
        ...extraHeaders
    });
    res.end(text);
}

async function readJsonBody(req, maxBytes) {
    const declared = Number(req.headers["content-length"] || 0);
    if (declared > maxBytes) throw new Error("body too large");
    let size = 0;
    const chunks = [];
    for await (const chunk of req) {
        size += chunk.length;
        if (size > maxBytes) throw new Error("body too large");
        chunks.push(chunk);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function isJsonRequest(req) {
    return /^application\/json\b/i.test(String(req.headers["content-type"] || ""));
}

// حماية CSRF: الطلبات التي تغيّر الحالة يجب أن تأتي من صفحات موقعنا نفسه.
// المتصفحات ترسل ترويسة Origin مع كل POST، فنقارنها بعنوان الموقع.
function isSameOrigin(req) {
    const origin = req.headers.origin;
    if (origin) {
        try {
            return new URL(origin).host === req.headers.host;
        } catch {
            return false;
        }
    }
    const site = req.headers["sec-fetch-site"];
    return !site || site === "same-origin" || site === "none";
}

// عنوان الزائر. خلف Render كل الطلبات تصل من عنوان الوسيط، فنقرأ العنوان الحقيقي من ترويسات الوسيط.
function getClientIp(req, config) {
    if (config.trustProxy) {
        // Cloudflare (أمام Render) تضع True-Client-IP. اسم الترويسة قابل للتغيير بـ CLIENT_IP_HEADER،
        // وتأكد من أنها غير قابلة للتزوير عبر /api/admin/ipcheck.
        const headerName = config.clientIpHeader || "true-client-ip";
        const trueClientIp = String(req.headers[headerName] || "").split(",")[0].trim();
        if (trueClientIp && /^[0-9a-f.:]{3,45}$/i.test(trueClientIp)) return trueClientIp;
        // X-Forwarded-For يمكن تزويرها، فهي احتياط فقط، والسقف العام يبقى يحمينا.
        const forwarded = String(req.headers["x-forwarded-for"] || "").split(",").map(s => s.trim()).filter(Boolean);
        if (forwarded.length) return forwarded[0];
    }
    return (req.socket && req.socket.remoteAddress) || "unknown";
}

function parseCookies(header) {
    const cookies = {};
    for (const part of String(header || "").split(";")) {
        const index = part.indexOf("=");
        if (index < 0) continue;
        const name = part.slice(0, index).trim();
        // نتجاهل الأسماء الفارغة والأسماء التي قد تعبث ببنية الكائن (مثل __proto__)
        if (!name || name === "__proto__" || Object.prototype.hasOwnProperty.call(cookies, name)) continue;
        cookies[name] = part.slice(index + 1).trim();
    }
    return cookies;
}

module.exports = {
    CSP, isHttps, applySecurityHeaders, sendJson, sendText, readJsonBody, isJsonRequest,
    isSameOrigin, getClientIp, parseCookies
};
