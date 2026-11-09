"use strict";

/*
  إعدادات الخادم. كل شيء يُقرأ من متغيرات البيئة، ولا يوجد أي سر داخل الكود.

  OPENAI_API_KEY, OPENAI_MODEL     تفعيل ردود CyberBot بالذكاء الاصطناعي (اختياري)
  OPENAI_WEB_SEARCH=1              السماح للنموذج بالبحث على الإنترنت (اختياري، قد يكلّف)
  OPENAI_BASE_URL                  عنوان مزوّد النموذج (الافتراضي https://api.openai.com/v1)
  ADMINS                           حسابات الأدمن: user:salt:hash[:totpSecret]، تفصل بينها فاصلة.
                                   تُولَّد بالأمر: npm run make-admin   (بدونها صفحة الأدمن مغلقة تماماً)
  TRUST_PROXY=1                    قراءة عنوان الزائر من ترويسات الوسيط (يُفعَّل تلقائياً على Render)
  CYBERBOT_ORIGIN                  أصل موقع آخر يُسمح له باستدعاء /api/chat (اختياري)
  CYBERBOT_GLOBAL_LIMIT            أقصى عدد رسائل CyberBot بالدقيقة لكل الزوار معاً (الافتراضي 120)
  HOST, PORT                       عنوان ومنفذ الاستماع
*/

const path = require("node:path");

const HEX_32_BYTES = /^[0-9a-f]{64}$/i;

// صيغة كل حساب: username:saltHex:hashHex[:totpSecretBase32]
function parseAdmins(value) {
    const admins = new Map();
    for (const entry of String(value || "").split(",")) {
        const [user, salt, hash, totpSecret] = entry.trim().split(":");
        if (!user || !salt || !HEX_32_BYTES.test(hash || "")) continue;
        admins.set(user.toLowerCase(), {
            salt,
            hash: Buffer.from(hash, "hex"),
            totpSecret: totpSecret || "",
            lastTotpCounter: -1
        });
    }
    return admins;
}

function loadConfig(env = process.env) {
    const onRender = Boolean(env.RENDER);
    const root = path.resolve(__dirname, "..");
    return {
        root,
        publicDir: path.join(root, "public"),
        adminDir: path.join(__dirname, "admin"),
        host: env.HOST || (onRender ? "0.0.0.0" : "127.0.0.1"),
        port: Number(env.PORT || 8080),
        trustProxy: env.TRUST_PROXY === "1" || onRender,
        allowedOrigin: env.CYBERBOT_ORIGIN || "",
        openai: {
            apiKey: env.OPENAI_API_KEY || "",
            model: env.OPENAI_MODEL || "",
            webSearch: env.OPENAI_WEB_SEARCH === "1",
            baseUrl: (env.OPENAI_BASE_URL || "https://api.openai.com/v1").replace(/\/+$/, "")
        },
        admins: parseAdmins(env.ADMINS),
        // سجل التدقيق كسطور JSON في سجلات الاستضافة (تلقائي على Render، يُعطَّل بـ AUDIT_STDOUT=0)
        auditStdout: env.AUDIT_STDOUT === "1" || (onRender && env.AUDIT_STDOUT !== "0"),
        health: {},   // عتبات مراقب الصحة (انظر server/health.js)، تُعدَّل بالاختبارات فقط
        billing: {
            // سر توقيع مفاتيح الترخيص (32 حرفاً فأكثر). بدونه لا يمكن إصدار مفاتيح ولا التحقق منها. npm run make-secret
            licenseSecret: env.LICENSE_SECRET || "",
            // مجلد حفظ سجل المبيعات. على Render يجب أن يكون قرصاً دائماً (Persistent Disk) وإلا يضيع عند كل نشر.
            dataDir: env.DATA_DIR || path.join(root, "data"),
            persistentDiskConfigured: Boolean(env.DATA_DIR),
            // بيانات التواصل التي تظهر بصفحة الباقات (أنت تحددها بالمتغيرات، لا شيء مكتوب بالكود)
            contact: {
                whatsapp: /^\d{7,15}$/.test(env.CONTACT_WHATSAPP || "") ? env.CONTACT_WHATSAPP : "",
                telegram: /^[A-Za-z0-9_]{5,32}$/.test(env.CONTACT_TELEGRAM || "") ? env.CONTACT_TELEGRAM : "",
                note: String(env.PAYMENT_NOTE || "").replace(/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/g, " ").slice(0, 400)
            }
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
            badLicenseKeysPerWindow: 20,
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
