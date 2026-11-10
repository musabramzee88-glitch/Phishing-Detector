"use strict";

/*
  إحصاءات وسجل تدقيق (Audit Log) للوحة الأدمن. تُحفظ في الذاكرة (تتصفّر عند إعادة التشغيل).
  عند تفعيل AUDIT_STDOUT (تلقائي على Render) يُكتب كل حدث أيضاً كسطر JSON في سجلات الاستضافة،
  فيبقى عندك سجل تدقيق خارج ذاكرة الخادم.
  لا تُسجَّل أي روابط أو رسائل أو ملفات: فقط عدّادات (نوع الفحص ونتيجته) وأحداث أمنية قصيرة.
*/

const SCAN_KINDS = ["url", "text", "file", "media"];
const SCAN_LEVELS = ["safe", "warning", "danger"];
const MAX_EVENTS = 200;

// نخفي آخر جزء من عنوان الزائر حتى لا نحتفظ بعنوان كامل
function maskIp(ip) {
    const value = String(ip || "");
    const v4 = /(\d{1,3}\.\d{1,3}\.\d{1,3})\.\d{1,3}$/.exec(value);
    if (v4) return v4[1] + ".x";
    if (value.includes(":")) return value.split(":").slice(0, 3).join(":") + ":…";
    return value ? "غير معروف" : "";
}

function cleanText(value, max = 160) {
    // نحذف المحارف الخفية ونقصّ الطول حتى لا يُستخدم السجل لحقن شيء
    return String(value || "").replace(/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/g, " ").slice(0, max);
}

function createStats({ audit } = {}) {
    const startedAt = Date.now();
    const counters = {
        requests: 0, chatOk: 0, chatErrors: 0, rateLimited: 0,
        loginOk: 0, loginFailed: 0, blockedRequests: 0,
        clientErrors: 0, serverErrors: 0,
        registrations: 0, userLogins: 0, userLoginFailed: 0, paymentRequests: 0, quotaExceeded: 0, bulkScans: 0, filesCleaned: 0
    };
    const scans = {};
    for (const kind of SCAN_KINDS) scans[kind] = { safe: 0, warning: 0, danger: 0 };
    const events = [];

    function event(type, detail, ip) {
        const entry = { time: new Date().toISOString(), type: cleanText(type, 40), detail: cleanText(detail), ip: maskIp(ip) };
        events.unshift(entry);
        if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;
        if (audit) {
            try { audit(entry); } catch { /* السجل الخارجي لا يجوز أن يعطّل الطلب */ }
        }
    }

    return {
        count(name) {
            if (Object.prototype.hasOwnProperty.call(counters, name)) counters[name] += 1;
        },
        // يرجع true إذا كان النوع والنتيجة من القائمة المسموحة
        scan(kind, level) {
            if (!SCAN_KINDS.includes(kind) || !SCAN_LEVELS.includes(level)) return false;
            scans[kind][level] += 1;
            return true;
        },
        event,
        // عدد أحداث نوع معين خلال آخر windowMs (من السجل المحفوظ)
        recent(type, windowMs, now = Date.now()) {
            let n = 0;
            for (const e of events) {
                if (now - Date.parse(e.time) > windowMs) break;
                if (e.type === type) n += 1;
            }
            return n;
        },
        snapshot(eventLimit = 100) {
            return {
                startedAt: new Date(startedAt).toISOString(),
                uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
                counters: { ...counters },
                scans: JSON.parse(JSON.stringify(scans)),
                events: events.slice(0, eventLimit)
            };
        }
    };
}

module.exports = { createStats, maskIp, cleanText, SCAN_KINDS, SCAN_LEVELS };
