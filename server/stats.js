"use strict";

/*
  إحصاءات مجهولة لصفحة الأدمن. تُحفظ في الذاكرة فقط (تتصفّر عند إعادة تشغيل الخادم).
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

function cleanText(value) {
    // نحذف المحارف الخفية ونقصّ الطول حتى لا يُستخدم السجل لحقن شيء
    return String(value || "").replace(/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/g, " ").slice(0, 160);
}

function createStats() {
    const startedAt = Date.now();
    const counters = {
        requests: 0, chatOk: 0, chatErrors: 0, rateLimited: 0,
        loginOk: 0, loginFailed: 0, blockedRequests: 0
    };
    const scans = {};
    for (const kind of SCAN_KINDS) scans[kind] = { safe: 0, warning: 0, danger: 0 };
    const events = [];

    return {
        count(name) {
            if (name in counters) counters[name] += 1;
        },
        // يرجع true إذا كان النوع والنتيجة من القائم المسموحة
        scan(kind, level) {
            if (!SCAN_KINDS.includes(kind) || !SCAN_LEVELS.includes(level)) return false;
            scans[kind][level] += 1;
            return true;
        },
        event(type, detail, ip) {
            events.unshift({ time: new Date().toISOString(), type: cleanText(type), detail: cleanText(detail), ip: maskIp(ip) });
            if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;
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

module.exports = { createStats, maskIp, SCAN_KINDS, SCAN_LEVELS };
