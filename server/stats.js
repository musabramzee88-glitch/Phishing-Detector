"use strict";

/*
  إحصاءات وسجل تدقيق (Audit Log) للوحة الأدمن. تُعدّ في الذاكرة وتُحفظ دورياً في قاعدة البيانات (attach)،
  فتبقى بعد إعادة التشغيل وكل نشر جديد. بدون قاعدة دائمة (تشغيل محلي) تتصفّر عند إعادة التشغيل.
  نحفظ الفروقات فقط (HINCRBY) فلا تتعارض نسختان تعملان معاً أثناء النشر.
  عند تفعيل AUDIT_STDOUT (تلقائي على Render) يُكتب كل حدث أيضاً كسطر JSON في سجلات الاستضافة،
  فيبقى عندك سجل تدقيق خارج ذاكرة الخادم.
  لا تُسجَّل أي روابط أو رسائل أو ملفات: فقط عدّادات (نوع الفحص ونتيجته) وأحداث أمنية قصيرة.
*/

const crypto = require("node:crypto");

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

// HGETALL قد ترجع مصفوفة مسطحة أو كائناً
function hashToFlat(raw) {
    const out = {};
    if (Array.isArray(raw)) for (let i = 0; i + 1 < raw.length; i += 2) out[raw[i]] = raw[i + 1];
    else if (raw && typeof raw === "object") Object.assign(out, raw);
    return out;
}

function createStats({ audit } = {}) {
    const startedAt = Date.now();
    const counters = {
        requests: 0, chatOk: 0, chatAi: 0, chatErrors: 0, rateLimited: 0,
        loginOk: 0, loginFailed: 0, blockedRequests: 0,
        clientErrors: 0, serverErrors: 0,
        registrations: 0, userLogins: 0, userLoginFailed: 0, paymentRequests: 0, quotaExceeded: 0, bulkScans: 0, filesCleaned: 0,
        liveVisits: 0, snapshotViews: 0, guestEntries: 0, ssrfBlocked: 0
    };
    const scans = {};
    for (const kind of SCAN_KINDS) scans[kind] = { safe: 0, warning: 0, danger: 0 };
    const events = [];

    // ما لم يُحفظ بعد في القاعدة
    let pending = { counters: {}, scans: {}, events: [] };
    let store = null;
    let since = new Date(startedAt).toISOString();
    let timer = null;
    let flushing = null;
    let loaded = false;
    let seq = 0;      // يرتّب الأحداث التي وقعت في نفس الميلي ثانية

    function bump(map, key) { map[key] = (map[key] || 0) + 1; }

    function event(type, detail, ip) {
        const entry = { time: new Date().toISOString(), type: cleanText(type, 40), detail: cleanText(detail), ip: maskIp(ip) };
        events.unshift(entry);
        pending.events.push(entry);
        if (pending.events.length > MAX_EVENTS) pending.events.splice(0, pending.events.length - MAX_EVENTS);
        if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;
        if (audit) {
            try { audit(entry); } catch { /* السجل الخارجي لا يجوز أن يعطّل الطلب */ }
        }
    }

    return {
        count(name) {
            if (Object.prototype.hasOwnProperty.call(counters, name)) {
                counters[name] += 1;
                bump(pending.counters, name);
            }
        },
        // يرجع true إذا كان النوع والنتيجة من القائمة المسموحة
        scan(kind, level) {
            if (!SCAN_KINDS.includes(kind) || !SCAN_LEVELS.includes(level)) return false;
            scans[kind][level] += 1;
            bump(pending.scans, kind + ":" + level);
            return true;
        },
        // نربط الإحصاءات بقاعدة البيانات: نحمّل القيم المحفوظة ونبدأ الحفظ الدوري
        async attach(db, { intervalMs = 5_000 } = {}) {
            const kc = db.key("stats", "counters");
            const ks = db.key("stats", "scans");
            const ke = db.key("stats", "events");
            const kt = db.key("stats", "since");
            try {
                const [rawC, rawS, rawE] = await db.pipe([["HGETALL", kc], ["HGETALL", ks], ["ZREVRANGE", ke, 0, MAX_EVENTS - 1]]);
                const saved = hashToFlat(rawC);
                for (const name of Object.keys(counters)) counters[name] += Number(saved[name]) || 0;
                const savedScans = hashToFlat(rawS);
                for (const kind of SCAN_KINDS) for (const level of SCAN_LEVELS) scans[kind][level] += Number(savedScans[kind + ":" + level]) || 0;
                const loaded = [];
                for (const item of Array.isArray(rawE) ? rawE : []) {
                    try {
                        const e = JSON.parse(String(item).slice(String(item).indexOf("|") + 1));
                        if (e && typeof e.time === "string") loaded.push({ time: e.time, type: cleanText(e.type, 40), detail: cleanText(e.detail), ip: cleanText(e.ip, 40) });
                    } catch { /* سطر تالف: نتجاهله */ }
                }
                // أحداث هذه العملية (قبل الربط) أولاً ثم المحفوظة
                const merged = events.concat(loaded).sort((a, b) => Date.parse(b.time) - Date.parse(a.time)).slice(0, MAX_EVENTS);
                events.length = 0;
                events.push(...merged);
                await db.cmd(["SET", kt, since, "NX"]);
                const first = await db.cmd(["GET", kt]);
                if (first) since = String(first);
            } catch (error) {
                // لا نعطّل الموقع: نكمل بعدّ جديد بالذاكرة ونعيد المحاولة عند الحفظ
                store = { db, kc, ks, ke };
                return { ok: false, error: db.describeError ? db.describeError(error) : String(error && error.message) };
            }
            store = { db, kc, ks, ke };
            loaded = true;
            if (intervalMs > 0 && !timer) {
                timer = setInterval(() => { this.flush().catch(() => {}); }, intervalMs);
                if (timer.unref) timer.unref();
            }
            return { ok: true };
        },
        // يحفظ الفروقات. عند الفشل نعيدها لنجرّب لاحقاً.
        flush() {
            if (!store) return Promise.resolve(false);
            if (flushing) return flushing;
            const batch = pending;
            const empty = !Object.keys(batch.counters).length && !Object.keys(batch.scans).length && !batch.events.length;
            if (empty) return Promise.resolve(true);
            pending = { counters: {}, scans: {}, events: [] };
            const { db, kc, ks, ke } = store;
            const commands = [];
            for (const [name, n] of Object.entries(batch.counters)) commands.push(["HINCRBY", kc, name, n]);
            for (const [name, n] of Object.entries(batch.scans)) commands.push(["HINCRBY", ks, name, n]);
            if (batch.events.length) {
                for (const e of batch.events) commands.push(["ZADD", ke, Date.parse(e.time), String(++seq).padStart(10, "0") + crypto.randomBytes(3).toString("hex") + "|" + JSON.stringify(e)]);
                commands.push(["ZREMRANGEBYRANK", ke, 0, -(MAX_EVENTS + 1)]);
            }
            flushing = Promise.resolve(db.pipe(commands)).then(() => true, () => {
                for (const [k, v] of Object.entries(batch.counters)) pending.counters[k] = (pending.counters[k] || 0) + v;
                for (const [k, v] of Object.entries(batch.scans)) pending.scans[k] = (pending.scans[k] || 0) + v;
                pending.events = batch.events.concat(pending.events).slice(-MAX_EVENTS);
                return false;
            }).finally(() => { flushing = null; });
            return flushing;
        },
        async close() {
            if (timer) { clearInterval(timer); timer = null; }
            if (flushing) await flushing;
            return this.flush();
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
                since,
                persistent: !!(store && loaded && store.db.persistent),
                uptimeSeconds: Math.round((Date.now() - startedAt) / 1000),
                counters: { ...counters },
                scans: JSON.parse(JSON.stringify(scans)),
                events: events.slice(0, eventLimit)
            };
        }
    };
}

module.exports = { createStats, maskIp, cleanText, SCAN_KINDS, SCAN_LEVELS };
