"use strict";

/*
  عدّاد زوار تقريبي يحترم الخصوصية: لا نحفظ العنوان ولا المتصفح، بل بصمة مجزّأة (HMAC) بملح يتغيّر كل يوم.
  لا يمكن ربط نفس الزائر بين يومين ولا استرجاع عنوانه. الأرقام تقريبية (تشمل الروبوتات).
  عند attach(db) تُحفظ البصمات المجزّأة وأعداد المشاهدات في القاعدة فلا تتصفّر عند النشر
  (الملح اليومي مشتق من سر عشوائي محفوظ، فتبقى البصمة ثابتة خلال اليوم الواحد حتى بعد إعادة التشغيل).
*/

const crypto = require("node:crypto");

const ACTIVE_WINDOW_MS = 5 * 60_000;
const KEEP_DAYS = 8;
const MAX_IDS_PER_DAY = 100_000;

function dayKey(time) {
    return new Date(time).toISOString().slice(0, 10);
}

function createVisitorCounter() {
    const days = new Map();      // yyyy-mm-dd -> { salt, ids:Set, views }
    const recent = new Map();    // fingerprint -> آخر ظهور
    let totalViews = 0;
    let secret = null;           // يُحمَّل من القاعدة بعد attach
    let store = null;
    let timer = null;
    let flushing = null;
    let pending = { ids: new Map(), views: new Map(), total: 0 };   // day -> Set / عدد

    function bucket(time) {
        const key = dayKey(time);
        let entry = days.get(key);
        if (!entry) {
            entry = { salt: secret ? crypto.createHmac("sha256", secret).update(key).digest().subarray(0, 16) : crypto.randomBytes(16), ids: new Set(), views: 0 };
            days.set(key, entry);
            while (days.size > KEEP_DAYS) days.delete(days.keys().next().value);
        }
        return entry;
    }

    async function attach(db, { intervalMs = 5_000, now = Date.now() } = {}) {
        const keyTotal = db.key("visitors", "total");
        const keyDay = day => db.key("visitors", "day", day);
        try {
            await db.cmd(["SET", db.key("visitors", "secret"), crypto.randomBytes(32).toString("hex"), "NX"]);
            secret = Buffer.from(String(await db.cmd(["GET", db.key("visitors", "secret")])), "hex");
            const keys = [];
            for (let i = KEEP_DAYS - 1; i >= 0; i--) keys.push(dayKey(now - i * 86_400_000));
            const replies = await db.pipe([["GET", keyTotal], ...keys.flatMap(day => [["SMEMBERS", keyDay(day) + ":ids"], ["GET", keyDay(day) + ":views"]])]);
            totalViews += Number(replies[0]) || 0;
            keys.forEach((day, i) => {
                const ids = replies[1 + i * 2];
                const views = Number(replies[2 + i * 2]) || 0;
                const salt = crypto.createHmac("sha256", secret).update(day).digest().subarray(0, 16);
                const entry = days.get(day) || { salt, ids: new Set(), views: 0 };
                // نشاط هذه العملية قبل الربط كان بملح عشوائي: نبقيه في العدّ لكنه لا يُحفظ
                entry.views += views;
                for (const id of Array.isArray(ids) ? ids : []) if (entry.ids.size < MAX_IDS_PER_DAY) entry.ids.add(String(id));
                if (!days.has(day)) days.set(day, entry);
            });
            pending.ids = new Map();    // بصمات ما قبل الربط بملح مؤقت: لا تُحفظ
            while (days.size > KEEP_DAYS) days.delete(days.keys().next().value);
            // أيام لاحقة: يُشتق ملحها من السر
            for (const [day, entry] of days) entry.salt = crypto.createHmac("sha256", secret).update(day).digest().subarray(0, 16);
        } catch (error) {
            store = { db, keyDay, keyTotal };
            return { ok: false, error: db.describeError ? db.describeError(error) : String(error && error.message) };
        }
        store = { db, keyDay, keyTotal };
        if (intervalMs > 0 && !timer) {
            timer = setInterval(() => { flush().catch(() => {}); }, intervalMs);
            if (timer.unref) timer.unref();
        }
        return { ok: true };
    }

    function flush() {
        if (!store) return Promise.resolve(false);
        if (flushing) return flushing;
        const batch = pending;
        if (!batch.total && !batch.ids.size) return Promise.resolve(true);
        pending = { ids: new Map(), views: new Map(), total: 0 };
        const { db, keyDay, keyTotal } = store;
        const commands = [];
        if (batch.total) commands.push(["INCRBY", keyTotal, batch.total]);
        for (const [day, n] of batch.views) {
            commands.push(["INCRBY", keyDay(day) + ":views", n]);
            commands.push(["EXPIRE", keyDay(day) + ":views", (KEEP_DAYS + 1) * 86_400]);
        }
        for (const [day, ids] of batch.ids) {
            const list = [...ids];
            for (let i = 0; i < list.length; i += 500) commands.push(["SADD", keyDay(day) + ":ids", ...list.slice(i, i + 500)]);
            commands.push(["EXPIRE", keyDay(day) + ":ids", (KEEP_DAYS + 1) * 86_400]);
        }
        flushing = Promise.resolve(db.pipe(commands)).then(() => true, () => {
            pending.total += batch.total;
            for (const [day, n] of batch.views) pending.views.set(day, (pending.views.get(day) || 0) + n);
            for (const [day, ids] of batch.ids) {
                if (!pending.ids.has(day)) pending.ids.set(day, new Set());
                for (const id of ids) pending.ids.get(day).add(id);
            }
            return false;
        }).finally(() => { flushing = null; });
        return flushing;
    }

    async function close() {
        if (timer) { clearInterval(timer); timer = null; }
        if (flushing) await flushing;
        return flush();
    }

    return {
        attach, flush, close,
        hit(ip, userAgent, time = Date.now()) {
            const entry = bucket(time);
            const id = crypto.createHmac("sha256", entry.salt).update(String(ip) + "|" + String(userAgent || "").slice(0, 200)).digest("hex").slice(0, 16);
            entry.views += 1;
            totalViews += 1;
            const day = dayKey(time);
            pending.total += 1;
            pending.views.set(day, (pending.views.get(day) || 0) + 1);
            if (entry.ids.size < MAX_IDS_PER_DAY) {
                if (!entry.ids.has(id)) {
                    if (!pending.ids.has(day)) pending.ids.set(day, new Set());
                    pending.ids.get(day).add(id);
                }
                entry.ids.add(id);
            }
            if (recent.size < MAX_IDS_PER_DAY) recent.set(id, time);
            else if (recent.has(id)) recent.set(id, time);
        },
        snapshot(time = Date.now()) {
            for (const [id, seen] of recent) if (time - seen > ACTIVE_WINDOW_MS) recent.delete(id);
            const today = days.get(dayKey(time));
            const series = [];
            for (let i = 6; i >= 0; i--) {
                const key = dayKey(time - i * 86_400_000);
                const entry = days.get(key);
                series.push({ day: key, unique: entry ? entry.ids.size : 0, views: entry ? entry.views : 0 });
            }
            return {
                uniqueToday: today ? today.ids.size : 0,
                viewsToday: today ? today.views : 0,
                activeNow: recent.size,
                totalViews,
                series
            };
        }
    };
}

module.exports = { createVisitorCounter };
