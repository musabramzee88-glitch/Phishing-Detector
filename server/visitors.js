"use strict";

/*
  عدّاد زوار تقريبي يحترم الخصوصية: لا نحفظ العنوان ولا المتصفح، بل بصمة مجزّأة (HMAC) بملح يتغيّر كل يوم.
  لا يمكن ربط نفس الزائر بين يومين ولا استرجاع عنوانه. الأرقام تقريبية (تشمل الروبوتات، وتتصفّر عند إعادة التشغيل).
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

    function bucket(time) {
        const key = dayKey(time);
        let entry = days.get(key);
        if (!entry) {
            entry = { salt: crypto.randomBytes(16), ids: new Set(), views: 0 };
            days.set(key, entry);
            while (days.size > KEEP_DAYS) days.delete(days.keys().next().value);
        }
        return entry;
    }

    return {
        hit(ip, userAgent, time = Date.now()) {
            const entry = bucket(time);
            const id = crypto.createHmac("sha256", entry.salt).update(String(ip) + "|" + String(userAgent || "").slice(0, 200)).digest("hex").slice(0, 16);
            entry.views += 1;
            totalViews += 1;
            if (entry.ids.size < MAX_IDS_PER_DAY) entry.ids.add(id);
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
