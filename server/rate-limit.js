"use strict";

/* محددات الطلبات. كلها في الذاكرة، وتُنظَّف تلقائياً حتى لا تكبر الذاكرة بلا حد. */

// حد طلبات لكل مفتاح (عنوان الزائر) + سقف عام لكل الزوار معاً.
function createRateLimiter({ windowMs, max, globalMax = Infinity, maxKeys = 10_000 }) {
    const hits = new Map();
    const globalWindow = { start: 0, count: 0 };

    const timer = setInterval(() => {
        const now = Date.now();
        for (const [key, entry] of hits) if (now - entry.start > windowMs) hits.delete(key);
    }, windowMs);
    timer.unref();

    function take(key, now = Date.now()) {
        if (now - globalWindow.start > windowMs) {
            globalWindow.start = now;
            globalWindow.count = 0;
        }
        if (globalWindow.count >= globalMax) return false;

        const entry = hits.get(key);
        if (!entry || now - entry.start > windowMs) {
            if (hits.size >= maxKeys) hits.delete(hits.keys().next().value);   // نحذف أقدم مفتاح
            hits.set(key, { start: now, count: 1 });
            globalWindow.count += 1;
            return true;
        }
        if (entry.count >= max) return false;
        entry.count += 1;
        globalWindow.count += 1;
        return true;
    }

    return { take, size: () => hits.size };
}

// يحسب المحاولات الفاشلة فقط (لتسجيل الدخول). بعد عدد معين من الفشل يُحظر المفتاح لحين انتهاء النافذة.
function createFailureLimiter({ windowMs, max, maxKeys = 10_000 }) {
    const failures = new Map();

    const timer = setInterval(() => {
        const now = Date.now();
        for (const [key, entry] of failures) if (now - entry.start > windowMs) failures.delete(key);
    }, Math.min(windowMs, 60_000));
    timer.unref();

    function current(key, now) {
        const entry = failures.get(key);
        return entry && now - entry.start <= windowMs ? entry : null;
    }

    return {
        isBlocked(key, now = Date.now()) {
            const entry = current(key, now);
            return Boolean(entry && entry.count >= max);
        },
        retryAfterSeconds(key, now = Date.now()) {
            const entry = current(key, now);
            return entry ? Math.max(1, Math.ceil((entry.start + windowMs - now) / 1000)) : 0;
        },
        fail(key, now = Date.now()) {
            const entry = current(key, now);
            if (entry) {
                entry.count += 1;
                return;
            }
            if (failures.size >= maxKeys) failures.delete(failures.keys().next().value);
            failures.set(key, { start: now, count: 1 });
        },
        clear(key) {
            failures.delete(key);
        }
    };
}

module.exports = { createRateLimiter, createFailureLimiter };
