"use strict";

/*
  الكشف البصري عن صفحات التصيد (جهة الموقع الرئيسي).

  كثير من صفحات التصيد دومينها عشوائي (x7k2.top) وما بيه أي اسم علامة، فمحرك الروابط ما يلكاها، بس شكلها نسخة
  طبق الأصل من صفحة دخول فيسبوك أو مصرف. هنا:
    1) خدمة الكشف البصري (visual-worker) تفتح الصفحة بمتصفح مخفي وترجع لقطة + بصمات بصرية (pHash/dHash) للصفحة والأيقونة.
    2) نقارن البصمات بمكتبة «صفحات الدخول الحقيقية» (يديرها الأدمن، ونخزن البصمات فقط مو الصور).
    3) إذا الصفحة تشبه صفحة دخول علامة بنسبة عالية والموقع مو من نطاقات العلامة الرسمية = تصيد شبه مؤكد.

  الفحص البصري ياخذ ثواني، فيشتغل بالخلفية: الفحص العادي يرجع فوراً ومعه رقم مهمة، والواجهة تسأل عنها
  وتحدّث النتيجة لما تخلص.

  الإعداد (متغيرات البيئة بالموقع الرئيسي):
    VISUAL_WORKER_URL    عنوان خدمة الكشف البصري (https)
    VISUAL_WORKER_TOKEN  نفس المفتاح السري المضبوط بالخدمة (24 حرفاً أو أكثر)
*/

const crypto = require("node:crypto");
const engine = require("../public/js/detection-engine.js");

const JOB_TTL_MS = 10 * 60_000;
const SHOT_TTL_MS = 15 * 60_000;
const MAX_SHOTS = 60;
const MAX_SHOT_BYTES = 20 * 1024 * 1024;
const CACHE_TTL_MS = 30 * 60_000;
const CALL_TIMEOUT_MS = 70_000;     // يشمل وقت «صحوة» الخدمة إذا كانت نايمة بخطة مجانية
const MAX_REFS = 60;

// عتبات التطابق (المسافة من 64 بت). مجرّبة: نسخة الصفحة = 0-6، صفحة مختلفة = 20+
const PAGE_PHASH_MAX = 8;
const PAGE_DHASH_MAX = 12;
const ICON_PHASH_MAX = 6;

// مراجع أولية: صفحات دخول رسمية معروفة. الأدمن يضيف المصارف والمحافظ العراقية من لوحة الإدارة
const DEFAULT_REFS = [
    { brand: "فيسبوك", key: "facebook", url: "https://www.facebook.com/login/" },
    { brand: "إنستغرام", key: "instagram", url: "https://www.instagram.com/accounts/login/" },
    { brand: "جوجل", key: "google", url: "https://accounts.google.com/" },
    { brand: "مايكروسوفت", key: "microsoft", url: "https://login.microsoftonline.com/" },
    { brand: "باي بال", key: "paypal", url: "https://www.paypal.com/signin" },
    { brand: "نتفليكس", key: "netflix", url: "https://www.netflix.com/login" },
    { brand: "لينكدإن", key: "linkedin", url: "https://www.linkedin.com/login" }
];

class VisualError extends Error {
    constructor(message, status = 400) {
        super(message);
        this.status = status;
    }
}

function hamming(a, b) {
    if (typeof a !== "string" || typeof b !== "string" || a.length !== 16 || b.length !== 16) return 64;
    let d = 0;
    for (let i = 0; i < 16; i++) {
        let x = parseInt(a[i], 16) ^ parseInt(b[i], 16);
        while (x) { d += x & 1; x >>= 1; }
    }
    return d;
}

const validHash = h => Boolean(h) && /^[0-9a-f]{16}$/.test(h.phash) && /^[0-9a-f]{16}$/.test(h.dhash);
const similarity = dist => Math.round((1 - dist / 64) * 100);

function domainsForKey(key) {
    const brand = (engine.BRANDS || []).find(b => b.keys.includes(key));
    return brand ? brand.domains.slice() : [];
}

function normalizeDomains(list) {
    return [...new Set((Array.isArray(list) ? list : String(list || "").split(/[\s,،]+/))
        .map(d => String(d).trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/?#]/)[0].replace(/^www\./, ""))
        .filter(d => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d) && d.length <= 100))].slice(0, 20);
}

// يقارن لقطة بالمراجع. يرجع أفضل تطابق أو null
function compare(capture, refs) {
    if (!capture || !validHash(capture.page)) return null;
    let best = null;
    for (const ref of refs) {
        if (!ref.hashes || !validHash(ref.hashes.page)) continue;
        const p = hamming(capture.page.phash, ref.hashes.page.phash);
        const d = hamming(capture.page.dhash, ref.hashes.page.dhash);
        const i = capture.favicon && ref.hashes.favicon && validHash(capture.favicon) && validHash(ref.hashes.favicon)
            ? hamming(capture.favicon.phash, ref.hashes.favicon.phash) : 64;
        let kind = "";
        if (p <= PAGE_PHASH_MAX && d <= PAGE_DHASH_MAX) kind = "page";
        else if (i <= ICON_PHASH_MAX && capture.hasPassword) kind = "favicon";
        if (!kind) continue;
        const score = kind === "page" ? similarity(p) : similarity(i);
        if (!best || score > best.similarity) best = { ref, kind, similarity: score, pageSimilarity: similarity(p), iconSimilarity: i < 64 ? similarity(i) : null };
    }
    return best;
}

function hostOf(url) {
    try { return new URL(url).hostname.toLowerCase(); } catch { return ""; }
}

function onDomains(host, domains) {
    return domains.some(d => host === d || host.endsWith("." + d));
}

function createVisual({ db, config, settings, fetchImpl = fetch, now = () => Date.now(), log = () => {} }) {
    const conf = (config && config.visual) || {};
    const configured = Boolean(conf.url && conf.token);
    const feature = () => !settings || settings.get().features.visual !== false;
    const enabled = () => configured && feature();
    const k = (...p) => db.key(...p);
    let refs = null;
    const jobs = new Map();
    const shots = new Map();
    let shotBytes = 0;
    const cache = new Map();   // finalUrl -> { at, capture }
    const stats = { jobs: 0, matches: 0, failures: 0, lastError: "", lastOkAt: 0 };

    async function loadRefs() {
        if (refs) return refs;
        let stored = null;
        try { stored = JSON.parse(await db.cmd(["GET", k("visualrefs")]) || "null"); } catch { stored = null; }
        refs = Array.isArray(stored) ? stored : DEFAULT_REFS.map(r => ({
            id: crypto.randomBytes(6).toString("hex"), brand: r.brand, url: r.url, domains: domainsForKey(r.key), hashes: null, updatedAt: 0, error: ""
        }));
        return refs;
    }
    const saveRefs = () => db.cmd(["SET", k("visualrefs"), JSON.stringify(refs)]);

    async function callWorker(url, kind) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), CALL_TIMEOUT_MS);
        try {
            const res = await fetchImpl(conf.url.replace(/\/+$/, "") + "/capture", {
                method: "POST", signal: controller.signal,
                headers: { "Content-Type": "application/json", Authorization: "Bearer " + conf.token },
                body: JSON.stringify({ url, kind })
            });
            const text = await res.text();
            if (text.length > 6 * 1024 * 1024) throw new Error("response too large");
            const body = JSON.parse(text);
            if (!res.ok && !(body && body.error)) throw new Error("HTTP " + res.status);
            return body;
        } finally {
            clearTimeout(timer);
        }
    }

    function storeShot(base64, uid) {
        if (typeof base64 !== "string" || !base64) return "";
        const buf = Buffer.from(base64, "base64");
        if (buf.length < 100 || buf.length > 3 * 1024 * 1024 || buf[0] !== 0xff || buf[1] !== 0xd8) return "";   // JPEG فقط
        const t = now();
        const drop = key => { shotBytes -= shots.get(key).buf.length; shots.delete(key); };
        for (const [id, s] of shots) if (t - s.at > SHOT_TTL_MS) drop(id);
        while (shots.size && (shots.size >= MAX_SHOTS || shotBytes + buf.length > MAX_SHOT_BYTES)) drop(shots.keys().next().value);
        const id = crypto.randomBytes(18).toString("base64url");
        shots.set(id, { buf, at: t, uid });
        shotBytes += buf.length;
        return id;
    }

    // اللقطة وأي مهمة تخص المستخدم اللي سوى الفحص فقط
    function getShot(id, uid) {
        if (typeof id !== "string" || !/^[A-Za-z0-9_-]{24}$/.test(id)) return null;
        const s = shots.get(id);
        if (!s || s.uid !== uid || now() - s.at > SHOT_TTL_MS) return null;
        return s.buf;
    }

    // يحوّل نتيجة اللقطة لإشارات تنضاف لحكم الفحص
    function signalsFor(capture, match, finalUrl) {
        if (!capture || !capture.ok) return [];
        if (!match) return [{ weight: 0, type: "info", text: "الفحص البصري: الصفحة ما تشبه أي صفحة دخول بمكتبة الصفحات الرسمية عندنا." }];
        const host = hostOf(finalUrl || capture.finalUrl);
        if (onDomains(host, match.ref.domains)) return [{ weight: 0, type: "safe", text: `الفحص البصري: الصفحة هي صفحة ${match.ref.brand} الرسمية فعلاً (${host}).` }];
        if (match.kind === "page") {
            return [{ weight: 0.9, type: "danger", text: `الفحص البصري: الصفحة نسخة من صفحة دخول ${match.ref.brand} (تشابه ${match.similarity}%) بس الموقع (${host}) مو تابع لها. هذا تصيد شبه مؤكد.` }];
        }
        return [{ weight: 0.6, type: "danger", text: `الفحص البصري: أيقونة الموقع نفس أيقونة ${match.ref.brand} (تشابه ${match.similarity}%) والصفحة تطلب كلمة سر، بس الموقع (${host}) مو تابع لها.` }];
    }

    // يبدأ مهمة بالخلفية. finish(capture, signals) يرجع النتيجة المحدّثة للفحص
    function start(url, finish, uid) {
        if (!enabled()) return null;
        const t = now();
        for (const [id, j] of jobs) if (t - j.at > JOB_TTL_MS) jobs.delete(id);
        if (jobs.size > 200) return null;
        const id = crypto.randomBytes(18).toString("base64url");
        const job = { at: t, status: "pending", out: null, uid };
        jobs.set(id, job);
        stats.jobs++;
        (async () => {
            try {
                const hit = cache.get(url);
                let capture = hit && t - hit.at < CACHE_TTL_MS ? hit.capture : null;
                if (!capture) {
                    capture = await callWorker(url, "scan");
                    if (capture && capture.ok) {
                        if (cache.size > 300) cache.delete(cache.keys().next().value);
                        cache.set(url, { at: now(), capture });
                        stats.lastOkAt = now();
                    }
                }
                if (!capture || !capture.ok) {
                    stats.failures++;
                    job.out = { status: capture && capture.error === "blocked" ? "blocked" : capture && capture.error === "busy" ? "busy" : "failed" };
                    job.status = "done";
                    return;
                }
                const match = compare(capture, await loadRefs());
                const signals = signalsFor(capture, match, capture.finalUrl);
                if (match && signals[0] && signals[0].weight > 0) stats.matches++;
                const shotId = storeShot(capture.screenshot, uid);
                job.out = {
                    status: "ok", shotId, title: String(capture.title || "").slice(0, 200), finalUrl: String(capture.finalUrl || "").slice(0, 500),
                    hasPassword: Boolean(capture.hasPassword),
                    match: match ? { brand: match.ref.brand, kind: match.kind, similarity: match.similarity, official: onDomains(hostOf(capture.finalUrl), match.ref.domains) } : null,
                    result: finish ? finish(signals) : null
                };
                job.status = "done";
            } catch (error) {
                stats.failures++;
                stats.lastError = String(error && error.name === "AbortError" ? "timeout" : error && error.message).slice(0, 100);
                log("visual: " + stats.lastError);
                job.out = { status: "failed" };
                job.status = "done";
            }
        })();
        return id;
    }

    function poll(id, uid) {
        if (typeof id !== "string" || !/^[A-Za-z0-9_-]{24}$/.test(id)) return null;
        const job = jobs.get(id);
        if (!job || job.uid !== uid) return null;
        return job.status === "done" ? { status: "done", ...job.out } : { status: "pending" };
    }

    // ---------------------------------------------------------------- إدارة المكتبة (للأدمن)
    async function listRefs() {
        return (await loadRefs()).map(r => ({
            id: r.id, brand: r.brand, url: r.url, domains: r.domains, ready: validHash(r.hashes && r.hashes.page),
            hasIcon: validHash(r.hashes && r.hashes.favicon), updatedAt: r.updatedAt, error: r.error
        }));
    }

    async function addRef({ brand, url, domains }) {
        const name = String(brand || "").trim().slice(0, 60);
        let u;
        try { u = new URL(String(url || "").trim()); } catch { throw new VisualError("اكتب رابط صفحة الدخول الرسمية كاملاً (https://...)."); }
        if (u.protocol !== "https:" || u.username || u.password) throw new VisualError("الرابط لازم يبدي بـ https://");
        if (!name) throw new VisualError("اكتب اسم الجهة.");
        const list = normalizeDomains(domains);
        const host = u.hostname.toLowerCase().replace(/^www\./, "");
        if (!list.length) list.push(engine.splitDomain(host).registrable || host);
        if (!onDomains(u.hostname.toLowerCase(), list)) throw new VisualError("نطاق الرابط لازم يكون من ضمن النطاقات الرسمية اللي كتبتها.");
        const all = await loadRefs();
        if (all.length >= MAX_REFS) throw new VisualError(`الحد ${MAX_REFS} صفحة بالمكتبة.`);
        const ref = { id: crypto.randomBytes(6).toString("hex"), brand: name, url: u.href, domains: list, hashes: null, updatedAt: 0, error: "" };
        all.push(ref);
        await saveRefs();
        return ref;
    }

    async function removeRef(id) {
        const all = await loadRefs();
        refs = all.filter(r => r.id !== id);
        await saveRefs();
    }

    // يلتقط بصمات صفحة مرجعية (أو كل الصفحات) من الخدمة
    async function refreshRef(id) {
        if (!configured) throw new VisualError("خدمة الكشف البصري غير مضبوطة (VISUAL_WORKER_URL و VISUAL_WORKER_TOKEN).", 503);
        const all = await loadRefs();
        const targets = id ? all.filter(r => r.id === id) : all;
        if (!targets.length) throw new VisualError("الصفحة غير موجودة.", 404);
        for (const ref of targets) {
            try {
                const c = await callWorker(ref.url, "reference");
                if (c && c.ok && validHash(c.page)) {
                    ref.hashes = { page: { phash: c.page.phash, dhash: c.page.dhash }, favicon: validHash(c.favicon) ? { phash: c.favicon.phash, dhash: c.favicon.dhash } : null };
                    ref.updatedAt = now();
                    ref.error = onDomains(hostOf(c.finalUrl), ref.domains) ? "" : "الصفحة حولتنا لنطاق خارج النطاقات الرسمية: " + hostOf(c.finalUrl);
                } else {
                    ref.error = "تعذر التقاط الصفحة (" + String((c && c.error) || "خطأ") + ")";
                }
            } catch (error) {
                ref.error = "تعذر الاتصال بخدمة الكشف البصري";
                stats.lastError = String(error && error.message).slice(0, 100);
            }
        }
        await saveRefs();
        return listRefs();
    }

    async function health() {
        if (!configured) return { configured: false };
        try {
            const controller = new AbortController();
            const timer = setTimeout(() => controller.abort(), 15_000);
            const res = await fetchImpl(conf.url.replace(/\/+$/, "") + "/health", { signal: controller.signal });
            clearTimeout(timer);
            const body = await res.json();
            return { configured: true, reachable: res.ok, queue: body.queue, captured: body.captured, failed: body.failed };
        } catch {
            return { configured: true, reachable: false };
        }
    }

    const status = () => ({ configured, enabled: enabled(), ...stats, shots: shots.size });

    return { enabled, start, poll, getShot, compare: c => loadRefs().then(r => compare(c, r)), listRefs, addRef, removeRef, refreshRef, health, status, signalsFor };
}

module.exports = { createVisual, compare, hamming, VisualError, DEFAULT_REFS, PAGE_PHASH_MAX, ICON_PHASH_MAX };
