"use strict";

/*
  واجهات الفحص على الخادم (تتطلب حساباً، وتُحسب من حصة اليوم حسب الخطة):
    POST /api/scan/url     { url, strict }      رابط: المحرك + قوائم التهديدات + عمر النطاق (Pro)
    POST /api/scan/text    { text }             رسالة: المحرك + فحص روابطها بقوائم التهديدات
    POST /api/scan/file    { name, size }       يحجز فحص ملف (الملف نفسه يُحلَّل داخل المتصفح ولا يُرفع)
    POST /api/scan/record  { kind, label, score, level }   يحفظ نتيجة فحص الملف بالسجل (Pro)
    POST /api/scan/bulk    { urls: [...] }      فحص جماعي (Pro)
  واجهة API لمشتركي Pro (بمفتاح API بدل الكوكي، من أي برنامج):
    POST /api/v1/scan-url  Authorization: Bearer pd_...   { url }  أو  { urls: [...] }
    POST /api/v1/scan-text Authorization: Bearer pd_...   { text }

  لا نحفظ الروابط أو النصوص إلا بسجل مشتركي Pro (ويمكنهم إيقافه أو مسحه من حسابهم).
*/

const h = require("./http");
const engine = require("../public/js/detection-engine.js");
const { createRateLimiter, createFailureLimiter } = require("./rate-limit");
const { limitsFor } = require("./plans");

const MAX_URL = 2048;
const MAX_TEXT = 10_000;
const LEVELS = new Set(["safe", "warning", "danger"]);

// يدمج إشارات إضافية مع نتيجة المحرك بنفس طريقة noisy-OR التي يستخدمها المحرك
function merge(result, extra, thresholds) {
    if (!extra.length) return result;
    let keep = 1 - result.score / 100;
    for (const s of extra) if (s.weight > 0) keep *= 1 - Math.min(s.weight, 0.99);
    const score = Math.round((1 - keep) * 100);
    const level = score >= thresholds.danger ? "danger" : score >= thresholds.warning ? "warning" : "safe";
    const order = { danger: 0, warning: 1, info: 2, safe: 3 };
    const reasons = [...extra.map(s => ({ type: s.type, text: s.text, w: s.weight })), ...result.reasons.map(r => ({ ...r, w: 0.5 }))]
        // إذا صار الحكم خطراً أو تنبيهاً، تسقط عبارة "لم تُرصد مؤشرات"
        .filter(r => !(level !== "safe" && r.type === "safe"))
        .sort((a, b) => (order[a.type] - order[b.type]) || (b.w - a.w))
        .map(({ w, ...r }) => r);
    // المؤشرات القابلة للقراءة آلياً: نضيف إشارات المصادر الخارجية ونعيد حساب مساهمة كل مؤشر بالدرجة
    const all = [
        ...extra.filter(s => s.weight > 0).map(s => ({ type: s.type, weight: s.weight, text: s.text })),
        ...(result.indicators || []).map(i => ({ type: i.type, weight: i.weight / 100, text: i.text }))
    ];
    const impact = engine.contributions(all);
    const indicators = all
        .map((s, i) => ({ type: s.type, weight: Math.round(s.weight * 100), impact: impact[i], text: s.text }))
        .sort((a, b) => (order[a.type] - order[b.type]) || (b.weight - a.weight));
    const confidence = engine.confidenceFor(score, thresholds, indicators.length);
    return { ...result, score, level, confidence, reasons, indicators };
}

function createScan({ config, users, auth, intel, stats, inspector = null, settings = null }) {
    const liveOn = () => Boolean(inspector) && (!settings || settings.get().features.liveInspect !== false);
    const perMinute = createRateLimiter({ windowMs: 60_000, max: config.limits.scanPerMinute });
    const badKeys = createFailureLimiter({ windowMs: config.limits.loginWindowMs, max: config.limits.badApiKeysPerWindow });

    async function scanUrl(rawUrl, { strict = false, deep = false, inspect = false } = {}) {
        const url = String(rawUrl || "").trim().slice(0, MAX_URL);
        const result = engine.analyzeUrl(url, { strict });
        if (result.error) return result;
        const thresholds = strict ? engine.STRICT_THRESHOLDS : engine.THRESHOLDS;
        const extra = [];
        const feedHits = result.host ? intel.lookup(result.input, result.host) : [];
        // النطاقات الرسمية المعروفة لا نحكم عليها من قوائم التهديدات إلا بتطابق الرابط كاملاً
        extra.push(...(result.official ? feedHits.filter(s => s.weight >= 0.9) : feedHits));
        // عمر النطاق (Pro) والزيارة الآمنة يعملان بالتوازي
        const wantsAge = deep && result.registrable && !result.official && !/^\d+\.\d+\.\d+\.\d+$/.test(result.host);
        // النطاقات الرسمية المعروفة ونطاق الموقع نفسه لا نزورها (ما نحتاج، وممكن الرابط يحمل رمزاً خاصاً بالمستخدم)
        const wantsVisit = inspect && liveOn() && !result.official && !engine.isSiteHost(result.host);
        const [age, inspection] = await Promise.all([
            wantsAge ? intel.domainAge(result.registrable) : null,
            wantsVisit ? inspector.inspect(result.input, result).catch(() => null) : null
        ]);
        extra.push(...intel.ageSignals(age));
        if (inspection) extra.push(...inspection.signals.filter(s => s.weight > 0 || s.type === "info"));
        const merged = merge(result, extra, thresholds);
        // الموقع غير موجود: ملاحظة «الاتصال مشفر» لا معنى لها
        // الموقع غير موجود أو شهادته غير صالحة: ملاحظة «الاتصال مشفر» تناقض الواقع
        if (inspection && (inspection.exists === false || (inspection.tls && inspection.tls.valid === false))) merged.reasons = merged.reasons.filter(r => !(r.type === "info" && /HTTPS/.test(r.text)));
        merged.checks = { feeds: intel.status().enabled, deep, domainAge: age, live: Boolean(inspection), liveSkipped: inspect && !wantsVisit ? (result.official ? "official" : liveOn() ? "site" : "disabled") : "" };
        if (inspection) {
            const { signals, ...visible } = inspection;
            merged.inspection = visible;
        }
        return merged;
    }

    function scanText(rawText) {
        const text = String(rawText || "").trim().slice(0, MAX_TEXT);
        const result = engine.analyzeText(text);
        if (result.error) return result;
        const extra = [];
        for (const u of result.urls || []) {
            const analysis = engine.analyzeUrl(u.url);
            if (analysis.error) continue;
            const hits = intel.lookup(analysis.input, analysis.host).filter(s => !analysis.official || s.weight >= 0.9);
            if (hits.length) extra.push({ weight: 0.9, type: "danger", text: `الرابط ${u.url} داخل الرسالة: ${hits[0].text}` });
        }
        return merge(result, extra, engine.THRESHOLDS);
    }

    // يرجع المستخدم من الكوكي، أو من مفتاح API (لمسارات /api/v1)
    async function who(req, res, viaApi) {
        if (!viaApi) return auth.requireUser(req, res);
        const ip = h.getClientIp(req, config);
        if (badKeys.isBlocked(ip)) {
            h.sendJson(res, 429, { error: "Too many invalid API keys" }, { "Retry-After": String(badKeys.retryAfterSeconds(ip)) });
            return null;
        }
        const bearer = /^Bearer\s+(\S+)$/i.exec(String(req.headers.authorization || ""));
        const user = bearer ? await users.userFromApiKey(bearer[1]).catch(() => null) : null;
        if (!user || !limitsFor(user).api) {
            badKeys.fail(ip);
            h.sendJson(res, 401, { error: "Invalid API key or plan does not include API access" });
            return null;
        }
        return user;
    }

    async function body(req, res, viaApi, maxBytes) {
        if (req.method !== "POST") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "POST" }), undefined;
        if (!viaApi) return auth.jsonBody(req, res, maxBytes);
        if (!h.isJsonRequest(req)) return h.sendJson(res, 415, { error: "Content-Type must be application/json" }), undefined;
        try {
            const parsed = await h.readJsonBody(req, maxBytes);
            if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("bad");
            return parsed;
        } catch {
            return h.sendJson(res, 400, { error: "Bad request" }), undefined;
        }
    }

    async function quota(res, user, kind, amount = 1) {
        const q = await users.consume(user, kind, amount);
        if (!q.ok) {
            stats.count("quotaExceeded");
            const pro = limitsFor(user).api;
            h.sendJson(res, 429, {
                error: pro ? `وصلت للحد اليومي (${q.limit}). يتجدد غداً.` : `وصلت لحد الخطة المجانية اليوم (${q.limit} فحصاً). اشترك بـ Pro بـ ${config.plans.priceUsd}$ شهرياً للفحص بلا حدود.`,
                code: "quota", used: q.used, limit: q.limit
            });
            return null;
        }
        return q;
    }

    const publicResult = r => ({
        score: r.score, level: r.level, confidence: r.confidence, reasons: r.reasons, indicators: r.indicators,
        engineVersion: r.engineVersion, input: r.input, host: r.host, unicodeHost: r.unicodeHost,
        registrable: r.registrable, official: r.official, brand: r.brand, checks: r.checks,
        categories: r.categories, urls: r.urls, advice: r.advice, inspection: r.inspection
    });

    // معاينة الصفحة المعقّمة: تُعرض داخل إطار معزول (sandbox) بصفحة الفحص فقط
    const SNAPSHOT_CSP = "sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'; frame-ancestors 'self'; base-uri 'none'; form-action 'none'";
    async function snapshot(req, res, id) {
        if (req.method !== "GET") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET" });
        const user = await auth.requireUser(req, res);
        if (!user) return;
        const doc = inspector && inspector.getSnapshot ? inspector.getSnapshot(id) : null;
        if (!doc) return h.sendJson(res, 404, { error: "انتهت صلاحية المعاينة. أعد فحص الرابط." });
        const body = Buffer.from(doc);
        res.setHeader("Content-Security-Policy", SNAPSHOT_CSP);
        res.setHeader("X-Frame-Options", "SAMEORIGIN");
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Length": body.length, "Cache-Control": "private, no-store", "X-Robots-Tag": "noindex" });
        res.end(body);
    }

    async function handle(req, res, url) {
        const p = url.pathname;
        const snap = /^\/api\/scan\/snapshot\/([A-Za-z0-9_-]{1,64})$/.exec(p);
        if (snap) return await snapshot(req, res, snap[1]), true;
        const viaApi = p.startsWith("/api/v1/");
        const routes = ["/api/scan/url", "/api/scan/text", "/api/scan/file", "/api/scan/record", "/api/scan/bulk", "/api/scan/clean", "/api/v1/scan-url", "/api/v1/scan-text"];
        if (!routes.includes(p)) return false;
        if (viaApi && req.method === "OPTIONS") {
            res.writeHead(204, { Allow: "POST" });
            res.end();
            return true;
        }

        const user = await who(req, res, viaApi);
        if (!user) return true;
        if (!perMinute.take(user.id)) {
            h.sendJson(res, 429, { error: "طلبات كثيرة بالدقيقة. تمهّل قليلاً." }, { "Retry-After": "60" });
            return true;
        }
        const limits = limitsFor(user);
        const input = await body(req, res, viaApi, (p.endsWith("bulk") || p === "/api/v1/scan-url") ? 256 * 1024 : 32 * 1024);
        if (input === undefined) return true;

        try {
            if (p === "/api/scan/url" || (p === "/api/v1/scan-url" && !Array.isArray(input.urls))) {
                if (typeof input.url !== "string" || !input.url.trim()) return h.sendJson(res, 400, { error: "أرسل الرابط بالحقل url." }), true;
                if (!(await quota(res, user, "scan"))) return true;
                const result = await scanUrl(input.url, { strict: Boolean(input.strict), deep: limits.deepChecks, inspect: input.inspect !== false });
                if (result.error) return h.sendJson(res, 400, { error: "الرابط غير صالح هيكلياً.", code: result.error }), true;
                stats.scan("url", result.level);
                await users.addHistory(user, { kind: "url", label: result.input.slice(0, 200), score: result.score, level: result.level }).catch(() => {});
                h.sendJson(res, 200, { result: publicResult(result) });
                return true;
            }
            if (p === "/api/scan/text" || p === "/api/v1/scan-text") {
                if (typeof input.text !== "string" || !input.text.trim()) return h.sendJson(res, 400, { error: "أرسل النص بالحقل text." }), true;
                if (!(await quota(res, user, "scan"))) return true;
                const result = scanText(input.text);
                stats.scan("text", result.level);
                const preview = input.text.trim().slice(0, 60) + (input.text.trim().length > 60 ? "…" : "");
                await users.addHistory(user, { kind: "text", label: preview, score: result.score, level: result.level }).catch(() => {});
                h.sendJson(res, 200, { result: publicResult(result) });
                return true;
            }
            if (p === "/api/scan/file") {
                const q = await quota(res, user, "scan");
                if (!q) return true;
                h.sendJson(res, 200, { ok: true, used: q.used, limit: q.limit });
                return true;
            }
            // تنظيف الملفات (Pro): المعالجة نفسها داخل المتصفح، والخادم يتحقق من الخطة ويسجّل العملية
            if (p === "/api/scan/clean") {
                if (!limits.clean) return h.sendJson(res, 403, { error: "تنظيف الملفات متاح لمشتركي Pro.", code: "pro_only" }), true;
                if (input.kind !== "image") return h.sendJson(res, 400, { error: "تنظيف هذا النوع من الملفات غير مدعوم.", code: "unsupported" }), true;
                const size = Number(input.size);
                if (!Number.isFinite(size) || size <= 0 || size > 25 * 1024 * 1024) return h.sendJson(res, 413, { error: "الحد الأقصى لحجم الصورة 25MB." }), true;
                stats.count("filesCleaned");
                h.sendJson(res, 200, { ok: true });
                return true;
            }
            if (p === "/api/scan/record") {
                const kind = ["file", "media"].includes(input.kind) ? input.kind : "";
                const score = Number(input.score);
                if (!kind || !LEVELS.has(input.level) || !Number.isFinite(score) || score < 0 || score > 100) return h.sendJson(res, 400, { error: "Bad request" }), true;
                stats.scan(kind === "file" ? "file" : "media", input.level);
                await users.addHistory(user, { kind, label: String(input.label || "").replace(/[\u0000-\u001f<>]/g, "").slice(0, 120), score: Math.round(score), level: input.level }).catch(() => {});
                res.writeHead(204, { "Cache-Control": "no-store" });
                res.end();
                return true;
            }
            // الفحص الجماعي: من الصفحة (/api/scan/bulk) أو API بقائمة urls
            if (p === "/api/scan/bulk" || p === "/api/v1/scan-url") {
                if (!limits.bulkMaxUrls) return h.sendJson(res, 403, { error: "الفحص الجماعي متاح لمشتركي Pro.", code: "pro_only" }), true;
                if (!Array.isArray(input.urls)) return h.sendJson(res, 400, { error: "أرسل قائمة روابط بالحقل urls." }), true;
                const unique = [...new Set(input.urls.filter(u => typeof u === "string").map(u => u.trim().slice(0, MAX_URL)).filter(Boolean))];
                if (!unique.length) return h.sendJson(res, 400, { error: "لا توجد روابط صالحة بالقائمة." }), true;
                if (unique.length > limits.bulkMaxUrls) return h.sendJson(res, 413, { error: `الحد الأقصى ${limits.bulkMaxUrls} رابطاً بالطلب الواحد.`, limit: limits.bulkMaxUrls }), true;
                if (!(await quota(res, user, "scan", unique.length))) return true;
                const results = [];
                // عمر النطاق نطلبه مرة لكل نطاق (المحرك يخزّنه مؤقتاً)، وبحد 6 طلبات متوازية
                const queue = unique.map((u, i) => ({ u, i }));
                const workers = Array.from({ length: 6 }, async () => {
                    while (queue.length) {
                        const { u, i } = queue.shift();
                        try {
                            const r = await scanUrl(u, { deep: limits.deepChecks });
                            results[i] = r.error ? { url: u.slice(0, 200), error: r.error }
                                : { url: u.slice(0, 200), level: r.level, score: r.score, confidence: r.confidence, host: r.host, registrable: r.registrable || "", brand: r.brand || r.official || "", reasons: r.reasons.filter(x => x.type !== "info").slice(0, 4) };
                        } catch {
                            results[i] = { url: u.slice(0, 200), error: "analysis_failed" };
                        }
                    }
                });
                await Promise.all(workers);
                stats.count("bulkScans");
                h.sendJson(res, 200, { count: results.length, limit: limits.bulkMaxUrls, results });
                return true;
            }
        } catch (error) {
            auth.sendError(res, error);
            return true;
        }
        return false;
    }

    return { handle, scanUrl, scanText };
}

module.exports = { createScan, merge };
