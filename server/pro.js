"use strict";

/*
  الواجهات المدفوعة والعامة المتعلقة بالاشتراكات:
    GET  /api/pricing         الباقات وبيانات التواصل (عام)
    POST /api/license/check   التحقق من مفتاح ترخيص
    POST /api/pro/scan-urls   فحص جماعي للروابط (يتطلب مفتاحاً صالحاً: ترويسة X-License-Key أو Authorization: Bearer)
  الحدود تُفرض هنا على الخادم حسب الباقة، فلا يمكن تجاوزها بتعديل الصفحة.
*/

const h = require("./http");
const { createRateLimiter, createFailureLimiter } = require("./rate-limit");
const { LIMITS, publicPricing } = require("./pricing");
const engine = require("../public/js/detection-engine.js");

const MAX_URL_LENGTH = 2048;
const MAX_BODY_BYTES = 256 * 1024;
const REASON_MESSAGES = {
    format: "شكل المفتاح غير صحيح.",
    signature: "المفتاح غير صحيح.",
    expired: "انتهت صلاحية هذا المفتاح. تواصل معنا للتجديد.",
    revoked: "تم إلغاء هذا المفتاح. تواصل معنا.",
    disabled: "الاشتراكات غير مفعّلة حالياً."
};

function createPro({ config, license, store, stats }) {
    // عدد الطلبات بالدقيقة لكل ترخيص (حسب باقته)
    const perLicense = {};
    for (const tier of Object.keys(LIMITS)) {
        perLicense[tier] = createRateLimiter({ windowMs: 60_000, max: LIMITS[tier].requestsPerMinute });
    }
    // محاولات المفاتيح الخاطئة لكل عنوان: تمنع تخمين المفاتيح
    const badKeys = createFailureLimiter({ windowMs: config.limits.loginWindowMs, max: config.limits.badLicenseKeysPerWindow });

    function pricing(req, res) {
        if (req.method !== "GET") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET" });
        res.writeHead(200, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "public, max-age=60" });
        res.end(JSON.stringify(publicPricing(config, license.enabled)));
    }

    // يتحقق من المفتاح ويرجع { ok, ... } أو يرد بالخطأ ويرجع null
    function authenticate(req, res, rawKey) {
        const ip = h.getClientIp(req, config);
        if (!license.enabled) {
            h.sendJson(res, 503, { error: REASON_MESSAGES.disabled, reason: "disabled" });
            return null;
        }
        if (badKeys.isBlocked(ip)) {
            h.sendJson(res, 429, { error: "محاولات كثيرة بمفاتيح خاطئة. حاول لاحقاً." }, { "Retry-After": String(badKeys.retryAfterSeconds(ip)) });
            return null;
        }
        const result = license.verify(rawKey);
        const revoked = result.ok && store.isRevoked(result.id);
        if (!result.ok || revoked) {
            badKeys.fail(ip);
            const reason = revoked ? "revoked" : result.reason;
            h.sendJson(res, 401, { error: REASON_MESSAGES[reason] || REASON_MESSAGES.signature, reason });
            return null;
        }
        return result;
    }

    function keyFromHeaders(req) {
        const bearer = /^Bearer\s+(.+)$/i.exec(String(req.headers.authorization || ""));
        return String(req.headers["x-license-key"] || (bearer && bearer[1]) || "").slice(0, 100);
    }

    async function guardedJson(req, res) {
        if (req.method !== "POST") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "POST" }), undefined;
        if (!h.isSameOrigin(req) || !h.isJsonRequest(req)) return h.sendJson(res, 403, { error: "Forbidden" }), undefined;
        try {
            const body = await h.readJsonBody(req, MAX_BODY_BYTES);
            if (body === null || typeof body !== "object" || Array.isArray(body)) throw new Error("bad body");
            return body;
        } catch {
            return h.sendJson(res, 400, { error: "طلب غير صالح." }), undefined;
        }
    }

    async function check(req, res) {
        const body = await guardedJson(req, res);
        if (body === undefined) return;
        const result = authenticate(req, res, body.key);
        if (!result) return;
        h.sendJson(res, 200, {
            valid: true,
            tier: result.tier,
            expiresAt: new Date(result.expiresAt).toISOString(),
            limits: LIMITS[result.tier]
        });
    }

    async function scanUrls(req, res) {
        if (req.method !== "POST") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "POST" });
        const auth = authenticate(req, res, keyFromHeaders(req));
        if (!auth) return;
        const body = await guardedJson(req, res);
        if (body === undefined) return;

        if (!perLicense[auth.tier].take(auth.id)) {
            stats.count("rateLimited");
            return h.sendJson(res, 429, { error: "تجاوزت عدد الطلبات المسموح بالدقيقة لباقتك." }, { "Retry-After": "60" });
        }
        const limit = LIMITS[auth.tier].maxUrls;
        if (!Array.isArray(body.urls) || body.urls.length === 0) return h.sendJson(res, 400, { error: "أرسل قائمة روابط بالحقل urls." });
        const unique = [...new Set(body.urls.filter(u => typeof u === "string").map(u => u.trim().slice(0, MAX_URL_LENGTH)).filter(Boolean))];
        if (unique.length === 0) return h.sendJson(res, 400, { error: "لا توجد روابط صالحة بالقائمة (أرسل نصوصاً غير فارغة)." });
        if (unique.length > limit) return h.sendJson(res, 413, { error: `الحد الأقصى لباقتك ${limit} رابطاً بالطلب الواحد.`, limit });

        const results = unique.map(url => {
            let analysis;
            try {
                analysis = engine.analyzeUrl(url);
            } catch {
                return { url: url.slice(0, 200), error: "analysis_failed" };       // رابط واحد معطوب لا يوقف الباقي
            }
            if (analysis.error) return { url: url.slice(0, 200), error: analysis.error };
            return {
                url: url.slice(0, 200),
                level: analysis.level,
                score: analysis.score,
                host: analysis.host,
                registrable: analysis.registrable || "",
                brand: analysis.brand || analysis.official || "",
                reasons: analysis.reasons.filter(r => r.type !== "info").slice(0, 4)
            };
        });
        stats.count("proRequests");
        h.sendJson(res, 200, { tier: auth.tier, count: results.length, limit, results });
    }

    return { pricing, check, scanUrls };
}

module.exports = { createPro };
