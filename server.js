"use strict";

/*
  خادم Phishing Detector. بدون أي مكتبات خارجية (Node.js 20 أو أحدث).

  المسارات:
    /                 الموقع (ملفات مجلد public/)
    /healthz          فحص الصحة لـ Render ولأدوات المراقبة (503 إذا كان النظام بحالة حرجة)
    /api/chat         جسر CyberBot (المفتاح يبقى على الخادم)
    /api/event        إحصاءات مجهولة من الصفحة (نوع الفحص ونتيجته فقط)
    /api/client-error تقارير أخطاء متصفحات الزوار (للمراقبة فقط)
    /admin            لوحة الأدمن (مغلقة إلا إذا ضُبط ADMINS)

  الإعدادات: انظر server/config.js. الأدمن: npm run make-admin
*/

const http = require("node:http");
const { loadConfig } = require("./server/config");
const h = require("./server/http");
const { createRateLimiter } = require("./server/rate-limit");
const { createStats, cleanText } = require("./server/stats");
const { createHealthMonitor } = require("./server/health");
const { createVisitorCounter } = require("./server/visitors");
const { createChatHandler } = require("./server/chat");
const { createAdmin } = require("./server/admin");
const { serveStatic } = require("./server/static");

const CLIENT_ERROR_KINDS = new Set(["error", "promise", "action"]);

function createApp(config = loadConfig()) {
    const audit = config.auditStdout ? entry => console.log(JSON.stringify({ audit: true, ...entry })) : undefined;
    const stats = createStats({ audit });
    const visitors = createVisitorCounter();
    const health = createHealthMonitor(config.health);
    const chatLimiter = createRateLimiter({ windowMs: 60_000, max: config.limits.chatPerMinute, globalMax: config.limits.globalChatPerMinute });
    const eventLimiter = createRateLimiter({ windowMs: 60_000, max: config.limits.eventPerMinute });
    const errorLimiter = createRateLimiter({ windowMs: 60_000, max: config.limits.clientErrorPerMinute, globalMax: config.limits.globalClientErrorPerMinute });
    const currentHealth = () => health.evaluate(stats.recent("client_error", 5 * 60_000));
    const admin = createAdmin(config, stats, { visitors, health: currentHealth });
    const chat = createChatHandler(config, chatLimiter, stats);

    // نقاط الاستقبال الصغيرة (POST/JSON من صفحاتنا فقط). كل واحدة تقبل بيانات محددة وتتجاهل أي شيء آخر.
    // يرجع كائن JSON صالحاً، أو undefined بعد أن يكون ردّ بالخطأ المناسب (فعلى المنادي أن يتوقف)
    async function readClientJson(req, res, limiter, maxBytes) {
        const reject = (status, error, headers) => { h.sendJson(res, status, { error }, headers); return undefined; };
        if (req.method !== "POST") return reject(405, "Method not allowed", { Allow: "POST" });
        if (!h.isSameOrigin(req) || !h.isJsonRequest(req)) return reject(403, "Forbidden");
        if (!limiter.take(h.getClientIp(req, config))) return reject(429, "Too many requests");
        let body;
        try {
            body = await h.readJsonBody(req, maxBytes);
        } catch {
            return reject(400, "Bad request");
        }
        if (body === null || typeof body !== "object" || Array.isArray(body)) return reject(400, "Bad request");
        return body;
    }

    // إحصاءات الفحص المجهولة: نقبل فقط نوعاً ونتيجة من قائمة محددة، ولا نخزّن أي شيء آخر
    async function handleEvent(req, res) {
        const body = await readClientJson(req, res, eventLimiter, 512);
        if (body === undefined) return;
        if (!stats.scan(body.kind, body.level)) return h.sendJson(res, 400, { error: "Bad request" });
        res.writeHead(204, { "Cache-Control": "no-store" });
        res.end();
    }

    // تقارير أخطاء المتصفح: نص قصير منظَّف + اسم الملف فقط (بدون روابط كاملة)
    async function handleClientError(req, res) {
        const body = await readClientJson(req, res, errorLimiter, 1024);
        if (body === undefined) return;
        if (!CLIENT_ERROR_KINDS.has(body.kind)) return h.sendJson(res, 400, { error: "Bad request" });
        const source = cleanText(String(body.source || "").split("/").pop().split("?")[0], 60);
        const line = Number.isInteger(body.line) && body.line >= 0 && body.line < 1e6 ? body.line : 0;
        stats.count("clientErrors");
        stats.event("client_error", `${body.kind}: ${cleanText(body.message, 120)} @ ${source}:${line}`, h.getClientIp(req, config));
        res.writeHead(204, { "Cache-Control": "no-store" });
        res.end();
    }

    const server = http.createServer(async (req, res) => {
        stats.count("requests");
        h.applySecurityHeaders(req, res, config);
        try {
            let url;
            try {
                url = new URL(req.url, "http://localhost");
            } catch {
                return h.sendJson(res, 400, { error: "Invalid request URL" });
            }
            const pathname = url.pathname;

            if (pathname === "/healthz") {
                if (req.method !== "GET" && req.method !== "HEAD") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET, HEAD" });
                // حالة حرجة متواصلة => 503 => Render تعيد تشغيل الخدمة تلقائياً
                const critical = currentHealth().status === "critical";
                return h.sendText(res, critical ? 503 : 200, critical ? "unhealthy" : "ok");
            }
            if (pathname === "/api/chat") return await chat(req, res);
            if (pathname === "/api/event") return await handleEvent(req, res);
            if (pathname === "/api/client-error") return await handleClientError(req, res);
            if (await admin.handle(req, res, url)) return;

            if (req.method === "GET" && (pathname === "/" || pathname === "/index.html")) {
                visitors.hit(h.getClientIp(req, config), req.headers["user-agent"]);
            }
            serveStatic(req, res, pathname, config);
        } catch (error) {
            // لا نكشف تفاصيل الخطأ للزائر أبداً
            console.error("Unhandled request error:", error && error.message);
            stats.count("serverErrors");
            stats.event("server_error", error && error.message, "");
            if (!res.headersSent) h.sendJson(res, 500, { error: "Internal server error" });
            else res.destroy();
        }
    });

    // مهلات تحمي من الاتصالات البطيئة التي تستهلك موارد الخادم (Slowloris)
    server.headersTimeout = 15_000;
    server.requestTimeout = 60_000;
    server.keepAliveTimeout = 5_000;
    server.maxHeadersCount = 50;
    server.on("close", () => health.stop());

    return { server, stats, config, admin, visitors };
}

function main() {
    const { server, stats, config, admin } = createApp();

    server.listen(config.port, config.host, () => {
        console.log(`Phishing Detector listening at http://${config.host}:${config.port}`);
        if (!config.openai.apiKey || !config.openai.model) console.log("CyberBot: set OPENAI_API_KEY and OPENAI_MODEL to enable AI replies.");
        console.log(admin.enabled ? `Admin page enabled (${config.admins.size} account(s)).` : "Admin page disabled: set ADMINS (run: npm run make-admin).");
    });

    // Render يرسل SIGTERM عند كل نشر جديد: نُنهي الاتصالات الجارية بهدوء
    const shutdown = signal => {
        console.log(`${signal} received, shutting down.`);
        server.close(() => process.exit(0));
        setTimeout(() => process.exit(0), 10_000).unref();
    };
    process.on("SIGTERM", () => shutdown("SIGTERM"));
    process.on("SIGINT", () => shutdown("SIGINT"));

    // الوعد المرفوض (Promise) عادة يخص طلباً واحداً: نسجّله ونكمل.
    process.on("unhandledRejection", reason => {
        const message = reason && reason.message ? reason.message : String(reason);
        console.error("Unhandled rejection:", message);
        stats.count("serverErrors");
        stats.event("server_error", "unhandledRejection: " + message, "");
    });

    // الاستثناء غير الملتقط يعني أن حالة العملية قد تكون تالفة. الأسلم: نسجّل ونخرج، وRender تعيد التشغيل تلقائياً.
    // (إكمال العمل بعد استثناء مجهول قد يكمل بحالة فاسدة أو يسرّب بيانات بين الطلبات.)
    process.on("uncaughtException", error => {
        console.error("Fatal uncaught exception:", error && error.stack ? error.stack : error);
        stats.count("serverErrors");
        stats.event("process_crash", error && error.message, "");
        setTimeout(() => process.exit(1), 200);
    });
}

if (require.main === module) main();

module.exports = { createApp };
