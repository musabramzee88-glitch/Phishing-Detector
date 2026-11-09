"use strict";

/*
  خادم Phishing Detector. بدون أي مكتبات خارجية (Node.js 20 أو أحدث).

  المسارات:
    /                 الموقع (ملفات مجلد public/)
    /healthz          فحص الصحة لـ Render ولأدوات المراقبة
    /api/chat         جسر CyberBot (المفتاح يبقى على الخادم)
    /api/event        إحصاءات مجهولة من الصفحة (نوع الفحص ونتيجته فقط)
    /admin            لوحة الأدمن (مغلقة إلا إذا ضُبط ADMINS)

  الإعدادات: انظر server/config.js. الأدمن: npm run make-admin
*/

const http = require("node:http");
const { loadConfig } = require("./server/config");
const h = require("./server/http");
const { createRateLimiter } = require("./server/rate-limit");
const { createStats } = require("./server/stats");
const { createChatHandler } = require("./server/chat");
const { createAdmin } = require("./server/admin");
const { serveStatic } = require("./server/static");

function createApp(config = loadConfig()) {
    const stats = createStats();
    const chatLimiter = createRateLimiter({ windowMs: 60_000, max: config.limits.chatPerMinute, globalMax: config.limits.globalChatPerMinute });
    const eventLimiter = createRateLimiter({ windowMs: 60_000, max: config.limits.eventPerMinute });
    const admin = createAdmin(config, stats);
    const chat = createChatHandler(config, chatLimiter, stats);

    // إحصاءات الفحص المجهولة: نقبل فقط نوعاً ونتيجة من قائمة محددة، ولا نخزّن أي شيء آخر
    async function handleEvent(req, res) {
        if (req.method !== "POST") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "POST" });
        if (!h.isSameOrigin(req) || !h.isJsonRequest(req)) return h.sendJson(res, 403, { error: "Forbidden" });
        if (!eventLimiter.take(h.getClientIp(req, config))) return h.sendJson(res, 429, { error: "Too many requests" });
        let body;
        try {
            body = await h.readJsonBody(req, 512);
        } catch {
            return h.sendJson(res, 400, { error: "Bad request" });
        }
        if (!body || !stats.scan(body.kind, body.level)) return h.sendJson(res, 400, { error: "Bad request" });
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
                return h.sendText(res, 200, "ok");
            }
            if (pathname === "/api/chat") return await chat(req, res);
            if (pathname === "/api/event") return await handleEvent(req, res);
            if (await admin.handle(req, res, url)) return;
            serveStatic(req, res, pathname, config);
        } catch (error) {
            // لا نكشف تفاصيل الخطأ للزائر أبداً
            console.error("Unhandled request error:", error && error.message);
            if (!res.headersSent) h.sendJson(res, 500, { error: "Internal server error" });
            else res.destroy();
        }
    });

    // مهلات تحمي من الاتصالات البطيئة التي تستهلك موارد الخادم (Slowloris)
    server.headersTimeout = 15_000;
    server.requestTimeout = 60_000;
    server.keepAliveTimeout = 5_000;
    server.maxHeadersCount = 50;

    return { server, stats, config, admin };
}

function main() {
    const { server, config, admin } = createApp();

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
    process.on("unhandledRejection", reason => console.error("Unhandled rejection:", reason && reason.message ? reason.message : reason));
}

if (require.main === module) main();

module.exports = { createApp };
