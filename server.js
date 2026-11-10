"use strict";

/*
  خادم Phishing Detector (ApexSec). بدون أي مكتبات خارجية (Node.js 20 أو أحدث).

  الصفحات:
    /login            تسجيل الدخول وإنشاء الحساب (أول صفحة يراها الزائر)
    /                 التطبيق (يتطلب تسجيل الدخول، وإلا يحوَّل إلى /login)
    /admin            لوحة الأدمن (مغلقة إلا إذا ضُبط ADMINS)
  الواجهات:
    /api/auth/*, /auth/<provider>/*   الحسابات والدخول (server/auth.js)
    /api/account/*, /api/billing/*    الحساب والاشتراك
    /api/scan/*, /api/v1/*            الفحص (server/scan.js)
    /api/chat                         CyberBot (server/chat.js)
    /api/event, /api/client-error     إحصاءات مجهولة وتقارير أخطاء المتصفح
    /healthz                          فحص الصحة لـ Render

  الإعدادات: server/config.js و README.md
*/

const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { loadConfig } = require("./server/config");
const h = require("./server/http");
const { createRateLimiter } = require("./server/rate-limit");
const { createStats, cleanText } = require("./server/stats");
const { createHealthMonitor } = require("./server/health");
const { createVisitorCounter } = require("./server/visitors");
const { openDb } = require("./server/db");
const { createUsers } = require("./server/users");
const { createMailer } = require("./server/mailer");
const { createOAuth } = require("./server/oauth");
const { createAuth } = require("./server/auth");
const { createIntel } = require("./server/intel");
const { createScan } = require("./server/scan");
const { createChatHandler } = require("./server/chat");
const { createAdmin } = require("./server/admin");
const { serveStatic } = require("./server/static");

const CLIENT_ERROR_KINDS = new Set(["error", "promise", "action"]);

function createApp(config = loadConfig(), overrides = {}) {
    const audit = config.auditStdout ? entry => console.log(JSON.stringify({ audit: true, ...entry })) : undefined;
    const stats = createStats({ audit });
    const visitors = createVisitorCounter();
    const health = createHealthMonitor(config.health);
    const eventLimiter = createRateLimiter({ windowMs: 60_000, max: config.limits.eventPerMinute });
    const errorLimiter = createRateLimiter({ windowMs: 60_000, max: config.limits.clientErrorPerMinute, globalMax: config.limits.globalClientErrorPerMinute });
    const currentHealth = () => health.evaluate(stats.recent("client_error", 5 * 60_000));

    const db = overrides.db || openDb(config);
    const users = createUsers({ db, config, now: overrides.now });
    const oauth = createOAuth({ config, db, fetchImpl: overrides.fetch || fetch });
    const intel = overrides.intel || createIntel({ enabled: config.intel.enabled, log: message => stats.event("intel", message, "") });
    const mailer = createMailer(config);
    const auth = createAuth({ config, users, oauth, stats, mailer });
    const scan = createScan({ config, users, auth, intel, stats });
    const chat = createChatHandler({ config, users, auth, scan, stats, ...(overrides.chatFetch ? { fetchImpl: overrides.chatFetch } : {}) });
    const admin = createAdmin(config, stats, { visitors, health: currentHealth, users, db, intel, chat: chat.status, chatTest: chat.test, mail: mailer.status });

    const pages = {
        app: fs.readFileSync(path.join(config.publicDir, "index.html")),
        login: fs.readFileSync(path.join(config.publicDir, "login.html"))
    };

    function sendPage(req, res, body) {
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Length": body.length, "Cache-Control": "no-store" });
        res.end(req.method === "HEAD" ? undefined : body);
    }

    function redirect(res, location) {
        res.writeHead(302, { Location: location, "Cache-Control": "no-store" });
        res.end();
    }

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

    // إحصاءات مجهولة لفحوصات تتم داخل المتصفح (الوسائط): نوع ونتيجة فقط
    async function handleEvent(req, res) {
        const body = await readClientJson(req, res, eventLimiter, 512);
        if (body === undefined) return;
        if (!stats.scan(body.kind, body.level)) return h.sendJson(res, 400, { error: "Bad request" });
        res.writeHead(204, { "Cache-Control": "no-store" });
        res.end();
    }

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
                const critical = currentHealth().status === "critical";
                return h.sendText(res, critical ? 503 : 200, critical ? "unhealthy" : "ok");
            }

            // الصفحات: الدخول أولاً، والتطبيق للمسجّلين فقط
            if (pathname === "/" || pathname === "/index.html" || pathname === "/login" || pathname === "/login.html") {
                if (req.method !== "GET" && req.method !== "HEAD") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET, HEAD" });
                const user = await auth.currentUser(req);
                const wantsLogin = pathname.startsWith("/login");
                if (wantsLogin) {
                    // رابط إعادة تعيين كلمة السر يُعرض حتى لو كان المستخدم داخلاً
                    if (user && !url.searchParams.has("reset")) return redirect(res, "/");
                    if (req.method === "GET") visitors.hit(h.getClientIp(req, config), req.headers["user-agent"]);
                    return sendPage(req, res, pages.login);
                }
                if (!user) return redirect(res, "/login");
                if (req.method === "GET") visitors.hit(h.getClientIp(req, config), req.headers["user-agent"]);
                return sendPage(req, res, pages.app);
            }

            // أرقام عامة مجمّعة للصفحة الرئيسية (بدون أي بيانات شخصية)
            if (pathname === "/api/public/stats") {
                if (req.method !== "GET" && req.method !== "HEAD") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET, HEAD" });
                const snap = stats.snapshot(0);
                let scansTotal = 0, threats = 0;
                for (const kind of Object.keys(snap.scans)) {
                    const s = snap.scans[kind];
                    scansTotal += s.safe + s.warning + s.danger;
                    threats += s.warning + s.danger;
                }
                const intelStatus = intel.status();
                return h.sendJson(res, 200, {
                    scans: scansTotal, threats, chats: snap.counters.chatOk,
                    threatIntel: intelStatus.enabled ? intelStatus.urls + intelStatus.hosts : 0,
                    since: snap.since
                }, { "Cache-Control": "public, max-age=60" });
            }

            if (await auth.handle(req, res, url)) return;
            if (await scan.handle(req, res, url)) return;
            if (pathname === "/api/chat") return await chat.handle(req, res);
            if (pathname === "/api/event") return await handleEvent(req, res);
            if (pathname === "/api/client-error") return await handleClientError(req, res);
            if (await admin.handle(req, res, url)) return;

            serveStatic(req, res, pathname, config);
        } catch (error) {
            console.error("Unhandled request error:", error && error.message);
            stats.count("serverErrors");
            stats.event("server_error", error && error.message, "");
            if (!res.headersSent) h.sendJson(res, 500, { error: "Internal server error" });
            else res.destroy();
        }
    });

    server.headersTimeout = 15_000;
    server.requestTimeout = 60_000;
    server.keepAliveTimeout = 5_000;
    server.maxHeadersCount = 50;
    server.on("close", () => { health.stop(); intel.stop(); });

    // نتأكد أن القاعدة تعمل قبل الاستماع (ونكمل حتى لو فشلت، مع تحذير)
    const ready = db.cmd(["PING"]).then(() => ({ ok: true }), error => ({ ok: false, error: db.describeError(error) }))
        .then(async state => {
            // الإحصاءات والزوار تُحفظ في القاعدة حتى لا تتصفّر عند كل نشر
            if (state.ok) {
                const a = await stats.attach(db);
                const b = await visitors.attach(db);
                if (!a.ok || !b.ok) state.statsError = a.error || b.error;
            }
            return state;
        });
    const flushAll = () => Promise.all([stats.close(), visitors.close()]);

    return { server, stats, config, admin, visitors, db, users, intel, scan, ready, flushAll };
}

async function main() {
    const { server, config, admin, db, intel, ready, flushAll } = createApp();
    const dbState = await ready;

    server.listen(config.port, config.host, () => {
        console.log(`Phishing Detector listening at http://${config.host}:${config.port} (public URL: ${config.appUrl})`);
        if (dbState.statsError) console.log(`Stats persistence problem: ${dbState.statsError}`);
        else if (dbState.ok && db.persistent) console.log("Stats: persistent (saved to the database).");
        if (db.backend === "upstash") console.log(dbState.ok ? "Database: Upstash (persistent)." : `Database: Upstash UNREACHABLE (${dbState.error}). Logins will fail until it is back.`);
        else console.log(config.onRender ? "WARNING: no UPSTASH_REDIS_REST_URL/TOKEN. Accounts live in memory and are LOST on every deploy." : "Database: in-memory (local development).");
        if (config.billing.upstashError) console.log(config.billing.upstashError);
        const providers = Object.keys(config.oauth).filter(k => config.oauth[k]);
        console.log(`Sign-in providers: email${providers.length ? ", " + providers.join(", ") : ""}.`);
        console.log(config.openai.apiKey && config.openai.model ? `CyberBot: ${config.openai.model} via ${config.openai.style === "gemini" ? "Gemini native" : config.openai.style} API.` : "CyberBot: no AI_API_KEY/AI_MODEL, using local replies.");
        console.log(admin.enabled ? `Admin page enabled (${config.admins.size} account(s)).` : "Admin page disabled: set ADMINS (run: npm run make-admin).");
        intel.start();
    });

    const shutdown = signal => {
        console.log(`${signal} received, shutting down.`);
        // نحفظ الإحصاءات قبل الإغلاق حتى لا نخسر آخر عدّات قبل النشر
        const saved = Promise.race([flushAll().catch(() => {}), new Promise(r => setTimeout(r, 4_000))]);
        saved.then(() => server.close(() => process.exit(0)));
        setTimeout(() => process.exit(0), 10_000).unref();
    };
    process.on("SIGTERM", () => shutdown("SIGTERM"));
    process.on("SIGINT", () => shutdown("SIGINT"));
    process.on("unhandledRejection", reason => {
        console.error("Unhandled rejection:", reason && reason.message ? reason.message : String(reason));
    });
    process.on("uncaughtException", error => {
        console.error("Fatal uncaught exception:", error && error.stack ? error.stack : error);
        setTimeout(() => process.exit(1), 200);
    });
}

if (require.main === module) {
    main().catch(error => {
        console.error("Failed to start:", error && error.message);
        process.exit(1);
    });
}

module.exports = { createApp };
