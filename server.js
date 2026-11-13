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
const zlib = require("node:zlib");
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
const { createSms } = require("./server/sms");
const { createPhoneAuth } = require("./server/phone-auth");
const { createIntel } = require("./server/intel");
const { createInspector } = require("./server/inspect");
const { createCommunity, CommunityError } = require("./server/community");
const { createIdentifiers, IdentifierError } = require("./server/identifiers");
const { createCourse, CourseError } = require("./server/course");
const { createMonitor, MonitorError } = require("./server/monitor");
const { limitsFor } = require("./server/plans");
const { createScan } = require("./server/scan");
const { createChatHandler } = require("./server/chat");
const { createAdmin } = require("./server/admin");
const { createSettings } = require("./server/settings");
const { serveStatic, versionAssets } = require("./server/static");

const CLIENT_ERROR_KINDS = new Set(["error", "promise", "action"]);

function createApp(config = loadConfig(), overrides = {}) {
    // نطاق الموقع نفسه يُعتبر موثوقاً بالفحص (ما نحذّر من رابطنا لأنه على onrender.com)
    require("./public/js/detection-engine.js").setSiteHosts([new URL(config.appUrl).hostname]);
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
    const settings = createSettings({ db, config });
    const sms = overrides.sms || createSms(config.sms);
    const phoneAuth = createPhoneAuth({ db, sms, now: overrides.now });
    const auth = createAuth({ config, users, oauth, stats, mailer, settings, sms, phoneAuth });
    // الزيارة الآمنة للروابط ومعلومات الاستضافة (تتعطل مع THREAT_FEEDS=0 بالاختبارات، أو LIVE_INSPECT=0)
    const inspector = overrides.inspector !== undefined ? overrides.inspector : createInspector({ enabled: config.intel.enabled && config.liveInspect });
    const community = createCommunity({ db });
    const identifiers = createIdentifiers({ db });
    const course = createCourse({ db, users });
    const monitor = overrides.monitor || createMonitor({ db, users, mailer, appUrl: config.appUrl, log: message => stats.event("monitor", String(message).slice(0, 120), "") });
    const idLookupLimiter = createRateLimiter({ windowMs: 60_000, max: 20 });
    const disputeLimiter = createRateLimiter({ windowMs: 60 * 60_000, max: 5 });
    const scan = createScan({ config, users, auth, intel, stats, inspector, settings, community });
    const chat = createChatHandler({ config, users, auth, scan, stats, settings, ...(overrides.chatFetch ? { fetchImpl: overrides.chatFetch } : {}) });
    const admin = createAdmin(config, stats, { visitors, health: currentHealth, users, db, intel, chat: chat.status, chatTest: chat.test, mail: mailer.status, sms: sms.status, mailer, settings, community, identifiers });

    // الصفحات تُقرأ وتُضغط مرة واحدة عند التشغيل
    const loadPage = name => {
        // %APP_URL% بالصفحة يُستبدل بعنوان الموقع (للروابط المطلقة: canonical و og:image)
        const v = config.siteVerification || {};
        const verify = [
            v.google ? `<meta name="google-site-verification" content="${v.google}">` : "",
            v.bing ? `<meta name="msvalidate.01" content="${v.bing}">` : ""
        ].filter(Boolean).join("\n    ");
        const html = fs.readFileSync(path.join(config.publicDir, name), "utf8")
            .split("%APP_URL%").join(config.appUrl).split("<!--SITE_VERIFICATION-->").join(verify);
        const raw = Buffer.from(versionAssets(html, config.publicDir));
        return { raw, br: zlib.brotliCompressSync(raw), gzip: zlib.gzipSync(raw, { level: 9 }) };
    };
    const pages = { app: loadPage("index.html"), login: loadPage("login.html"), dispute: loadPage("dispute.html") };

    function sendPage(req, res, page) {
        const accept = String(req.headers["accept-encoding"] || "");
        const encoding = /\bbr\b/.test(accept) ? "br" : /\bgzip\b/.test(accept) ? "gzip" : "";
        const body = encoding ? page[encoding] : page.raw;
        const headers = { "Content-Type": "text/html; charset=utf-8", "Content-Length": body.length, "Cache-Control": "no-store", Vary: "Accept-Encoding" };
        if (encoding) headers["Content-Encoding"] = encoding;
        res.writeHead(200, headers);
        res.end(req.method === "HEAD" ? undefined : body);
    }

    // صفحة الصيانة (يفعّلها الأدمن). لوحة الإدارة تبقى تعمل.
    function sendMaintenance(req, res) {
        const message = String(settings.get().features.maintenanceMessage).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
        const body = Buffer.from(`<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>صيانة - Phishing Detector</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0a0f1d;color:#e8edf9;font-family:Tahoma,system-ui,sans-serif;padding:16px}main{max-width:520px;text-align:center;background:#131b2e;border:1px solid #243152;border-radius:18px;padding:32px 24px}img{width:84px;height:84px;border-radius:18px}h1{font-size:1.4rem;margin:18px 0 8px}p{color:#8e9aaf;line-height:1.9}</style></head>
<body><main><img src="/img/logo-256.jpg" alt="Phishing Detector"><h1>الموقع تحت الصيانة</h1><p>${message}</p></main></body></html>`);
        res.writeHead(503, { "Content-Type": "text/html; charset=utf-8", "Content-Length": body.length, "Cache-Control": "no-store", "Retry-After": "600" });
        res.end(req.method === "HEAD" ? undefined : body);
    }

    // الخدمة المطلوبة متوقفة من الإدارة؟ يرجع رسالة الإيقاف أو ""
    function featureBlock(pathname) {
        const f = settings.get().features;
        if (f.maintenance && (pathname === "/api/chat" || pathname.startsWith("/api/scan/") || pathname.startsWith("/api/v1/"))) return f.maintenanceMessage;
        const map = [
            ["/api/chat", "cyberbot", "CyberBot متوقف مؤقتاً."],
            ["/api/scan/url", "urlScan", "فحص الروابط متوقف مؤقتاً."],
            ["/api/v1/scan-url", "urlScan", "فحص الروابط متوقف مؤقتاً."],
            ["/api/scan/text", "textScan", "فحص الرسائل متوقف مؤقتاً."],
            ["/api/v1/scan-text", "textScan", "فحص الرسائل متوقف مؤقتاً."],
            ["/api/scan/file", "fileScan", "فحص الملفات متوقف مؤقتاً."],
            ["/api/scan/clean", "fileScan", "تنظيف الملفات متوقف مؤقتاً."],
            ["/api/scan/bulk", "bulk", "الفحص الجماعي متوقف مؤقتاً."]
        ];
        for (const [route, key, text] of map) if (pathname === route && f[key] === false) return text;
        return "";
    }

    // معاملات المشاركة فقط (لا نمرّر أي شيء آخر بالتحويل)
    function shareQuery(url) {
        const keep = new URLSearchParams();
        for (const k of ["share_title", "share_text", "share_url"]) if (url.searchParams.get(k)) keep.set(k, url.searchParams.get(k).slice(0, 10000));
        return keep.toString() ? "?" + keep : "";
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

    const escHtml = v => String(v).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
    const SEVERITY = { danger: ["خطر", "#e5484d"], warn: ["تحذير", "#f5b014"], info: ["معلومة", "#3b82f6"] };
    function sendAlertsPage(req, res, list) {
        const items = list.map(a => {
            const [label, color] = SEVERITY[a.severity] || SEVERITY.warn;
            const day = new Date(a.at).toISOString().slice(0, 10);
            return `<article class="alert-item" style="border-inline-start:4px solid ${color}"><p class="muted"><b style="color:${color}">${label}</b> · <time datetime="${day}">${day}</time></p><h2>${escHtml(a.title)}</h2><p>${escHtml(a.body).replace(/\n/g, "<br>")}</p></article>`;
        }).join("\n") || '<p class="muted">لا توجد تنبيهات حالياً.</p>';
        const base = config.appUrl;
        const body = Buffer.from(versionAssets(`<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>تنبيهات الاحتيال الإلكتروني بالعراق | Phishing Detector</title>
<meta name="description" content="آخر رسائل وروابط الاحتيال المنتشرة بالعراق (مصارف، زين كاش، جوائز وهمية) وشلون تحمي نفسك. من فريق ApexSec.">
<link rel="canonical" href="${base}/alerts"><link rel="icon" href="/favicon.ico" sizes="48x48">
<link rel="stylesheet" href="/vendor/tajawal/tajawal.css?v=1"><link rel="stylesheet" href="/css/legal.css?v=1">
<style>.alert-item{padding:4px 16px;margin:16px 0;border-radius:10px;background:rgba(127,127,127,.06)}.alert-item h2{margin:4px 0 8px;font-size:1.15rem}</style></head>
<body><header class="legal-top"><a class="legal-brand" href="/login"><img src="/img/logo-192.jpg?v=1" width="192" height="192" alt=""> Phishing Detector</a><nav><a href="/login">افحص رابط أو رسالة</a></nav></header>
<main><h1>تنبيهات الاحتيال الإلكتروني</h1><p class="muted">آخر عمليات الاحتيال المنتشرة وشلون تتجنبها. وصلتك رسالة مشكوك بيها؟ افحصها مجاناً من <a href="/login">Phishing Detector</a>.</p>
${items}</main><footer class="legal-foot"><a href="/privacy">الخصوصية</a> · <a href="/terms">الشروط</a></footer></body></html>`, config.publicDir));
        res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Content-Length": body.length, "Cache-Control": "public, max-age=300" });
        res.end(req.method === "HEAD" ? undefined : body);
    }

    // بلاغ احتيال من مستخدم مسجّل
    async function handleReport(req, res) {
        if (req.method !== "POST") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "POST" });
        const user = await auth.requireUser(req, res);
        if (!user) return;
        const body = await auth.jsonBody(req, res, 8 * 1024);
        if (body === undefined) return;
        try {
            const report = await community.createReport(user, { kind: body.kind, content: body.content, note: body.note });
            stats.count("reports");
            stats.event("report", `بلاغ احتيال جديد (${report.kind === "url" ? report.domain : "رسالة"})`, h.getClientIp(req, config));
            h.sendJson(res, 201, { ok: true, message: "وصلنا بلاغك، شكراً! راح نراجعه، وإذا تأكدنا ينضاف لقائمة الاحتيال ويحمي غيرك." });
        } catch (error) {
            if (error instanceof CommunityError) return h.sendJson(res, error.status, { error: error.message });
            auth.sendError(res, error);
        }
    }

    // مراقبة انتحال الدومين (Pro)
    async function handleMonitor(req, res, pathname) {
        const user = await auth.requireUser(req, res);
        if (!user) return;
        if (!limitsFor(user).deepChecks) return h.sendJson(res, 403, { error: "مراقبة انتحال الدومين متاحة لمشتركي Pro.", code: "pro_only" });
        try {
            if (pathname === "/api/monitor" && req.method === "GET") return h.sendJson(res, 200, await monitor.load(user.id));
            const body = await auth.jsonBody(req, res, 1024);
            if (body === undefined) return;
            const action = pathname.slice("/api/monitor/".length);
            if (action === "add") return h.sendJson(res, 200, await monitor.add(user, body.domain));
            if (action === "remove") return h.sendJson(res, 200, await monitor.remove(user, body.domain));
            if (action === "dismiss") return h.sendJson(res, 200, await monitor.dismiss(user, body.domain, body.finding));
            if (action === "check") {
                const r = await monitor.check(user, body.domain);
                stats.event("monitor", `فحص انتحال الدومين: ${r.fresh.length} نتيجة جديدة`, "");
                return h.sendJson(res, 200, { ...r.data, newFindings: r.fresh.length, failed: !!r.failed });
            }
            h.sendJson(res, 404, { error: "Not found" });
        } catch (error) {
            if (error instanceof MonitorError) return h.sendJson(res, error.status, { error: error.message });
            auth.sendError(res, error);
        }
    }

    // الدورة التوعوية: الدروس والاختبار (التصحيح هنا فقط) والشهادة
    async function handleCourse(req, res, pathname) {
        const user = await auth.requireUser(req, res);
        if (!user) return;
        try {
            if (pathname === "/api/course" && req.method === "GET") return h.sendJson(res, 200, course.overview(user));
            const body = await auth.jsonBody(req, res, 4096);
            if (body === undefined) return;
            if (pathname === "/api/course/quiz") return h.sendJson(res, 200, await course.startQuiz(user, String(body.level || "")));
            if (pathname === "/api/course/submit") {
                const result = await course.submitQuiz(user, body.attemptId, body.answers);
                if (result.passed) stats.event("course", `اجتياز مستوى بالدورة التوعوية (${result.score}/${result.total})`, "");
                return h.sendJson(res, 200, result);
            }
            if (pathname === "/api/course/certificate") {
                const fresh = await users.get(user.id);
                const cert = await course.issueCertificate(fresh || user, body.name);
                stats.event("course", "إصدار شهادة إتمام الدورة", "");
                return h.sendJson(res, 201, { certificate: cert, url: `/certificate/${cert.id}` });
            }
            h.sendJson(res, 404, { error: "Not found" });
        } catch (error) {
            if (error instanceof CourseError) return h.sendJson(res, error.status, { error: error.message });
            auth.sendError(res, error);
        }
    }

    // صفحة الشهادة (للطباعة أو الحفظ PDF) وصفحة التحقق العامة
    async function sendCertificatePage(req, res, kind, id) {
        const cert = await course.getCertificate(id).catch(() => null);
        const base = config.appUrl;
        const verifyUrl = `${base}/verify/${id}`;
        const day = cert ? new Date(cert.issuedAt).toISOString().slice(0, 10) : "";
        let main;
        if (!cert) {
            main = `<main class="verify bad"><h1>❌ ما لكينا شهادة بهذا الرقم</h1><p>الرقم <code dir="ltr">${escHtml(id)}</code> غير موجود بسجلاتنا. تأكد من كتابته، أو إن الشهادة ممكن تكون مزورة.</p></main>`;
        } else if (kind === "verify") {
            main = `<main class="verify ok"><h1>✅ شهادة صحيحة</h1>
<p>صادرة من منصة Phishing Detector باسم <strong>${escHtml(cert.name)}</strong> بتاريخ <time datetime="${day}">${day}</time>.</p>
<ul>${cert.levels.map(l => `<li>${escHtml(l.title)}: ${Number(l.score)}/5</li>`).join("")}</ul>
<p class="muted">رقم التحقق: <code dir="ltr">${escHtml(cert.id)}</code>. هذه شهادة إتمام دورة توعوية على المنصة، وليست شهادة معتمدة من جهة حكومية أو أكاديمية.</p>
<p><a href="/certificate/${escHtml(cert.id)}">عرض الشهادة</a></p></main>`;
        } else {
            main = `<main class="cert" id="cert" data-verify="${escHtml(verifyUrl)}">
<div class="cert-border"><img src="/img/icon-192.png" width="72" height="72" alt="">
<p class="cert-kicker">شهادة إتمام</p><h1>${escHtml(cert.name)}</h1>
<p>أتمّ بنجاح الدورة التوعوية «كشف التصيد والاحتيال الإلكتروني» بمستوياتها الثلاثة على منصة <strong>Phishing Detector</strong> (فريق ApexSec)، بمجموع ${Number(cert.points)} نقطة.</p>
<ul class="cert-levels">${cert.levels.map(l => `<li>${escHtml(l.title)}: ${Number(l.score)}/5</li>`).join("")}</ul>
<div class="cert-foot"><div><p>تاريخ الإصدار: <time datetime="${day}">${day}</time></p><p>رقم التحقق: <code dir="ltr">${escHtml(cert.id)}</code></p><p class="muted">تحقق منها: <span dir="ltr">${escHtml(verifyUrl)}</span></p></div><div id="certQr" class="cert-qr" aria-label="رمز QR للتحقق"></div></div>
<p class="cert-disclaimer">هذه شهادة إتمام دورة توعوية على المنصة، وليست شهادة معتمدة من أي جهة حكومية أو أكاديمية.</p></div>
<p class="no-print"><button type="button" id="printCert">طباعة أو حفظ PDF</button></p></main>`;
        }
        const body = Buffer.from(versionAssets(`<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${kind === "verify" ? "التحقق من شهادة" : "شهادة إتمام"} | Phishing Detector</title><meta name="robots" content="noindex">
<link rel="icon" href="/favicon.ico" sizes="48x48"><link rel="stylesheet" href="/vendor/tajawal/tajawal.css?v=1"><link rel="stylesheet" href="/css/legal.css?v=1"><link rel="stylesheet" href="/css/certificate.css?v=1"></head>
<body>${main}${kind === "certificate" && cert ? '<script src="/vendor/qrcode/qrcode.js?v=1"></script><script src="/js/certificate.js?v=1"></script>' : ""}</body></html>`, config.publicDir));
        res.writeHead(cert ? 200 : 404, { "Content-Type": "text/html; charset=utf-8", "Content-Length": body.length, "Cache-Control": "no-cache", "X-Robots-Tag": "noindex" });
        res.end(req.method === "HEAD" ? undefined : body);
    }

    // فحص رقم أو حساب أو محفظة: بحث وبلاغ (بحساب)، واعتراض (لأي شخص)
    async function handleIdentifier(req, res, pathname) {
        const action = pathname.slice("/api/identifier/".length);
        if (!["lookup", "report", "dispute"].includes(action)) return h.sendJson(res, 404, { error: "Not found" });
        if (req.method !== "POST") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "POST" });
        const ip = h.getClientIp(req, config);
        let user = null;
        if (action !== "dispute") {
            user = await auth.requireUser(req, res);
            if (!user) return;
            if (!idLookupLimiter.take(user.id)) return h.sendJson(res, 429, { error: "طلبات كثيرة بالدقيقة. تمهّل قليلاً." }, { "Retry-After": "60" });
        } else if (!disputeLimiter.take(ip)) {
            return h.sendJson(res, 429, { error: "أرسلت اعتراضات كثيرة. حاول بعد ساعة." }, { "Retry-After": "3600" });
        }
        const body = await auth.jsonBody(req, res, 4096);
        if (body === undefined) return;
        try {
            if (action === "lookup") return h.sendJson(res, 200, { result: await identifiers.lookup(body.kind, body.value) });
            if (action === "report") {
                const result = await identifiers.report(user, { kind: body.kind, value: body.value, category: body.category, note: body.note });
                stats.count("reports");
                stats.event("identifier_report", "بلاغ عن رقم أو حساب", ip);
                return h.sendJson(res, 201, { result, message: "وصل بلاغك، شكراً. يظهر للناس كعدد بلاغات فقط، وبدون اسمك." });
            }
            await identifiers.dispute({ kind: body.kind, value: body.value, contact: body.contact, reason: body.reason });
            stats.event("identifier_dispute", "اعتراض على بلاغات معرّف", ip);
            return h.sendJson(res, 201, { ok: true, message: "وصل اعتراضك. راح تراجعه الإدارة، وإذا كان محقاً تنحذف البلاغات." });
        } catch (error) {
            if (error instanceof IdentifierError) return h.sendJson(res, error.status, { error: error.message });
            auth.sendError(res, error);
        }
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

            // robots.txt و sitemap.xml تُبنى من عنوان الموقع (APP_URL) حتى تبقى صحيحة على أي نطاق
            if (pathname === "/robots.txt" || pathname === "/sitemap.xml") {
                if (req.method !== "GET" && req.method !== "HEAD") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET, HEAD" });
                const base = config.appUrl.replace(/\/+$/, "");
                const body = pathname === "/robots.txt"
                    ? `User-agent: *\nAllow: /login\nAllow: /alerts\nAllow: /privacy\nAllow: /terms\nDisallow: /admin\nDisallow: /api/\nDisallow: /auth/\n\nSitemap: ${base}/sitemap.xml\n`
                    : `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${[["/login", "1.0", "weekly"], ["/alerts", "0.8", "daily"], ["/privacy", "0.3", "monthly"], ["/terms", "0.3", "monthly"]].map(([p, pr, cf]) => `  <url><loc>${base}${p}</loc><changefreq>${cf}</changefreq><priority>${pr}</priority></url>`).join("\n")}\n</urlset>\n`;
                res.writeHead(200, { "Content-Type": pathname.endsWith(".xml") ? "application/xml; charset=utf-8" : "text/plain; charset=utf-8", "Content-Length": Buffer.byteLength(body), "Cache-Control": "public, max-age=3600" });
                return res.end(req.method === "HEAD" ? undefined : body);
            }

            // إعدادات الموقع العامة (نصوص الرئيسية، الخدمات المفعّلة، CyberBot)
            if (pathname === "/api/site") {
                if (req.method !== "GET" && req.method !== "HEAD") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET, HEAD" });
                return h.sendJson(res, 200, settings.publicView());
            }

            // الصفحات: الدخول أولاً، والتطبيق للمسجّلين فقط
            if (pathname === "/" || pathname === "/index.html" || pathname === "/login" || pathname === "/login.html") {
                if (req.method !== "GET" && req.method !== "HEAD") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET, HEAD" });
                if (settings.get().features.maintenance) return sendMaintenance(req, res);
                const user = await auth.currentUser(req);
                const wantsLogin = pathname.startsWith("/login");
                if (wantsLogin) {
                    // رابط إعادة تعيين كلمة السر يُعرض حتى لو كان المستخدم داخلاً
                    if (user && !url.searchParams.has("reset")) return redirect(res, "/" + shareQuery(url));
                    if (req.method === "GET") visitors.hit(h.getClientIp(req, config), req.headers["user-agent"]);
                    return sendPage(req, res, pages.login);
                }
                // الضيف يشوف واجهة التطبيق فقط (نفس الملفات العامة)، وكل الواجهات ترفضه
                if (!user && !(auth.isGuest(req) && settings.get().features.guest !== false)) {
                    // محتوى مشارك (Web Share Target) يبقى معه حتى بعد تسجيل الدخول
                    return redirect(res, "/login" + shareQuery(url));
                }
                if (req.method === "GET") visitors.hit(h.getClientIp(req, config), req.headers["user-agent"]);
                return sendPage(req, res, pages.app);
            }

            // قائمة النطاقات المؤكدة كاحتيال (لإضافة المتصفح): عامة، بدون أي بيانات مستخدمين
            if (pathname === "/api/blocklist") {
                if (req.method !== "GET" && req.method !== "HEAD") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET, HEAD" });
                const domains = await community.listBlocked().catch(() => []);
                return h.sendJson(res, 200, { domains: domains.slice(0, 20000), updatedAt: new Date().toISOString() }, { "Cache-Control": "public, max-age=600" });
            }

            // تنبيهات الاحتيال: صفحة عامة (للناس ولمحركات البحث) + JSON للتطبيق
            if (pathname === "/alerts" || pathname === "/api/alerts") {
                if (req.method !== "GET" && req.method !== "HEAD") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET, HEAD" });
                const list = community.alerts().map(({ by, ...a }) => a);
                if (pathname === "/api/alerts") return h.sendJson(res, 200, { alerts: list.slice(0, 20) });
                return sendAlertsPage(req, res, list);
            }
            if (pathname === "/api/report") return await handleReport(req, res);
            if (pathname.startsWith("/api/identifier/")) return await handleIdentifier(req, res, pathname);
            if (pathname === "/api/course" || pathname.startsWith("/api/course/")) return await handleCourse(req, res, pathname);
            if (pathname === "/api/monitor" || pathname.startsWith("/api/monitor/")) return await handleMonitor(req, res, pathname);
            const certMatch = /^\/(certificate|verify)\/([A-Za-z0-9]{1,20})$/.exec(pathname);
            if (certMatch) {
                if (req.method !== "GET" && req.method !== "HEAD") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET, HEAD" });
                return await sendCertificatePage(req, res, certMatch[1], certMatch[2].toUpperCase());
            }
            if (pathname === "/dispute") {
                if (req.method !== "GET" && req.method !== "HEAD") return h.sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET, HEAD" });
                return sendPage(req, res, pages.dispute);
            }

            const blocked = featureBlock(pathname);
            if (blocked) return h.sendJson(res, 503, { error: blocked, code: "feature_disabled" });

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
    server.on("close", () => { health.stop(); intel.stop(); settings.stop(); community.stop(); if (monitor.stop) monitor.stop(); });

    // نتأكد أن القاعدة تعمل قبل الاستماع (ونكمل حتى لو فشلت، مع تحذير)
    const ready = db.cmd(["PING"]).then(() => ({ ok: true }), error => ({ ok: false, error: db.describeError(error) }))
        .then(async state => {
            // إعدادات الموقع من القاعدة (ثم تُحدَّث كل 30 ثانية)
            if (state.ok) {
                const loaded = await settings.load();
                if (!loaded.ok) state.settingsError = loaded.error;
            }
            settings.start();
            community.start();
            if (config.intel.enabled && monitor.start) monitor.start();
            // الإحصاءات والزوار تُحفظ في القاعدة حتى لا تتصفّر عند كل نشر
            if (state.ok) {
                const a = await stats.attach(db);
                const b = await visitors.attach(db);
                if (!a.ok || !b.ok) state.statsError = a.error || b.error;
            }
            return state;
        });
    const flushAll = () => Promise.all([stats.close(), visitors.close()]);

    return { server, stats, config, admin, visitors, db, users, intel, scan, settings, ready, flushAll };
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
        console.log(admin.enabled
            ? `Admin page enabled: ${[...config.admins.values()].filter(a => a.email).length} account(s) with password + email code, ${config.adminEmails.size} email-only login(s), ${[...config.admins.values()].filter(a => !a.email).length} password-only account(s).`
            : "Admin page disabled: set ADMINS (npm run make-admin -- <user> <email>) or ADMIN_EMAILS.");
        const needsMail = config.adminEmails.size > 0 || [...config.admins.values()].some(a => a.email);
        if (needsMail && !config.mail.enabled) console.log("WARNING: admin login needs email codes but no mail provider is configured, so codes cannot be sent. Set BREVO_API_KEY and MAIL_FROM.");
        const no2fa = [...config.admins].filter(([, a]) => !a.totpSecret && !a.email).map(([name]) => name);
        if (no2fa.length) console.log(`WARNING: admin account(s) without 2FA: ${no2fa.join(", ")}. Re-run "npm run make-admin" and add the secret to your authenticator app.`);
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
