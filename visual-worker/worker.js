"use strict";

/*
  خدمة الكشف البصري (Visual Phishing Detection worker) — خدمة منفصلة عن الموقع.

  الموقع الرئيسي يرسل رابط ← الخدمة تفتحه بمتصفح مخفي (Chromium) ← تأخذ لقطة شاشة + أيقونة الموقع (favicon)
  ← تحسب بصمات بصرية (pHash/dHash) ← ترجعها مع اللقطة. المقارنة بمكتبة صفحات الدخول الحقيقية تصير بالموقع الرئيسي.

  ليش خدمة منفصلة؟ المتصفح ياكل ذاكرة (150-300MB للصفحة)، فلو شغلناه بنفس خادم الموقع (512MB) ممكن يطيّحه.

  الحماية:
    - كل طلبات المتصفح تمر من وكيل الحماية (guard-proxy.js): ما يوصل لأي عنوان داخلي، حتى عبر التحويلات أو الصور.
    - صفحة وحدة بالمرة (طابور مهام بحد أقصى)، ومهلة لكل صفحة، وسياق متصفح جديد لكل مهمة (بلا كوكيز ولا تخزين).
    - بلا تنزيلات، بلا Service Workers، بلا صلاحيات (كاميرا، موقع...)، WebRTC و QUIC معطّلة.
    - المتصفح ينعاد تشغيله كل 40 مهمة حتى ما تتراكم الذاكرة.
    - الطلبات لازم تحمل VISUAL_WORKER_TOKEN (مفتاح سري مشترك مع الموقع الرئيسي).

  التشغيل:  VISUAL_WORKER_TOKEN=... PORT=8090 node visual-worker/worker.js
*/

const http = require("node:http");
const crypto = require("node:crypto");
const { createGuardProxy } = require("./guard-proxy");
const { computeHashes } = require("./hash-browser");

const VIEWPORT = { width: 1280, height: 800 };
const NAV_TIMEOUT = 15_000;
const JOB_TIMEOUT = 30_000;
const MAX_REQUESTS_PER_PAGE = 200;
const RESTART_EVERY = 40;

function createWorker({ token, launch, isAllowedIp, allowedPorts, maxQueue = 8, log = () => {} }) {
    if (!token || token.length < 24) throw new Error("VISUAL_WORKER_TOKEN must be at least 24 characters");
    if (typeof launch !== "function") throw new Error("launch() required");
    const proxy = createGuardProxy({ isAllowedIp, ...(allowedPorts ? { allowedPorts } : {}) });
    let proxyPort = 0;
    let browser = null;
    let jobsSinceStart = 0;
    const queue = [];
    let running = false;
    const stats = { captured: 0, failed: 0, rejected: 0, startedAt: Date.now() };

    async function getBrowser() {
        if (browser && jobsSinceStart < RESTART_EVERY && browser.isConnected()) return browser;
        if (browser) await browser.close().catch(() => {});
        if (!proxyPort) proxyPort = await proxy.listen();
        browser = await launch({
            headless: true,
            proxy: { server: `http://127.0.0.1:${proxyPort}`, bypass: "<-loopback>" },
            args: [
                "--disable-dev-shm-usage", "--disable-gpu", "--disable-quic", "--no-first-run",
                "--disable-background-networking", "--disable-sync", "--disable-extensions",
                "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                "--webrtc-ip-handling-policy=disable_non_proxied_udp"
            ]
        });
        jobsSinceStart = 0;
        return browser;
    }

    async function capture({ url, kind }) {
        const b = await getBrowser();
        jobsSinceStart++;
        const context = await b.newContext({
            viewport: VIEWPORT, deviceScaleFactor: 1, javaScriptEnabled: true, acceptDownloads: false,
            serviceWorkers: "block", ignoreHTTPSErrors: true, locale: "en-US", permissions: [],
            userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
        });
        try {
            const page = await context.newPage();
            let requests = 0;
            await page.route("**/*", route => {
                const r = route.request();
                const u = r.url();
                if (!/^(https?:|data:|blob:)/i.test(u) || ++requests > MAX_REQUESTS_PER_PAGE || ["media", "websocket", "eventsource"].includes(r.resourceType())) return route.abort();
                return route.continue();
            });
            page.on("dialog", d => d.dismiss().catch(() => {}));
            let status = 0;
            try {
                const res = await page.goto(url, { waitUntil: "domcontentloaded", timeout: NAV_TIMEOUT });
                status = res ? res.status() : 0;
                // وكيل الحماية رفض الصفحة نفسها أو تحويلاً بالطريق (مثلاً لعنوان داخلي)
                if (res && res.headers()["x-pd-guard"] === "blocked") return { ok: false, error: "blocked" };
            } catch (error) {
                return { ok: false, error: /ERR_TUNNEL|ERR_PROXY|403/.test(String(error && error.message)) ? "blocked" : "nav_failed" };
            }
            await page.waitForLoadState("load", { timeout: 5000 }).catch(() => {});
            await page.waitForTimeout(800);
            const info = await page.evaluate(() => {
                const icon = document.querySelector('link[rel~="icon"], link[rel="shortcut icon"], link[rel="apple-touch-icon"]');
                return {
                    title: (document.title || "").slice(0, 200),
                    hasPassword: Boolean(document.querySelector('input[type="password"]')),
                    forms: document.forms.length,
                    icon: icon && icon.href ? icon.href : new URL("/favicon.ico", location.href).href,
                    finalUrl: location.href
                };
            }).catch(() => null);
            const shot = await page.screenshot({ type: "jpeg", quality: 62, clip: { x: 0, y: 0, ...VIEWPORT } });

            // الأيقونة: نعرضها بصفحة ثانية (نفس السياق فتمر من الوكيل) ونصوّر العنصر، فما نحتاج نقرا ملف الصورة
            let iconShot = null;
            if (info && /^https?:/i.test(info.icon)) {
                const p2 = await context.newPage();
                try {
                    await p2.setContent('<body style="margin:0;background:#fff"><img id="i" alt="" style="width:64px;height:64px;display:block"></body>');
                    const loaded = await p2.evaluate(src => new Promise(done => {
                        const el = document.getElementById("i");
                        el.onload = () => done(el.naturalWidth > 0);
                        el.onerror = () => done(false);
                        el.src = src;
                        setTimeout(() => done(false), 4000);
                    }), info.icon);
                    if (loaded) iconShot = await (await p2.$("#i")).screenshot({ type: "png" });
                } catch { /* الأيقونة اختيارية */ } finally {
                    await p2.close().catch(() => {});
                }
            }

            const hp = await context.newPage();
            await hp.route("**/*", route => route.abort());   // صفحة الحساب ما تطلب شي من الشبكة
            await hp.setContent("<body></body>");
            const pageHash = await hp.evaluate(computeHashes, "data:image/jpeg;base64," + shot.toString("base64"));
            const iconHash = iconShot ? await hp.evaluate(computeHashes, "data:image/png;base64," + iconShot.toString("base64")).catch(() => null) : null;
            return {
                ok: true, status, finalUrl: info ? info.finalUrl : url, title: info ? info.title : "",
                hasPassword: Boolean(info && info.hasPassword), forms: info ? info.forms : 0,
                page: pageHash, favicon: iconHash,
                screenshot: kind === "reference" ? undefined : shot.toString("base64")
            };
        } finally {
            await context.close().catch(() => {});
        }
    }

    async function pump() {
        if (running) return;
        running = true;
        while (queue.length) {
            const job = queue.shift();
            const t0 = Date.now();
            let timer;
            try {
                const out = await Promise.race([
                    capture(job),
                    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("timeout")), JOB_TIMEOUT); })
                ]);
                if (out.ok) stats.captured++; else stats.failed++;
                job.resolve({ ...out, ms: Date.now() - t0 });
            } catch (error) {
                stats.failed++;
                log("capture failed: " + String(error && error.message).slice(0, 120));
                if (String(error && error.message) === "timeout" && browser) { await browser.close().catch(() => {}); browser = null; }
                job.resolve({ ok: false, error: String(error && error.message) === "timeout" ? "timeout" : "failed", ms: Date.now() - t0 });
            } finally {
                clearTimeout(timer);
            }
        }
        running = false;
    }

    function enqueue(job) {
        return new Promise(resolve => {
            queue.push({ ...job, resolve });
            pump();
        });
    }

    const expected = Buffer.from("Bearer " + token);
    function authorized(req) {
        const got = Buffer.from(String(req.headers.authorization || ""));
        return got.length === expected.length && crypto.timingSafeEqual(got, expected);
    }

    function send(res, status, body) {
        const json = JSON.stringify(body);
        res.writeHead(status, { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(json), "Cache-Control": "no-store" });
        res.end(json);
    }

    const server = http.createServer(async (req, res) => {
        const path = new URL(req.url, "http://x").pathname;
        if (path === "/health" && req.method === "GET") {
            return send(res, 200, { ok: true, queue: queue.length, busy: running, ...stats, proxy: proxy.stats });
        }
        if (path !== "/capture" || req.method !== "POST") return send(res, 404, { error: "not found" });
        if (!authorized(req)) return send(res, 401, { error: "unauthorized" });
        let raw = "";
        for await (const chunk of req) {
            raw += chunk;
            if (raw.length > 4096) return send(res, 413, { error: "too large" });
        }
        let body;
        try { body = JSON.parse(raw); } catch { return send(res, 400, { error: "bad json" }); }
        let url;
        try { url = new URL(String(body.url || "")); } catch { return send(res, 400, { error: "bad url" }); }
        if (!/^https?:$/.test(url.protocol) || url.username || url.password) return send(res, 400, { error: "bad url" });
        if (queue.length >= maxQueue) {
            stats.rejected++;
            return send(res, 429, { ok: false, error: "busy" });
        }
        const out = await enqueue({ url: url.href, kind: body.kind === "reference" ? "reference" : "scan" });
        send(res, 200, out);
    });

    async function close() {
        await new Promise(r => server.close(r));
        if (browser) await browser.close().catch(() => {});
        await proxy.close();
    }

    return { server, close, stats, proxy };
}

module.exports = { createWorker };

if (require.main === module) {
    const { chromium } = require("playwright");
    const { isPublicIp } = require("../server/inspect.js");
    const worker = createWorker({
        token: process.env.VISUAL_WORKER_TOKEN || "",
        launch: opts => chromium.launch(opts),
        isAllowedIp: isPublicIp,
        maxQueue: Number(process.env.VISUAL_MAX_QUEUE) || 8,
        log: m => console.log(new Date().toISOString(), m)
    });
    const port = Number(process.env.PORT) || 8090;
    worker.server.listen(port, "0.0.0.0", () => console.log(`visual worker listening on ${port}`));
    const stop = () => worker.close().finally(() => process.exit(0));
    process.on("SIGTERM", stop);
    process.on("SIGINT", stop);
}
