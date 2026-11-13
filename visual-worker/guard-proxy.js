"use strict";

/*
  وكيل حماية (SSRF guard) يمر منه كل طلب يسويه المتصفح المخفي: الصفحة، التحويلات، الصور، السكربتات، WebSocket...

  ليش؟ المتصفح يحل أسماء النطاقات بنفسه ويتبع التحويلات، فلو تركناه حر ممكن صفحة خبيثة توديه لعنوان داخلي
  (169.254.169.254، 10.x، localhost...) وتقرا خدمات داخلية. هنا Chromium يشتغل بـ --proxy-server على هذا الوكيل،
  فما يوصل لأي مكان إلا من خلالنا، وإحنا:
    - نحل اسم النطاق بأنفسنا ونرفض إذا أي عنوان من عناوينه داخلي أو محجوز (isPublicIp من server/inspect.js)
    - نتصل بالعنوان اللي فحصناه بالضبط (DNS pinning) فما ينفع تبديل DNS بين الفحص والاتصال (rebinding)
    - نسمح بمنافذ الويب فقط
  HTTPS يمر كنفق CONNECT فالتشفير يبقى بين المتصفح والموقع، والمتصفح نفسه يتحقق من الشهادة.
*/

const http = require("node:http");
const net = require("node:net");
const dns = require("node:dns");

const DEFAULT_PORTS = new Set([80, 443, 8080, 8443]);

function createGuardProxy({ isAllowedIp, allowedPorts = DEFAULT_PORTS, lookup = dns.promises.lookup, idleMs = 20_000 } = {}) {
    if (typeof isAllowedIp !== "function") throw new Error("isAllowedIp required");
    const stats = { allowed: 0, blocked: 0 };

    // يرجع عنواناً مسموحاً للاتصال، أو null
    async function resolve(host) {
        const bare = host.replace(/^\[|\]$/g, "");
        if (net.isIP(bare)) return isAllowedIp(bare) ? bare : null;
        if (!/^[a-z0-9.-]{1,253}$/i.test(bare) || /^localhost$|\.localhost$|\.local$|\.internal$/i.test(bare)) return null;
        let addresses;
        try {
            addresses = await lookup(bare, { all: true, verbatim: true });
        } catch {
            return null;
        }
        if (!addresses.length || addresses.some(a => !isAllowedIp(a.address))) return null;
        const v4 = addresses.find(a => a.family === 4);
        return (v4 || addresses[0]).address;
    }

    function deny(res, code = 403) {
        stats.blocked++;
        res.writeHead(code, { "Content-Type": "text/plain", Connection: "close", "X-PD-Guard": "blocked" });
        res.end("blocked");
    }

    // طلبات HTTP العادية (المتصفح يرسل الرابط كاملاً للوكيل)
    const server = http.createServer(async (req, res) => {
        let url;
        try { url = new URL(req.url); } catch { return deny(res, 400); }
        if (url.protocol !== "http:") return deny(res, 400);
        const port = Number(url.port || 80);
        if (!allowedPorts.has(port)) return deny(res);
        const ip = await resolve(url.hostname);
        if (!ip) return deny(res);
        stats.allowed++;
        const headers = { ...req.headers, host: url.host };
        delete headers["proxy-connection"];
        delete headers["proxy-authorization"];
        const upstream = http.request({ host: ip, port, method: req.method, path: url.pathname + url.search, headers, setHost: false, timeout: idleMs }, up => {
            res.writeHead(up.statusCode || 502, up.headers);
            up.pipe(res);
        });
        upstream.on("timeout", () => upstream.destroy());
        upstream.on("error", () => { if (!res.headersSent) res.writeHead(502); res.end(); });
        req.pipe(upstream);
    });

    // HTTPS و WebSocket الآمن: نفق CONNECT
    server.on("connect", async (req, client, head) => {
        client.on("error", () => {});
        const m = /^(\[[^\]]+\]|[^:]+):(\d{1,5})$/.exec(String(req.url || ""));
        const port = m ? Number(m[2]) : 0;
        const ip = m && allowedPorts.has(port) ? await resolve(m[1]) : null;
        if (!ip) {
            stats.blocked++;
            client.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n");
            return;
        }
        stats.allowed++;
        const upstream = net.connect(port, ip, () => {
            client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
            if (head && head.length) upstream.write(head);
            upstream.pipe(client);
            client.pipe(upstream);
        });
        upstream.setTimeout(idleMs, () => upstream.destroy());
        client.setTimeout(idleMs, () => client.destroy());
        upstream.on("error", () => client.destroy());
        client.on("close", () => upstream.destroy());
    });

    server.on("clientError", (_e, socket) => socket.destroy());

    function listen() {
        return new Promise(resolveListen => server.listen(0, "127.0.0.1", () => resolveListen(server.address().port)));
    }

    return { server, listen, close: () => new Promise(r => server.close(r)), stats, resolve };
}

module.exports = { createGuardProxy, DEFAULT_PORTS };
