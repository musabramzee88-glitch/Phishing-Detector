"use strict";

/*
  الزيارة الآمنة للرابط + معلومات الاستضافة (تعمل على الخادم فقط).

  1) هل الموقع موجود؟  DNS: النطاق مسجّل وله عنوان؟ والخادم يرد؟
  2) زيارة آمنة: نطلب الصفحة من خادمنا (بدون تشغيل JavaScript وبدون كوكيز)، نتبع التحويلات بأنفسنا،
     ونستخرج حقائق فقط: العنوان، نص مختصر، حقول كلمة السر/البطاقة/الرمز، وين ترسل النماذج بياناتها،
     إرسال البيانات لبوت تيليجرام، الشعارات المسحوبة من الموقع الرسمي، التمويه، تنزيل ملفات APK/EXE...
     HTML الصفحة نفسه لا يصل للمتصفح أبداً.
  3) الاستضافة: رقم الشبكة (ASN) والشركة والدولة المسجّل بيها عنوان الخادم، عبر DNS من Team Cymru
     (مجاني، بدون مفتاح، ولا نرسل الرابط لأي جهة: فقط عنوان IP).

  الحماية من SSRF (استغلال خادمنا للوصول لشبكات داخلية):
  - نحلّ النطاق بأنفسنا ونرفض أي عنوان خاص/داخلي/محلي (127.x, 10.x, 169.254.x, ::1, fc00::/7 ...)،
    ثم نتصل بنفس العنوان الذي فحصناه (يمنع DNS rebinding).
  - كل تحويل (redirect) يُفحص من جديد، وبحد 5 تحويلات، والمنافذ 80/443/8080/8443 فقط.
  - مهلة كلية، وحد أقصى لحجم الصفحة، وحد للزيارات المتزامنة.

  ملاحظة صياغة: دولة الاستضافة هي مكان تسجيل عنوان الخادم، وليست مكان المحتال.
*/

const dns = require("node:dns");
const net = require("node:net");
const http = require("node:http");
const https = require("node:https");
const zlib = require("node:zlib");
const engine = require("../public/js/detection-engine.js");

const MAX_REDIRECTS = 5;
const MAX_BODY = 600 * 1024;
const TOTAL_TIMEOUT_MS = 10_000;
const HOP_TIMEOUT_MS = 7_000;
const ALLOWED_PORTS = new Set([80, 443, 8080, 8443]);
const MAX_CONCURRENT = 8;
const CACHE_MS = 10 * 60_000;
const HOSTING_CACHE_MS = 6 * 60 * 60_000;
const USER_AGENT = "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Mobile Safari/537.36";

// شبكات توصيل وحماية تخفي الخادم الحقيقي (وجودها وحده ليس مؤشر خطر)
const CDN_ORGS = /cloudflare|akamai|fastly|incapsula|imperva|sucuri|ddos-guard|stackpath|edgecast|cdn77|bunny|gcore|cloudfront/i;

// ---------------------------------------------------------------- عناوين IP

function ipv4ToInt(ip) {
    return ip.split(".").reduce((n, o) => (n * 256) + Number(o), 0);
}

const PRIVATE_V4 = [
    ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16],
    ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16],
    ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]
].map(([base, bits]) => ({ base: ipv4ToInt(base), mask: bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0 }));

function expandIpv6(ip) {
    let value = ip.toLowerCase().split("%")[0];
    // ::ffff:1.2.3.4 ← آخر جزأين
    const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(value);
    if (v4) {
        const n = ipv4ToInt(v4[1]);
        value = value.slice(0, -v4[1].length) + ((n >>> 16) & 0xffff).toString(16) + ":" + (n & 0xffff).toString(16);
    }
    const [head, tail] = value.split("::");
    const h = head ? head.split(":") : [];
    const t = tail !== undefined ? (tail ? tail.split(":") : []) : [];
    const missing = 8 - h.length - t.length;
    const groups = tail !== undefined ? [...h, ...Array(Math.max(0, missing)).fill("0"), ...t] : h;
    return groups.map(g => g.padStart(4, "0"));
}

// عنوان عام على الإنترنت؟ (أي عنوان خاص أو محلي أو محجوز = لا)
function isPublicIp(ip) {
    const family = net.isIP(ip);
    if (family === 4) {
        const n = ipv4ToInt(ip);
        return !PRIVATE_V4.some(r => ((n & r.mask) >>> 0) === r.base);
    }
    if (family === 6) {
        const g = expandIpv6(ip);
        if (g.length !== 8) return false;
        const first = parseInt(g[0], 16);
        if (g.every(x => x === "0000") || g.slice(0, 7).every(x => x === "0000")) return false;   // :: و ::1
        if (g.slice(0, 5).every(x => x === "0000") && g[5] === "ffff") {
            // ::ffff:a.b.c.d
            const n = parseInt(g[6], 16) * 65536 + parseInt(g[7], 16);
            return isPublicIp([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join("."));
        }
        if ((first & 0xfe00) === 0xfc00) return false;    // fc00::/7 خاص
        if ((first & 0xffc0) === 0xfe80) return false;    // fe80::/10 محلي
        if ((first & 0xff00) === 0xff00) return false;    // متعدد البث
        if (g[0] === "2001" && g[1] === "0db8") return false;   // للتوثيق
        if (g[0] === "0064" && g[1] === "ff9b") return false;   // NAT64
        return (first & 0xe000) === 0x2000;               // 2000::/3 فقط هو العام
    }
    return false;
}

// ---------------------------------------------------------------- أدوات HTML

const ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };
function decodeEntities(text) {
    return String(text).replace(/&(#x[0-9a-f]{1,6}|#\d{1,7}|[a-z]{2,6});/gi, (m, e) => {
        if (e[0] === "#") {
            const code = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
            return code > 0 && code < 0x110000 ? String.fromCodePoint(code) : "";
        }
        return ENTITIES[e.toLowerCase()] !== undefined ? ENTITIES[e.toLowerCase()] : m;
    });
}

const cleanLine = (text, max) => decodeEntities(text)
    .replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069]/g, " ")
    .replace(/\s+/g, " ").trim().slice(0, max);

function attr(tag, name) {
    const m = new RegExp("\\s" + name + "\\s*=\\s*(\"[^\"]*\"|'[^']*'|[^\\s>]+)", "i").exec(tag);
    return m ? decodeEntities(m[1].replace(/^["']|["']$/g, "")).trim() : "";
}

function registrableOf(host) {
    const clean = String(host || "").toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
    if (!clean || net.isIP(clean)) return clean;
    return engine.splitDomain(clean).registrable;
}

function resolveUrl(value, base) {
    try {
        const u = new URL(value, base);
        return /^https?:$/.test(u.protocol) ? u : null;
    } catch {
        return null;
    }
}

const CARD_FIELD = /(card.?num|cc-?num|cardnumber|cc-number|credit.?card|\bcvv|\bcvc|cc-csc|cc-exp|expir|card.?holder|رقم البطاقة|رقم الكارت)/i;
const OTP_FIELD = /(\botp\b|one-time-code|verif\w*.?code|sms.?code|\bpin\b|passcode|رمز التحقق|رمز التأكيد|الرمز السري|كود التحقق)/i;
const EMAIL_FIELD = /(e-?mail|username|user.?name|login|البريد|اسم المستخدم|رقم الهاتف|phone)/i;

// يحلل HTML ويرجع حقائق فقط (بدون أي HTML)
function analyzeHtml(html, pageUrl) {
    const lower = html.toLowerCase();
    const titleMatch = /<title[^>]*>([\s\S]{0,400}?)<\/title>/i.exec(html);
    const title = titleMatch ? cleanLine(titleMatch[1], 160) : "";
    const descTag = /<meta\b[^>]*name\s*=\s*["']?description["']?[^>]*>/i.exec(html);
    const description = descTag ? cleanLine(attr(descTag[0], "content"), 200) : "";

    // النص الظاهر تقريباً: نحذف السكربتات والأنماط والوسوم
    const text = cleanLine(html
        .replace(/<(script|style|noscript|template|svg)\b[\s\S]*?<\/\1>/gi, " ")
        .replace(/<!--[\s\S]*?-->/g, " ")
        .replace(/<[^>]+>/g, " "), 4000);

    const pageHost = pageUrl.hostname.toLowerCase();
    const pageReg = registrableOf(pageHost);

    const inputs = html.match(/<input\b[^>]*>/gi) || [];
    let password = 0, card = 0, otp = 0, identity = 0;
    for (const tag of inputs.slice(0, 300)) {
        const type = attr(tag, "type").toLowerCase();
        if (["hidden", "submit", "button", "checkbox", "radio", "image", "reset", "file"].includes(type)) continue;
        const hint = [attr(tag, "name"), attr(tag, "id"), attr(tag, "autocomplete"), attr(tag, "placeholder"), attr(tag, "aria-label")].join(" ");
        if (type === "password") password++;
        else if (CARD_FIELD.test(hint)) card++;
        else if (OTP_FIELD.test(hint)) otp++;
        else if (type === "email" || type === "tel" || EMAIL_FIELD.test(hint)) identity++;
    }

    const forms = [];
    for (const tag of (html.match(/<form\b[^>]*>/gi) || []).slice(0, 30)) {
        const raw = attr(tag, "action");
        const target = raw ? resolveUrl(raw, pageUrl) : pageUrl;
        const mailto = /^mailto:/i.test(raw);
        const host = target ? target.hostname.toLowerCase() : "";
        forms.push({
            method: (attr(tag, "method") || "get").toLowerCase().slice(0, 6),
            host: mailto ? "mailto" : host.slice(0, 120),
            external: mailto || Boolean(host && registrableOf(host) !== pageReg),
            insecure: Boolean(target && target.protocol === "http:")
        });
    }

    // موارد تُسحب من نطاقات رسمية لعلامات معروفة (شعار/أيقونة/أنماط) بينما الصفحة على نطاق آخر
    const hotlinked = new Set();
    for (const m of html.matchAll(/<(?:img|link|script)\b[^>]*\s(?:src|href)\s*=\s*["']?(https?:\/\/[^"'\s>]{4,300})/gi)) {
        const u = resolveUrl(m[1], pageUrl);
        if (!u) continue;
        const official = engine.officialBrandFor(u.hostname.toLowerCase().replace(/^www\./, ""));
        if (official && !engine.officialBrandFor(pageHost.replace(/^www\./, ""))) hotlinked.add(official.brand.name);
        if (hotlinked.size >= 3) break;
    }

    // التحويل من داخل الصفحة (meta refresh أو JavaScript)
    let redirectTo = "";
    const refresh = /<meta\b[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*>/i.exec(html);
    if (refresh) {
        const m = /url\s*=\s*['"]?([^'">\s]+)/i.exec(attr(refresh[0], "content"));
        if (m) redirectTo = m[1];
    }
    if (!redirectTo) {
        const js = /(?:window|document|top|self)\.location(?:\.href)?\s*=\s*["'](https?:\/\/[^"']{4,300})["']|location\.(?:replace|assign)\(\s*["'](https?:\/\/[^"']{4,300})["']/i.exec(html);
        if (js) redirectTo = js[1] || js[2];
    }
    const redirectUrl = redirectTo ? resolveUrl(redirectTo, pageUrl) : null;

    const obfuscationHits = (lower.match(/\beval\s*\(|\batob\s*\(|\bunescape\s*\(|string\.fromcharcode|document\.write\s*\(|\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}/g) || []).length;
    const longBlob = /["'][A-Za-z0-9+/=]{3000,}["']/.test(html.slice(0, 300_000));

    return {
        title, description,
        excerpt: text.slice(0, 240),
        textForBrands: (title + " " + description + " " + text.slice(0, 1500)),
        fields: { password, card, otp, identity },
        forms: forms.slice(0, 10),
        hotlinked: [...hotlinked],
        redirectTo: redirectUrl ? redirectUrl.href.slice(0, 300) : "",
        exfil: /api\.telegram\.org\/bot|discord(?:app)?\.com\/api\/webhooks|hooks\.slack\.com\/services/i.test(html),
        obfuscated: obfuscationHits >= 4 || longBlob,
        iframes: (html.match(/<iframe\b/gi) || []).length,
        parked: /(domain (?:is )?for sale|buy this domain|parked (?:free|domain)|هذا النطاق للبيع|this domain may be for sale)/i.test(text.slice(0, 2000)),
        emptyShell: text.length < 40 && /<script\b/i.test(html)
    };
}

// ---------------------------------------------------------------- الطلب الآمن

function decodeBody(buffer, encoding, contentType) {
    let body = buffer;
    try {
        if (/\bgzip\b/.test(encoding)) body = zlib.gunzipSync(buffer, { maxOutputLength: MAX_BODY * 4 });
        else if (/\bbr\b/.test(encoding)) body = zlib.brotliDecompressSync(buffer, { maxOutputLength: MAX_BODY * 4 });
        else if (/\bdeflate\b/.test(encoding)) body = zlib.inflateSync(buffer, { maxOutputLength: MAX_BODY * 4 });
    } catch {
        body = buffer;
    }
    body = body.subarray(0, MAX_BODY * 2);
    const head = body.subarray(0, 2048).toString("latin1");
    const charset = (/charset\s*=\s*["']?([\w-]+)/i.exec(contentType || "") || /<meta[^>]+charset\s*=\s*["']?([\w-]+)/i.exec(head) || [])[1] || "utf-8";
    try {
        return new TextDecoder(charset.toLowerCase(), { fatal: false }).decode(body);
    } catch {
        return body.toString("utf8");
    }
}

const TLS_ERRORS = /CERT|SELF_SIGNED|UNABLE_TO_VERIFY|ALTNAME|ERR_TLS/i;

function createInspector({
    enabled = true,
    lookup = (host) => dns.promises.lookup(host, { all: true, verbatim: true }),
    resolveTxt = (name) => dns.promises.resolveTxt(name),
    isAllowedIp = isPublicIp,
    allowedPorts = ALLOWED_PORTS,   // للاختبارات فقط
    now = () => Date.now()
} = {}) {
    let active = 0;
    const cache = new Map();         // url -> { at, value }
    const hostingCache = new Map();  // ip|AS -> { at, value }

    // ------------------------------------------------ الاستضافة (Team Cymru عبر DNS)
    function withTimeout(promise, ms) {
        let timer;
        return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("timeout")), ms); })])
            .finally(() => clearTimeout(timer));
    }

    async function txt(name) {
        const records = await withTimeout(resolveTxt(name), 3000);
        return (Array.isArray(records) && records[0] ? [].concat(records[0]).join("") : "").split("|").map(s => s.trim());
    }

    async function hosting(ip) {
        const hit = hostingCache.get(ip);
        if (hit && now() - hit.at < HOSTING_CACHE_MS) return hit.value;
        let value = null;
        try {
            const family = net.isIP(ip);
            const reversed = family === 4
                ? ip.split(".").reverse().join(".") + ".origin.asn.cymru.com"
                : expandIpv6(ip).join("").split("").reverse().join(".") + ".origin6.asn.cymru.com";
            const [asn, prefix, country] = await txt(reversed);
            if (/^\d+/.test(asn || "")) {
                const asNumber = asn.split(" ")[0];
                const asKey = "AS" + asNumber;
                let org = "";
                const orgHit = hostingCache.get(asKey);
                if (orgHit && now() - orgHit.at < HOSTING_CACHE_MS) org = orgHit.value;
                else {
                    const fields = await txt(asKey + ".asn.cymru.com").catch(() => []);
                    org = cleanLine(fields[4] || "", 80);
                    hostingCache.set(asKey, { at: now(), value: org });
                }
                const cc = /^[A-Z]{2}$/.test(country || "") ? country : "";
                value = { asn: Number(asNumber), prefix: String(prefix || "").slice(0, 50), country: cc, countryName: countryName(cc), org, cdn: CDN_ORGS.test(org) };
            }
        } catch {
            value = null;
        }
        if (hostingCache.size > 5000) hostingCache.delete(hostingCache.keys().next().value);
        hostingCache.set(ip, { at: now(), value });
        return value;
    }

    // ------------------------------------------------ DNS مع فحص العناوين
    async function resolveSafe(hostname) {
        const host = hostname.replace(/^\[|\]$/g, "");
        if (net.isIP(host)) {
            if (!isAllowedIp(host)) return { blocked: true };
            return { address: host, family: net.isIP(host) };
        }
        let list;
        try {
            list = await withTimeout(lookup(host), 4000);
        } catch (error) {
            const code = error && error.code;
            if (code === "ENOTFOUND" || code === "ENODATA") return { nxdomain: true };
            return { dnsError: true };
        }
        const addresses = (Array.isArray(list) ? list : [list]).filter(a => a && a.address);
        if (!addresses.length) return { nxdomain: true };
        // إذا كان أي عنوان داخلياً نرفض كلياً (نطاق يشير لشبكة داخلية = محاولة استغلال أو إعداد مريب)
        if (addresses.some(a => !isAllowedIp(a.address))) return { blocked: true };
        const v4 = addresses.find(a => a.family === 4) || addresses[0];
        return { address: v4.address, family: v4.family || net.isIP(v4.address) };
    }

    // طلب واحد (بدون تتبع التحويلات) إلى عنوان IP مُتحقَّق منه مسبقاً
    function requestOnce(url, target, insecureTls, deadline) {
        return new Promise((resolve, reject) => {
            const isHttps = url.protocol === "https:";
            const lib = isHttps ? https : http;
            const hostname = url.hostname.replace(/^\[|\]$/g, "");
            const options = {
                method: "GET",
                host: hostname,
                port: url.port || (isHttps ? 443 : 80),
                path: (url.pathname || "/") + url.search,
                headers: {
                    "User-Agent": USER_AGENT,
                    Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "ar,en;q=0.8",
                    "Accept-Encoding": "gzip, deflate, br"
                },
                // نتصل بالعنوان الذي فحصناه نفسه (يمنع تغيير DNS بين الفحص والاتصال)
                lookup: (_h, opts, cb) => (opts && opts.all ? cb(null, [{ address: target.address, family: target.family }]) : cb(null, target.address, target.family)),
                timeout: Math.max(500, Math.min(HOP_TIMEOUT_MS, deadline - Date.now())),
                agent: false
            };
            if (isHttps) {
                options.rejectUnauthorized = !insecureTls;
                if (!net.isIP(hostname)) options.servername = hostname;
            }
            const req = lib.request(options, res => {
                const chunks = [];
                let size = 0;
                const type = String(res.headers["content-type"] || "").toLowerCase();
                const isHtml = /html|xml|text\/plain/.test(type) || !type;
                const tlsInfo = isHttps && res.socket && typeof res.socket.getPeerCertificate === "function" ? res.socket.getPeerCertificate() : null;
                const finish = () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks), cert: tlsInfo });
                if (res.statusCode >= 300 && res.statusCode < 400) { res.resume(); return finish(); }
                if (!isHtml) { res.destroy(); return finish(); }   // ملف: نكتفي بالترويسات
                res.on("data", chunk => {
                    size += chunk.length;
                    if (size > MAX_BODY) { chunks.push(chunk.subarray(0, Math.max(0, chunk.length - (size - MAX_BODY)))); res.destroy(); finish(); return; }
                    chunks.push(chunk);
                });
                res.on("end", finish);
                res.on("error", finish);
            });
            req.on("timeout", () => req.destroy(Object.assign(new Error("timeout"), { code: "ETIMEDOUT" })));
            req.on("error", reject);
            req.end();
        });
    }

    // ------------------------------------------------ الزيارة الكاملة
    async function visit(startUrl) {
        const deadline = Date.now() + TOTAL_TIMEOUT_MS;
        const chain = [];
        let url = startUrl;
        let tls = null;
        let firstAddress = "";
        for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
            // DNS أولاً (آمن: استعلام فقط) حتى نعرف هل النطاق موجود أصلاً، ثم نقرر هل نتصل
            const target = await resolveSafe(url.hostname);
            if (target.nxdomain) return { ok: false, reason: hop === 0 ? "nxdomain" : "redirect_nxdomain", chain, url };
            if (target.dnsError) return { ok: false, reason: "dns", chain, url };
            if (target.blocked) return { ok: false, reason: "blocked", chain, url };
            const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
            if (!allowedPorts.has(port)) return { ok: false, reason: "port", chain, url };
            if (!firstAddress) firstAddress = target.address;
            if (Date.now() > deadline) return { ok: false, reason: "timeout", chain, url, address: firstAddress };

            let response;
            try {
                response = await requestOnce(url, target, false, deadline);
                if (url.protocol === "https:" && hop === 0) tls = { valid: true };
            } catch (error) {
                const code = String(error && (error.code || error.message) || "");
                if (url.protocol === "https:" && TLS_ERRORS.test(code)) {
                    if (hop === 0 || !tls) tls = { valid: false, error: code.slice(0, 60) };
                    try {
                        response = await requestOnce(url, target, true, deadline);
                    } catch (second) {
                        return { ok: false, reason: networkReason(second), chain, url, address: firstAddress, tls };
                    }
                } else {
                    return { ok: false, reason: networkReason(error), chain, url, address: firstAddress, tls };
                }
            }

            chain.push({ url: url.href.slice(0, 300), status: response.status });
            const location = response.headers.location;
            if (response.status >= 300 && response.status < 400 && location) {
                const next = resolveUrl(String(location), url);
                if (!next) return { ok: true, url, response, chain, address: firstAddress, tls };
                url = next;
                continue;
            }
            return { ok: true, url, response, chain, address: firstAddress, tls };
        }
        return { ok: false, reason: "too_many_redirects", chain, url, address: firstAddress, tls };
    }

    function networkReason(error) {
        const code = String(error && (error.code || error.message) || "");
        if (/ETIMEDOUT|timeout/i.test(code)) return "timeout";
        if (/ECONNREFUSED/.test(code)) return "refused";
        if (/ECONNRESET|EPIPE|socket hang up/i.test(code)) return "reset";
        return "unreachable";
    }

    // ------------------------------------------------ الحكم
    // analysis: نتيجة المحرك للرابط (فيها host و brand و official)
    async function inspect(rawUrl, analysis = {}) {
        if (!enabled) return null;
        let start;
        try { start = new URL(rawUrl); } catch { return null; }
        if (!/^https?:$/.test(start.protocol)) return null;
        start.hash = "";
        start.username = "";
        start.password = "";

        const key = start.href;
        const hit = cache.get(key);
        if (hit && now() - hit.at < CACHE_MS) return hit.value;
        if (active >= MAX_CONCURRENT) return { visited: false, reason: "busy", signals: [] };

        active++;
        let value;
        try {
            value = await buildReport(start, analysis);
        } catch {
            value = { visited: false, reason: "failed", signals: [] };
        } finally {
            active--;
        }
        if (cache.size > 2000) cache.delete(cache.keys().next().value);
        if (value.reason !== "busy") cache.set(key, { at: now(), value });
        return value;
    }

    async function buildReport(start, analysis) {
        const signals = [];
        const add = (weight, type, text) => signals.push({ weight, type, text });
        const result = await visit(start);
        const out = {
            visited: Boolean(result.ok),
            exists: true,
            reason: result.ok ? "" : result.reason,
            status: result.response ? result.response.status : 0,
            finalUrl: result.url ? result.url.href.slice(0, 300) : start.href,
            redirects: Math.max(0, (result.chain || []).length - 1),
            chain: (result.chain || []).slice(0, 6),
            https: Boolean(result.url && result.url.protocol === "https:"),
            tls: result.tls,
            hosting: null,
            page: null,
            download: null,
            signals
        };

        if (result.reason === "nxdomain") {
            out.exists = false;
            add(0, "info", "النطاق غير موجود حالياً: ما إله أي عنوان على الإنترنت (يا إما ما مسجّل، أو انحذف، أو أغلقوه بعد التبليغ عنه).");
            return out;
        }
        if (result.reason === "redirect_nxdomain") add(0.15, "warning", "الرابط يحوّل لنطاق غير موجود.");
        if (result.reason === "blocked") {
            add(0.45, "danger", "الرابط يشير لعنوان داخلي أو محلي (مثل 127.0.0.1 أو شبكة خاصة). المواقع الحقيقية ما تسوي هيج، وغالباً هي محاولة استغلال.");
            return out;
        }
        if (result.reason === "port") {
            add(0.2, "warning", "الرابط يستخدم منفذاً غير معتاد للمواقع، فما زرناه.");
            return out;
        }

        // الاستضافة (لا نوقف التقرير إذا فشلت)
        if (result.address) out.hosting = await hosting(result.address).then(h => (h ? { ip: result.address, ...h } : { ip: result.address }), () => ({ ip: result.address }));

        if (!result.ok) {
            const why = { timeout: "ما رد الخادم خلال المهلة", refused: "الخادم رفض الاتصال", reset: "الخادم قطع الاتصال", unreachable: "تعذر الوصول للخادم", dns: "تعذر الاستعلام عن النطاق", too_many_redirects: "تحويلات كثيرة متتالية" }[result.reason] || "تعذر فتح الصفحة";
            add(result.reason === "too_many_redirects" ? 0.2 : 0, result.reason === "too_many_redirects" ? "warning" : "info", `ما كدرنا نفتح الصفحة: ${why}. النطاق موجود، بس الموقع ممكن يكون متوقف أو يحجب الزوار الآليين.`);
            if (out.tls && out.tls.valid === false) add(0.2, "warning", "شهادة الأمان (HTTPS) لهذا الموقع غير صالحة أو مزيفة.");
            return out;
        }

        const response = result.response;
        const finalUrl = result.url;
        const finalHost = finalUrl.hostname.toLowerCase().replace(/^www\./, "");
        const startReg = registrableOf(start.hostname);
        const finalReg = registrableOf(finalHost);
        const finalOfficial = engine.officialBrandFor(finalHost);

        if (out.tls && out.tls.valid === false) add(0.25, "warning", "شهادة الأمان (HTTPS) لهذا الموقع غير صالحة أو منتهية أو صادرة لنطاق آخر. المواقع الرسمية ما تكون هيج.");

        // التحويل لنطاق آخر: نحلل الوجهة النهائية بالمحرك أيضاً
        if (finalReg && startReg && finalReg !== startReg) {
            const dest = engine.analyzeUrl(finalUrl.href);
            if (!dest.error && dest.level === "danger") add(Math.min(0.85, dest.score / 100), "danger", `الرابط يحوّلك إلى ${finalHost}، وهذا النطاق نفسه خطر حسب الفحص (${dest.score}%).`);
            else if (!dest.error && dest.level === "warning") add(0.25, "warning", `الرابط يحوّلك إلى نطاق ثاني: ${finalHost} (بيه مؤشرات تستدعي الحذر).`);
            else add(0, "info", `الرابط يحوّلك إلى: ${finalHost}${dest.official ? " (نطاق رسمي لـ " + dest.official + ")" : ""}.`);
        }
        if (out.redirects >= 4) add(0.12, "warning", `الرابط يمر بـ ${out.redirects} تحويلات قبل ما يوصل. سلاسل التحويل الطويلة تُستخدم لإخفاء الوجهة.`);

        const type = String(response.headers["content-type"] || "").toLowerCase();
        const disposition = String(response.headers["content-disposition"] || "");
        const fileName = (/filename\*?=(?:utf-8'')?["']?([^"';]+)/i.exec(disposition) || [])[1] || decodeURIComponent(finalUrl.pathname.split("/").pop() || "");
        const isHtml = /html|xml|text\/plain/.test(type) || (!type && response.body.length);

        if (response.status >= 400) {
            add(0, "info", response.status === 404 || response.status === 410
                ? `الصفحة غير موجودة على الخادم (${response.status}). ممكن انحذفت بعد التبليغ عنها، أو الرابط غلط.`
                : `الخادم رد بخطأ (${response.status}).`);
        }

        // تنزيل ملف مباشر (أخطرها APK و EXE: أسلوب شائع لسرقة الحسابات والبنوك)
        if (!isHtml || /attachment/i.test(disposition)) {
            const ext = (/\.([a-z0-9]{2,5})$/i.exec(fileName) || [])[1] || "";
            out.download = { type: type.slice(0, 80), name: cleanLine(fileName, 80), ext: ext.toLowerCase() };
            if (/^(apk|xapk|exe|scr|msi|bat|cmd|ps1|vbs|js|jar|dmg|pkg|lnk|hta|iso)$/i.test(ext) || /android\.package-archive|x-msdownload|x-msdos-program/.test(type)) {
                add(0.55, "danger", `الرابط ينزّل ملف تطبيق/برنامج مباشرة (${ext ? "." + ext : type}). لا تنصّبه: تطبيقات الاحتيال تُرسل بهذي الطريقة لسرقة الحسابات والرسائل.`);
            } else {
                add(0, "info", `الرابط ينزّل ملفاً (${out.download.name || type || "غير معروف"}). افحصه بقسم فحص الملفات قبل فتحه.`);
            }
            return out;
        }

        const html = decodeBody(response.body, String(response.headers["content-encoding"] || ""), type);
        const page = analyzeHtml(html, finalUrl);
        out.page = {
            title: page.title, description: page.description, excerpt: page.excerpt,
            fields: page.fields, forms: page.forms.map(f => ({ host: f.host, external: f.external, method: f.method })),
            hotlinked: page.hotlinked, redirectTo: page.redirectTo, exfil: page.exfil, obfuscated: page.obfuscated, parked: page.parked
        };

        // العلامات التي تدّعيها الصفحة (بالعنوان والنص) مقابل النطاق الحقيقي
        const latin = page.textForBrands.toLowerCase();
        const arabic = engine.normalizeArabic(page.textForBrands);
        const claimed = engine.brandsMentioned(latin, arabic)
            .filter(b => !(finalOfficial && finalOfficial.brand === b) && b.domains.length);
        const titleBrands = engine.brandsMentioned(page.title.toLowerCase(), engine.normalizeArabic(page.title))
            .filter(b => !(finalOfficial && finalOfficial.brand === b));
        const isSite = engine.isSiteHost ? engine.isSiteHost(finalHost) : false;
        const asksSecrets = page.fields.password + page.fields.card + page.fields.otp > 0;
        const claimedBrand = titleBrands[0] || (asksSecrets ? claimed[0] : null) || (analysis.brand ? { name: analysis.brand, domains: [] } : null);
        out.page.claims = claimedBrand ? claimedBrand.name : "";

        if (!finalOfficial && !isSite) {
            if (page.exfil) add(0.75, "danger", "كود الصفحة يرسل البيانات مباشرة لبوت تيليجرام أو Discord. هذا أسلوب مميز لعُدّة التصيد الجاهزة: أي شي تكتبه يوصل للمحتال فوراً.");
            if (claimedBrand && page.fields.password) add(0.65, "danger", `الصفحة تعرض نفسها كـ «${claimedBrand.name}» وتطلب كلمة السر، لكنها مو على نطاقه الرسمي.`);
            else if (claimedBrand && (page.fields.card || page.fields.otp)) add(0.6, "danger", `الصفحة تعرض نفسها كـ «${claimedBrand.name}» وتطلب ${page.fields.card ? "بيانات البطاقة" : "رمز التحقق"}، لكنها مو على نطاقه الرسمي.`);
            else if (titleBrands.length) add(0.18, "warning", `عنوان الصفحة يذكر «${titleBrands[0].name}» بينما الموقع مو تابع لها رسمياً.`);
            if (page.hotlinked.length) add(asksSecrets ? 0.35 : 0.15, asksSecrets ? "danger" : "warning", `الصفحة تسحب شعارات أو ملفات من الموقع الرسمي لـ «${page.hotlinked.join("، ")}» حتى تشبهه، وهي مو تابعة له.`);
            if (page.fields.card && !claimedBrand) add(0.25, "warning", "الصفحة تطلب بيانات بطاقة مصرفية. لا تدخلها إلا بموقع تعرفه وكتبت عنوانه بنفسك.");
            if (page.fields.otp && !claimedBrand && !page.fields.password) add(0.15, "warning", "الصفحة تطلب رمز تحقق (OTP). الرمز لا يُعطى لأي موقع أو شخص وصلك برابط.");
            const externalForm = page.forms.find(f => f.external);
            if (externalForm && asksSecrets) add(0.35, "danger", `نموذج الدخول يرسل بياناتك إلى نطاق ثاني (${externalForm.host}) غير الموقع نفسه.`);
            if (asksSecrets && !out.https) add(0.3, "warning", "الصفحة تطلب كلمة سر أو بيانات حساسة بدون تشفير (HTTP).");
            if (page.obfuscated && asksSecrets) add(0.2, "warning", "كود الصفحة مموّه (مخفي بقصد) وهي تطلب بيانات حساسة.");
            if (page.redirectTo) {
                const to = resolveUrl(page.redirectTo, finalUrl);
                if (to && registrableOf(to.hostname) !== finalReg) {
                    const dest = engine.analyzeUrl(to.href);
                    add(!dest.error && dest.level === "danger" ? 0.5 : 0.1, !dest.error && dest.level === "danger" ? "danger" : "warning", `الصفحة تحوّلك تلقائياً إلى ${to.hostname}.`);
                }
            }
            if (page.emptyShell && !page.title) add(0.08, "warning", "الصفحة فارغة تقريباً ومحتواها يُبنى بالكامل بـ JavaScript (أسلوب يستخدم لإخفاء المحتوى عن أدوات الفحص).");
        }
        if (page.parked) add(0, "info", "النطاق معروض للبيع أو مركون (ما بيه موقع فعلي).");

        // الاستضافة مقابل الجهة التي تدّعيها الصفحة أو الرابط
        const h = out.hosting;
        if (h && h.country && !finalOfficial && !isSite) {
            const iraqiBrand = claimedBrand && (claimedBrand.domains || []).some(d => d.endsWith(".iq"));
            if (h.cdn) add(0, "info", `خادم الموقع مخفي خلف خدمة حماية/توصيل (${h.org.split(" - ").pop() || h.org})، فمكانه الحقيقي غير معروف.`);
            else if (iraqiBrand && h.country !== "IQ" && (asksSecrets || page.fields.identity)) add(0.15, "warning", `الصفحة تدّعي إنها لـ «${claimedBrand.name}» (جهة عراقية) لكن خادمها مسجّل في ${h.countryName || h.country}.`);
        }

        if (!signals.length && out.visited) add(0, "info", "زرنا الصفحة بأمان ولم نجد فيها حقول كلمة سر أو بطاقة، ولا انتحال واضح.");
        return out;
    }

    return { inspect, hosting, status: () => ({ enabled, active }) };
}

// اسم الدولة بالعربي من رمزها (ICU المدمج بـ Node)
let regionNames = null;
function countryName(code) {
    if (!code) return "";
    try {
        regionNames = regionNames || new Intl.DisplayNames(["ar"], { type: "region" });
        return regionNames.of(code) || code;
    } catch {
        return code;
    }
}

module.exports = { createInspector, isPublicIp, analyzeHtml, expandIpv6, countryName };
