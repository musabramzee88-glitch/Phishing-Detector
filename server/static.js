"use strict";

/*
  تقديم ملفات الموقع العامة من مجلد public/ فقط. أي مسار آخر يرجع 404.
  - ضغط Brotli أو gzip للملفات النصية (CSS / JS / SVG ...) يُحسب مرة ويُخزَّن بالذاكرة.
  - ETag لكل ملف، فالمتصفح يعيد استخدام نسخته (304) بدل تنزيلها من جديد.
  - الملفات المطلوبة برقم نسخة (?v=4.0.0) تُخزَّن سنة كاملة: تغيير الرقم بالصفحة يجبر التحديث.
*/

const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");
const { sendJson } = require("./http");

const MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".webp": "image/webp",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".woff2": "font/woff2",
    ".gz": "application/gzip",
    ".txt": "text/plain; charset=utf-8",
    ".xml": "application/xml; charset=utf-8",
    ".webmanifest": "application/manifest+json; charset=utf-8"
};
const CLEAN_PAGES = new Set(["/privacy", "/terms"]);
const COMPRESSIBLE = /^(text\/|application\/(json|xml|manifest\+json)|image\/svg\+xml)/;
const MAX_CACHED_FILE = 2 * 1024 * 1024;
const cache = new Map();   // path -> { mtimeMs, size, etag, raw, br, gzip }

// بصمة محتوى لكل ملف: /js/app.js?v=4.0.0 ← /js/app.js?v=<أول 10 من sha1>
// الملفات برقم نسخة تُخزَّن سنة بالمتصفح، فلو بقي الرقم ثابتاً بعد التحديث يبقى الزائر على النسخة القديمة.
// البصمة تتغير تلقائياً مع أي تعديل، فما نحتاج نتذكر نغيّر الرقم يدوياً.
const crypto = require("node:crypto");
const fingerprints = new Map();   // path -> { mtimeMs, hash }
function fingerprint(publicDir, assetPath) {
    const file = path.resolve(publicDir, "." + assetPath);
    if (!file.startsWith(publicDir + path.sep)) return "";
    try {
        const stat = fs.statSync(file);
        const hit = fingerprints.get(file);
        if (hit && hit.mtimeMs === stat.mtimeMs) return hit.hash;
        const hash = crypto.createHash("sha1").update(fs.readFileSync(file)).digest("hex").slice(0, 10);
        fingerprints.set(file, { mtimeMs: stat.mtimeMs, hash });
        return hash;
    } catch {
        return "";
    }
}

function versionAssets(html, publicDir) {
    return String(html).replace(/(["'])(\/(?:css|js|img|vendor)\/[\w./-]+)\?v=[\w.-]+\1/g, (m, q, asset) => {
        const hash = fingerprint(publicDir, asset);
        return hash ? `${q}${asset}?v=${hash}${q}` : m;
    });
}

let notFoundPage = null;
function sendNotFound(req, res, config) {
    // المتصفح يحصل على صفحة 404 مفهومة، وبرامج الـ API تحصل على JSON
    const wantsHtml = /text\/html/.test(String(req.headers.accept || ""));
    if (wantsHtml) {
        try {
            notFoundPage = notFoundPage || Buffer.from(versionAssets(fs.readFileSync(path.join(config.publicDir, "404.html"), "utf8"), config.publicDir));
            res.writeHead(404, { "Content-Type": "text/html; charset=utf-8", "Content-Length": notFoundPage.length, "Cache-Control": "no-cache" });
            res.end(req.method === "HEAD" ? undefined : notFoundPage);
            return;
        } catch { /* لا توجد صفحة 404: نكمل بـ JSON */ }
    }
    sendJson(res, 404, { error: "Not found" });
}

function pickEncoding(req) {
    const accept = String(req.headers["accept-encoding"] || "");
    if (/\bbr\b/.test(accept)) return "br";
    if (/\bgzip\b/.test(accept)) return "gzip";
    return "";
}

function loadEntry(candidate, stats, publicDir) {
    const cached = cache.get(candidate);
    if (cached && cached.mtimeMs === stats.mtimeMs && cached.size === stats.size) return cached;
    let raw = fs.readFileSync(candidate);
    if (candidate.endsWith(".html")) raw = Buffer.from(versionAssets(raw.toString("utf8"), publicDir));
    const entry = {
        mtimeMs: stats.mtimeMs,
        size: stats.size,
        etag: `"${stats.size.toString(36)}-${Math.floor(stats.mtimeMs).toString(36)}"`,
        raw,
        br: zlib.brotliCompressSync(raw, { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 11 } }),
        gzip: zlib.gzipSync(raw, { level: 9 })
    };
    cache.set(candidate, entry);
    return entry;
}

function serveStatic(req, res, pathname, config) {
    if (req.method !== "GET" && req.method !== "HEAD") {
        sendJson(res, 405, { error: "Method not allowed" }, { Allow: "GET, HEAD" });
        return;
    }

    let decoded;
    try {
        decoded = decodeURIComponent(pathname);
    } catch {
        sendJson(res, 400, { error: "Invalid path" });
        return;
    }
    if (decoded === "/") decoded = "/index.html";
    // روابط قصيرة للصفحات العامة: /privacy بدل /privacy.html
    if (CLEAN_PAGES.has(decoded.replace(/\/+$/, ""))) decoded = decoded.replace(/\/+$/, "") + ".html";

    // نرفض المحارف الخطرة والمسارات المخفية قبل أي تعامل مع نظام الملفات
    if (decoded.includes("\0") || decoded.includes("\\") || decoded.split("/").some(part => part.startsWith("."))) {
        sendNotFound(req, res, config);
        return;
    }

    const candidate = path.resolve(config.publicDir, "." + decoded);
    const contentType = MIME_TYPES[path.extname(candidate).toLowerCase()];
    if (!contentType || !candidate.startsWith(config.publicDir + path.sep)) {
        sendNotFound(req, res, config);
        return;
    }

    fs.stat(candidate, (error, stats) => {
        if (error || !stats.isFile()) {
            sendNotFound(req, res, config);
            return;
        }
        const versioned = /[?&]v=[\w.-]+/.test(req.url || "");
        const headers = {
            "Content-Type": contentType,
            // الصفحات تُراجع دائماً، والملفات برقم نسخة تُخزَّن سنة، والباقي يوماً مع إعادة تحقق
            // sw.js يتحدث فوراً مع كل نشر (المتصفح يقارنه بالنسخة المسجلة)
            "Cache-Control": contentType.startsWith("text/html") || decoded === "/sw.js" ? "no-cache"
                : versioned ? "public, max-age=31536000, immutable" : "public, max-age=86400, must-revalidate"
        };
        const compressible = COMPRESSIBLE.test(contentType) && stats.size <= MAX_CACHED_FILE;

        if (!compressible) {
            const etag = `"${stats.size.toString(36)}-${Math.floor(stats.mtimeMs).toString(36)}"`;
            if (req.headers["if-none-match"] === etag) {
                res.writeHead(304, { ETag: etag, "Cache-Control": headers["Cache-Control"] });
                res.end();
                return;
            }
            res.writeHead(200, { ...headers, ETag: etag, "Content-Length": stats.size });
            if (req.method === "HEAD") return res.end();
            fs.createReadStream(candidate).on("error", () => res.destroy()).pipe(res);
            return;
        }

        let entry;
        try {
            entry = loadEntry(candidate, stats, config.publicDir);
        } catch {
            sendNotFound(req, res, config);
            return;
        }
        headers.ETag = entry.etag;
        headers.Vary = "Accept-Encoding";
        if (req.headers["if-none-match"] === entry.etag) {
            res.writeHead(304, { ETag: entry.etag, "Cache-Control": headers["Cache-Control"], Vary: "Accept-Encoding" });
            res.end();
            return;
        }
        const encoding = pickEncoding(req);
        const body = encoding ? entry[encoding] : entry.raw;
        if (encoding) headers["Content-Encoding"] = encoding;
        headers["Content-Length"] = body.length;
        res.writeHead(200, headers);
        res.end(req.method === "HEAD" ? undefined : body);
    });
}

module.exports = { serveStatic, versionAssets };
