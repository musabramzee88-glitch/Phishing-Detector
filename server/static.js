"use strict";

/* تقديم ملفات الموقع العامة من مجلد public/ فقط. أي مسار آخر يرجع 404. */

const fs = require("node:fs");
const path = require("node:path");
const { sendJson } = require("./http");

const MIME_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".svg": "image/svg+xml",
    ".ico": "image/x-icon",
    ".txt": "text/plain; charset=utf-8"
};

function notFound(res) {
    sendJson(res, 404, { error: "Not found" });
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

    // نرفض المحارف الخطرة والمسارات المخفية قبل أي تعامل مع نظام الملفات
    if (decoded.includes("\0") || decoded.includes("\\") || decoded.split("/").some(part => part.startsWith("."))) {
        notFound(res);
        return;
    }

    const candidate = path.resolve(config.publicDir, "." + decoded);
    const contentType = MIME_TYPES[path.extname(candidate).toLowerCase()];
    if (!contentType || !candidate.startsWith(config.publicDir + path.sep)) {
        notFound(res);
        return;
    }

    fs.stat(candidate, (error, stats) => {
        if (error || !stats.isFile()) {
            notFound(res);
            return;
        }
        res.writeHead(200, {
            "Content-Type": contentType,
            "Content-Length": stats.size,
            // الصفحات تُراجع دائماً (حتى يصل التحديث فوراً)، والباقي يُخزَّن لخمس دقائق
            "Cache-Control": contentType.startsWith("text/html") ? "no-cache" : "public, max-age=300"
        });
        if (req.method === "HEAD") {
            res.end();
            return;
        }
        fs.createReadStream(candidate).on("error", () => res.destroy()).pipe(res);
    });
}

module.exports = { serveStatic };
