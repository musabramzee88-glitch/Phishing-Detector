#!/usr/bin/env node
"use strict";

/*
  يبني إضافة المتصفح جاهزة للتحميل أو للرفع على متجر Chrome:
    npm run build-extension -- https://your-site.onrender.com
  الناتج:
    build/extension/                       مجلد للتجربة (chrome://extensions ← وضع المطوّر ← تحميل غير مضغوط)
    build/phishing-detector-extension.zip  للرفع على Chrome Web Store
  ينسخ محرك الكشف نفسه من public/js حتى تبقى الإضافة والموقع بنفس القواعد.
*/

const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");

const ROOT = path.resolve(__dirname, "..");
const SRC = path.join(ROOT, "extension");

function siteOrigin(raw) {
    let u;
    try { u = new URL(String(raw || "")); } catch { return ""; }
    const local = ["localhost", "127.0.0.1"].includes(u.hostname);
    if (u.protocol !== "https:" && !(u.protocol === "http:" && local)) return "";
    return u.origin;
}

// كاتب ZIP بسيط (Deflate) بدون مكتبات
const CRC_TABLE = Array.from({ length: 256 }, (_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
function crc32(buf) {
    let c = 0xffffffff;
    for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
    return (c ^ 0xffffffff) >>> 0;
}
// تاريخ ثابت صالح للملفات داخل الأرشيف (2026-01-01 00:00) حتى يكون البناء متطابقاً كل مرة
const DOS_DATE = ((2026 - 1980) << 9) | (1 << 5) | 1, DOS_TIME = 0;
function makeZip(files) {
    const locals = [], centrals = [];
    let offset = 0;
    for (const { name, data } of files) {
        const nameBuf = Buffer.from(name, "utf8");
        const packed = zlib.deflateRawSync(data, { level: 9 });
        const crc = crc32(data);
        const local = Buffer.alloc(30);
        local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0x0800, 6); local.writeUInt16LE(8, 8);
        local.writeUInt16LE(DOS_TIME, 10); local.writeUInt16LE(DOS_DATE, 12);
        local.writeUInt32LE(crc, 14); local.writeUInt32LE(packed.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(nameBuf.length, 26);
        locals.push(local, nameBuf, packed);
        const central = Buffer.alloc(46);
        central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(20, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(0x0800, 8); central.writeUInt16LE(8, 10);
        central.writeUInt16LE(DOS_TIME, 12); central.writeUInt16LE(DOS_DATE, 14);
        central.writeUInt32LE(crc, 16); central.writeUInt32LE(packed.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(nameBuf.length, 28); central.writeUInt32LE(offset, 42);
        centrals.push(central, nameBuf);
        offset += 30 + nameBuf.length + packed.length;
    }
    const cd = Buffer.concat(centrals);
    const end = Buffer.alloc(22);
    end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(files.length, 8); end.writeUInt16LE(files.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
    return Buffer.concat([...locals, cd, end]);
}

function listFiles(dir, base = "") {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => {
        const rel = base ? base + "/" + e.name : e.name;
        return e.isDirectory() ? listFiles(path.join(dir, e.name), rel) : [rel];
    });
}

function build(rawUrl, outDir = path.join(ROOT, "build")) {
    const origin = siteOrigin(rawUrl);
    if (!origin) throw new Error("اكتب عنوان موقعك بـ https، مثل: npm run build-extension -- https://your-site.onrender.com");
    const files = listFiles(SRC).map(name => {
        let data = fs.readFileSync(path.join(SRC, name));
        if (/\.(js|json|html)$/.test(name)) data = Buffer.from(data.toString("utf8").split("__SITE_ORIGIN__").join(origin));
        return { name, data };
    });
    files.push({ name: "detection-engine.js", data: fs.readFileSync(path.join(ROOT, "public", "js", "detection-engine.js")) });
    files.sort((a, b) => a.name.localeCompare(b.name));
    const dir = path.join(outDir, "extension");
    fs.rmSync(dir, { recursive: true, force: true });
    for (const f of files) {
        fs.mkdirSync(path.dirname(path.join(dir, f.name)), { recursive: true });
        fs.writeFileSync(path.join(dir, f.name), f.data);
    }
    const zipPath = path.join(outDir, "phishing-detector-extension.zip");
    fs.writeFileSync(zipPath, makeZip(files));
    return { dir, zipPath, origin, files: files.map(f => f.name) };
}

if (require.main === module) {
    try {
        const r = build(process.argv[2]);
        console.log(`Built for ${r.origin}\n  folder: ${path.relative(ROOT, r.dir)}\n  zip:    ${path.relative(ROOT, r.zipPath)}`);
    } catch (error) {
        console.error(error.message);
        process.exit(1);
    }
}

module.exports = { build, makeZip, crc32, siteOrigin };
