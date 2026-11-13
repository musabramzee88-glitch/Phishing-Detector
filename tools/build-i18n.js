#!/usr/bin/env node
"use strict";

/*
  يبني قواميس اللغات من i18n/strings.tsv:
    i18n/strings.tsv  →  public/i18n/ar.json  ku.json  en.json  (+ رقم نسخة داخل public/js/i18n.js)

  الملف المصدر: كل سطر = النص الأصلي (اللهجة العراقية) ثم الفصحى ثم الكردية (سۆرانی) ثم الإنكليزية، مفصولة بـ Tab.
  الأسطر التي تبدأ بـ # تعليقات. {0} {1} داخل النص = أجزاء متغيرة (أرقام، أسماء...) تنترجم بالقالب.

  الاستخدام:  npm run build-i18n
  بعد أي تعديل على نص بالموقع: أضف سطراً بالترجمات وشغّل الأمر. اختبار tests/i18n.test.js يكشف النصوص الناقصة.
*/

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const ROOT = path.join(__dirname, "..");
const LANGS = ["ar", "ku", "en"];
const norm = s => String(s).replace(/\s+/g, " ").trim();

function parse(text) {
    const rows = [];
    text.split("\n").forEach((line, i) => {
        if (!line.trim() || line.startsWith("#")) return;
        const cols = line.split("\t");
        if (cols.length !== 4) throw new Error(`i18n/strings.tsv:${i + 1}: لازم 4 أعمدة (لكيت ${cols.length})`);
        const [src, ...tr] = cols.map(norm);
        if (!src || tr.some(t => !t)) throw new Error(`i18n/strings.tsv:${i + 1}: عمود فارغ`);
        const holes = s => (s.match(/\{\d\}/g) || []).sort().join();
        tr.forEach((t, j) => {
            if (holes(t) !== holes(src)) throw new Error(`i18n/strings.tsv:${i + 1}: المتغيرات {n} بـ ${LANGS[j]} ما تطابق الأصل`);
        });
        rows.push([src, ...tr]);
    });
    return rows;
}

function build() {
    const rows = parse(fs.readFileSync(path.join(ROOT, "i18n", "strings.tsv"), "utf8"));
    const outDir = path.join(ROOT, "public", "i18n");
    fs.mkdirSync(outDir, { recursive: true });
    const hash = crypto.createHash("sha256");
    LANGS.forEach((lang, j) => {
        const dict = {};
        const patterns = [];
        for (const row of rows) {
            if (/\{\d\}/.test(row[0])) patterns.push([row[0], row[j + 1]]);
            else dict[row[0]] = row[j + 1];
        }
        const json = JSON.stringify({ lang, dict, patterns });
        fs.writeFileSync(path.join(outDir, lang + ".json"), json);
        hash.update(json);
    });
    // رقم النسخة داخل i18n.js: أي تعديل بالترجمات يغيّر بصمة i18n.js فالمتصفحات تجيب القاموس الجديد
    const version = hash.digest("hex").slice(0, 10);
    const runtime = path.join(ROOT, "public", "js", "i18n.js");
    const src = fs.readFileSync(runtime, "utf8");
    const next = src.replace(/const DICT_VERSION = '[^']*';/, `const DICT_VERSION = '${version}';`);
    if (next !== src) fs.writeFileSync(runtime, next);
    return { count: rows.length, version };
}

if (require.main === module) {
    const r = build();
    console.log(`i18n: ${r.count} نص × ${LANGS.length} لغات (نسخة ${r.version})`);
}

module.exports = { build, parse, norm };
