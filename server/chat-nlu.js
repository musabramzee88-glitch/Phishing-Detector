"use strict";

/*
  مصنّف نوايا خفيف بدون مكتبات: يقارن رسالة المستخدم بأمثلة التدريب بتشابه TF-IDF على n-grams الحروف.
  يتحمل الأخطاء الإملائية والصياغات المختلفة (مثلاً «انهكر» و«اتهكر»). يُستعمل عندما لا تطابق القواعد (regex) شيئاً.
*/

const engine = require("../public/js/detection-engine.js");
const BASE = require("./chat-examples");
let EXTRA = {};
try { EXTRA = require("./chat-examples-extra"); } catch { /* اختياري */ }
const EXAMPLES = {};
for (const source of [BASE, EXTRA]) for (const [topic, phrases] of Object.entries(source)) EXAMPLES[topic] = (EXAMPLES[topic] || []).concat(phrases);

const STOP = new Set(["شنو", "شلون", "كيف", "هل", "ليش", "اني", "انا", "هذا", "هاي", "هذي", "الي", "اللي", "من", "على", "علي", "في", "مو", "لو", "او", "ما", "وين", "يعني", "شي", "اريد", "ريد", "اعرف", "اسوي", "شسوي", "سوي", "اكدر", "ممكن", "وبعدين", "بعدين", "بس", "هسه", "الان", "شكد", "اكو", "ماكو", "كل", "شي"]);

function features(text) {
    const words = engine.normalizeArabic(text).replace(/[^؀-ۿa-z0-9\s]/g, " ").split(/\s+/).filter(w => w && !STOP.has(w)).slice(0, 80);
    const out = [];
    for (const word of words) {
        out.push("w:" + word);
        const padded = "#" + word + "#";
        if (padded.length >= 4) for (let i = 0; i + 3 <= padded.length; i++) out.push("g:" + padded.slice(i, i + 3));
    }
    return out;
}

function vectorize(list, idf) {
    const tf = new Map();
    for (const f of list) tf.set(f, (tf.get(f) || 0) + 1);
    const vec = new Map();
    let norm = 0;
    for (const [f, c] of tf) {
        const weight = (1 + Math.log(c)) * (idf.get(f) || Math.log(1 + docs.length));
        vec.set(f, weight);
        norm += weight * weight;
    }
    norm = Math.sqrt(norm) || 1;
    for (const [f, w] of vec) vec.set(f, w / norm);
    return vec;
}

const docs = [];
for (const [topic, phrases] of Object.entries(EXAMPLES)) for (const phrase of phrases) docs.push({ topic, feats: features(phrase) });

const df = new Map();
for (const d of docs) for (const f of new Set(d.feats)) df.set(f, (df.get(f) || 0) + 1);
const idf = new Map();
for (const [f, n] of df) idf.set(f, Math.log(1 + docs.length / n));
for (const d of docs) d.vec = vectorize(d.feats, idf);

function cosine(a, b) {
    let sum = 0;
    const [small, big] = a.size < b.size ? [a, b] : [b, a];
    for (const [f, w] of small) { const o = big.get(f); if (o) sum += w * o; }
    return sum;
}

// يرجع [{ topic, score }] مرتبة. نأخذ أعلى 3 أمثلة لكل موضوع ونوسّطها لتقليل أثر مثال واحد صدفة.
function classify(message, limit = 3) {
    const feats = features(String(message || "").slice(0, 500));
    if (!feats.length) return [];
    const q = vectorize(feats, idf);
    const best = new Map();
    for (const d of docs) {
        const s = cosine(q, d.vec);
        if (s <= 0) continue;
        const list = best.get(d.topic) || [];
        list.push(s);
        best.set(d.topic, list);
    }
    const ranked = [];
    for (const [topic, list] of best) {
        list.sort((a, b) => b - a);
        ranked.push({ topic, score: list[0] * 0.8 + (list[1] || 0) * 0.2 });
    }
    return ranked.sort((a, b) => b.score - a.score).slice(0, limit);
}

module.exports = { classify, features, EXAMPLES };
