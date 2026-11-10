"use strict";

/*
  موجّه المواضيع: يدمج قواعد الكلمات المفتاحية (chat-topics) مع مصنّف النوايا المتعلَّم (chat-nlu).
  الدمج أدق من أي منهما وحده: القواعد تلتقط الكلمات الصريحة، والمصنّف يلتقط الصياغات الجديدة والأخطاء الإملائية.
  الأوزان من تجربة على مئات الأسئلة (RE 0.6 + NLU 1.0).
*/

const engine = require("../public/js/detection-engine.js");
const { TOPICS } = require("./chat-topics");
const nlu = require("./chat-nlu");

const W_RE = 0.6;
const W_NLU = 1.0;
const MIN_NLU = 0.2;      // درجة أدنى من هذا تُنصَّف (تشابه ضعيف)
const MIN_SCORE = 0.24;   // أقل من هذا = لا موضوع واضح
const MIN_NLU_ONLY = 0.38; // موضوع بلا أي كلمة مفتاحية يلزمه تشابه قوي مع أمثلة التدريب
const CLOSE = 0.08;       // موضوع ثانٍ قريب بالدرجة يُعرض كتكملة

function route(message) {
    const text = engine.normalizeArabic(String(message || "").slice(0, 2000));
    const scores = new Map();
    const rawNlu = new Map();
    for (const topic of TOPICS) {
        const count = (text.match(new RegExp(topic.re.source, "g")) || []).length;
        if (count) scores.set(topic.id, W_RE * Math.min(1, (count * 10 + topic.priority) / 25));
    }
    for (const guess of nlu.classify(String(message || ""), 6)) {
        rawNlu.set(guess.topic, guess.score);
        const value = W_NLU * (guess.score >= MIN_NLU ? guess.score : guess.score * 0.5);
        scores.set(guess.topic, (scores.get(guess.topic) || 0) + value);
    }
    const hit = new Set();
    for (const topic of TOPICS) if (new RegExp(topic.re.source).test(text)) hit.add(topic.id);
    const ranked = [...scores].map(([id, score]) => ({ id, score }))
        .filter(r => hit.has(r.id) || (rawNlu.get(r.id) || 0) >= MIN_NLU_ONLY)
        .sort((a, b) => b.score - a.score);
    if (!ranked.length || ranked[0].score < MIN_SCORE) return { topics: [], confidence: ranked.length ? ranked[0].score : 0 };
    const out = [ranked[0]];
    if (ranked[1] && ranked[0].score - ranked[1].score < CLOSE && ranked[1].score >= MIN_SCORE) out.push(ranked[1]);
    return {
        topics: out.map(r => TOPICS.find(t => t.id === r.id)).filter(Boolean),
        confidence: ranked[0].score
    };
}

module.exports = { route };
