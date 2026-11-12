"use strict";

/*
  إعدادات الموقع التي يعدّلها الأدمن من لوحة الإدارة (بدون نشر جديد):
    home       عنوان الصفحة الرئيسية ووصفها وشريط إعلان
    features   تشغيل/إيقاف الخدمات ووضع الصيانة
    plans      الأسعار والتجربة المجانية والحدود اليومية
    cyberbot   رسالة الترحيب والأسئلة الجاهزة وتعليمات إضافية للذكاء الاصطناعي
    security   رمز الدخول بالبريد (MFA)

  تُحفظ في قاعدة البيانات (مفتاح settings) وتُقرأ كل 30 ثانية حتى تتزامن النسخ أثناء النشر.
  كل قيمة تمر بتحقق صارم (أنواع، أطوال، حدود)، وما لا نعرفه يُتجاهل.
*/

const { LIMITS } = require("./plans");

const REFRESH_MS = 30_000;

const DEFAULT_SUGGESTIONS = [
    "افحص هذا الرابط: http://paypa1-account-verify.xyz/login",
    "وصلتني رسالة تكول ربحت جائزة وتطلب رقم بطاقتي، شسوي؟",
    "انسرق حسابي بالواتساب، شلون أرجعه؟",
    "شلون أسوي كلمة سر قوية وأحمي حساباتي؟",
    "شنو هو التصيد الإلكتروني وشلون أكشفه؟"
];

function defaults(config) {
    return {
        home: {
            title: "منظومة كشف ومكافحة التصيد الإلكتروني الذكية",
            subtitle: "حل أمني استباقي يعتمد خوارزميات التحليل متعدد الطبقات لحماية المؤسسات والمستخدمين من الروابط الضارة وهجمات الهندسة الاجتماعية وتزييف الوسائط.",
            announcement: "",
            announcementTone: "info"
        },
        features: {
            cyberbot: true, registration: true, urlScan: true, textScan: true, fileScan: true, mediaScan: true,
            bulk: true, awareness: true, liveInspect: true, guest: true, maintenance: false,
            maintenanceMessage: "الموقع تحت الصيانة حالياً لتحسين الخدمة. نرجع خلال وقت قصير."
        },
        plans: {
            priceUsd: config.plans.priceUsd, priceIqd: config.plans.priceIqd, trialDays: config.plans.trialDays,
            freeScansPerDay: 20, freeChatPerDay: 10, proScansPerDay: 1000, proChatPerDay: 200, proBulkMaxUrls: 50
        },
        cyberbot: { greeting: "", suggestions: DEFAULT_SUGGESTIONS.slice(), extraInstructions: "" },
        response: { contacts: "" },
        security: { mfaEmail: true }
    };
}

// مخطط التحقق: نوع كل حقل وحدوده
const SCHEMA = {
    home: { title: ["text", 120], subtitle: ["text", 400], announcement: ["text", 300], announcementTone: ["enum", ["info", "warn", "success"]] },
    features: {
        cyberbot: ["bool"], registration: ["bool"], urlScan: ["bool"], textScan: ["bool"], fileScan: ["bool"], mediaScan: ["bool"],
        bulk: ["bool"], awareness: ["bool"], liveInspect: ["bool"], guest: ["bool"], maintenance: ["bool"], maintenanceMessage: ["text", 300]
    },
    plans: {
        priceUsd: ["num", 0, 1000], priceIqd: ["num", 0, 10_000_000], trialDays: ["int", 0, 365],
        freeScansPerDay: ["int", 0, 10_000], freeChatPerDay: ["int", 0, 10_000],
        proScansPerDay: ["int", 1, 100_000], proChatPerDay: ["int", 1, 100_000], proBulkMaxUrls: ["int", 1, 500]
    },
    cyberbot: { greeting: ["text", 600], suggestions: ["list", 6, 140], extraInstructions: ["text", 1500] },
    response: { contacts: ["text", 600] },
    security: { mfaEmail: ["bool"] }
};

// نص نظيف: بدون محارف تحكم، ونقصّه للطول المسموح
function cleanString(value, max) {
    return String(value).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "").replace(/\r\n?/g, "\n").trim().slice(0, max);
}

function validField(spec, value) {
    const [type, a, b] = spec;
    if (type === "bool") return typeof value === "boolean" ? { ok: true, value } : { ok: false };
    if (type === "text") return typeof value === "string" ? { ok: true, value: cleanString(value, a) } : { ok: false };
    if (type === "enum") return a.includes(value) ? { ok: true, value } : { ok: false };
    if (type === "num" || type === "int") {
        const n = Number(value);
        if (value === "" || value === null || !Number.isFinite(n)) return { ok: false };
        const clamped = Math.min(b, Math.max(a, type === "int" ? Math.round(n) : Math.round(n * 100) / 100));
        return { ok: true, value: clamped };
    }
    if (type === "list") {
        if (!Array.isArray(value)) return { ok: false };
        return { ok: true, value: value.filter(x => typeof x === "string").map(x => cleanString(x, b).replace(/\n/g, " ")).filter(Boolean).slice(0, a) };
    }
    return { ok: false };
}

// يدمج تعديلاً جزئياً مع الإعدادات الحالية، ويرجع { next, changed, errors }
function mergeSettings(current, patch) {
    const next = JSON.parse(JSON.stringify(current));
    const changed = [];
    const errors = [];
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) return { next, changed, errors: ["طلب غير صالح."] };
    for (const section of Object.keys(SCHEMA)) {
        const part = patch[section];
        if (part === undefined) continue;
        if (!part || typeof part !== "object" || Array.isArray(part)) { errors.push(section); continue; }
        for (const field of Object.keys(SCHEMA[section])) {
            if (!Object.prototype.hasOwnProperty.call(part, field)) continue;
            const result = validField(SCHEMA[section][field], part[field]);
            if (!result.ok) { errors.push(`${section}.${field}`); continue; }
            if (JSON.stringify(next[section][field]) !== JSON.stringify(result.value)) {
                next[section][field] = result.value;
                changed.push(`${section}.${field}`);
            }
        }
    }
    return { next, changed, errors };
}

function createSettings({ db, config }) {
    const base = defaults(config);
    let current = JSON.parse(JSON.stringify(base));
    let timer = null;
    let updatedAt = null;
    let updatedBy = "";

    // يطبّق الأسعار والحدود على الكائنات المشتركة فيصير التغيير فورياً بكل الخادم
    function apply() {
        const p = current.plans;
        config.plans.priceUsd = p.priceUsd;
        config.plans.priceIqd = p.priceIqd;
        config.plans.trialDays = p.trialDays;
        LIMITS.free.scansPerDay = p.freeScansPerDay;
        LIMITS.free.chatPerDay = p.freeChatPerDay;
        LIMITS.pro.scansPerDay = p.proScansPerDay;
        LIMITS.pro.chatPerDay = p.proChatPerDay;
        LIMITS.pro.bulkMaxUrls = p.proBulkMaxUrls;
    }

    function adopt(stored) {
        // القيم المحفوظة تمر بنفس التحقق؛ الحقول الجديدة تأخذ القيم الافتراضية
        const { next } = mergeSettings(base, stored && stored.values ? stored.values : {});
        current = next;
        updatedAt = stored && stored.updatedAt || null;
        updatedBy = stored && stored.updatedBy || "";
        apply();
    }

    async function load() {
        try {
            const raw = await db.cmd(["GET", db.key("settings")]);
            if (raw) adopt(JSON.parse(raw));
            else apply();
            return { ok: true };
        } catch (error) {
            apply();
            return { ok: false, error: String(error && error.message || error) };
        }
    }

    function start() {
        if (timer) return;
        timer = setInterval(() => { load().catch(() => {}); }, REFRESH_MS);
        timer.unref();
    }

    function stop() {
        if (timer) clearInterval(timer);
        timer = null;
    }

    async function update(patch, admin = "") {
        const { next, changed, errors } = mergeSettings(current, patch);
        if (errors.length) return { ok: false, errors };
        const record = { values: next, updatedAt: new Date().toISOString(), updatedBy: String(admin).slice(0, 40) };
        await db.cmd(["SET", db.key("settings"), JSON.stringify(record)]);
        adopt(record);
        return { ok: true, changed, settings: adminView() };
    }

    async function reset(admin = "") {
        const record = { values: JSON.parse(JSON.stringify(base)), updatedAt: new Date().toISOString(), updatedBy: String(admin).slice(0, 40) };
        await db.cmd(["SET", db.key("settings"), JSON.stringify(record)]);
        adopt(record);
        return { ok: true, settings: adminView() };
    }

    const get = () => current;
    const adminView = () => ({ values: JSON.parse(JSON.stringify(current)), defaults: base, updatedAt, updatedBy });

    // ما يُعرض للزوار (بدون التعليمات الإضافية للذكاء الاصطناعي)
    function publicView() {
        const c = current;
        return {
            home: { ...c.home },
            features: { ...c.features },
            plans: { priceUsd: c.plans.priceUsd, priceIqd: c.plans.priceIqd, trialDays: c.plans.trialDays },
            cyberbot: { greeting: c.cyberbot.greeting, suggestions: c.cyberbot.suggestions.slice() },
            response: { contacts: (c.response && c.response.contacts) || "" }
        };
    }

    apply();
    return { load, start, stop, update, reset, get, adminView, publicView };
}

module.exports = { createSettings, mergeSettings, defaults, SCHEMA };
