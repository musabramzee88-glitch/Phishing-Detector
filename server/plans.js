"use strict";

/*
  الخطط والأسعار والحدود. هذا المكان الوحيد لتعديلها.
  الحدود تُفرض على الخادم (server/scan.js و server/chat.js) فلا يمكن تجاوزها بتعديل الصفحة.

  free   مجاني دائماً
  pro    2$ شهرياً. كل حساب جديد يحصل على أول شهر مجاناً (TRIAL_DAYS) مرة واحدة فقط.
*/

const DAY_MS = 24 * 60 * 60 * 1000;

const LIMITS = {
    free: {
        scansPerDay: 20,          // روابط + نصوص + ملفات معاً
        chatPerDay: 10,
        bulkMaxUrls: 0,           // الفحص الجماعي غير متاح
        deepChecks: false,        // عمر النطاق (RDAP)
        history: false,
        api: false,
        clean: false              // تنظيف الملفات (الصور) غير متاح
    },
    pro: {
        scansPerDay: 1000,        // "بلا حدود" عملياً مع سقف يمنع الإساءة
        chatPerDay: 200,
        bulkMaxUrls: 50,
        deepChecks: true,
        history: true,
        api: true,
        clean: true
    }
};

// نصوص المزايا تُبنى من الحدود الحالية (يعدّلها الأدمن من لوحة الإدارة)
function featuresFor() {
    const f = LIMITS.free, p = LIMITS.pro;
    return {
        free: [
            `${f.scansPerDay} فحصاً يومياً (روابط ورسائل وملفات)`,
            `${f.chatPerDay} رسائل يومياً مع CyberBot`,
            "قوائم التهديدات المحدّثة (OpenPhish و Phishing Army)",
            "المسار التوعوي ومحاكي التصيد"
        ],
        pro: [
            `فحص حتى ${p.scansPerDay} يومياً`,
            `CyberBot حتى ${p.chatPerDay} رسالة يومياً`,
            "فحص عميق: عمر النطاق وتاريخ تسجيله",
            `فحص جماعي حتى ${p.bulkMaxUrls} رابطاً دفعة واحدة + تصدير CSV`,
            "تنظيف الصور: إزالة البيانات المخفية والأكواد الملحقة وتسليم نسخة سليمة",
            "سجل فحوصاتك محفوظ بحسابك",
            "مفتاح API لربط أنظمتك"
        ]
    };
}
const FEATURES = featuresFor();

const PAYMENT_MONTHS = [1, 3, 6, 12];

function planOf(user, now = Date.now()) {
    if (!user) return { id: "free", source: "none", until: null };
    const paid = Number(user.paidUntil || 0);
    const trial = Number(user.trialEndsAt || 0);
    if (paid > now) return { id: "pro", source: "paid", until: paid };
    if (trial > now) return { id: "pro", source: "trial", until: trial };
    return { id: "free", source: trial ? "trial_ended" : "free", until: null };
}

function limitsFor(user, now) {
    return LIMITS[planOf(user, now).id];
}

// السعر بالدولار، ومقابله بالدينار للدفع المحلي (يُضبط بمتغيرات البيئة)
function pricingInfo(config) {
    const p = config.plans;
    const features = featuresFor();
    return {
        currency: "USD",
        monthlyUsd: p.priceUsd,
        monthlyIqd: p.priceIqd,
        trialDays: p.trialDays,
        months: PAYMENT_MONTHS,
        tiers: [
            { id: "free", name: "المجانية", priceUsd: 0, features: features.free, limits: LIMITS.free },
            { id: "pro", name: "Pro", priceUsd: p.priceUsd, priceIqd: p.priceIqd, features: features.pro, limits: LIMITS.pro }
        ],
        payment: config.payment
    };
}

module.exports = { LIMITS, FEATURES, featuresFor, PAYMENT_MONTHS, DAY_MS, planOf, limitsFor, pricingInfo };
