"use strict";

/*
  الباقات والأسعار. **الأرقام هنا أمثلة، عدّلها حسب سوقك.** هذا الملف هو المكان الوحيد للأسعار والحدود.
  الفرض الفعلي للحدود يتم على الخادم (server/pro.js)، وصفحة الباقات تقرأ من هنا عبر /api/pricing.
*/

const TIERS = [
    {
        id: "free",
        name: "مجاني",
        price: { IQD: 0, USD: 0 },
        period: "",
        features: [
            "فحص الروابط والرسائل والملفات بدون حدود (داخل متصفحك)",
            "المسار التوعوي ومحاكي التصيد",
            "مساعد CyberBot (بحدود طلبات)"
        ]
    },
    {
        id: "pro",
        name: "Pro",
        price: { IQD: 15000, USD: 10 },
        period: "شهرياً",
        features: [
            "كل مزايا المجاني",
            "فحص جماعي: حتى 50 رابطاً بالطلب الواحد",
            "تصدير النتائج CSV",
            "دعم عبر واتساب/تيليجرام"
        ]
    },
    {
        id: "enterprise",
        name: "Enterprise",
        price: { IQD: 70000, USD: 49 },
        period: "شهرياً",
        features: [
            "كل مزايا Pro",
            "فحص جماعي: حتى 500 رابط بالطلب الواحد",
            "وصول API ببرمجتك الخاصة (مفتاح الترخيص هو مفتاح الـ API)",
            "أولوية بالدعم وتدريب فريقك"
        ]
    }
];

// حدود الفرض على الخادم لكل باقة
const LIMITS = {
    pro: { maxUrls: 50, requestsPerMinute: 20 },
    enterprise: { maxUrls: 500, requestsPerMinute: 60 }
};

const PAYMENT_METHODS = ["ZainCash", "FIB", "Qi Card", "Asia Hawala", "نقداً", "تحويل مصرفي", "أخرى"];
const CURRENCIES = ["IQD", "USD"];

function publicPricing(config, licensingEnabled) {
    return {
        licensingEnabled,
        currencies: CURRENCIES,
        tiers: TIERS,
        limits: LIMITS,
        contact: config.billing.contact
    };
}

module.exports = { TIERS, LIMITS, PAYMENT_METHODS, CURRENCIES, publicPricing };
