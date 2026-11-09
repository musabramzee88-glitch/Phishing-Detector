"use strict";

/*
  مراقب صحة النظام. يأخذ عينة كل بضع ثوانٍ من الذاكرة وتأخر حلقة الأحداث (Event Loop).
  - degraded: تحذير يظهر بلوحة الأدمن.
  - critical (عدة عينات متتالية): /healthz يرد 503، فتعيد Render تشغيل الخدمة تلقائياً. هذه آلية "الإصلاح الذاتي".
  لا يوجد نظام يضمن عدم التعطل. المراقبة + إعادة التشغيل التلقائي تقلل زمن التوقف، ولا تلغيه.
*/

const { monitorEventLoopDelay } = require("node:perf_hooks");

const DEFAULTS = {
    degradedRssMb: 350,        // خطة Render المجانية: 512MB
    criticalRssMb: 450,
    degradedLagMs: 200,
    criticalLagMs: 1000,
    sampleMs: 5000,
    criticalSamples: 6,        // 6 عينات × 5 ثوانٍ = 30 ثانية متواصلة قبل اعتبارها حرجة
    degradedClientErrors: 20   // أخطاء متصفحات الزوار خلال 5 دقائق
};

function level(sample, limits) {
    if (sample.rssMb >= limits.criticalRssMb || sample.lagMs >= limits.criticalLagMs) return 2;
    if (sample.rssMb >= limits.degradedRssMb || sample.lagMs >= limits.degradedLagMs) return 1;
    return 0;
}

function createHealthMonitor(overrides = {}) {
    const limits = { ...DEFAULTS, ...overrides };
    const histogram = monitorEventLoopDelay({ resolution: 20 });
    histogram.enable();
    const samples = [];

    function sample() {
        const raw = histogram.percentile(99);
        histogram.reset();
        const lagMs = Number.isFinite(raw) && raw < 1e12 ? raw / 1e6 : 0;   // العدّاد الفارغ يرجع قيمة ضخمة
        samples.push({ rssMb: process.memoryUsage().rss / 1048576, lagMs });
        if (samples.length > Math.max(12, limits.criticalSamples)) samples.shift();
    }

    sample();
    const timer = setInterval(sample, limits.sampleMs);
    timer.unref();

    // recentClientErrors: عدد أخطاء المتصفحات بآخر 5 دقائق (من الإحصاءات)
    function evaluate(recentClientErrors = 0) {
        const latest = samples[samples.length - 1] || { rssMb: 0, lagMs: 0 };
        const window = samples.slice(-limits.criticalSamples);
        const sustainedCritical = window.length >= limits.criticalSamples && window.every(s => level(s, limits) === 2);
        const reasons = [];
        if (latest.rssMb >= limits.degradedRssMb) reasons.push(`استهلاك الذاكرة مرتفع (${Math.round(latest.rssMb)} MB)`);
        if (latest.lagMs >= limits.degradedLagMs) reasons.push(`تأخر المعالجة مرتفع (${Math.round(latest.lagMs)} ms)`);
        if (recentClientErrors >= limits.degradedClientErrors) reasons.push(`أخطاء كثيرة بمتصفحات الزوار (${recentClientErrors} خلال 5 دقائق)`);

        let status = "ok";
        if (sustainedCritical) status = "critical";
        else if (reasons.length) status = "degraded";
        return {
            status,
            reasons,
            rssMb: Math.round(latest.rssMb),
            heapUsedMb: Math.round(process.memoryUsage().heapUsed / 1048576),
            eventLoopP99Ms: Math.round(latest.lagMs * 10) / 10
        };
    }

    return { evaluate, stop() { clearInterval(timer); histogram.disable(); } };
}

module.exports = { createHealthMonitor, DEFAULTS };
