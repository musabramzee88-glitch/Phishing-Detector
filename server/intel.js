"use strict";

/*
  مصادر خارجية تكمّل محرك القواعد (تعمل على الخادم فقط):

  1) قوائم التهديدات المفتوحة، تُحمَّل بالذاكرة وتتحدّث كل 3 ساعات:
       OpenPhish (community feed)   روابط تصيد نشطة
       URLhaus (abuse.ch)           روابط توزّع برمجيات خبيثة
     الفحص محلي تماماً (لا نرسل روابط المستخدمين لأي جهة).
  2) عمر النطاق عبر RDAP (rdap.org): النطاقات المسجّلة حديثاً من أقوى مؤشرات التصيد.
     هنا يُرسل اسم النطاق فقط (وليس الرابط كاملاً) لسجل النطاقات، ونخزّن النتيجة 24 ساعة.

  إذا تعذر الوصول لأي مصدر، يكمل الفحص بالقواعد فقط ويُذكر ذلك بالتقرير.
*/

const FEEDS = [
    { id: "openphish", label: "OpenPhish", url: "https://openphish.com/feed.txt", kind: "phishing" },
    { id: "urlhaus", label: "URLhaus", url: "https://urlhaus.abuse.ch/downloads/text_online/", kind: "malware" }
];
const REFRESH_MS = 3 * 60 * 60 * 1000;
const MAX_FEED_BYTES = 15 * 1024 * 1024;
const RDAP_TTL_MS = 24 * 60 * 60 * 1000;
const DAY_MS = 24 * 60 * 60 * 1000;

// نطاقات منصات كبيرة تظهر بالقوائم بسبب ملفات يرفعها مستخدمون؛ لا نحكم على النطاق كله بسببها
const SHARED_PLATFORMS = /(^|\.)(google\.com|googleusercontent\.com|googleapis\.com|github\.com|githubusercontent\.com|dropbox\.com|dropboxusercontent\.com|microsoft\.com|sharepoint\.com|live\.com|1drv\.ms|discord\.com|discordapp\.com|cdn\.discordapp\.com|amazonaws\.com|cloudfront\.net|mediafire\.com|bit\.ly|t\.me|telegram\.org|facebook\.com|instagram\.com|wa\.me|whatsapp\.com|apple\.com|icloud\.com|yandex\.ru|ipfs\.io|cloudflare-ipfs\.com|weebly\.com|wixsite\.com|blogspot\.com|github\.io|pages\.dev|workers\.dev|vercel\.app|netlify\.app|web\.app|firebaseapp\.com|onrender\.com)$/;

function normalizeUrl(value) {
    try {
        const u = new URL(String(value).trim());
        if (!/^https?:$/.test(u.protocol)) return "";
        u.hash = "";
        const host = u.hostname.toLowerCase().replace(/^www\./, "");
        return host + u.pathname.replace(/\/+$/, "") + u.search;
    } catch {
        return "";
    }
}

async function fetchText(fetchImpl, url, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetchImpl(url, { signal: controller.signal, headers: { "User-Agent": "PhishingDetector/2 (+threat-feed sync)" } });
        if (!response.ok) throw new Error("HTTP " + response.status);
        const text = await response.text();
        if (text.length > MAX_FEED_BYTES) throw new Error("feed too large");
        return text;
    } finally {
        clearTimeout(timer);
    }
}

function createIntel({ enabled = true, fetchImpl = fetch, feeds = FEEDS, now = () => Date.now(), log = () => {} } = {}) {
    const state = {};
    const urls = new Map();     // normalized url -> feed id
    const hosts = new Map();    // host -> feed id
    const rdapCache = new Map();
    let timer = null;

    for (const feed of feeds) state[feed.id] = { label: feed.label, count: 0, updatedAt: 0, error: "" };

    async function refresh() {
        if (!enabled) return;
        const nextUrls = new Map();
        const nextHosts = new Map();
        for (const feed of feeds) {
            try {
                const text = await fetchText(fetchImpl, feed.url, 20_000);
                let count = 0;
                for (const line of text.split(/\r?\n/)) {
                    const value = line.trim();
                    if (!value || value.startsWith("#")) continue;
                    const n = normalizeUrl(value);
                    if (!n) continue;
                    nextUrls.set(n, feed.id);
                    const host = n.split("/")[0].split("?")[0];
                    if (!SHARED_PLATFORMS.test(host)) nextHosts.set(host, feed.id);
                    count++;
                }
                state[feed.id] = { label: feed.label, count, updatedAt: now(), error: "" };
            } catch (error) {
                // نبقي آخر نسخة ناجحة من هذا المصدر
                for (const [u, f] of urls) if (f === feed.id) nextUrls.set(u, f);
                for (const [h, f] of hosts) if (f === feed.id) nextHosts.set(h, f);
                state[feed.id].error = String(error && error.message || error).slice(0, 120);
                log(`Threat feed ${feed.label} failed: ${state[feed.id].error}`);
            }
        }
        urls.clear(); for (const [u, f] of nextUrls) urls.set(u, f);
        hosts.clear(); for (const [h, f] of nextHosts) hosts.set(h, f);
    }

    function start() {
        if (!enabled || timer) return;
        refresh().catch(() => {});
        timer = setInterval(() => refresh().catch(() => {}), REFRESH_MS);
        timer.unref();
    }

    function stop() {
        if (timer) clearInterval(timer);
        timer = null;
    }

    const feedLabel = id => (feeds.find(f => f.id === id) || {}).label || id;
    const feedKind = id => (feeds.find(f => f.id === id) || {}).kind || "phishing";

    // يرجع إشارات إضافية لرابط (تُدمج مع نتيجة المحرك)
    function lookup(href, host) {
        const signals = [];
        if (!enabled) return signals;
        const n = normalizeUrl(href);
        const cleanHost = String(host || "").toLowerCase().replace(/^www\./, "");
        const exact = n && urls.get(n);
        if (exact) {
            const kind = feedKind(exact) === "malware" ? "توزيع برمجيات خبيثة" : "تصيد";
            signals.push({ weight: 0.97, type: "danger", text: `هذا الرابط مُدرج حالياً في قائمة ${feedLabel(exact)} لروابط ${kind} النشطة.` });
        } else if (cleanHost && hosts.has(cleanHost)) {
            const id = hosts.get(cleanHost);
            signals.push({ weight: 0.7, type: "danger", text: `النطاق ${cleanHost} ظهر في قائمة ${feedLabel(id)} لروابط ضارة نشطة.` });
        }
        return signals;
    }

    // عمر النطاق من سجل النطاقات (RDAP). يرجع { createdAt, ageDays } أو null
    async function domainAge(registrable) {
        if (!enabled || !registrable || !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(registrable)) return null;
        const cached = rdapCache.get(registrable);
        if (cached && now() - cached.at < RDAP_TTL_MS) return cached.value;
        let value = null;
        try {
            const controller = new AbortController();
            const t = setTimeout(() => controller.abort(), 4000);
            let data;
            try {
                const response = await fetchImpl("https://rdap.org/domain/" + encodeURIComponent(registrable), {
                    signal: controller.signal, headers: { Accept: "application/rdap+json, application/json" }, redirect: "follow"
                });
                data = response.ok ? await response.json() : null;
            } finally {
                clearTimeout(t);
            }
            const event = data && Array.isArray(data.events) ? data.events.find(e => e && e.eventAction === "registration") : null;
            const created = event ? Date.parse(event.eventDate) : NaN;
            if (Number.isFinite(created)) value = { createdAt: new Date(created).toISOString(), ageDays: Math.floor((now() - created) / DAY_MS) };
        } catch {
            value = null;
        }
        if (rdapCache.size > 5000) rdapCache.delete(rdapCache.keys().next().value);
        rdapCache.set(registrable, { at: now(), value });
        return value;
    }

    function ageSignals(age) {
        if (!age) return [];
        const d = age.ageDays;
        const date = age.createdAt.slice(0, 10);
        if (d < 0) return [];
        if (d <= 7) return [{ weight: 0.6, type: "danger", text: `النطاق مسجّل قبل ${d} يوم فقط (${date}). أغلب مواقع التصيد تُستخدم خلال أيامها الأولى.` }];
        if (d <= 30) return [{ weight: 0.38, type: "warning", text: `النطاق جديد جداً: مسجّل قبل ${d} يوماً (${date}).` }];
        if (d <= 180) return [{ weight: 0.12, type: "warning", text: `النطاق حديث نسبياً: مسجّل قبل ${d} يوماً (${date}).` }];
        return [{ weight: 0, type: "info", text: `النطاق مسجّل منذ ${date} (قرابة ${Math.floor(d / 365)} سنة).${d > 730 ? " النطاقات القديمة أقل ارتباطاً بالتصيد، لكن قد تُخترق." : ""}` }];
    }

    function status() {
        return { enabled, urls: urls.size, hosts: hosts.size, feeds: state };
    }

    return { start, stop, refresh, lookup, domainAge, ageSignals, status };
}

module.exports = { createIntel, normalizeUrl, FEEDS };
