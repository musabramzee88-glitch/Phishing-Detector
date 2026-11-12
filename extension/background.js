/*
  Phishing Detector: إضافة المتصفح (Manifest V3).
  الخصوصية أولاً: كل صفحة تنفحص هنا داخل المتصفح بمحرك الموقع نفسه. ما نرسل أي رابط تزوره لخادمنا.
  الشي الوحيد اللي نجيبه من الخادم: قائمة النطاقات المؤكدة كاحتيال (كل ساعة).
  الفحص العميق بالموقع يصير فقط إذا المستخدم ضغط بنفسه.
*/
importScripts('config.js', 'detection-engine.js');

const engine = self.PhishingEngine;
const SITE = self.PD_CONFIG.site;
const SITE_HOST = new URL(SITE).hostname;
engine.setSiteHosts([SITE_HOST]);

async function syncBlocklist() {
    try {
        const res = await fetch(SITE + '/api/blocklist', { credentials: 'omit', cache: 'no-store' });
        if (!res.ok) return;
        const data = await res.json();
        const domains = Array.isArray(data.domains) ? data.domains.filter(d => typeof d === 'string').slice(0, 20000) : [];
        await chrome.storage.local.set({ blocklist: domains, syncedAt: Date.now() });
    } catch { /* نبقي آخر نسخة */ }
}

chrome.runtime.onInstalled.addListener(() => {
    chrome.contextMenus.create({ id: 'pd-link', title: 'افحص هذا الرابط بـ Phishing Detector', contexts: ['link'] });
    chrome.contextMenus.create({ id: 'pd-page', title: 'افحص هذي الصفحة بـ Phishing Detector', contexts: ['page'] });
    chrome.alarms.create('pd-sync', { periodInMinutes: 60 });
    chrome.storage.local.get({ enabled: true }, v => chrome.storage.local.set({ enabled: v.enabled }));
    syncBlocklist();
});
chrome.runtime.onStartup.addListener(syncBlocklist);
chrome.alarms.onAlarm.addListener(a => { if (a.name === 'pd-sync') syncBlocklist(); });

// الكلك اليمين: يفتح الموقع ويفحص الرابط هناك (بطلب صريح من المستخدم)
chrome.contextMenus.onClicked.addListener(info => {
    const target = info.menuItemId === 'pd-link' ? info.linkUrl : info.pageUrl;
    if (!target || !/^https?:/i.test(target)) return;
    chrome.tabs.create({ url: SITE + '/?share_url=' + encodeURIComponent(target) });
});

function blockedMatch(host, list) {
    const parts = host.replace(/^www\./, '').split('.');
    for (let i = 0; i < parts.length - 1; i++) {
        const candidate = parts.slice(i).join('.');
        if (list.includes(candidate)) return candidate;
    }
    return '';
}

// يرجع سبب التحذير أو null
async function verdict(url) {
    let u;
    try { u = new URL(url); } catch { return null; }
    if (!/^https?:$/.test(u.protocol)) return null;
    const host = u.hostname.toLowerCase();
    if (host === SITE_HOST) return null;
    const { blocklist = [], enabled = true } = await chrome.storage.local.get(['blocklist', 'enabled']);
    if (!enabled) return null;
    const { allowed = [] } = await chrome.storage.session.get('allowed');
    if (allowed.includes(host)) return null;
    const listed = blockedMatch(host, blocklist);
    if (listed) return { score: 99, reasons: [`النطاق ${listed} مؤكَّد كاحتيال ببلاغات مستخدمي Phishing Detector.`] };
    const r = engine.analyzeUrl(url);
    if (r.error || r.level !== 'danger') return null;
    return { score: r.score, reasons: r.reasons.filter(x => x.type === 'danger').slice(0, 3).map(x => x.text) };
}

chrome.webNavigation.onBeforeNavigate.addListener(async details => {
    if (details.frameId !== 0) return;
    const v = await verdict(details.url);
    if (!v) return;
    const page = chrome.runtime.getURL('warning.html') + '?u=' + encodeURIComponent(details.url) + '&s=' + v.score + '&r=' + encodeURIComponent(JSON.stringify(v.reasons));
    chrome.tabs.update(details.tabId, { url: page });
});

// من صفحة التحذير: «كمّل على مسؤوليتي» يسمح بالنطاق لهذي الجلسة فقط
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
    if (msg && msg.type === 'allow' && typeof msg.host === 'string' && sender.id === chrome.runtime.id) {
        chrome.storage.session.get({ allowed: [] }).then(({ allowed }) => {
            chrome.storage.session.set({ allowed: [...new Set([...allowed, msg.host])].slice(-200) }).then(() => reply({ ok: true }));
        });
        return true;
    }
    if (msg && msg.type === 'check' && typeof msg.url === 'string') {
        const r = engine.analyzeUrl(msg.url);
        chrome.storage.local.get(['blocklist', 'syncedAt']).then(({ blocklist = [], syncedAt = 0 }) => {
            let host = '';
            try { host = new URL(msg.url).hostname; } catch { /* تجاهل */ }
            reply({ result: r.error ? null : { score: r.score, level: r.level, reasons: r.reasons.slice(0, 4) }, listed: host ? blockedMatch(host, blocklist) : '', syncedAt, site: SITE });
        });
        return true;
    }
    return false;
});
