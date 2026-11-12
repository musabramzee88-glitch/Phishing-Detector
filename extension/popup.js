(function () {
    'use strict';
    const LABELS = { safe: ['لم تُرصد مؤشرات خطر', 'safe'], warning: ['تنبيه: مؤشرات تستدعي الحذر', 'warn'], danger: ['خطر: مؤشرات تصيد قوية', 'danger'] };
    const box = document.getElementById('current');
    let tabUrl = '', site = '';
    chrome.storage.local.get({ syncedAt: 0 }, v => {
        document.getElementById('sync').textContent = v.syncedAt ? 'آخر تحديث لقائمة الاحتيال: ' + new Date(v.syncedAt).toLocaleString('ar-IQ') : 'قائمة الاحتيال ما تحدّثت بعد.';
    });
    chrome.tabs.query({ active: true, currentWindow: true }, async tabs => {
        tabUrl = (tabs[0] && tabs[0].url) || '';
        if (!/^https?:/i.test(tabUrl)) { box.innerHTML = ''; const p = document.createElement('p'); p.className = 'muted'; p.textContent = 'هذي الصفحة ما تنفحص (مو موقع ويب).'; box.append(p); return; }
        const res = await chrome.runtime.sendMessage({ type: 'check', url: tabUrl });
        site = res.site;
        box.replaceChildren();
        const host = document.createElement('p');
        host.className = 'host';
        host.dir = 'ltr';
        host.textContent = new URL(tabUrl).hostname;
        box.append(host);
        if (res.listed) {
            const p = document.createElement('p'); p.className = 'verdict danger'; p.textContent = 'مؤكَّد كاحتيال ببلاغات المستخدمين'; box.append(p);
        } else if (res.result) {
            const [text, cls] = LABELS[res.result.level];
            const p = document.createElement('p'); p.className = 'verdict ' + cls; p.textContent = `${text} (${res.result.score}%)`; box.append(p);
            const ul = document.createElement('ul');
            for (const r of res.result.reasons.filter(x => x.type !== 'info').slice(0, 3)) { const li = document.createElement('li'); li.textContent = r.text; ul.append(li); }
            box.append(ul);
        }
    });
    document.getElementById('deep').addEventListener('click', () => {
        if (!site || !tabUrl) return;
        chrome.tabs.create({ url: site + '/?share_url=' + encodeURIComponent(tabUrl) });
    });
    const toggle = document.getElementById('enabled');
    chrome.storage.local.get({ enabled: true }, v => { toggle.checked = v.enabled; });
    toggle.addEventListener('change', () => chrome.storage.local.set({ enabled: toggle.checked }));
})();
