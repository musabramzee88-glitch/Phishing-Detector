(function () {
    'use strict';
    const params = new URLSearchParams(location.search);
    const url = params.get('u') || '';
    let reasons = [];
    try { reasons = JSON.parse(params.get('r') || '[]'); } catch { reasons = []; }
    document.getElementById('url').textContent = url;
    document.getElementById('score').textContent = String(Math.min(100, Math.max(0, Number(params.get('s')) || 0)));
    const list = document.getElementById('reasons');
    for (const r of reasons.slice(0, 5)) { const li = document.createElement('li'); li.textContent = String(r); list.append(li); }
    document.getElementById('back').addEventListener('click', () => { if (history.length > 2) history.go(-2); else location.href = 'about:blank'; });
    document.getElementById('deep').addEventListener('click', () => { location.href = self.PD_CONFIG.site + '/?share_url=' + encodeURIComponent(url); });
    document.getElementById('proceed').addEventListener('click', async () => {
        let host = '';
        try { host = new URL(url).hostname; } catch { return; }
        if (!/^https?:/i.test(url)) return;
        await chrome.runtime.sendMessage({ type: 'allow', host });
        location.href = url;
    });
})();
