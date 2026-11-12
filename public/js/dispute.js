/* صفحة الاعتراض العامة على بلاغات رقم أو حساب */
(function () {
    'use strict';
    const $ = id => document.getElementById(id);
    const params = new URLSearchParams(location.search);
    if (params.get('kind')) $('dKind').value = params.get('kind');
    if (params.get('value')) $('dValue').value = params.get('value').slice(0, 200);
    $('disputeForm').addEventListener('submit', async event => {
        event.preventDefault();
        const msg = $('dMsg');
        msg.textContent = 'جارٍ الإرسال...';
        try {
            const res = await fetch('/api/identifier/dispute', {
                method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ kind: $('dKind').value, value: $('dValue').value, contact: $('dContact').value, reason: $('dReason').value })
            });
            const data = await res.json().catch(() => ({}));
            msg.textContent = res.ok ? data.message : (data.error || 'تعذر الإرسال.');
            if (res.ok) $('disputeForm').reset();
        } catch {
            msg.textContent = 'تعذر الاتصال. حاول بعد قليل.';
        }
    });
})();
