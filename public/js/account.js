/*
  الحساب والاشتراك داخل التطبيق: قائمة المستخدم، شريط الخطة والاستهلاك، صفحة "حسابي واشتراكي"،
  طلبات الدفع، مفتاح API، سجل الفحوصات، والفحص الجماعي (Pro).
  يعتمد على api() و escapeHtml() و ACTIONS و switchPage من app.js.
*/
(function () {
    'use strict';

    const $ = id => document.getElementById(id);
    const state = { user: null, usage: { scan: 0, chat: 0, scanLimit: 0, chatLimit: 0 }, pricing: null, payments: [], lastBulk: [] };
    const LEVEL_LABELS = { safe: 'لا مؤشرات', warning: 'تنبيه', danger: 'خطر' };
    const LEVEL_BADGES = { safe: 'score-safe', warning: 'score-warning', danger: 'score-danger' };
    const STATUS_LABELS = { pending: 'قيد المراجعة', approved: 'مفعّل', rejected: 'مرفوض' };
    const PROVIDER_NAMES = { google: 'Google', microsoft: 'Microsoft', apple: 'Apple' };

    const fmtDate = iso => { try { return new Date(iso).toLocaleDateString('ar-IQ', { year: 'numeric', month: 'long', day: 'numeric' }); } catch { return iso; } };
    const daysLeft = iso => Math.max(0, Math.ceil((Date.parse(iso) - Date.now()) / 86400000));
    const isPro = () => state.user && state.user.plan === 'pro';

    function node(tag, className, text) {
        const el = document.createElement(tag);
        if (className) el.className = className;
        if (text !== undefined) el.textContent = text;
        return el;
    }

    function msg(id, text, ok) {
        const el = $(id);
        if (!el) return;
        el.textContent = text || '';
        el.className = 'inline-msg ' + (text ? (ok ? 'ok' : 'err') : '');
    }

    // ---------------------------------------------------------------- الحالة العامة

    function applyUser(data) {
        if (!data || !data.user) return;
        state.user = data.user;
        if (data.usage) state.usage = data.usage;
        window.PDAccount.user = state.user;
        renderHeader();
        renderBanner();
        renderAccount();
    }

    function planText(u) {
        if (u.plan === 'pro' && u.planSource === 'trial') return `Pro (تجربة مجانية، باقي ${daysLeft(u.planUntil)} يوم)`;
        if (u.plan === 'pro') return `Pro حتى ${fmtDate(u.planUntil)}`;
        return 'الخطة المجانية';
    }

    function renderHeader() {
        const u = state.user;
        $('userAvatar').textContent = (u.name || u.email || '؟').trim().charAt(0).toUpperCase();
        $('userChipName').textContent = u.name;
        $('ddName').textContent = u.name;
        $('ddEmail').textContent = u.email;
        const badge = $('planBadge');
        badge.textContent = u.plan === 'pro' ? (u.planSource === 'trial' ? 'Pro تجربة' : 'Pro') : 'مجاني';
        badge.classList.toggle('pro', u.plan === 'pro');
    }

    function renderBanner() {
        const u = state.user;
        const usage = state.usage;
        const banner = $('planBanner');
        banner.hidden = false;
        let text;
        if (u.plan === 'pro' && u.planSource === 'trial') text = `<i class="fa-solid fa-gift"></i> أنت بالشهر المجاني من Pro. باقي <b>${daysLeft(u.planUntil)}</b> يوم.`;
        else if (u.plan === 'pro') text = `<i class="fa-solid fa-crown" style="color:#ffab00"></i> مشترك Pro حتى ${escapeHtml(fmtDate(u.planUntil))}.`;
        else if (u.planSource === 'trial_ended') text = '<i class="fa-solid fa-hourglass-end"></i> انتهى شهرك المجاني. أنت على الخطة المجانية الآن.';
        else text = '<i class="fa-solid fa-user"></i> أنت على الخطة المجانية.';
        $('planBannerText').innerHTML = text;
        $('usageScan').textContent = usage.scan;
        $('usageScanLimit').textContent = usage.scanLimit;
        $('usageChat').textContent = usage.chat;
        $('usageChatLimit').textContent = usage.chatLimit;
        $('usageScanBar').style.width = Math.min(100, usage.scanLimit ? (usage.scan / usage.scanLimit) * 100 : 0) + '%';
        const btn = $('planBannerBtn');
        btn.hidden = u.plan === 'pro' && u.planSource === 'paid' && daysLeft(u.planUntil) > 7;
        btn.lastChild.textContent = u.planSource === 'paid' ? ' جدّد اشتراكك' : ' اشترك بـ Pro';
    }

    function noteUsage(kind, used, limit) {
        if (!state.user) return;
        if (kind === 'chat') { state.usage.chat = used; state.usage.chatLimit = limit; }
        else { state.usage.scan = used; state.usage.scanLimit = limit; }
        renderBanner();
    }

    // ---------------------------------------------------------------- صفحة الحساب

    function renderPlans() {
        const box = $('planCards');
        if (!state.pricing || !state.user) return;
        box.replaceChildren();
        for (const tier of state.pricing.tiers) {
            const card = node('div', 'plan-card' + (tier.id === 'pro' ? ' featured' : ''));
            if (tier.id === 'pro' && state.pricing.trialDays && !state.user.trialUsed) card.append(node('span', 'plan-ribbon', `أول ${state.pricing.trialDays} يوم مجاناً`));
            card.append(node('h3', '', tier.id === 'pro' ? 'Pro' : 'المجانية'));
            const price = node('div', 'plan-price', tier.priceUsd ? `${tier.priceUsd}$` : '0$');
            price.append(node('small', '', tier.priceUsd ? ` / شهرياً (≈ ${Number(tier.priceIqd).toLocaleString('ar-IQ')} د.ع)` : ' للأبد'));
            card.append(price);
            const list = node('ul');
            for (const f of tier.features) list.append(node('li', '', f));
            card.append(list);
            if (state.user.plan === tier.id) card.append(node('span', 'current-tag', '✓ خطتك الحالية'));
            box.append(card);
        }
    }

    function renderPayment() {
        const p = state.pricing;
        if (!p) return;
        const methods = $('payMethods');
        methods.replaceChildren();
        for (const m of p.payment.methods) {
            const row = node('div', 'pay-method');
            row.append(node('strong', '', m.label));
            if (m.account) row.append(node('code', '', m.account));
            methods.append(row);
        }
        const contact = [];
        if (p.payment.whatsapp) contact.push('واتساب: +' + p.payment.whatsapp);
        if (p.payment.telegram) contact.push('تيليجرام: @' + p.payment.telegram);
        $('payNote').textContent = [p.payment.note, contact.length ? 'للاستفسار: ' + contact.join(' | ') : ''].filter(Boolean).join(' — ');

        const months = $('payMonths');
        if (!months.options.length) {
            for (const m of p.months) {
                const label = m === 1 ? 'شهر واحد' : m === 12 ? 'سنة (12 شهراً)' : `${m} أشهر`;
                months.append(new Option(`${label} — ${m * p.monthlyUsd}$ (≈ ${(m * p.monthlyIqd).toLocaleString('ar-IQ')} د.ع)`, String(m)));
            }
            months.addEventListener('change', updateTotal);
        }
        const method = $('payMethod');
        if (!method.options.length) for (const m of p.payment.methods) method.append(new Option(m.label, m.id));
        updateTotal();

        const list = $('paymentsList');
        list.replaceChildren();
        if (state.payments.length) {
            const table = node('table', 'simple-table');
            const head = node('tr');
            for (const t of ['التاريخ', 'المدة', 'المبلغ', 'الطريقة', 'الحالة']) head.append(node('th', '', t));
            table.append(head);
            for (const pay of state.payments) {
                const tr = node('tr');
                const status = node('td');
                status.append(node('span', 'status-pill status-' + pay.status, STATUS_LABELS[pay.status] || pay.status));
                if (pay.status === 'rejected' && pay.reason) status.append(node('div', 'muted', pay.reason));
                const methodLabel = (p.payment.methods.find(m => m.id === pay.method) || {}).label || pay.method;
                tr.append(node('td', '', fmtDate(pay.createdAt)), node('td', '', pay.months + ' شهر'), node('td', '', pay.amountUsd + '$'), node('td', '', methodLabel), status);
                table.append(tr);
            }
            list.append(node('h4', '', 'طلباتي'), table);
        }
    }

    function updateTotal() {
        const p = state.pricing;
        const m = Number($('payMonths').value || 1);
        $('payTotal').textContent = `المجموع: ${m * p.monthlyUsd}$ (≈ ${(m * p.monthlyIqd).toLocaleString('ar-IQ')} د.ع)`;
    }

    function renderAccount() {
        const u = state.user;
        if (!u) return;
        $('accountPlanLine').textContent = `خطتك: ${planText(u)}`;
        $('profileEmail').textContent = u.email;
        $('profileProviders').textContent = 'طرق الدخول: ' + [u.hasPassword ? 'البريد وكلمة السر' : '', ...u.providers.map(p => PROVIDER_NAMES[p] || p)].filter(Boolean).join('، ');
        if (document.activeElement !== $('profileName')) $('profileName').value = u.name;
        $('pwCurrent').hidden = !u.hasPassword;
        $('apiKeyHint').textContent = u.limits.api
            ? (u.apiKeyHint ? `مفتاحك الحالي: ${u.apiKeyHint}` : 'لم تنشئ مفتاحاً بعد.')
            : 'متاح لمشتركي Pro.';
        $('historyToggle').disabled = !u.limits.history;
        $('historyToggle').checked = u.limits.history && u.historyEnabled;
        renderPlans();
        renderBulkNotice();
    }

    async function loadBilling() {
        try {
            const { ok, data } = await api('/api/billing');
            if (!ok) return;
            state.pricing = data.pricing;
            state.payments = data.payments || [];
            renderPlans();
            renderPayment();
        } catch { /* يُعاد المحاولة عند فتح الصفحة */ }
    }

    async function loadHistory() {
        const box = $('historyList');
        if (!isPro()) {
            box.textContent = 'سجل الفحوصات متاح لمشتركي Pro.';
            return;
        }
        try {
            const { ok, data } = await api('/api/account/history');
            if (!ok) return;
            box.replaceChildren();
            if (!data.history.length) {
                box.textContent = 'لا توجد فحوصات محفوظة بعد.';
                return;
            }
            const table = node('table', 'simple-table');
            const kinds = { url: 'رابط', text: 'رسالة', file: 'ملف', media: 'وسائط' };
            for (const h of data.history.slice(0, 50)) {
                const tr = node('tr');
                const badge = node('td');
                badge.append(node('span', 'status-pill ' + (h.level === 'danger' ? 'status-rejected' : h.level === 'warning' ? 'status-pending' : 'status-approved'), `${LEVEL_LABELS[h.level]} ${h.score}%`));
                const label = node('td', '', h.label);
                label.style.direction = h.kind === 'url' ? 'ltr' : '';
                label.style.wordBreak = 'break-all';
                tr.append(node('td', '', new Date(h.at).toLocaleString('ar-IQ')), node('td', '', kinds[h.kind] || h.kind), label, badge);
                table.append(tr);
            }
            box.append(table);
        } catch { /* تجاهل */ }
    }

    async function refreshMe() {
        try {
            const { ok, data } = await api('/api/auth/me');
            if (ok) applyUser(data);
        } catch { /* الصفحة تكمل */ }
    }

    // ---------------------------------------------------------------- الأوامر

    function openUpgrade() {
        $('userDropdown').classList.remove('show');
        switchPage('accountPage', 'حسابي واشتراكي', 'fa-solid fa-user-shield');
        loadBilling().then(() => {
            const card = $('subscribeCard');
            if (card) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
        });
    }

    function toggleUserMenu() {
        $('userDropdown').classList.toggle('show');
    }

    async function logout() {
        try { await api('/api/auth/logout', {}); } catch { /* نكمل */ }
        window.location.replace('/login');
    }

    async function submitPayment() {
        const reference = $('payReference').value.trim();
        if (reference.length < 4) return msg('paymentMsg', 'اكتب رقم العملية كما يظهر بإشعار التحويل.');
        const { ok, data } = await api('/api/billing/request', {
            method: $('payMethod').value, months: Number($('payMonths').value), reference, note: $('payNoteInput').value.trim()
        });
        if (!ok) return msg('paymentMsg', data.error || 'تعذر إرسال الطلب.');
        $('payReference').value = '';
        $('payNoteInput').value = '';
        msg('paymentMsg', 'وصلنا طلبك! سنراجعه ونفعّل حسابك قريباً، وتشوف حالته هنا.', true);
        loadBilling();
    }

    async function saveProfileName() {
        const { ok, data } = await api('/api/account/name', { name: $('profileName').value });
        if (!ok) return msg('profileMsg', data.error);
        applyUser(data);
        msg('profileMsg', 'تم الحفظ.', true);
    }

    async function changePassword() {
        const { ok, data } = await api('/api/account/password', { current: $('pwCurrent').value, next: $('pwNext').value });
        if (!ok) return msg('passwordMsg', data.error);
        $('pwCurrent').value = '';
        $('pwNext').value = '';
        applyUser(data);
        msg('passwordMsg', 'تم تغيير كلمة السر.', true);
    }

    async function rotateApiKey() {
        if (state.user && state.user.apiKeyHint && !window.confirm('إنشاء مفتاح جديد يوقف المفتاح الحالي فوراً. متأكد؟')) return;
        const { ok, data } = await api('/api/account/api-key', {});
        if (!ok) return msg('apiKeyMsg', data.error);
        applyUser(data);
        const box = $('apiKeyBox');
        box.replaceChildren(node('div', 'api-key-box', data.key), node('p', 'muted', 'انسخ المفتاح الآن واحفظه بمكان آمن. لن يظهر مرة ثانية.'));
        msg('apiKeyMsg', '');
    }

    async function toggleHistory(input) {
        const { ok, data } = await api('/api/account/history-setting', { enabled: input.checked });
        if (ok) { applyUser(data); loadHistory(); }
    }

    async function clearHistory() {
        if (!window.confirm('مسح كل سجل فحوصاتك؟')) return;
        await api('/api/account/history/clear', {});
        loadHistory();
    }

    async function deleteAccount() {
        const confirmEmail = $('deleteConfirm').value.trim();
        if (!window.confirm('سيُحذف حسابك نهائياً. متأكد؟')) return;
        const { ok, data } = await api('/api/account/delete', { confirm: confirmEmail });
        if (!ok) return msg('deleteMsg', data.error);
        window.location.replace('/login');
    }

    // ---------------------------------------------------------------- الفحص الجماعي

    function renderBulkNotice() {
        const box = $('bulkNotice');
        if (!box || !state.user) return;
        box.replaceChildren();
        if (!state.user.limits.bulkMaxUrls) {
            const callout = node('div', 'upgrade-callout');
            callout.append(node('span', '', 'الفحص الجماعي متاح لمشتركي Pro (حتى 50 رابطاً دفعة واحدة).'));
            const btn = node('button', 'app-btn small', 'الترقية إلى Pro');
            btn.type = 'button';
            btn.dataset.action = 'openUpgrade';
            callout.append(btn);
            box.append(callout);
        } else {
            box.append(node('p', 'muted', `حتى ${state.user.limits.bulkMaxUrls} رابطاً بالمرة. كل رابط يُحسب فحصاً واحداً من حصتك اليومية.`));
        }
    }

    function renderBulk(data) {
        const box = $('bulkReport');
        box.style.display = 'block';
        state.lastBulk = data.results;
        const counts = { safe: 0, warning: 0, danger: 0, error: 0 };
        for (const r of data.results) counts[r.error ? 'error' : r.level] += 1;
        const summary = node('p', 'muted', `فُحص ${data.count} رابطاً: خطر ${counts.danger} | تنبيه ${counts.warning} | لا مؤشرات ${counts.safe}${counts.error ? ' | غير صالح ' + counts.error : ''}`);
        const table = node('table', 'simple-table');
        const head = node('tr');
        for (const t of ['الرابط', 'النتيجة', 'أهم الأسباب']) head.append(node('th', '', t));
        table.append(head);
        for (const r of data.results) {
            const tr = node('tr');
            const url = node('td', '', r.url);
            url.style.direction = 'ltr';
            url.style.wordBreak = 'break-all';
            const result = node('td');
            if (r.error) result.append(node('span', 'risk-score-badge score-warning', 'غير صالح'));
            else result.append(node('span', 'risk-score-badge ' + LEVEL_BADGES[r.level], `${LEVEL_LABELS[r.level]} ${r.score}%`));
            tr.append(url, result, node('td', '', r.error ? 'تعذر تحليل هذا الرابط' : r.reasons.slice(0, 2).map(x => x.text).join(' ؛ ')));
            table.append(tr);
        }
        const wrap = node('div');
        wrap.style.overflowX = 'auto';
        wrap.append(table);
        box.replaceChildren(summary, wrap);
    }

    async function runBulkScan() {
        const box = $('bulkReport');
        const urls = $('bulkInput').value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
        box.style.display = 'block';
        if (!state.user || !state.user.limits.bulkMaxUrls) {
            box.innerHTML = quotaHtml('الفحص الجماعي متاح لمشتركي Pro.');
            return;
        }
        if (!urls.length) {
            box.replaceChildren(node('p', 'muted', 'ألصق رابطاً واحداً على الأقل (رابط بكل سطر).'));
            return;
        }
        box.innerHTML = loadingHtml(`جارٍ فحص ${urls.length} رابطاً...`);
        const { ok, data } = await api('/api/scan/bulk', { urls });
        if (!ok) {
            box.innerHTML = data.code === 'quota' || data.code === 'pro_only' ? quotaHtml(data.error) : errorHtml(data.error || 'تعذر إكمال الفحص.');
            return;
        }
        renderBulk(data);
        refreshMe();
    }

    function csvCell(value) {
        let text = String(value == null ? '' : value);
        if (/^[=+\-@\t\r]/.test(text)) text = "'" + text;
        return /[",\n\r]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
    }

    function exportBulkCsv() {
        if (!state.lastBulk.length) return;
        const rows = [['url', 'level', 'score', 'host', 'top_reasons'].join(',')];
        for (const r of state.lastBulk) {
            rows.push([r.url, r.error ? 'invalid' : r.level, r.error ? '' : r.score, r.host || '', r.error ? '' : r.reasons.slice(0, 3).map(x => x.text).join(' | ')].map(csvCell).join(','));
        }
        const blob = new Blob(['﻿' + rows.join('\r\n') + '\r\n'], { type: 'text/csv;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = 'bulk-scan.csv';
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    // ---------------------------------------------------------------- التسجيل

    window.PDAccount = { user: null, noteUsage, refresh: refreshMe };
    Object.assign(ACTIONS, {
        openUpgrade, toggleUserMenu, logout, submitPayment, saveProfileName, changePassword,
        rotateApiKey, toggleHistory, clearHistory, deleteAccount, runBulkScan, exportBulkCsv
    });

    // عند فتح صفحة الحساب نحدّث بياناتها
    document.addEventListener('click', event => {
        const el = event.target.closest('[data-page="accountPage"]');
        if (el) { $('userDropdown').classList.remove('show'); loadBilling(); loadHistory(); refreshMe(); }
        if (!event.target.closest('#userMenu')) $('userDropdown').classList.remove('show');
    });

    refreshMe().then(() => { loadBilling(); });
})();
