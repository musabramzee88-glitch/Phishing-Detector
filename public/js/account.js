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
        $('ddEmail').textContent = u.email || (u.phone ? '0' + u.phone.slice(3) : '');
        const badge = $('planBadge');
        badge.textContent = u.plan === 'pro' ? (u.planSource === 'trial' ? 'Pro تجربة' : 'Pro') : 'مجاني';
        badge.classList.toggle('pro', u.plan === 'pro');
    }

    function renderBanner() {
        renderHero();
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
        // مشترك Pro (مدفوع أو بالتجربة) لا نعرض له زر الاشتراك إلا قرب انتهاء خطته
        const left = daysLeft(u.planUntil);
        btn.hidden = u.plan === 'pro' && left > 7;
        btn.lastChild.textContent = u.plan !== 'pro' ? ' اشترك بـ Pro'
            : u.planSource === 'trial' ? ' اشترك قبل انتهاء التجربة' : ' جدّد اشتراكك';
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
            const head = node('tr', 'head-row');
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

    // ملخص الحساب بأعلى الصفحة: الصورة والاسم والخطة واستهلاك اليوم
    function renderHero() {
        const u = state.user;
        if (!u) return;
        $('accAvatar').textContent = (u.name || u.email || '؟').trim().charAt(0).toUpperCase();
        $('accName').textContent = u.name || 'حسابي';
        const badge = $('accPlanBadge');
        badge.textContent = u.plan === 'pro' ? (u.planSource === 'trial' ? 'Pro تجربة' : 'Pro') : 'مجاني';
        badge.classList.toggle('pro', u.plan === 'pro');
        $('accSince').textContent = 'عضو منذ ' + fmtDate(u.createdAt);
        const usage = state.usage;
        if (usage) {
            const meter = (textId, barId, used, limit) => {
                $(textId).textContent = `${used} / ${limit}`;
                const pct = limit ? Math.min(100, (used / limit) * 100) : 0;
                const bar = $(barId);
                bar.style.width = pct + '%';
                bar.classList.toggle('high', pct >= 80);
            };
            meter('accScanText', 'accScanBar', usage.scan, usage.scanLimit);
            meter('accChatText', 'accChatBar', usage.chat, usage.chatLimit);
        }
    }

    // تبويبات صفحة الحساب (القسم المفتوح يُحفظ للجلسة)
    const ACC_TABS = ['overview', 'billing', 'security', 'history'];
    function showAccountTab(name) {
        const tab = ACC_TABS.includes(name) ? name : 'overview';
        document.querySelectorAll('[data-acc-panel]').forEach(p => { p.hidden = p.dataset.accPanel !== tab; });
        document.querySelectorAll('[data-acc-tab]').forEach(b => {
            const active = b.dataset.accTab === tab;
            b.classList.toggle('active', active);
            b.setAttribute('aria-selected', String(active));
            if (active && b.scrollIntoView) b.scrollIntoView({ block: 'nearest', inline: 'center' });
        });
        try { sessionStorage.setItem('acc_tab', tab); } catch { /* اختياري */ }
        if (tab === 'history') loadHistory();
        if (tab === 'billing') loadBilling();
    }
    document.addEventListener('click', event => {
        const t = event.target.closest('[data-acc-tab],[data-acc-goto]');
        if (t) showAccountTab(t.dataset.accTab || t.dataset.accGoto);
    });

    function renderAccount() {
        const u = state.user;
        if (!u) return;
        renderHero();
        $('accountPlanLine').textContent = planText(u);
        $('accPlanFact').textContent = planText(u);
        $('profileEmail').textContent = u.email || (u.phone ? '0' + u.phone.slice(3) : '');
        $('profileProviders').textContent = [u.hasPassword ? 'البريد وكلمة السر' : '', ...u.providers.map(p => PROVIDER_NAMES[p] || p), u.phone ? 'رقم الهاتف' : ''].filter(Boolean).join('، ');
        renderPhoneCard();
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

    // سجل الفحوصات مع فلاتر (النوع، النتيجة، الفترة) وإعادة فحص الروابط
    const historyFilter = { kind: 'all', level: 'all', range: 'all' };
    let historyItems = [];

    function historyFilters() {
        const bar = node('div', 'history-filters');
        const group = (key, options) => {
            const wrap = node('div', 'filter-group');
            for (const [value, label] of options) {
                const b = node('button', 'filter-chip' + (historyFilter[key] === value ? ' active' : ''), label);
                b.type = 'button';
                b.setAttribute('aria-pressed', String(historyFilter[key] === value));
                b.addEventListener('click', () => { historyFilter[key] = value; renderHistory(); });
                wrap.append(b);
            }
            return wrap;
        };
        bar.append(
            group('level', [['all', 'الكل'], ['danger', 'خطر'], ['warning', 'تنبيه'], ['safe', 'آمن']]),
            group('kind', [['all', 'كل الأنواع'], ['url', 'روابط'], ['text', 'رسائل'], ['file', 'ملفات']]),
            group('range', [['all', 'كل الوقت'], ['week', 'هذا الأسبوع'], ['today', 'اليوم']])
        );
        return bar;
    }

    function renderHistory() {
        const box = $('historyList');
        const now = Date.now();
        const since = historyFilter.range === 'today' ? now - 86400000 : historyFilter.range === 'week' ? now - 7 * 86400000 : 0;
        const list = historyItems.filter(h =>
            (historyFilter.level === 'all' || h.level === historyFilter.level) &&
            (historyFilter.kind === 'all' || h.kind === historyFilter.kind || (historyFilter.kind === 'file' && h.kind === 'media')) &&
            h.at >= since);
        box.replaceChildren(historyFilters());
        if (!list.length) {
            box.append(node('p', 'muted', historyItems.length ? 'ما اكو فحوصات تطابق هذا الفلتر.' : 'لا توجد فحوصات محفوظة بعد.'));
            return;
        }
        const table = node('table', 'simple-table');
        const kinds = { url: 'رابط', text: 'رسالة', file: 'ملف', media: 'وسائط' };
        for (const h of list.slice(0, 100)) {
            const tr = node('tr');
            const badge = node('td');
            badge.append(node('span', 'status-pill ' + (h.level === 'danger' ? 'status-rejected' : h.level === 'warning' ? 'status-pending' : 'status-approved'), `${LEVEL_LABELS[h.level]} ${h.score}%`));
            const label = node('td', '', h.label);
            label.style.direction = h.kind === 'url' ? 'ltr' : '';
            label.style.wordBreak = 'break-all';
            const actions = node('td');
            if (h.kind === 'url') {
                const again = node('button', 'btn-quick', 'إعادة فحص');
                again.type = 'button';
                again.addEventListener('click', () => {
                    switchPage('scannerPage', 'فحص الروابط', 'fa-solid fa-link');
                    $('urlInput').value = h.label;
                    analyzeUrl();
                });
                actions.append(again);
            }
            tr.append(node('td', '', new Date(h.at).toLocaleString('ar-IQ')), node('td', '', kinds[h.kind] || h.kind), label, badge, actions);
            table.append(tr);
        }
        box.append(table);
        box.append(node('p', 'muted', `يعرض ${Math.min(list.length, 100)} من ${historyItems.length} فحصاً محفوظاً.`));
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
            historyItems = data.history || [];
            renderHistory();
        } catch { /* تجاهل */ }
    }

    async function refreshMe() {
        try {
            const { ok, data } = await api('/api/auth/me');
            if (ok) applyUser(data);
            else if (data && data.code === 'guest') applyGuest();
        } catch { /* الصفحة تكمل */ }
    }

    // ---------------------------------------------------------------- وضع الضيف (مشاهدة فقط)
    function applyGuest() {
        state.guest = true;
        window.PDAccount.guest = true;
        document.body.classList.add('guest-mode');
        $('userAvatar').textContent = '👤';
        $('userChipName').textContent = 'ضيف';
        $('ddName').textContent = 'وضع الضيف';
        $('ddEmail').textContent = 'مشاهدة فقط';
        const badge = $('planBadge');
        badge.textContent = 'ضيف';
        badge.classList.remove('pro');
        const banner = $('planBanner');
        banner.hidden = false;
        const text = $('planBannerText');
        text.replaceChildren(node('strong', '', 'أنت تتصفح كضيف (مشاهدة فقط). '), document.createTextNode('الفحص والمحادثة مع المساعد وكل الخدمات تحتاج حساب مجاني.'));
        const usage = banner.querySelector('.usage');
        if (usage) usage.hidden = true;
        const btn = $('planBannerBtn');
        btn.dataset.action = 'leaveGuest';
        btn.innerHTML = '<i class="fa-solid fa-user-plus"></i> أنشئ حساباً مجانياً';
    }

    let lastNotice = 0;
    function guestNotice() {
        if (!state.guest) applyGuest();
        if (Date.now() - lastNotice < 1500) return;
        lastNotice = Date.now();
        const banner = $('planBanner');
        banner.classList.remove('flash');
        void banner.offsetWidth;
        banner.classList.add('flash');
        banner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    async function leaveGuest() {
        try { await api('/api/auth/logout', {}); } catch { /* نكمل */ }
        window.location.replace('/login');
    }

    // ---------------------------------------------------------------- الأوامر

    function openUpgrade() {
        $('userDropdown').classList.remove('show');
        switchPage('accountPage', 'حسابي واشتراكي', 'fa-solid fa-user-shield');
        showAccountTab('billing');
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

    // ---------------------------------------------------------------- رقم الهاتف
    let phoneAvailable = null;
    let phoneChallenge = '';
    async function renderPhoneCard() {
        const u = state.user;
        if (phoneAvailable === null) {
            phoneAvailable = false;
            try { phoneAvailable = Boolean((await (await fetch('/api/auth/config', { credentials: 'same-origin' })).json()).phone); } catch { /* اختياري */ }
        }
        $('phoneCard').hidden = !phoneAvailable && !u.phone;
        if (phoneChallenge) return;
        $('phoneLinkInput').value = '';
        $('phoneLinkInput').placeholder = '07XX XXX XXXX';
        $('phoneLinkInput').setAttribute('inputmode', 'tel');
        $('phoneLinkBtn').textContent = u.phone ? 'غيّر الرقم' : 'أرسل الرمز';
        $('phoneState').textContent = u.phone
            ? `رقمك المربوط: \u20660${u.phone.slice(3)}\u2069. تكدر تدخل بيه برمز يوصلك برسالة.`
            : 'اربط رقم موبايلك حتى تكدر تدخل بيه برمز يوصلك برسالة، بدون كلمة سر.';
        $('phoneLinkForm').hidden = !phoneAvailable;
        $('phoneUnlinkBtn').hidden = !u.phone || !u.email;
    }

    async function phoneLinkStep() {
        const value = $('phoneLinkInput').value.trim();
        if (!phoneChallenge) {
            const { ok, data } = await api('/api/account/phone/start', { phone: value });
            if (!ok) return msg('phoneMsg', data.error);
            phoneChallenge = data.challenge;
            $('phoneLinkInput').value = '';
            $('phoneLinkInput').placeholder = 'الرمز (6 أرقام)';
            $('phoneLinkInput').setAttribute('inputmode', 'numeric');
            $('phoneLinkBtn').textContent = 'تأكيد';
            return msg('phoneMsg', `أرسلنا رمز إلى \u2066${data.masked}\u2069. اكتبه هنا.`, true);
        }
        const { ok, data } = await api('/api/account/phone/verify', { challenge: phoneChallenge, code: value });
        if (!ok) {
            if (data.code === 'expired' || data.code === 'too_many') phoneChallenge = '';
            msg('phoneMsg', data.error);
            if (!phoneChallenge) renderPhoneCard();
            return;
        }
        phoneChallenge = '';
        applyUser(data);
        msg('phoneMsg', 'تم ربط الرقم.', true);
    }

    async function phoneUnlink() {
        if (!window.confirm('إزالة رقم الهاتف من حسابك؟ ما تكدر تدخل بيه بعدها.')) return;
        const { ok, data } = await api('/api/account/phone/remove', {});
        if (!ok) return msg('phoneMsg', data.error);
        applyUser(data);
        msg('phoneMsg', 'انشال الرقم.', true);
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

    window.PDAccount = { user: null, guest: false, noteUsage, refresh: refreshMe, guestNotice };
    Object.assign(ACTIONS, {
        openUpgrade, toggleUserMenu, logout, submitPayment, saveProfileName, changePassword,
        rotateApiKey, toggleHistory, clearHistory, deleteAccount, runBulkScan, exportBulkCsv, leaveGuest,
        phoneLinkStep, phoneUnlink
    });

    // عند فتح صفحة الحساب نحدّث بياناتها
    document.addEventListener('click', event => {
        const el = event.target.closest('[data-page="accountPage"]');
        if (el) { $('userDropdown').classList.remove('show'); loadBilling(); loadHistory(); refreshMe(); }
        if (!event.target.closest('#userMenu')) $('userDropdown').classList.remove('show');
    });

    let savedTab = 'overview';
    try { savedTab = sessionStorage.getItem('acc_tab') || 'overview'; } catch { /* اختياري */ }
    refreshMe().then(() => { if (!state.guest) { loadBilling(); showAccountTab(savedTab); } });
})();
