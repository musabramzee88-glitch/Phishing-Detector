/* صفحة الدخول: بريد وكلمة سر، أو Google / Microsoft / Apple، وإعادة تعيين كلمة السر برابط. */
(function () {
    'use strict';

    const $ = id => document.getElementById(id);
    let mode = 'login';
    let busy = false;

    try {
        const theme = localStorage.getItem('selected_theme');
        if (theme && /^[a-z]+$/.test(theme)) document.body.setAttribute('data-theme', theme);
    } catch { /* المظهر اختياري */ }

    const ERRORS = {
        cancelled: 'تم إلغاء الدخول.',
        failed: 'تعذر إكمال الدخول. حاول مرة أخرى.',
        unavailable: 'الخدمة غير متاحة مؤقتاً. حاول بعد قليل.',
        provider: 'طريقة الدخول هذه غير مفعّلة.',
        rate: 'محاولات كثيرة. انتظر دقيقة ثم حاول.',
        no_email: 'لم يرسل المزوّد بريدك الإلكتروني. اسمح بمشاركة البريد وحاول مجدداً.',
        link_unverified: 'هذا البريد مسجّل مسبقاً. سجّل الدخول بالبريد وكلمة السر.',
        email_taken: 'هذا البريد مسجّل مسبقاً.',
        disabled: 'هذا الحساب موقوف. تواصل مع الدعم.',
        bad_verify: 'رابط التأكيد غير صالح أو منتهي. سجّل الدخول واطلب رابطاً جديداً.'
    };
    const PROVIDER_ICONS = { google: 'fa-brands fa-google', microsoft: 'fa-brands fa-microsoft', apple: 'fa-brands fa-apple' };

    function notice(text, kind = 'error') {
        const box = $('authNotice');
        box.textContent = text;
        box.className = 'auth-notice ' + kind;
        box.hidden = !text;
    }

    function setMode(next, keepNotice) {
        mode = next;
        document.querySelectorAll('.auth-tab').forEach(tab => {
            const active = tab.dataset.mode === next;
            tab.classList.toggle('active', active);
            tab.setAttribute('aria-selected', String(active));
        });
        const register = next === 'register';
        $('nameField').hidden = !register;
        $('passwordHint').hidden = !register;
        $('registerTerms').hidden = !register;
        $('forgotHint').hidden = register;
        $('authSubmitText').textContent = register ? 'إنشاء الحساب وبدء الشهر المجاني' : 'دخول';
        $('authPassword').setAttribute('autocomplete', register ? 'new-password' : 'current-password');
        if (!keepNotice) notice('');
    }

    let verifyEmailAddress = '';
    function showVerify(email, message) {
        verifyEmailAddress = email;
        $('authMain').hidden = true;
        $('verifyForm').hidden = false;
        $('verifyIntro').textContent = 'أرسلنا كوداً من 6 أرقام إلى ' + email + '. اكتبه هنا (صالح 15 دقيقة).';
        $('verifyCode').value = '';
        $('verifyCode').focus();
        if (message) notice(message, 'success');
    }

    async function submitVerify(event) {
        event.preventDefault();
        if (busy) return;
        const form = $('verifyForm');
        const code = $('verifyCode').value.replace(/\D/g, '');
        if (code.length !== 6) return notice('اكتب الكود المكوّن من 6 أرقام.');
        setBusy(form, true);
        try {
            await post('/api/auth/verify-code', { email: verifyEmailAddress, code });
            notice('تم تأكيد بريدك! جارٍ فتح لوحتك...', 'success');
            window.location.replace('/');
        } catch (error) {
            notice(error.message);
            setBusy(form, false);
        }
    }

    async function mailAction(path, text) {
        const email = $('authEmail').value.trim();
        if (!email || !/^\S+@\S+\.\S+$/.test(email)) return notice('اكتب بريدك في الحقل أولاً.');
        try {
            const data = await post(path, { email });
            notice(data.message || text, 'success');
        } catch (error) {
            notice(error.message);
        }
    }

    async function post(url, body) {
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            credentials: 'same-origin',
            body: JSON.stringify(body)
        });
        let data = {};
        try { data = await response.json(); } catch { /* رد غير JSON */ }
        if (!response.ok) {
            const error = new Error(data.error || 'حدث خطأ. حاول مرة أخرى.');
            error.code = data.code || '';
            throw error;
        }
        return data;
    }

    function setBusy(form, value) {
        busy = value;
        form.querySelectorAll('button, input').forEach(el => { el.disabled = value; });
        form.classList.toggle('busy', value);
    }

    async function submitAuth(event) {
        event.preventDefault();
        if (busy) return;
        const form = $('authForm');
        const email = $('authEmail').value.trim();
        const password = $('authPassword').value;
        if (!email || !/^\S+@\S+\.\S+$/.test(email)) return notice('اكتب بريداً إلكترونياً صحيحاً.');
        if (password.length < 8) return notice('كلمة السر 8 أحرف على الأقل.');
        setBusy(form, true);
        try {
            if (mode === 'register') {
                const data = await post('/api/auth/register', { email, password, name: $('authName').value.trim() });
                if (data.needsVerification) {
                    setBusy(form, false);
                    return showVerify(data.email, data.sent
                        ? 'أرسلنا كود التحقق. افتح بريدك (وافحص الرسائل غير المرغوبة).'
                        : 'تم إنشاء الحساب لكن تعذر إرسال الكود الآن. اضغط «أرسل كوداً جديداً» بعد قليل.');
                }
            } else {
                await post('/api/auth/login', { email, password });
            }
            notice('تم! جارٍ فتح لوحتك...', 'success');
            window.location.replace('/');
        } catch (error) {
            if (error.code === 'email_unverified') {
                setBusy(form, false);
                post('/api/auth/resend', { email }).catch(() => {});
                return showVerify(email, 'حسابك غير مؤكَّد. أرسلنا لك كوداً جديداً.');
            }
            notice(error.message);
            setBusy(form, false);
        }
    }

    async function submitReset(event) {
        event.preventDefault();
        if (busy) return;
        const form = $('resetForm');
        const token = new URLSearchParams(window.location.search).get('reset') || '';
        const password = $('resetPassword').value;
        if (password.length < 8) return notice('كلمة السر 8 أحرف على الأقل.');
        setBusy(form, true);
        try {
            await post('/api/auth/reset', { token, password });
            window.location.replace('/');
        } catch (error) {
            notice(error.message);
            setBusy(form, false);
        }
    }

    async function loadConfig() {
        try {
            const response = await fetch('/api/auth/config', { credentials: 'same-origin' });
            const config = await response.json();
            const list = $('providerButtons');
            list.replaceChildren();
            for (const provider of config.providers || []) {
                const link = document.createElement('a');
                link.className = 'provider-btn provider-' + provider.id;
                link.href = '/auth/' + encodeURIComponent(provider.id) + '/start';
                const icon = document.createElement('i');
                icon.className = PROVIDER_ICONS[provider.id] || 'fa-solid fa-right-to-bracket';
                link.append(icon, ' المتابعة عبر ' + provider.label);
                list.appendChild(link);
            }
            const any = list.children.length > 0;
            list.hidden = !any;
            $('providerDivider').hidden = !any;
            if (config.trialDays > 0) {
                $('trialOfferText').textContent = `لكل حساب جديد ${config.trialDays} يوماً مجاناً، وبعدها ${config.priceUsd}$ شهرياً أو الخطة المجانية.`;
            } else {
                $('trialOffer').hidden = true;
            }
        } catch {
            // الدخول بالبريد يبقى متاحاً
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        const params = new URLSearchParams(window.location.search);
        if (params.get('reset')) {
            $('authMain').hidden = true;
            $('resetForm').hidden = false;
        }
        const error = params.get('error');
        if (error) notice(ERRORS[error] || ERRORS.failed);
        if (params.get('mode') === 'register') setMode('register');
        if (params.get('verified')) notice('تم تأكيد بريدك. سجّل الدخول الآن وابدأ شهرك المجاني.', 'success');
        $('forgotBtn').addEventListener('click', () => mailAction('/api/auth/forgot', 'أرسلنا رابط إعادة التعيين.'));
        $('resendBtn').addEventListener('click', () => mailAction('/api/auth/resend', 'أرسلنا كوداً جديداً.'));
        $('verifyForm').addEventListener('submit', submitVerify);
        $('verifyResend').addEventListener('click', async () => {
            try { const d = await post('/api/auth/resend', { email: verifyEmailAddress }); notice(d.message || 'أرسلنا كوداً جديداً.', 'success'); } catch (error) { notice(error.message); }
        });
        $('verifyBack').addEventListener('click', () => { $('verifyForm').hidden = true; $('authMain').hidden = false; notice(''); });

        document.querySelectorAll('.auth-tab').forEach(tab => tab.addEventListener('click', () => setMode(tab.dataset.mode)));
        $('authForm').addEventListener('submit', submitAuth);
        $('resetForm').addEventListener('submit', submitReset);
        $('togglePassword').addEventListener('click', () => {
            const field = $('authPassword');
            field.type = field.type === 'password' ? 'text' : 'password';
        });
        loadConfig();
    });
})();
