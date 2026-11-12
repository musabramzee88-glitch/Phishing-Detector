/*
  فحص أمان حساباتك (Security Checkup): 10 أسئلة، درجة من 100، وخطوات لكل نقطة ناقصة.
  الإجابات تبقى بالمتصفح. لمشتركي Pro تُحفظ الدرجة فقط (بدون الإجابات) حتى يشوفون تطورها.
*/
(function () {
    'use strict';

    // good: الإجابة اللي تعني إنك محمي. الأوزان مجموعها 100
    const QUESTIONS = [
        { id: 'wa2fa', weight: 12, good: 'yes', q: 'مفعّل «التحقق بخطوتين» (رمز PIN) بالواتساب؟',
          fix: 'واتساب ← الإعدادات ← الحساب ← التحقق بخطوتين ← تفعيل. اختار رمز 6 أرقام ما تنساه، وضيف بريدك للاسترجاع.' },
        { id: 'social2fa', weight: 12, good: 'yes', q: 'مفعّل التحقق بخطوتين بفيسبوك وانستغرام؟',
          fix: 'فيسبوك وانستغرام ← مركز الحسابات ← كلمة السر والأمان ← المصادقة الثنائية. اختار «تطبيق مصادقة» إذا تكدر، أحسن من SMS.' },
        { id: 'mail2fa', weight: 14, good: 'yes', q: 'مفعّل التحقق بخطوتين ببريدك (Gmail أو Outlook)؟',
          fix: 'البريد هو مفتاح كل حساباتك (منه تسترجع كلشي). فعّل التحقق بخطوتين من صفحة أمان الحساب.',
          link: ['أمان حساب Google', 'https://myaccount.google.com/security'] },
        { id: 'reuse', weight: 14, good: 'no', q: 'تستعمل نفس كلمة السر (أو كلمة قريبة منها) بأكثر من موقع؟',
          fix: 'إذا تسربت من موقع واحد، المحتال يجربها على بريدك وحساباتك كلها. ابدي غيّر كلمة سر البريد والمصرف لكلمات مختلفة.' },
        { id: 'manager', weight: 8, good: 'yes', q: 'تستعمل مدير كلمات سر، أو كلمات طويلة ومختلفة لكل حساب؟',
          fix: 'مدير كلمات السر (المدمج بكروم أو آيفون مثلاً) يحفظ كلمة مختلفة لكل موقع. أو استعمل جملة طويلة من 4 كلمات ما بينها علاقة.' },
        { id: 'updates', weight: 8, good: 'yes', q: 'نظام الموبايل والتطبيقات عندك محدّثة؟',
          fix: 'التحديثات تسد ثغرات يستغلها المخترقين. فعّل التحديث التلقائي من المتجر ومن إعدادات النظام.' },
        { id: 'lock', weight: 8, good: 'yes', q: 'شاشة موبايلك مقفولة ببصمة أو رمز؟',
          fix: 'الإعدادات ← الأمان ← قفل الشاشة. استعمل رمز 6 أرقام على الأقل مع البصمة.' },
        { id: 'apk', weight: 10, good: 'no', q: 'تنزّل تطبيقات من خارج المتجر الرسمي (ملفات APK من روابط أو كروبات)؟',
          fix: 'أغلب تطبيقات سرقة الحسابات والبنوك توصل كملف APK. نزّل بس من Google Play أو App Store، واطفي خيار «تثبيت تطبيقات غير معروفة».' },
        { id: 'backup', weight: 6, good: 'yes', q: 'عندك نسخة احتياطية لصورك وملفاتك المهمة؟',
          fix: 'فعّل النسخ الاحتياطي (Google Photos أو iCloud) حتى إذا انسرق الموبايل أو اضطريت تمسحه ما تخسر شي.' },
        { id: 'recovery', weight: 8, good: 'yes', q: 'رقمك وبريد الاسترجاع محدّثين بحساباتك المهمة؟',
          fix: 'إذا انسرق حسابك، الاسترجاع يعتمد عليهم. راجع إعدادات الأمان بكل حساب مهم وتأكد إنهم صحيحين.' }
    ];

    const $ = id => document.getElementById(id);
    const answers = {};
    try { Object.assign(answers, JSON.parse(localStorage.getItem('checkup_answers') || '{}')); } catch { /* اختياري */ }

    function el(tag, cls, text) {
        const n = document.createElement(tag);
        if (cls) n.className = cls;
        if (text !== undefined) n.textContent = text;
        return n;
    }

    function score() {
        let total = 0, answered = 0;
        for (const q of QUESTIONS) {
            if (!answers[q.id]) continue;
            answered++;
            if (answers[q.id] === q.good) total += q.weight;
        }
        return { total, answered };
    }

    function renderQuestions() {
        const list = $('checkupList');
        if (!list) return;
        list.replaceChildren(...QUESTIONS.map((q, i) => {
            const card = el('fieldset', 'cq');
            card.append(el('legend', '', `${i + 1}. ${q.q}`));
            const row = el('div', 'cq-opts');
            for (const [value, label] of [['yes', 'نعم'], ['no', 'لا'], ['unsure', 'ما أدري']]) {
                const b = el('button', 'cq-opt' + (answers[q.id] === value ? ' active' : ''), label);
                b.type = 'button';
                b.setAttribute('aria-pressed', String(answers[q.id] === value));
                b.addEventListener('click', () => {
                    answers[q.id] = value;
                    try { localStorage.setItem('checkup_answers', JSON.stringify(answers)); } catch { /* اختياري */ }
                    renderQuestions();
                    renderResult();
                });
                row.append(b);
            }
            card.append(row);
            return card;
        }));
    }

    function renderResult() {
        const box = $('checkupResult');
        if (!box) return;
        const { total, answered } = score();
        if (answered < QUESTIONS.length) {
            box.replaceChildren(el('p', 'muted', `جاوبت ${answered} من ${QUESTIONS.length}. كمّل الأسئلة حتى تطلع درجتك.`));
            return;
        }
        const level = total >= 80 ? 'good' : total >= 50 ? 'mid' : 'low';
        const head = el('div', 'cq-score ' + level);
        head.append(el('b', '', String(total)), el('span', '', '/ 100'));
        const verdict = el('p', 'cq-verdict', level === 'good' ? 'ممتاز! حساباتك محمية زين. راجعها كل كم شهر.' : level === 'mid' ? 'زين، بس اكو نقاط مهمة ناقصة. سوّها من القائمة تحت.' : 'حساباتك معرضة للخطر. ابدي بالخطوات تحت من الأعلى للأسفل.');
        const todo = QUESTIONS.filter(q => answers[q.id] !== q.good).sort((a, b) => b.weight - a.weight);
        const steps = el('ol', 'cq-todo');
        for (const q of todo) {
            const li = el('li');
            li.append(el('strong', '', `${q.q} (+${q.weight})`), el('p', '', q.fix));
            if (q.link) {
                const a = el('a', '', q.link[0]);
                a.href = q.link[1];
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
                li.append(a);
            }
            steps.append(li);
        }
        const parts = [head, verdict];
        if (todo.length) parts.push(el('h4', '', 'شلون ترفع درجتك:'), steps);
        const save = el('button', 'app-btn small', 'احفظ درجتي بحسابي');
        save.type = 'button';
        save.addEventListener('click', async () => {
            try {
                const { ok, data } = await api('/api/account/checkup', { score: total });
                save.textContent = ok ? '✓ انحفظت' : (data.error || 'تعذر الحفظ');
                if (ok) renderTrend(data.checkups || []);
            } catch { save.textContent = 'تعذر الحفظ'; }
        });
        parts.push(save, el('p', 'muted cq-privacy', 'إجاباتك تبقى بجهازك. نحفظ بحسابك الدرجة والتاريخ بس (لمشتركي Pro).'));
        box.replaceChildren(...parts);
        const user = window.PDAccount && window.PDAccount.user;
        if (user && Array.isArray(user.checkups)) renderTrend(user.checkups);
    }

    function renderTrend(list) {
        const box = $('checkupTrend');
        if (!box || !list.length) return;
        box.replaceChildren(el('h4', '', 'تطور درجتك'), ...list.slice(-8).map(c => {
            const row = el('div', 'cq-trend-row');
            const bar = el('span', 'cq-trend-bar');
            bar.style.width = Math.max(4, c.score) + '%';
            row.append(el('small', '', new Date(c.at).toLocaleDateString('ar-IQ')), bar, el('b', '', String(c.score)));
            return row;
        }));
    }

    function resetCheckup() {
        for (const k of Object.keys(answers)) delete answers[k];
        try { localStorage.removeItem('checkup_answers'); } catch { /* اختياري */ }
        renderQuestions();
        renderResult();
    }

    if (typeof ACTIONS === 'object') ACTIONS.resetCheckup = resetCheckup;
    document.addEventListener('DOMContentLoaded', () => { renderQuestions(); renderResult(); });
})();
