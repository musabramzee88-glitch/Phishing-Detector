/* الدورة التوعوية: مستويات، دروس، اختبار (التصحيح على الخادم)، نقاط، وشهادة إتمام. كل النصوص تُعرض بـ textContent. */
(function () {
    'use strict';
    const $ = id => document.getElementById(id);
    let state = null, quiz = null;

    function el(tag, cls, text) {
        const n = document.createElement(tag);
        if (cls) n.className = cls;
        if (text !== undefined) n.textContent = text;
        return n;
    }
    function button(text, cls, onClick) {
        const b = el('button', cls, text);
        b.type = 'button';
        b.addEventListener('click', onClick);
        return b;
    }

    async function load() {
        const box = $('courseBox');
        if (!box) return;
        try {
            const { ok, data } = await api('/api/course');
            if (!ok) { box.replaceChildren(el('p', 'muted', data.code === 'guest' ? 'الدورة والشهادة تحتاج حساب مجاني.' : (data.error || 'تعذر تحميل الدورة.'))); return; }
            state = data;
            render();
        } catch { /* يُعاد لاحقاً */ }
    }

    function render() {
        const box = $('courseBox');
        const head = el('div', 'course-head');
        const done = state.levels.filter(l => l.passed).length;
        head.append(el('strong', '', `تقدّمك: ${done} من ${state.levels.length} مستويات`), el('span', 'course-points', `${state.points} نقطة`));
        const bar = el('div', 'course-bar');
        const fill = el('span');
        fill.style.width = Math.round((done / state.levels.length) * 100) + '%';
        bar.append(fill);
        const parts = [head, bar];
        for (const level of state.levels) {
            const card = el('div', 'course-level' + (level.passed ? ' passed' : level.unlocked ? '' : ' locked'));
            const title = el('div', 'course-level-head');
            title.append(el('strong', '', level.title), el('span', 'course-badge', level.passed ? `✓ اجتزته (${level.score}/5)` : level.unlocked ? `${level.points} نقطة` : '🔒 مقفول'));
            card.append(title);
            if (level.unlocked) {
                const lessons = el('details', 'course-lessons');
                lessons.append(el('summary', '', `الدروس (${level.lessons.length})`));
                for (const lesson of level.lessons) {
                    const l = el('div', 'course-lesson');
                    l.append(el('b', '', lesson.title), el('p', '', lesson.body));
                    lessons.append(l);
                }
                card.append(lessons, button(level.passed ? 'أعد الاختبار' : 'ابدأ الاختبار', 'app-btn small', () => startQuiz(level.id)));
            } else {
                card.append(el('p', 'muted', 'اجتاز المستوى اللي قبله حتى ينفتح.'));
            }
            card.append(el('div', 'course-quiz'));
            card.dataset.level = level.id;
            parts.push(card);
        }
        if (state.complete) {
            const cert = el('div', 'course-cert');
            cert.append(el('strong', '', '🎓 أكملت الدورة!'));
            if (state.certificateId) {
                const a = el('a', 'app-btn small', 'افتح شهادتي');
                a.href = '/certificate/' + state.certificateId;
                a.target = '_blank';
                a.rel = 'noopener noreferrer';
                cert.append(el('p', '', 'شهادتك جاهزة، وتكدر تطبعها أو تحفظها PDF.'), a);
            } else {
                const input = el('input', 'app-input');
                input.maxLength = 60;
                input.placeholder = 'اسمك كما تريده على الشهادة';
                input.value = (window.PDAccount && window.PDAccount.user && window.PDAccount.user.name) || '';
                const msg = el('p', 'muted');
                cert.append(el('p', '', 'اكتب اسمك كما تريده على الشهادة (ما يتغير بعد الإصدار).'), input, button('اصدر شهادتي', 'app-btn small', async () => {
                    const { ok, data } = await api('/api/course/certificate', { name: input.value });
                    if (!ok) { msg.textContent = data.error || 'تعذر الإصدار.'; return; }
                    window.open(data.url, '_blank', 'noopener');
                    load();
                }), msg);
            }
            parts.push(cert);
        }
        box.replaceChildren(...parts);
    }

    async function startQuiz(levelId) {
        const card = document.querySelector(`.course-level[data-level="${levelId}"] .course-quiz`);
        const { ok, data } = await api('/api/course/quiz', { level: levelId });
        if (!ok) { card.replaceChildren(el('p', 'muted', data.error || 'تعذر بدء الاختبار.')); return; }
        quiz = { level: levelId, attemptId: data.attemptId, answers: [] };
        const form = el('form', 'quiz-form');
        data.questions.forEach((q, i) => {
            const fs = el('fieldset', 'quiz-q');
            fs.append(el('legend', '', `${i + 1}. ${q.q}`));
            q.options.forEach((opt, j) => {
                const label = el('label', 'quiz-opt');
                const radio = el('input');
                radio.type = 'radio';
                radio.name = `q${i}`;
                radio.value = String(j);
                label.append(radio, ' ', document.createTextNode(opt));
                fs.append(label);
            });
            form.append(fs);
        });
        const submit = el('button', 'app-btn', 'تسليم الإجابات');
        submit.type = 'submit';
        form.append(submit);
        form.addEventListener('submit', event => { event.preventDefault(); submitQuiz(form, data.questions.length); });
        card.replaceChildren(form);
    }

    async function submitQuiz(form, count) {
        const answers = Array.from({ length: count }, (_, i) => {
            const checked = form.querySelector(`input[name="q${i}"]:checked`);
            return checked ? Number(checked.value) : -1;
        });
        const { ok, data } = await api('/api/course/submit', { attemptId: quiz.attemptId, answers });
        if (!ok) { form.append(el('p', 'muted', data.error || 'تعذر التسليم.')); return; }
        form.querySelectorAll('fieldset').forEach((fs, i) => {
            const r = data.results[i];
            const opts = fs.querySelectorAll('.quiz-opt');
            opts.forEach((o, j) => { o.classList.toggle('right', j === r.correctIndex); o.classList.toggle('wrong', j === answers[i] && !r.correct); o.querySelector('input').disabled = true; });
            fs.append(el('p', 'quiz-explain ' + (r.correct ? 'ok' : 'bad'), (r.correct ? '✓ ' : '✗ ') + r.explain));
        });
        form.querySelector('button[type=submit]').remove();
        const verdict = el('p', 'quiz-verdict ' + (data.passed ? 'ok' : 'bad'), data.passed ? `ممتاز! ${data.score}/${data.total}. اجتزت المستوى.` : `${data.score}/${data.total}. تحتاج 4 حتى تجتاز. راجع الدروس وجرّب مرة ثانية.`);
        form.append(verdict, button('رجوع للدورة', 'app-btn small secondary', () => { state = data.overview; render(); }));
    }

    document.addEventListener('click', e => { if (e.target.closest('[data-page="awarenessPage"]')) load(); });
    document.addEventListener('DOMContentLoaded', () => { if (document.getElementById('awarenessPage').classList.contains('active')) load(); });
})();
