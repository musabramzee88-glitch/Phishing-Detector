'use strict';

/* الدورة: الأسئلة بدون إجابات، التصحيح بالخادم، محاولة وحدة، المستويات بالترتيب، الشهادة والتحقق. */

const test = require('node:test');
const assert = require('node:assert/strict');
const { withServer, request, registerUser, authed } = require('./helpers');
const { LEVELS } = require('../server/course');

// يجاوب صح بالبحث عن نص الخيار الصحيح بالبنك (مثل طالب حافظ الدروس)
function correctAnswers(levelId, questions) {
    const bank = LEVELS.find(l => l.id === levelId).bank;
    return questions.map(q => { const item = bank.find(b => b.q === q.q); return q.options.indexOf(item.options[item.answer]); });
}

test('بنك الأسئلة سليم: 10 أسئلة لكل مستوى، 4 خيارات، إجابة صحيحة موجودة', () => {
    for (const level of LEVELS) {
        assert.equal(level.bank.length, 10, level.id);
        for (const q of level.bank) { assert.equal(q.options.length, 4); assert.ok(q.answer >= 0 && q.answer < 4); assert.ok(q.explain); }
    }
});

test('الدورة كاملة: مستويات بالترتيب، تصحيح بالخادم، محاولة وحدة، ثم شهادة وتحقق', () => withServer({ APP_URL: 'http://localhost:8080' }, async app => {
    const { cookie } = await registerUser(app, { name: 'علي حسن' });
    const H = authed(app, cookie);
    const locked = await request(app, 'POST', '/api/course/quiz', { headers: H, body: { level: 'advanced' } });
    assert.equal(locked.status, 403);

    for (const level of LEVELS) {
        // محاولة فاشلة أولاً (كل الإجابات غلط)
        const bad = await request(app, 'POST', '/api/course/quiz', { headers: H, body: { level: level.id } });
        assert.equal(bad.json.questions.length, 5);
        assert.doesNotMatch(JSON.stringify(bad.json), /"answer"|explain/, 'الإجابات ما توصل للمتصفح قبل التسليم');
        const wrong = correctAnswers(level.id, bad.json.questions).map(i => (i + 1) % 4);
        const fail = await request(app, 'POST', '/api/course/submit', { headers: H, body: { attemptId: bad.json.attemptId, answers: wrong } });
        assert.equal(fail.json.passed, false);
        const reuse = await request(app, 'POST', '/api/course/submit', { headers: H, body: { attemptId: bad.json.attemptId, answers: correctAnswers(level.id, bad.json.questions) } });
        assert.equal(reuse.status, 410, 'المحاولة ما تنقبل مرتين');

        const quiz = await request(app, 'POST', '/api/course/quiz', { headers: H, body: { level: level.id } });
        const pass = await request(app, 'POST', '/api/course/submit', { headers: H, body: { attemptId: quiz.json.attemptId, answers: correctAnswers(level.id, quiz.json.questions) } });
        assert.equal(pass.json.passed, true);
        assert.equal(pass.json.score, 5);
    }
    const overview = await request(app, 'GET', '/api/course', { headers: { Cookie: cookie } });
    assert.equal(overview.json.complete, true);
    assert.equal(overview.json.points, 500);

    const cert = await request(app, 'POST', '/api/course/certificate', { headers: H, body: { name: '<b>علي حسن</b>' } });
    assert.equal(cert.status, 201);
    const id = cert.json.certificate.id;
    assert.match(id, /^[A-Z2-9]{10}$/);
    assert.equal(cert.json.certificate.name, 'علي حسن');
    const again = await request(app, 'POST', '/api/course/certificate', { headers: H, body: { name: 'اسم ثاني' } });
    assert.equal(again.json.certificate.id, id, 'شهادة وحدة لكل حساب');

    const page = await request(app, 'GET', '/certificate/' + id);
    assert.equal(page.status, 200);
    assert.match(page.text, /data-verify="http:\/\/localhost:8080\/verify\/[A-Z2-9]{10}"/);
    assert.match(page.text, /ليست شهادة معتمدة من أي جهة حكومية أو أكاديمية/);
    assert.doesNotMatch(page.text, /جامعة تكريت/);
    const verify = await request(app, 'GET', '/verify/' + id.toLowerCase());
    assert.equal(verify.status, 200);
    assert.match(verify.text, /شهادة صحيحة/);
    const fake = await request(app, 'GET', '/verify/ABCDEFGH23');
    assert.equal(fake.status, 404);
    assert.match(fake.text, /ما لكينا شهادة/);
}));

test('الدورة تحتاج حساب، ومحاولة مستخدم ثاني مرفوضة', () => withServer({}, async app => {
    assert.equal((await request(app, 'GET', '/api/course')).status, 401);
    const a = await registerUser(app), b = await registerUser(app);
    const quiz = await request(app, 'POST', '/api/course/quiz', { headers: authed(app, a.cookie), body: { level: 'beginner' } });
    const steal = await request(app, 'POST', '/api/course/submit', { headers: authed(app, b.cookie), body: { attemptId: quiz.json.attemptId, answers: [0, 0, 0, 0, 0] } });
    assert.equal(steal.status, 403);
}));
