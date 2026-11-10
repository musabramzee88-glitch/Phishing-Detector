'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { startServer, request, sameOrigin, authed, cookieFrom } = require('./helpers');

// مزوّد بريد وهمي يسجّل الرسائل (بدل الإرسال الحقيقي)
async function fakeMailServer(status = 201) {
    const sent = [];
    const server = http.createServer((req, res) => {
        const chunks = [];
        req.on('data', c => chunks.push(c));
        req.on('end', () => {
            sent.push({ url: req.url, headers: req.headers, body: JSON.parse(Buffer.concat(chunks).toString() || '{}') });
            res.writeHead(status, { 'Content-Type': 'application/json' });
            res.end('{}');
        });
    });
    await new Promise(r => server.listen(0, '127.0.0.1', r));
    return { sent, base: 'http://127.0.0.1:' + server.address().port, close: () => new Promise(r => { server.closeAllConnections(); server.close(r); }) };
}

const PASSWORD = 'a long safe passphrase';
const register = (app, email) => request(app, 'POST', '/api/auth/register', { headers: sameOrigin(app), body: { email, password: PASSWORD, name: 'T' } });
const loginReq = (app, email) => request(app, 'POST', '/api/auth/login', { headers: sameOrigin(app), body: { email, password: PASSWORD } });
const codeIn = mail => mail.body.subject.match(/^(\d{6})/)[1];
const verifyCode = (app, email, code) => request(app, 'POST', '/api/auth/verify-code', { headers: sameOrigin(app), body: { email, code } });
const linkIn = mail => (mail.body.htmlContent || mail.body.html).match(/href="([^"]+)"/)[1].replace(/&amp;/g, '&');

async function withMail(fn, { status } = {}) {
    const mail = await fakeMailServer(status);
    const app = await startServer({ BREVO_API_KEY: 'test-key', MAIL_FROM: 'noreply@example.com', MAIL_API_BASE: mail.base, TRIAL_DAYS: '30' }, c => { c.limits.registrationsPerDay = 100; });
    try { await fn(app, mail); } finally { await app.close(); await mail.close(); }
}

test('بدون مزوّد بريد: التسجيل يعمل مباشرة كما كان، والتحقق غير مطلوب', async () => {
    const app = await startServer({ TRIAL_DAYS: '30' });
    try {
        const res = await register(app, 'plain@example.com');
        assert.equal(res.status, 201);
        assert.ok(cookieFrom(res));
        assert.equal(res.json.user.plan, 'pro');
        assert.equal((await request(app, 'GET', '/api/auth/config')).json.emailVerification, false);
        assert.equal((await request(app, 'POST', '/api/auth/forgot', { headers: sameOrigin(app), body: { email: 'plain@example.com' } })).status, 503);
    } finally { await app.close(); }
});

test('مع مزوّد البريد: لا جلسة ولا شهر مجاني قبل التأكيد، ثم يعمل بعد الضغط على الرابط', () => withMail(async (app, mail) => {
    const res = await register(app, 'new.user@example.com');
    assert.equal(res.status, 201);
    assert.equal(res.json.needsVerification, true);
    assert.equal(cookieFrom(res), '');
    assert.equal(mail.sent.length, 1);
    assert.equal(mail.sent[0].url, '/v3/smtp/email');
    assert.equal(mail.sent[0].headers['api-key'], 'test-key');
    assert.equal(mail.sent[0].body.to[0].email, 'new.user@example.com');

    // الدخول مرفوض قبل التأكيد
    const early = await loginReq(app, 'new.user@example.com');
    assert.equal(early.status, 403);
    assert.equal(early.json.code, 'email_unverified');

    // كود خاطئ
    const code = codeIn(mail.sent[0]);
    const wrong = code === '000000' ? '111111' : '000000';
    const bad = await verifyCode(app, 'new.user@example.com', wrong);
    assert.equal(bad.status, 400);
    assert.equal(bad.json.code, 'bad_code');
    assert.equal(cookieFrom(bad), '');

    // الكود الصحيح مرة واحدة فقط، ويفتح الجلسة
    const ok = await verifyCode(app, 'new.user@example.com', code);
    assert.equal(ok.status, 200);
    assert.ok(cookieFrom(ok));
    assert.equal(ok.json.user.emailVerified, true);
    const again = await verifyCode(app, 'new.user@example.com', code);
    assert.equal(again.status, 400);

    const logged = await loginReq(app, 'new.user@example.com');
    assert.equal(logged.status, 200);
    assert.equal(logged.json.user.emailVerified, true);
    assert.equal(logged.json.user.plan, 'pro');
    assert.equal(logged.json.user.planSource, 'trial');
}));

test('نفس الصندوق بشكل آخر (نقاط Gmail و +tag) والبريد المؤقت مرفوضان', () => withMail(async app => {
    assert.equal((await register(app, 'john.smith@gmail.com')).status, 201);
    for (const alias of ['johnsmith@gmail.com', 'j.o.h.n.smith@gmail.com', 'johnsmith+x@gmail.com', 'johnsmith@googlemail.com']) {
        const res = await register(app, alias);
        assert.equal(res.status, 409, alias);
    }
    const disposable = await register(app, 'abc@mailinator.com');
    assert.equal(disposable.status, 400);
    assert.equal(disposable.json.code, 'disposable_email');
}));

test('الشهر المجاني مرة واحدة لكل صندوق: حذف الحساب وإعادة التسجيل لا يعطي شهراً ثانياً', () => withMail(async (app, mail) => {
    const verify = async index => { await verifyCode(app, 'repeat@example.com', codeIn(mail.sent[index])); };
    await register(app, 'repeat@example.com');
    await verify(0);
    const first = await loginReq(app, 'repeat@example.com');
    assert.equal(first.json.user.plan, 'pro');
    const cookie = cookieFrom(first);
    const del = await request(app, 'POST', '/api/account/delete', { headers: authed(app, cookie), body: { confirm: 'repeat@example.com' } });
    assert.ok([200, 204].includes(del.status), 'حذف الحساب: ' + del.status);
    const second = await register(app, 'repeat@example.com');
    assert.equal(second.status, 201);
    await verify(1);
    const relogin = await loginReq(app, 'repeat@example.com');
    assert.equal(relogin.status, 200);
    assert.equal(relogin.json.user.plan, 'free');
}));

test('إعادة الإرسال ونسيت كلمة السر: رد موحّد، وحد 3 رسائل بالساعة، ورابط كلمة السر يعمل', () => withMail(async (app, mail) => {
    await register(app, 'forgot@example.com');
    const unknown = await request(app, 'POST', '/api/auth/resend', { headers: sameOrigin(app), body: { email: 'nobody@example.com' } });
    const known = await request(app, 'POST', '/api/auth/resend', { headers: sameOrigin(app), body: { email: 'forgot@example.com' } });
    assert.equal(unknown.status, 200);
    assert.deepEqual(unknown.json, known.json);
    // رسالة التسجيل + إعادة إرسال واحدة (البريد المجهول لا يرسل)
    assert.equal(mail.sent.length, 2);
    await request(app, 'POST', '/api/auth/resend', { headers: sameOrigin(app), body: { email: 'forgot@example.com' } });
    await request(app, 'POST', '/api/auth/resend', { headers: sameOrigin(app), body: { email: 'forgot@example.com' } });
    assert.equal(mail.sent.length, 3, 'الحد 3 رسائل بالساعة لكل صندوق');

    // تأكيد البريد ثم نسيان كلمة السر
    assert.equal((await verifyCode(app, 'forgot@example.com', codeIn(mail.sent[0]))).status, 400, 'الكود القديم يُلغى عند طلب كود جديد');
    assert.equal((await verifyCode(app, 'forgot@example.com', codeIn(mail.sent[2]))).status, 200);
    const before = mail.sent.length;
    const forgot = await request(app, 'POST', '/api/auth/forgot', { headers: sameOrigin(app), body: { email: 'forgot@example.com' } });
    assert.equal(forgot.status, 200);
    assert.equal(mail.sent.length, before + 1);
    const resetLink = new URL(linkIn(mail.sent[before]));
    const token = resetLink.searchParams.get('reset');
    assert.ok(token);
    const reset = await request(app, 'POST', '/api/auth/reset', { headers: sameOrigin(app), body: { token, password: 'another long passphrase' } });
    assert.equal(reset.status, 200);
    const unknownForgot = await request(app, 'POST', '/api/auth/forgot', { headers: sameOrigin(app), body: { email: 'ghost@example.com' } });
    assert.deepEqual(unknownForgot.json, forgot.json);
}));

test('فشل مزوّد البريد لا يوقف التسجيل ولا يسرّب المفتاح', () => withMail(async (app, mail) => {
    const res = await register(app, 'failmail@example.com');
    assert.equal(res.status, 201);
    assert.equal(res.json.needsVerification, true);
    assert.equal(res.json.sent, false);
    assert.ok(!res.text.includes('test-key'));
}, { status: 401 }));

test('Resend يُستخدم عند ضبط RESEND_API_KEY', async () => {
    const mail = await fakeMailServer(200);
    const app = await startServer({ RESEND_API_KEY: 'rk', MAIL_FROM: 'noreply@example.com', MAIL_FROM_NAME: 'ApexSec', MAIL_API_BASE: mail.base });
    try {
        await register(app, 'resend@example.com');
        assert.equal(mail.sent[0].url, '/emails');
        assert.equal(mail.sent[0].headers.authorization, 'Bearer rk');
        assert.equal(mail.sent[0].body.from, 'ApexSec <noreply@example.com>');
    } finally { await app.close(); await mail.close(); }
});

test('كود التحقق: 5 محاولات خاطئة تُلغي الكود حتى لو أُدخل الصحيح بعدها', () => withMail(async (app, mail) => {
    await register(app, 'brute@example.com');
    const code = codeIn(mail.sent[0]);
    const wrong = code === '000000' ? '111111' : '000000';
    for (let i = 0; i < 5; i++) assert.equal((await verifyCode(app, 'brute@example.com', wrong)).status, 400);
    assert.equal((await verifyCode(app, 'brute@example.com', code)).status, 400, 'الكود أُلغي');
    assert.equal((await verifyCode(app, 'brute@example.com', 'abcdef')).status, 400);
}));

test('Mailjet: يرسل كود التحقق بصيغة v3.1 مع Basic auth', async () => {
    const mail = await fakeMailServer(200);
    const app = await startServer({ MAILJET_API_KEY: 'pub', MAILJET_SECRET_KEY: 'sec', MAIL_FROM: 'noreply@example.com', MAIL_API_BASE: mail.base, TRIAL_DAYS: '30' }, c => { c.limits.registrationsPerDay = 100; });
    try {
        const res = await register(app, 'mj@example.com');
        assert.equal(res.status, 201);
        assert.equal(res.json.needsVerification, true);
        assert.equal(mail.sent.length, 1);
        assert.equal(mail.sent[0].url, '/v3.1/send');
        assert.equal(mail.sent[0].headers.authorization, 'Basic ' + Buffer.from('pub:sec').toString('base64'));
        const msg = mail.sent[0].body.Messages[0];
        assert.equal(msg.To[0].Email, 'mj@example.com');
        assert.match(msg.Subject, /^\d{6}/);
        const ok = await verifyCode(app, 'mj@example.com', msg.Subject.slice(0, 6));
        assert.equal(ok.status, 200);
    } finally { await app.close(); await mail.close(); }
});
