'use strict';
// دخول لوحة الإدارة برمز يصل للبريد (ADMIN_EMAILS)
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { request, sameOrigin, cookieFrom, startServer, withServer } = require('./helpers');

const ADMIN = 'owner@example.com';

async function fakeMailServer() {
    const sent = [];
    const server = http.createServer((req, res) => {
        const chunks = [];
        req.on('data', c => chunks.push(c));
        req.on('end', () => {
            sent.push(JSON.parse(Buffer.concat(chunks).toString() || '{}'));
            res.writeHead(201, { 'Content-Type': 'application/json' });
            res.end('{}');
        });
    });
    await new Promise(r => server.listen(0, '127.0.0.1', r));
    return { sent, base: 'http://127.0.0.1:' + server.address().port, close: () => new Promise(r => { server.closeAllConnections(); server.close(r); }) };
}

async function withAdminMail(fn, env = {}) {
    const mail = await fakeMailServer();
    const app = await startServer({ ADMIN_EMAILS: `${ADMIN}, second@example.com`, BREVO_API_KEY: 'test-key', MAIL_FROM: 'noreply@example.com', MAIL_API_BASE: mail.base, ...env });
    try { await fn(app, mail); } finally { await app.close(); await mail.close(); }
}

const start = (app, email, headers = {}) => request(app, 'POST', '/api/admin/email/start', { headers: { ...sameOrigin(app), ...headers }, body: { email } });
const verify = (app, ticket, code) => request(app, 'POST', '/api/admin/email/verify', { headers: sameOrigin(app), body: { ticket, code } });
const until = async (check, ms = 2000) => { const end = Date.now() + ms; while (!check() && Date.now() < end) await new Promise(r => setTimeout(r, 10)); };
const codeOf = mail => mail.subject.match(/^(\d{6})/)[1];

test('دخول الأدمن: البريد ← رمز يصل للبريد ← جلسة تفتح اللوحة', () => withAdminMail(async (app, mail) => {
    const methods = await request(app, 'GET', '/api/admin/methods');
    assert.deepEqual(methods.json, { account: false, email: true, emailReady: true, password: false });

    const first = await start(app, '  Owner@Example.com ');
    assert.equal(first.status, 200);
    assert.ok(first.json.ticket);
    assert.equal(first.json.expiresIn, 600);
    await until(() => mail.sent.length === 1);
    assert.equal(mail.sent[0].to[0].email, ADMIN);
    assert.match(mail.sent[0].subject, /رمز دخول الإدارة/);

    const ok = await verify(app, first.json.ticket, codeOf(mail.sent[0]));
    assert.equal(ok.status, 200);
    const cookie = cookieFrom(ok);
    assert.match(ok.headers['set-cookie'][0], /HttpOnly; SameSite=Strict/);
    const stats = await request(app, 'GET', '/api/admin/stats', { headers: { Cookie: cookie } });
    assert.equal(stats.status, 200);
    assert.equal(stats.json.user, ADMIN);
    assert.equal(stats.json.config.loginMethod, 'كود البريد');

    // الرمز لمرة واحدة
    assert.equal((await verify(app, first.json.ticket, codeOf(mail.sent[0]))).status, 401);
}));

test('بريد غير مسجّل كأدمن: نفس الرد بالضبط، ولا تُرسل أي رسالة، والرمز لا يفتح شيئاً', () => withAdminMail(async (app, mail) => {
    const stranger = await start(app, 'attacker@example.com');
    const admin = await start(app, ADMIN);
    assert.equal(stranger.status, admin.status);
    assert.deepEqual(Object.keys(stranger.json).sort(), Object.keys(admin.json).sort());
    await until(() => mail.sent.length === 1);
    await new Promise(r => setTimeout(r, 50));
    assert.equal(mail.sent.length, 1, 'الرسالة للأدمن فقط');
    for (const guess of ['000000', '123456']) assert.equal((await verify(app, stranger.json.ticket, guess)).status, 401);
}));

test('خمس محاولات خاطئة تُسقط الرمز حتى لو جاء الصحيح بعدها', () => withAdminMail(async (app, mail) => {
    const first = await start(app, ADMIN);
    await until(() => mail.sent.length === 1);
    const right = codeOf(mail.sent[0]);
    const wrong = right === '111111' ? '222222' : '111111';
    const r1 = await verify(app, first.json.ticket, wrong);
    assert.equal(r1.json.triesLeft, 4);
    for (let i = 0; i < 3; i++) await verify(app, first.json.ticket, wrong);
    const fifth = await verify(app, first.json.ticket, wrong);
    assert.equal(fifth.status, 401);
    assert.equal(fifth.json.code, 'expired');   // المحاولة الخامسة تُسقط الرمز
    // بعدها حتى الرمز الصحيح ما يفتح (والعنوان نفسه محظور مؤقتاً بعد 5 أخطاء)
    const late = await verify(app, first.json.ticket, right);
    assert.ok([401, 429].includes(late.status), `status ${late.status}`);
    assert.equal(late.headers['set-cookie'], undefined);
}));

test('إعادة الإرسال لنفس البريد لا تتكرر قبل دقيقة، وطلب الرموز محدود لكل عنوان', () => withAdminMail(async (app, mail) => {
    await start(app, ADMIN);
    await start(app, ADMIN);
    await until(() => mail.sent.length >= 1);
    await new Promise(r => setTimeout(r, 50));
    assert.equal(mail.sent.length, 1);
    const codes = [];
    for (let i = 0; i < 9; i++) codes.push((await start(app, `x${i}@example.com`)).status);
    assert.ok(codes.includes(429), `يجب أن يُحظر بعد عدة طلبات: ${codes}`);
}));

test('رمز الدخول يرفض الطلبات من موقع آخر وبدون JSON', () => withAdminMail(async app => {
    assert.equal((await start(app, ADMIN, { Origin: 'https://evil.example' })).status, 403);
    const form = await request(app, 'POST', '/api/admin/email/start', { headers: { Origin: `http://127.0.0.1:${app.base.port}`, 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'email=a' });
    assert.equal(form.status, 415);
    assert.equal((await request(app, 'GET', '/api/admin/email/start')).status, 405);
}));

test('بدون مزوّد بريد: الدخول بالرمز غير متاح بوضوح، والصفحة تبقى موجودة', () => withServer({ ADMIN_EMAILS: ADMIN }, async app => {
    assert.deepEqual((await request(app, 'GET', '/api/admin/methods')).json, { account: false, email: true, emailReady: false, password: false });
    const res = await start(app, ADMIN);
    assert.equal(res.status, 503);
    assert.equal(res.json.code, 'email_login_disabled');
    assert.equal((await request(app, 'GET', '/admin')).status, 200);
}));

test('بدون ADMIN_EMAILS ولا ADMINS: اللوحة غير موجودة', () => withServer({}, async app => {
    assert.equal((await request(app, 'GET', '/admin')).status, 404);
    assert.equal((await request(app, 'GET', '/api/admin/methods')).status, 404);
}));
