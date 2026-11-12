'use strict';
// دخول الإدارة بالحساب: اسم المستخدم ← البريد ← كلمة السر ← كود يصل للبريد
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { request, sameOrigin, cookieFrom, startServer, TEST_PASSWORD } = require('./helpers');

const scrypt = promisify(crypto.scrypt);
const EMAIL = 'owner@example.com';

async function accountEntry(user, email, password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = (await scrypt(password, salt, 32)).toString('hex');
    return `${user}:${email}:${salt}:${hash}`;
}

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

async function withAccount(fn, env = {}) {
    const mail = await fakeMailServer();
    const app = await startServer({
        ADMINS: await accountEntry('Musab', 'Owner@Example.com', TEST_PASSWORD),
        BREVO_API_KEY: 'test-key', MAIL_FROM: 'noreply@example.com', MAIL_API_BASE: mail.base, ...env
    });
    try { await fn(app, mail); } finally { await app.close(); await mail.close(); }
}

const start = (app, body) => request(app, 'POST', '/api/admin/account/start', { headers: sameOrigin(app), body });
const verify = (app, ticket, code) => request(app, 'POST', '/api/admin/email/verify', { headers: sameOrigin(app), body: { ticket, code } });
const codeOf = mail => mail.subject.match(/^(\d{6})/)[1];
const good = { username: 'musab', email: EMAIL, password: TEST_PASSWORD };

test('الحساب: اسم المستخدم + البريد + كلمة السر ← كود للبريد ← جلسة', () => withAccount(async (app, mail) => {
    const methods = await request(app, 'GET', '/api/admin/methods');
    assert.deepEqual(methods.json, { account: true, email: false, emailReady: true, password: false });

    const first = await start(app, { username: ' MUSAB ', email: ' Owner@Example.com ', password: TEST_PASSWORD });
    assert.equal(first.status, 200);
    assert.ok(first.json.ticket);
    assert.equal(first.json.sentTo, 'o***@e***.com');
    assert.equal(mail.sent.length, 1, 'الكود يُرسل قبل الرد');
    assert.equal(mail.sent[0].to[0].email, EMAIL);

    // بدون الكود ما في جلسة
    assert.equal(first.headers['set-cookie'], undefined);

    const ok = await verify(app, first.json.ticket, codeOf(mail.sent[0]));
    assert.equal(ok.status, 200);
    const stats = await request(app, 'GET', '/api/admin/stats', { headers: { Cookie: cookieFrom(ok) } });
    assert.equal(stats.status, 200);
    assert.equal(stats.json.user, 'musab');
    assert.equal(stats.json.config.loginMethod, 'كلمة سر + كود البريد');
    assert.ok(stats.json.events.some(e => e.type === 'login_ok' && /musab/.test(e.detail)));
}));

test('الحساب: أي خطأ بالاسم أو البريد أو كلمة السر يرجع نفس الرسالة ولا يرسل كوداً', () => withAccount(async (app, mail) => {
    const wrong = [
        { ...good, username: 'nobody' },
        { ...good, email: 'other@example.com' },
        { ...good, password: 'wrong-password-123' }
    ];
    const bodies = [];
    for (const body of wrong) {
        const res = await start(app, body);
        assert.equal(res.status, 401);
        assert.equal(res.json.ticket, undefined);
        bodies.push(JSON.stringify(res.json));
    }
    assert.equal(new Set(bodies).size, 1, 'الرد واحد لكل الأخطاء');
    assert.equal(mail.sent.length, 0);
}));

test('الحساب: كلمة السر وحدها لا تكفي عبر مسار الدخول القديم', () => withAccount(async (app) => {
    const res = await request(app, 'POST', '/api/admin/login', { headers: sameOrigin(app), body: { username: 'musab', password: TEST_PASSWORD } });
    assert.equal(res.status, 401);
    assert.equal(res.headers['set-cookie'], undefined);
}));

test('الحساب: كود خاطئ يُحسب، والطلب الجديد ينتظر دقيقة ويلغي الكود القديم', () => withAccount(async (app, mail) => {
    const first = await start(app, good);
    const bad = await verify(app, first.json.ticket, codeOf(mail.sent[0]) === '000000' ? '111111' : '000000');
    assert.equal(bad.status, 401);
    assert.equal(bad.json.triesLeft, 4);

    const again = await start(app, good);
    assert.equal(again.status, 429);
    assert.ok(again.json.retryAfter > 0);
    assert.equal(mail.sent.length, 1);
}));

test('الحساب: بعد 5 محاولات دخول خاطئة يُحظر العنوان مؤقتاً', () => withAccount(async (app) => {
    for (let i = 0; i < 5; i++) assert.equal((await start(app, { ...good, password: 'nope-' + i })).status, 401);
    assert.equal((await start(app, good)).status, 429);
}));

test('الحساب: بدون مزوّد بريد يرجع 503 والصفحة تبقى موجودة', async () => {
    const app = await startServer({ ADMINS: await accountEntry('musab', EMAIL, TEST_PASSWORD) });
    try {
        assert.equal((await request(app, 'GET', '/admin')).status, 200);
        const methods = await request(app, 'GET', '/api/admin/methods');
        assert.equal(methods.json.account, true);
        assert.equal(methods.json.emailReady, false);
        const res = await start(app, good);
        assert.equal(res.status, 503);
    } finally { await app.close(); }
});

test('صفحة الدخول فيها خطوات الحساب الأربع', () => withAccount(async (app) => {
    const page = await request(app, 'GET', '/admin');
    for (const id of ['accountForm', 'accUser', 'accEmail', 'accPassword', 'codeForm']) assert.match(page.text, new RegExp(`id="${id}"`));
    const js = await request(app, 'GET', '/admin/assets/login.js');
    assert.match(js.text, /\/api\/admin\/account\/start/);
}));
