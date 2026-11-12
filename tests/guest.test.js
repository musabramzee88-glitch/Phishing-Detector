'use strict';

/* وضع الضيف: يشاهد الواجهة فقط، وكل فحص أو عملية مرفوضة من الخادم. */

const test = require('node:test');
const assert = require('node:assert/strict');
const { withServer, request, sameOrigin, cookieFrom } = require('./helpers');

async function enterGuest(app) {
    const r = await request(app, 'POST', '/api/auth/guest', { headers: sameOrigin(app), body: {} });
    assert.equal(r.status, 200);
    assert.match(String(r.headers['set-cookie']), /pd_guest=1;.*HttpOnly.*SameSite=Lax/);
    return cookieFrom(r);
}

test('الضيف يشوف واجهة التطبيق بدون حساب', () => withServer({}, async app => {
    assert.equal((await request(app, 'GET', '/')).status, 302);
    const cookie = await enterGuest(app);
    const page = await request(app, 'GET', '/', { headers: { Cookie: cookie } });
    assert.equal(page.status, 200);
    assert.match(page.text, /id="scannerPage"/);
    const config = await request(app, 'GET', '/api/auth/config');
    assert.equal(config.json.guest, true);
}));

test('الضيف ممنوع من كل فحص وعملية (رد guest بدل التحويل للدخول)', () => withServer({}, async app => {
    const cookie = await enterGuest(app);
    const H = { ...sameOrigin(app), Cookie: cookie };
    const calls = [
        ['POST', '/api/scan/url', { url: 'https://example.com' }], ['POST', '/api/scan/text', { text: 'hello there friend' }],
        ['POST', '/api/scan/file', {}], ['POST', '/api/scan/bulk', { urls: ['https://a.com'] }], ['POST', '/api/scan/record', { kind: 'file', level: 'safe', score: 1 }],
        ['POST', '/api/scan/clean', { kind: 'image', size: 10 }], ['POST', '/api/chat', { message: 'hi' }], ['GET', '/api/auth/me'],
        ['GET', '/api/billing'], ['POST', '/api/billing/request', { method: 'contact', months: 1, reference: '12345678' }],
        ['POST', '/api/account/name', { name: 'x' }], ['POST', '/api/account/api-key', {}], ['GET', '/api/account/history'],
        ['GET', `/api/scan/snapshot/${'A'.repeat(24)}`]
    ];
    for (const [m, p, body] of calls) {
        const r = await request(app, m, p, { headers: H, body: m === 'POST' ? body : undefined });
        assert.equal(r.status, 401, `${m} ${p}`);
        assert.equal(r.json.code, 'guest', `${m} ${p}`);
    }
    // ولا يصل للإدارة
    assert.notEqual((await request(app, 'GET', '/api/admin/stats', { headers: H })).status, 200);
}));

test('الدخول كضيف من موقع آخر مرفوض، والخروج يمسح الكوكي، والأدمن يقدر يطفيه', () => withServer({}, async app => {
    const cross = await request(app, 'POST', '/api/auth/guest', { headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' }, body: {} });
    assert.equal(cross.status, 403);
    const cookie = await enterGuest(app);
    const out = await request(app, 'POST', '/api/auth/logout', { headers: { ...sameOrigin(app), Cookie: cookie }, body: {} });
    assert.match(String(out.headers['set-cookie']), /pd_guest=;.*Max-Age=0/);

    await app.settings.update({ features: { guest: false } }, 'test');
    assert.equal((await request(app, 'GET', '/', { headers: { Cookie: cookie } })).status, 302);
    assert.equal((await request(app, 'POST', '/api/auth/guest', { headers: sameOrigin(app), body: {} })).status, 403);
    assert.equal((await request(app, 'GET', '/api/auth/config')).json.guest, false);
}));

test('صفحة الدخول فيها زر الضيف، وزر زيارة الصفحة يظهر للروابط الآمنة فقط', () => {
    const fs = require('node:fs');
    const path = require('node:path');
    assert.match(fs.readFileSync(path.join(__dirname, '..', 'public', 'login.html'), 'utf8'), /id="guestBtn"/);
    const app = fs.readFileSync(path.join(__dirname, '..', 'public', 'js', 'app.js'), 'utf8');
    assert.match(app, /function visitButtonHtml[\s\S]{0,200}result\.level !== 'safe'/);
    assert.match(app, /target="_blank" rel="noopener noreferrer"/);
});

const { adminEntry, registerUser, authed } = require('./helpers');

test('الأدمن: «خروج من كل الأجهزة» يُسقط جلسات المستخدم ويسجَّل بالسجل', async () => {
    const admins = await adminEntry('qa', 'QA-admin-pass-123');
    await withServer({ ADMINS: admins }, async app => {
        const user = await registerUser(app, { email: 'victim@example.com' });
        assert.equal((await request(app, 'GET', '/api/auth/me', { headers: { Cookie: user.cookie } })).status, 200);
        const login = await request(app, 'POST', '/api/admin/login', { headers: sameOrigin(app), body: { username: 'qa', password: 'QA-admin-pass-123' } });
        const admin = cookieFrom(login);
        const r = await request(app, 'POST', '/api/admin/users/action', { headers: authed(app, admin), body: { id: user.json.user.id, action: 'revoke-sessions' } });
        assert.equal(r.status, 200);
        await new Promise(res => setTimeout(res, 5));
        assert.equal((await request(app, 'GET', '/api/auth/me', { headers: { Cookie: user.cookie } })).status, 401);
        // يقدر يدخل من جديد
        const again = await request(app, 'POST', '/api/auth/login', { headers: sameOrigin(app), body: { email: 'victim@example.com', password: 'a long safe passphrase' } });
        assert.equal((await request(app, 'GET', '/api/auth/me', { headers: { Cookie: cookieFrom(again) } })).status, 200);
        const stats = await request(app, 'GET', '/api/admin/stats', { headers: { Cookie: admin } });
        assert.ok(stats.json.events.some(e => /إنهاء كل جلسات/.test(e.detail)));
    });
});

test('محاولة فحص رابط داخلي (SSRF) تُمنع وتظهر كحدث أمني بلوحة الإدارة', async () => {
    const { createInspector } = require('../server/inspect');
    const inspector = createInspector({ lookup: async () => [{ address: '10.0.0.7', family: 4 }], resolveTxt: async () => [] });
    const admins = await adminEntry('qa', 'QA-admin-pass-123');
    await withServer({ ADMINS: admins }, async app => {
        const user = await registerUser(app);
        const r = await request(app, 'POST', '/api/scan/url', { headers: authed(app, user.cookie), body: { url: 'http://internal-service.example/admin' } });
        assert.equal(r.status, 200);
        assert.equal(r.json.result.inspection.reason, 'blocked');
        const login = await request(app, 'POST', '/api/admin/login', { headers: sameOrigin(app), body: { username: 'qa', password: 'QA-admin-pass-123' } });
        const stats = await request(app, 'GET', '/api/admin/stats', { headers: { Cookie: cookieFrom(login) } });
        assert.equal(stats.json.counters.ssrfBlocked, 1);
        assert.ok(stats.json.events.some(e => e.type === 'ssrf_blocked'));
    }, null, { inspector });
});
