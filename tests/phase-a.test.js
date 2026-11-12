'use strict';

/* المرحلة أ: خطة الاستجابة، فحص أمان الحسابات، الـ Service Worker، ومسار التحويل حتى 10 خطوات. */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { withServer, request, registerUser, authed, adminEntry, sameOrigin, cookieFrom } = require('./helpers');
const { createInspector } = require('../server/inspect');

test('خطط الاستجابة: كل خطة بيها خطوات، والحالات المالية تقول اتصل بالمصرف، وكل الروابط رسمية https', () => {
    const ctx = {};
    vm.runInNewContext(fs.readFileSync(path.join(__dirname, '..', 'public', 'js', 'response-plans.js'), 'utf8'), ctx);
    const { PLANS, LINKS } = JSON.parse(JSON.stringify(ctx.PD_RESPONSE));
    assert.deepEqual(PLANS.map(p => p.id), ['opened', 'password', 'card', 'otp', 'money', 'download']);
    for (const p of PLANS) {
        assert.ok(p.steps.length >= 4, p.id);
        if (p.money) assert.match(p.intro + p.steps.join(' '), /اتصل بمصرفك|من الرقم الرسمي/);
        for (const k of p.links || []) assert.ok(LINKS[k], k);
        assert.doesNotMatch(p.steps.join(' '), /\b0?7[3-9]\d{8}\b/, 'لا أرقام هواتف مكتوبة داخل الكود');
    }
    for (const l of Object.values(LINKS)) assert.match(l.href, /^https:\/\//);
});

test('أرقام الطوارئ يحدّثها الأدمن وتظهر بإعدادات الموقع العامة', async () => {
    await withServer({ ADMINS: await adminEntry('qa', 'QA-admin-pass-123') }, async app => {
        const login = await request(app, 'POST', '/api/admin/login', { headers: sameOrigin(app), body: { username: 'qa', password: 'QA-admin-pass-123' } });
        const admin = cookieFrom(login);
        const r = await request(app, 'POST', '/api/admin/settings', { headers: authed(app, admin), body: { values: { response: { contacts: 'مصرف الرافدين: الرقم الموجود على البطاقة' } } } });
        assert.equal(r.status, 200);
        const site = await request(app, 'GET', '/api/site');
        assert.equal(site.json.response.contacts, 'مصرف الرافدين: الرقم الموجود على البطاقة');
    });
});

test('فحص الأمان: Pro يحفظ الدرجة فقط (آخر 20)، والقيم غير الصالحة مرفوضة', () => withServer({}, async app => {
    const { cookie } = await registerUser(app);   // الحساب الجديد بتجربة Pro
    for (const bad of [101, -1, 50.5, 'x']) assert.equal((await request(app, 'POST', '/api/account/checkup', { headers: authed(app, cookie), body: { score: bad } })).status, 400);
    let last;
    for (let i = 0; i < 22; i++) last = await request(app, 'POST', '/api/account/checkup', { headers: authed(app, cookie), body: { score: i, answers: { secret: 'x' } } });
    assert.equal(last.status, 200);
    assert.equal(last.json.checkups.length, 20);
    assert.deepEqual(Object.keys(last.json.checkups[0]).sort(), ['at', 'score']);
    const me = await request(app, 'GET', '/api/auth/me', { headers: { Cookie: cookie } });
    assert.equal(me.json.user.checkups.at(-1).score, 21);
}));

test('Service Worker: يُقدَّم بدون تخزين طويل، ولا يخزّن الواجهات أو الصفحات الشخصية', () => withServer({}, async app => {
    const sw = await request(app, 'GET', '/sw.js');
    assert.equal(sw.status, 200);
    assert.equal(sw.headers['cache-control'], 'no-cache');
    assert.match(sw.text, /\^\\\/\(api\|admin\|auth\)/);
    assert.equal((await request(app, 'GET', '/offline.html')).status, 200);
}));

test('مسار التحويل: يتبع حتى 10 تحويلات ويرجع كل الحلقات', async () => {
    const server = http.createServer((req, res) => {
        const n = Number(req.url.slice(1)) || 0;
        if (n < 8) { res.writeHead(302, { Location: '/' + (n + 1) }); return res.end(); }
        res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<title>end</title>');
    });
    await new Promise(r => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;
    try {
        const inspector = createInspector({ lookup: async () => [{ address: '127.0.0.1', family: 4 }], resolveTxt: async () => [], isAllowedIp: ip => ip === '127.0.0.1', allowedPorts: new Set([port]) });
        const r = await inspector.inspect(`http://hops.test:${port}/0`);
        assert.equal(r.redirects, 8);
        assert.equal(r.chain.length, 9);
        assert.equal(r.page.title, 'end');
        assert.ok(r.signals.some(s => /8 تحويلات/.test(s.text) && s.weight === 0.2));
    } finally {
        server.closeAllConnections(); server.close();
    }
});
