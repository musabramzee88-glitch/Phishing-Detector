'use strict';

/* البلاغات والتنبيهات والقائمة المؤكدة، المشاركة من التطبيقات، والخطوط المستضافة محلياً. */

const test = require('node:test');
const assert = require('node:assert/strict');
const { withServer, request, sameOrigin, registerUser, authed, adminEntry, cookieFrom } = require('./helpers');

async function adminLogin(app) {
    const r = await request(app, 'POST', '/api/admin/login', { headers: sameOrigin(app), body: { username: 'qa', password: 'QA-admin-pass-123' } });
    return cookieFrom(r);
}

test('بلاغ رابط ← تأكيد الأدمن ← النطاق وفروعه «خطر» لكل المستخدمين، والإزالة ترجّعه', async () => {
    await withServer({ ADMINS: await adminEntry('qa', 'QA-admin-pass-123') }, async app => {
        const user = await registerUser(app);
        const before = await request(app, 'POST', '/api/scan/url', { headers: authed(app, user.cookie), body: { url: 'https://cheap-deals-shop.com/pay' } });
        assert.equal(before.json.result.level, 'safe');

        const rep = await request(app, 'POST', '/api/report', { headers: authed(app, user.cookie), body: { kind: 'url', content: 'https://cheap-deals-shop.com/pay', note: '<b>وصلتني بواتساب</b>' } });
        assert.equal(rep.status, 201);
        const official = await request(app, 'POST', '/api/report', { headers: authed(app, user.cookie), body: { kind: 'url', content: 'https://google.com' } });
        assert.equal(official.status, 400);

        const admin = await adminLogin(app);
        const list = await request(app, 'GET', '/api/admin/community', { headers: { Cookie: admin } });
        const report = list.json.reports[0];
        assert.equal(report.domain, 'cheap-deals-shop.com');
        assert.doesNotMatch(report.note, /[<>]/);
        assert.equal((await request(app, 'GET', '/api/admin/stats', { headers: { Cookie: admin } })).json.openReports, 1);

        const decide = await request(app, 'POST', '/api/admin/community/report', { headers: authed(app, admin), body: { id: report.id, confirm: true } });
        assert.equal(decide.status, 200);
        const again = await request(app, 'POST', '/api/admin/community/report', { headers: authed(app, admin), body: { id: report.id, confirm: true } });
        assert.equal(again.status, 409);

        for (const url of ['https://cheap-deals-shop.com/pay', 'https://login.cheap-deals-shop.com/']) {
            const r = await request(app, 'POST', '/api/scan/url', { headers: authed(app, user.cookie), body: { url } });
            assert.equal(r.json.result.level, 'danger', url);
            assert.match(JSON.stringify(r.json.result.reasons), /مؤكَّد كاحتيال/);
        }
        const text = await request(app, 'POST', '/api/scan/text', { headers: authed(app, user.cookie), body: { text: 'تخفيضات اليوم https://cheap-deals-shop.com/x' } });
        assert.notEqual(text.json.result.level, 'safe');

        await request(app, 'POST', '/api/admin/community/unblock', { headers: authed(app, admin), body: { domain: 'cheap-deals-shop.com' } });
        const after = await request(app, 'POST', '/api/scan/url', { headers: authed(app, user.cookie), body: { url: 'https://cheap-deals-shop.com/pay' } });
        assert.equal(after.json.result.level, 'safe');
    });
});

test('البلاغات: تحتاج حساباً، من نفس الموقع، وبحد يومي', () => withServer({}, async app => {
    assert.equal((await request(app, 'POST', '/api/report', { headers: sameOrigin(app), body: { kind: 'text', content: 'رسالة احتيال' } })).status, 401);
    const user = await registerUser(app);
    const cross = await request(app, 'POST', '/api/report', { headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example', Cookie: user.cookie }, body: { kind: 'text', content: 'رسالة احتيال' } });
    assert.equal(cross.status, 403);
    let last;
    for (let i = 0; i < 11; i++) last = await request(app, 'POST', '/api/report', { headers: authed(app, user.cookie), body: { kind: 'text', content: 'رسالة احتيال رقم ' + i } });
    assert.equal(last.status, 429);
}));

test('التنبيهات: الأدمن ينشر، والصفحة العامة تعرضها منظّفة، ومحركات البحث تعرفها', async () => {
    await withServer({ ADMINS: await adminEntry('qa', 'QA-admin-pass-123'), APP_URL: 'http://localhost:8080' }, async app => {
        const admin = await adminLogin(app);
        const add = await request(app, 'POST', '/api/admin/community/alert', { headers: authed(app, admin), body: { title: 'رسائل مزيفة باسم <script>الرافدين', body: 'تطلب تحديث البيانات عبر رابط. لا تضغطه.\nبلّغ عنه.', severity: 'danger' } });
        assert.equal(add.status, 201);
        assert.equal((await request(app, 'POST', '/api/admin/community/alert', { headers: authed(app, admin), body: { title: 'x', body: 'y' } })).status, 400);
        const page = await request(app, 'GET', '/alerts');
        assert.equal(page.status, 200);
        assert.match(page.text, /رسائل مزيفة باسم scriptالرافدين/);
        assert.doesNotMatch(page.text, /<script/i);
        assert.match(page.text, /<br>بلّغ عنه/);
        assert.match(page.text, /rel="canonical" href="http:\/\/localhost:8080\/alerts"/);
        const json = await request(app, 'GET', '/api/alerts');
        assert.equal(json.json.alerts.length, 1);
        assert.equal(json.json.alerts[0].by, undefined);
        assert.match((await request(app, 'GET', '/sitemap.xml')).text, /\/alerts<\/loc>/);
        assert.match((await request(app, 'GET', '/robots.txt')).text, /Allow: \/alerts/);
        const id = json.json.alerts[0].id;
        await request(app, 'POST', '/api/admin/community/alert/delete', { headers: authed(app, admin), body: { id } });
        assert.equal((await request(app, 'GET', '/api/alerts')).json.alerts.length, 0);
        // مستخدم عادي ما يقدر ينشر
        const user = await registerUser(app);
        assert.notEqual((await request(app, 'POST', '/api/admin/community/alert', { headers: authed(app, user.cookie), body: { title: 'test alert', body: 'some long body text' } })).status, 201);
    });
});

test('المشاركة من تطبيق آخر: المحتوى يبقى بعد تحويل الدخول، ولا يمرَّر غيره', () => withServer({}, async app => {
    const r = await request(app, 'GET', '/?share_text=' + encodeURIComponent('شوف http://x.example') + '&evil=1');
    assert.equal(r.status, 302);
    assert.equal(r.headers.location, '/login?share_text=' + encodeURIComponent('شوف http://x.example').replace(/%20/g, '+'));
    const user = await registerUser(app);
    const logged = await request(app, 'GET', '/login?share_url=' + encodeURIComponent('https://a.example/'), { headers: { Cookie: user.cookie } });
    assert.equal(logged.headers.location, '/?share_url=' + encodeURIComponent('https://a.example/'));
    const manifest = await request(app, 'GET', '/manifest.webmanifest');
    assert.equal(manifest.json.share_target.params.url, 'share_url');
}));

test('الخطوط والأيقونات من الموقع نفسه، والسياسة الأمنية بلا مصادر خارجية', () => withServer({}, async app => {
    const page = await request(app, 'GET', '/login');
    assert.doesNotMatch(page.text, /googleapis|gstatic|cdnjs/);
    assert.match(page.text, /\/vendor\/fontawesome\/css\/all\.min\.css\?v=[0-9a-f]{10}/);
    const csp = page.headers['content-security-policy'];
    assert.match(csp, /font-src 'self';/);
    assert.match(csp, /style-src 'self' 'unsafe-inline';/);
    assert.doesNotMatch(csp, /https:/);
    const font = await request(app, 'GET', '/vendor/fontawesome/webfonts/fa-solid-900.woff2');
    assert.equal(font.status, 200);
    assert.equal(font.headers['content-type'], 'font/woff2');
    const css = await request(app, 'GET', '/vendor/tajawal/tajawal.css');
    assert.match(css.text, /tajawal-arabic-400-normal\.woff2/);
    assert.equal((await request(app, 'GET', '/vendor/tajawal/tajawal-arabic-700-normal.woff2')).status, 200);
}));
