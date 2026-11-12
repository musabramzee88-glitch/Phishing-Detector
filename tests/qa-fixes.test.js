'use strict';

/* اختبارات لإصلاحات جولة المراجعة: الموافقة المزدوجة على الدفع، نص عمر النطاق، ترويسة Permissions-Policy، زر Enter بفحص الروابط. */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { openDb } = require('../server/db');
const { createUsers } = require('../server/users');
const { createIntel } = require('../server/intel');
const { loadConfig } = require('../server/config');
const { applySecurityHeaders } = require('../server/http');
const { DAY_MS } = require('../server/plans');

test('الموافقة على طلب دفع مرتين بنفس اللحظة تمدد الاشتراك مرة واحدة فقط', async () => {
    const config = loadConfig({ PAY_QICARD: '1234' });
    const db = openDb(config);
    const users = createUsers({ db, config });
    const user = await users.register({ email: 'payer@example.com', password: 'a long safe passphrase', name: 'P' });
    const payment = await users.createPayment(user, { method: 'qicard', months: 1, reference: '99887766' });
    const results = await Promise.allSettled([
        users.decidePayment(payment.id, { approve: true, admin: 'a' }),
        users.decidePayment(payment.id, { approve: true, admin: 'b' })
    ]);
    assert.strictEqual(results.filter(r => r.status === 'fulfilled').length, 1);
    assert.strictEqual(results.find(r => r.status === 'rejected').reason.code, 'decided');
    const fresh = await users.get(user.id);
    assert.ok(fresh.paidUntil - Date.now() <= 30 * DAY_MS + 5000, 'تمدد شهراً واحداً فقط');
    assert.strictEqual((await users.listPayments({ status: 'pending' })).length, 0);
});

test('عمر النطاق بين 6 أشهر وسنة لا يظهر «0 سنة»', () => {
    const intel = createIntel({ enabled: false });
    const [signal] = intel.ageSignals({ ageDays: 250, createdAt: '2026-03-01T00:00:00Z' });
    assert.doesNotMatch(signal.text, /0 سنة/);
    assert.match(signal.text, /8 أشهر/);
    assert.match(intel.ageSignals({ ageDays: 800, createdAt: '2024-01-01T00:00:00Z' })[0].text, /2 سنة/);
});

test('Permissions-Policy بدون ميزات لا يعرفها Chrome (تسبب تحذيراً بكل صفحة)', () => {
    const headers = {};
    applySecurityHeaders({ socket: {}, headers: {} }, { setHeader: (k, v) => { headers[k] = v; } }, { trustProxy: false });
    assert.doesNotMatch(headers['Permissions-Policy'], /bluetooth/);
    assert.match(headers['Permissions-Policy'], /camera=\(\)/);
});

test('حقل الرابط يفحص عند الضغط على Enter', () => {
    const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
    assert.match(html, /id="urlInput"[^>]*data-enter="analyzeUrl"/);
});

test('بحث الأدمن يجد الحسابات بجزء من البريد أو الاسم', async () => {
    const config = loadConfig({});
    const users = createUsers({ db: openDb(config), config });
    await users.register({ email: 'ali.hassan@example.com', password: 'a long safe passphrase', name: 'علي حسن' });
    await users.register({ email: 'sara@uni.edu.iq', password: 'a long safe passphrase', name: 'Sara' });
    assert.deepStrictEqual((await users.listUsers({ query: 'hassan' })).users.map(u => u.email), ['ali.hassan@example.com']);
    assert.deepStrictEqual((await users.listUsers({ query: 'edu.iq' })).users.map(u => u.email), ['sara@uni.edu.iq']);
    assert.deepStrictEqual((await users.listUsers({ query: 'علي' })).users.map(u => u.email), ['ali.hassan@example.com']);
    assert.strictEqual((await users.listUsers({ query: 'SARA@UNI.EDU.IQ' })).users.length, 1);
    assert.strictEqual((await users.listUsers({ query: 'nobody' })).users.length, 0);
});

const { withServer, request } = require('./helpers');

test('صفحة الدخول جاهزة لمحركات البحث: عنوان، وصف، بيانات منظمة، manifest، ورمز التوثيق', () => withServer({ APP_URL: 'http://localhost:8080', GOOGLE_SITE_VERIFICATION: 'abcDEF123_-xyz789' }, async app => {
    const page = await request(app, 'GET', '/login');
    assert.match(page.text, /<title>Phishing Detector \| كاشف التصيد/);
    assert.match(page.text, /<meta name="google-site-verification" content="abcDEF123_-xyz789">/);
    assert.doesNotMatch(page.text, /SITE_VERIFICATION|%APP_URL%/);
    const ld = JSON.parse(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/.exec(page.text)[1]);
    assert.ok(ld['@graph'].find(x => x['@type'] === 'WebSite').alternateName.includes('كاشف التصيد'));
    assert.match(page.headers['content-security-policy'], /manifest-src 'self'/);
    const manifest = await request(app, 'GET', '/manifest.webmanifest');
    assert.strictEqual(manifest.status, 200);
    assert.strictEqual(manifest.json.icons.length, 3);
    for (const icon of manifest.json.icons) assert.strictEqual((await request(app, 'GET', icon.src)).status, 200);
}));

test('رمز توثيق غير صالح يُتجاهل (لا حقن HTML)', () => withServer({ GOOGLE_SITE_VERIFICATION: '"><script>x</script>' }, async app => {
    const page = await request(app, 'GET', '/login');
    assert.doesNotMatch(page.text, /google-site-verification|<script>x/);
}));

test('ملفات CSS/JS بالصفحات تحمل بصمة محتواها (التحديث يصل للزوار بدل النسخة المخزنة)', () => withServer({}, async app => {
    const crypto = require('node:crypto');
    const page = await request(app, 'GET', '/login');
    const appJs = fs.readFileSync(path.join(__dirname, '..', 'public', 'js', 'login.js'));
    const hash = crypto.createHash('sha1').update(appJs).digest('hex').slice(0, 10);
    assert.match(page.text, new RegExp(`/js/login\\.js\\?v=${hash}"`));
    assert.doesNotMatch(page.text, /\?v=4\.0\.0/);
    const privacy = await request(app, 'GET', '/privacy');
    assert.doesNotMatch(privacy.text, /\?v=4\.0\.0/);
    assert.match(privacy.text, /\/css\/legal\.css\?v=[0-9a-f]{10}"/);
}));
