'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer, request, sameOrigin, cookieFrom, login, adminEntry, TEST_PASSWORD, registerUser, authed } = require('./helpers');
const { mergeSettings, defaults } = require('../server/settings');
const { LIMITS } = require('../server/plans');

async function withAdmin(fn) {
    const app = await startServer({ ADMINS: await adminEntry('musab', TEST_PASSWORD) });
    const res = await login(app);
    assert.equal(res.status, 200);
    const admin = { ...sameOrigin(app), Cookie: cookieFrom(res) };
    try { await fn(app, admin); } finally { await app.settings.reset(); await app.close(); }
}

test('التحقق من القيم: أنواع وحدود وأطوال، والحقول المجهولة تُتجاهل', () => {
    const base = defaults({ plans: { priceUsd: 2, priceIqd: 3000, trialDays: 30 } });
    const { next, errors, changed } = mergeSettings(base, {
        home: { title: 'عنوان\u0000 جديد' + 'x'.repeat(300), announcementTone: 'warn', evil: 'x' },
        plans: { priceUsd: 99999, freeChatPerDay: -5, trialDays: 7.6 },
        cyberbot: { suggestions: ['  سؤال 1 ', '', 5, 'سؤال\n2', 'a', 'b', 'c', 'd', 'e'] },
        unknown: { a: 1 }
    });
    assert.deepEqual(errors, []);
    assert.equal(next.home.title.length, 120);
    assert.ok(!next.home.title.includes('\u0000'));
    assert.equal(next.home.announcementTone, 'warn');
    assert.equal(next.home.evil, undefined);
    assert.equal(next.plans.priceUsd, 1000);
    assert.equal(next.plans.freeChatPerDay, 0);
    assert.equal(next.plans.trialDays, 8);
    assert.deepEqual(next.cyberbot.suggestions, ['سؤال 1', 'سؤال 2', 'a', 'b', 'c', 'd']);
    assert.ok(changed.includes('plans.priceUsd'));
    assert.deepEqual(mergeSettings(base, { features: { cyberbot: 'yes' } }).errors, ['features.cyberbot']);
    assert.deepEqual(mergeSettings(base, { home: { announcementTone: 'red' } }).errors, ['home.announcementTone']);
});

test('الأدمن يعدّل الإعدادات من اللوحة وتطبّق فوراً على الموقع والأسعار والحدود', () => withAdmin(async (app, admin) => {
    assert.equal((await request(app, 'GET', '/api/admin/settings')).status, 401);
    const evil = await request(app, 'POST', '/api/admin/settings', { headers: { ...admin, Origin: 'https://evil.example' }, body: { values: {} } });
    assert.equal(evil.status, 403);
    const bad = await request(app, 'POST', '/api/admin/settings', { headers: admin, body: { values: { features: { cyberbot: 'no' } } } });
    assert.equal(bad.status, 400);

    const save = await request(app, 'POST', '/api/admin/settings', { headers: admin, body: { values: {
        home: { title: 'منصة وزارية', announcement: '<b>إعلان</b> مهم' },
        plans: { priceUsd: 3, freeChatPerDay: 15 },
        cyberbot: { greeting: 'هلا {name}', suggestions: ['سؤال تجريبي'], extraInstructions: 'سر داخلي' }
    } } });
    assert.equal(save.status, 200);
    assert.ok(save.json.changed.includes('home.title'));
    assert.equal(save.json.settings.updatedBy, 'musab');

    const site = (await request(app, 'GET', '/api/site')).json;
    assert.equal(site.home.title, 'منصة وزارية');
    assert.equal(site.home.announcement, '<b>إعلان</b> مهم', 'stored as text; the page renders it with textContent');
    assert.deepEqual(site.cyberbot.suggestions, ['سؤال تجريبي']);
    assert.equal(site.cyberbot.extraInstructions, undefined, 'AI instructions are never public');
    assert.equal(LIMITS.free.chatPerDay, 15);
    const { cookie } = await registerUser(app);
    const billing = await request(app, 'GET', '/api/billing', { headers: authed(app, cookie) });
    assert.equal(billing.json.pricing.monthlyUsd, 3);
    assert.ok(billing.json.pricing.tiers[0].features.some(f => f.includes('15')));
    assert.equal((await request(app, 'GET', '/api/auth/config')).json.priceUsd, 3);

    const events = (await request(app, 'GET', '/api/admin/stats', { headers: admin })).json.events;
    assert.ok(events.some(e => e.type === 'admin_settings'));

    const reset = await request(app, 'POST', '/api/admin/settings/reset', { headers: admin, body: {} });
    assert.equal(reset.status, 200);
    assert.equal(LIMITS.free.chatPerDay, 10);
}));

test('إيقاف الخدمات ووضع الصيانة: الخادم يرفضها (مو بس الواجهة)، ولوحة الإدارة تبقى تعمل', () => withAdmin(async (app, admin) => {
    const { cookie } = await registerUser(app);
    const user = authed(app, cookie);
    await request(app, 'POST', '/api/admin/settings', { headers: admin, body: { values: { features: { cyberbot: false, urlScan: false } } } });
    const chat = await request(app, 'POST', '/api/chat', { headers: user, body: { message: 'هلا' } });
    assert.equal(chat.status, 503);
    assert.equal(chat.json.code, 'feature_disabled');
    assert.equal((await request(app, 'POST', '/api/scan/url', { headers: user, body: { url: 'https://example.com' } })).status, 503);
    assert.equal((await request(app, 'POST', '/api/scan/text', { headers: user, body: { text: 'رسالة عادية للتجربة' } })).status, 200);

    await request(app, 'POST', '/api/admin/settings', { headers: admin, body: { values: { features: { maintenance: true, maintenanceMessage: 'نرجع <script>x</script> الساعة 5' } } } });
    const home = await request(app, 'GET', '/', { headers: { Cookie: cookie } });
    assert.equal(home.status, 503);
    assert.match(home.text, /نرجع &lt;script&gt;x&lt;\/script&gt; الساعة 5/);
    assert.equal((await request(app, 'GET', '/login')).status, 503);
    assert.equal((await request(app, 'POST', '/api/scan/text', { headers: user, body: { text: 'رسالة عادية للتجربة' } })).status, 503);
    assert.equal((await request(app, 'GET', '/admin', { headers: admin })).status, 200);
    assert.equal((await request(app, 'GET', '/api/admin/stats', { headers: admin })).status, 200);
}));
