'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { TEST_PASSWORD, adminEntry, request, JSON_HEADERS, sameOrigin, cookieFrom, login, withServer } = require('./helpers');

// ---------------------------------------------------------------- أخطاء المتصفح، الصحة، الزوار

test('/api/client-error: يقبل تقريراً منظَّفاً ويظهر بلوحة الأدمن، ويرفض الباقي', async () => {
    const env = { ADMINS: await adminEntry('musab', TEST_PASSWORD) };
    await withServer(env, async app => {
        const ok = await request(app, 'POST', '/api/client-error', {
            headers: sameOrigin(app),
            body: { kind: 'action', message: 'x is not a function‮\u0000', source: 'https://evil.example/path/app.js?token=SECRET', line: 42 }
        });
        assert.equal(ok.status, 204);

        const badBodies = [{ kind: 'hack', message: 'x' }, { message: 'no kind' }, 'null', '[1,2]', 'not json'];
        for (const body of badBodies) {
            const res = await request(app, 'POST', '/api/client-error', { headers: sameOrigin(app), body });
            assert.equal(res.status, 400, JSON.stringify(body));      // حتى "null" لا يعلّق الطلب
        }
        const evil = await request(app, 'POST', '/api/client-error', { headers: { ...JSON_HEADERS, Origin: 'https://evil.example' }, body: { kind: 'error', message: 'x' } });
        assert.equal(evil.status, 403);
        const huge = await request(app, 'POST', '/api/client-error', { headers: sameOrigin(app), body: { kind: 'error', message: 'x'.repeat(3000) } });
        assert.equal(huge.status, 400);
        assert.equal((await request(app, 'GET', '/api/client-error')).status, 405);

        const cookie = cookieFrom(await login(app));
        const stats = await request(app, 'GET', '/api/admin/stats', { headers: { Cookie: cookie } });
        assert.equal(stats.json.counters.clientErrors, 1);
        const event = stats.json.events.find(e => e.type === 'client_error');
        assert.ok(event, 'client_error event missing');
        assert.match(event.detail, /^action: x is not a function/);
        assert.match(event.detail, /@ app\.js:42$/);                 // اسم الملف فقط، بدون الرابط ولا المفتاح
        assert.ok(!/SECRET|evil\.example|‮|\u0000/.test(event.detail));
    });
});

test('/api/client-error: حد الطلبات لكل زائر', () => withServer({}, async app => {
    const codes = [];
    for (let i = 0; i < 13; i++) {
        codes.push((await request(app, 'POST', '/api/client-error', { headers: sameOrigin(app), body: { kind: 'error', message: 'x' } })).status);
    }
    assert.equal(codes.filter(c => c === 204).length, 10);
    assert.equal(codes.filter(c => c === 429).length, 3);
}));

test('/healthz سليم بالوضع الطبيعي', () => withServer({}, async app => {
    assert.equal((await request(app, 'GET', '/healthz')).status, 200);
}));

test('/healthz يرد 503 عندما تكون الحالة حرجة بشكل متواصل (لتعيد Render التشغيل)', () => withServer({}, async app => {
    await new Promise(resolve => setTimeout(resolve, 250));
    const res = await request(app, 'GET', '/healthz');
    assert.equal(res.status, 503);
    assert.equal(res.text, 'unhealthy');
    assert.equal((await request(app, 'HEAD', '/healthz')).status, 503);
}, config => { config.health = { criticalRssMb: 1, degradedRssMb: 1, sampleMs: 20, criticalSamples: 3 }; }));

test('لوحة الأدمن تعرض الزوار وصحة النظام، والزيارة تُحسب لصفحة الموقع فقط', async () => {
    const env = { ADMINS: await adminEntry('musab', TEST_PASSWORD) };
    await withServer(env, async app => {
        await request(app, 'GET', '/', { headers: { 'User-Agent': 'TestBrowser/1' } });
        await request(app, 'GET', '/', { headers: { 'User-Agent': 'TestBrowser/1' } });
        await request(app, 'GET', '/js/app.js');                      // ملف ثابت: لا يُحسب زيارة
        await request(app, 'GET', '/admin');                          // الأدمن: لا يُحسب
        await request(app, 'GET', '/healthz');
        const cookie = cookieFrom(await login(app));
        const stats = await request(app, 'GET', '/api/admin/stats', { headers: { Cookie: cookie } });
        assert.equal(stats.json.visitors.uniqueToday, 1);
        assert.equal(stats.json.visitors.viewsToday, 2);
        assert.equal(stats.json.visitors.activeNow, 1);
        assert.equal(stats.json.visitors.series.length, 7);
        assert.equal(stats.json.health.status, 'ok');
        assert.equal(typeof stats.json.health.rssMb, 'number');
        assert.ok(!stats.text.includes('127.0.0.1'), 'raw visitor IP leaked');
    });
});
