'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createFakeUpstash } = require('./fake-upstash');
const { TEST_PASSWORD, adminEntry, request, sameOrigin, cookieFrom, login, startServer } = require('./helpers');

const TOKEN = 'tok_' + crypto.randomBytes(12).toString('hex');

// يقلّد النشر على Render: النسخة القديمة تُغلق (تحفظ)، ونسخة جديدة تفتح على نفس القاعدة عبر HTTP حقيقي
test('الإحصاءات والزوار تبقى بعد نشر جديد على Upstash (من الطلب حتى لوحة الأدمن)', async () => {
    const fake = createFakeUpstash({ token: TOKEN });
    await fake.start();
    try {
        const env = { UPSTASH_REDIS_REST_URL: fake.url(), UPSTASH_REDIS_REST_TOKEN: TOKEN, ADMINS: await adminEntry('musab', TEST_PASSWORD) };
        let app = await startServer(env);
        try {
            for (let i = 0; i < 3; i++) await request(app, 'GET', '/login', { headers: { 'User-Agent': 'UA' + i } });
            assert.equal((await request(app, 'POST', '/api/event', { headers: sameOrigin(app), body: { kind: 'media', level: 'danger' } })).status, 204);
            const before = (await request(app, 'GET', '/api/admin/stats', { headers: { Cookie: cookieFrom(await login(app)) } })).json;
            assert.equal(before.persistent, true);
            await app.flushAll();                        // ما يحدث عند SIGTERM
        } finally { await app.close(); }

        app = await startServer(env);                    // النسخة الجديدة بعد النشر
        try {
            const after = (await request(app, 'GET', '/api/admin/stats', { headers: { Cookie: cookieFrom(await login(app)) } })).json;
            assert.equal(after.persistent, true);
            assert.equal(after.scans.media.danger, 1);
            assert.ok(after.counters.requests >= 5, 'requests survived: ' + after.counters.requests);
            assert.equal(after.counters.loginOk >= 2, true);
            assert.equal(after.visitors.totalViews >= 3, true);
            assert.equal(after.visitors.uniqueToday >= 3, true);
            assert.ok(after.events.some(e => e.type === 'login_ok'));
        } finally { await app.close(); }
    } finally { await fake.stop(); }
});
