'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createFakeUpstash } = require('./fake-upstash');
const { createUpstashClient, UpstashError, describeError } = require('../server/upstash');
const { createRemoteStore, StoreUnavailableError } = require('../server/store');
const { loadConfig } = require('../server/config');
const { TEST_PASSWORD, adminEntry, request, JSON_HEADERS, sameOrigin, cookieFrom, login, withServer } = require('./helpers');

const TOKEN = 'tok_' + crypto.randomBytes(12).toString('hex');
const SECRET = crypto.randomBytes(32).toString('hex');
const DAY = 86_400_000;
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

async function withFake(fn) {
    const fake = createFakeUpstash({ token: TOKEN });
    await fake.start();
    try { await fn(fake); } finally { await fake.stop(); }
}

const clientFor = (fake, extra = {}) => createUpstashClient({ url: fake.url(), token: TOKEN, ...extra });
const sampleSale = (over = {}) => ({
    id: 'ABCDEF12', createdAt: new Date().toISOString(), customer: 'زبون', tier: 'pro',
    expiresAt: new Date(Date.now() + 30 * DAY).toISOString(), amount: 15000, currency: 'IQD', method: 'ZainCash', note: '', ...over
});

// ---------------------------------------------------------------- العميل

test('العميل: أمر ومسار pipeline بالترتيب، ويرسل الرمز بترويسة Bearer فقط', () => withFake(async fake => {
    const client = clientFor(fake);
    assert.equal(await client.command(['PING']), 'PONG');
    assert.deepEqual(await client.pipeline([['SADD', 'k', 'a'], ['SADD', 'k', 'a'], ['SMEMBERS', 'k']]), [1, 0, ['a']]);
    assert.ok(fake.authHeaders.every(h => h === 'Bearer ' + TOKEN));
}));

test('العميل: رمز خاطئ، أمر مرفوض، وفشل جزئي بالـ pipeline', () => withFake(async fake => {
    const bad = createUpstashClient({ url: fake.url(), token: 'wrong-token-value' });
    await assert.rejects(bad.command(['PING']), error => error instanceof UpstashError && error.kind === 'unauthorized' && error.status === 401);
    const client = clientFor(fake);
    await assert.rejects(client.command(['FLUSHALL']), error => error.kind === 'command' && /unknown command/.test(error.detail));
    await assert.rejects(client.pipeline([['PING'], ['NOPE', 'x']]), error => error.kind === 'command');
}));

test('العميل: لا تُسرَّب القيم السرية بأي رسالة خطأ', () => withFake(async fake => {
    const bad = createUpstashClient({ url: fake.url(), token: 'super-secret-token-123' });
    const error = await bad.command(['PING']).catch(e => e);
    for (const text of [error.message, error.detail, describeError(error), String(error), JSON.stringify(error)]) {
        assert.ok(!text.includes('super-secret-token-123'), 'token leaked');
        assert.ok(!text.includes(fake.url()), 'url leaked');
    }
    assert.match(describeError(error), /الرمز/);
}));

test('العميل: انقطاع الشبكة، مهلة بلا رد، ورد غير مفهوم', async () => {
    const fake = createFakeUpstash({ token: TOKEN });
    await fake.start();
    const url = fake.url();
    await fake.stop();
    await assert.rejects(createUpstashClient({ url, token: TOKEN }).command(['PING']), e => e.kind === 'network');

    const silent = http.createServer(() => { /* لا يرد أبداً */ });
    await new Promise(resolve => silent.listen(0, '127.0.0.1', resolve));
    const silentUrl = `http://127.0.0.1:${silent.address().port}`;
    await assert.rejects(createUpstashClient({ url: silentUrl, token: TOKEN, timeoutMs: 100 }).command(['PING']), e => e.kind === 'timeout');
    silent.closeAllConnections(); silent.close();

    const garbage = http.createServer((req, res) => { res.writeHead(200); res.end('not json at all'); });
    await new Promise(resolve => garbage.listen(0, '127.0.0.1', resolve));
    await assert.rejects(createUpstashClient({ url: `http://127.0.0.1:${garbage.address().port}`, token: TOKEN }).command(['PING']), e => e.kind === 'bad_response');
    garbage.closeAllConnections(); garbage.close();
});

// ---------------------------------------------------------------- التخزين البعيد

test('التخزين: يبقى بعد إعادة التشغيل (نسخة جديدة)، ولا يكرر الرقم نفسه', () => withFake(async fake => {
    const a = createRemoteStore({ client: clientFor(fake) });
    await a.ready;
    assert.equal(a.state.persistent, true);
    assert.equal(a.state.backend, 'upstash');
    await a.addSale(sampleSale());
    await a.revoke('ABCDEF12');
    await a.revoke('ABCDEF12');                                        // مكرر: لا ينفّذ أمراً ثانياً
    await assert.rejects(a.addSale(sampleSale()), /duplicate/);
    assert.equal(fake.commands.filter(c => c[0] === 'SADD').length, 1);

    const b = createRemoteStore({ client: clientFor(fake) });
    await b.ready;
    assert.equal(b.sales().length, 1);
    assert.equal(b.sales()[0].customer, 'زبون');
    assert.equal(b.isRevoked('ABCDEF12'), true);
    assert.deepEqual(b.revokedIds(), ['ABCDEF12']);
    a.close(); b.close();
}));

test('التخزين: يقبل HGETALL بشكل الكائن أيضاً، ويفصل المسارات بالبادئة', () => withFake(async fake => {
    fake.setObjectHashes(true);
    const a = createRemoteStore({ client: clientFor(fake), prefix: 'one' });
    const b = createRemoteStore({ client: clientFor(fake), prefix: 'two' });
    await Promise.all([a.ready, b.ready]);
    await a.addSale(sampleSale());
    const reload = createRemoteStore({ client: clientFor(fake), prefix: 'one' });
    await reload.ready;
    assert.equal(reload.sales().length, 1);
    assert.equal(b.sales().length, 0);
    assert.ok(fake.hashes.has('one:sales') && !fake.hashes.has('two:sales'));
    a.close(); b.close(); reload.close();
}));

test('التخزين: السجلات التالفة تُتجاهل مع تنبيه، والسليمة تُحمَّل مرتبة بالتاريخ', () => withFake(async fake => {
    const hash = new Map();
    const old = sampleSale({ id: '11111111', createdAt: new Date(Date.now() - 5 * DAY).toISOString() });
    const recent = sampleSale({ id: '22222222' });
    hash.set('22222222', JSON.stringify(recent));
    hash.set('11111111', JSON.stringify(old));
    hash.set('33333333', '{ not json');
    hash.set('44444444', JSON.stringify(sampleSale({ id: '55555555' })));           // الرقم لا يطابق الحقل
    hash.set('66666666', JSON.stringify({ id: '66666666', tier: 'vip' }));          // ناقص ونوع باقة غير معروف
    fake.hashes.set('pd:sales', hash);
    fake.sets.set('pd:revoked', new Set(['11111111', 'not-an-id']));
    const store = createRemoteStore({ client: clientFor(fake) });
    await store.ready;
    assert.deepEqual(store.sales().map(s => s.id), ['11111111', '22222222']);
    assert.match(store.state.notice, /3/);
    assert.deepEqual(store.revokedIds(), ['11111111']);
    store.close();
}));

test('التخزين: القاعدة غير متاحة عند البدء، يرفض الكتابة، ثم يتعافى تلقائياً', async () => {
    const fake = createFakeUpstash({ token: TOKEN });
    await fake.start();
    const url = fake.url();
    await fake.stop();                                                  // القاعدة طايحة
    const store = createRemoteStore({ client: createUpstashClient({ url, token: TOKEN, timeoutMs: 300 }), retryMs: 40 });
    try {
        await store.ready;
        assert.equal(store.state.persistent, false);
        assert.match(store.state.error, /تعذر الاتصال/);
        await assert.rejects(store.addSale(sampleSale()), error => error instanceof StoreUnavailableError && error.code === 'STORE_UNAVAILABLE');
        await assert.rejects(store.revoke('ABCDEF12'), StoreUnavailableError);
        assert.equal(store.sales().length, 0);

        await fake.start();                                             // رجعت القاعدة
        for (let i = 0; i < 40 && !store.state.persistent; i++) await wait(25);
        assert.equal(store.state.persistent, true);
        assert.equal(store.state.error, '');
        await store.addSale(sampleSale());
        assert.equal(fake.hashes.get('pd:sales').size, 1);
    } finally {
        store.close();
        await fake.stop();
    }
});

test('التخزين: فشل الكتابة بالمنتصف لا يُدخل البيع بالنسخة، ثم يعود طبيعياً', async () => {
    const fake = createFakeUpstash({ token: TOKEN });
    await fake.start();
    const store = createRemoteStore({ client: createUpstashClient({ url: fake.url(), token: TOKEN, timeoutMs: 300 }) });
    try {
        await store.ready;
        await store.addSale(sampleSale({ id: 'AAAAAAA1' }));
        await fake.stop();
        await assert.rejects(store.addSale(sampleSale({ id: 'AAAAAAA2' })), StoreUnavailableError);
        await assert.rejects(store.revoke('AAAAAAA1'), StoreUnavailableError);
        assert.deepEqual(store.sales().map(s => s.id), ['AAAAAAA1']);          // لم يدخل البيع الفاشل
        assert.equal(store.isRevoked('AAAAAAA1'), false);                       // ولا الإلغاء الفاشل
        assert.match(store.state.error, /فشلت آخر عملية كتابة/);
        await fake.start();
        await store.addSale(sampleSale({ id: 'AAAAAAA3' }));
        assert.equal(store.state.error, '');
        assert.deepEqual(store.sales().map(s => s.id), ['AAAAAAA1', 'AAAAAAA3']);
    } finally {
        store.close();
        await fake.stop();
    }
});

test('التخزين: رمز خاطئ عند البدء يظهر بوضوح ولا يسجّل شيئاً', () => withFake(async fake => {
    const store = createRemoteStore({ client: createUpstashClient({ url: fake.url(), token: 'wrong' }), retryMs: 10_000 });
    await store.ready;
    assert.equal(store.state.persistent, false);
    assert.match(store.state.error, /الرمز/);
    await assert.rejects(store.addSale(sampleSale()), StoreUnavailableError);
    assert.equal(fake.hashes.size, 0);
    store.close();
}));

// ---------------------------------------------------------------- الإعدادات

test('الإعدادات: عنوان Upstash صالح أو لا، وتُسقَط القيم الخطرة', () => {
    const ok = loadConfig({ UPSTASH_REDIS_REST_URL: 'https://eu1-x-123.upstash.io/', UPSTASH_REDIS_REST_TOKEN: 't', STORE_PREFIX: 'shop-1' }).billing;
    assert.deepEqual(ok.upstash, { url: 'https://eu1-x-123.upstash.io', token: 't', prefix: 'shop-1' });
    assert.equal(ok.upstashError, '');
    assert.equal(loadConfig({ UPSTASH_REDIS_REST_URL: 'https://a.upstash.io', UPSTASH_REDIS_REST_TOKEN: 't', STORE_PREFIX: 'bad prefix!' }).billing.upstash.prefix, 'pd');
    assert.equal(loadConfig({ UPSTASH_REDIS_REST_URL: 'http://127.0.0.1:9', UPSTASH_REDIS_REST_TOKEN: 't' }).billing.upstash.url, 'http://127.0.0.1:9');
    for (const env of [
        { UPSTASH_REDIS_REST_URL: 'http://example.com', UPSTASH_REDIS_REST_TOKEN: 't' },     // http خارجي
        { UPSTASH_REDIS_REST_URL: 'ftp://x.io', UPSTASH_REDIS_REST_TOKEN: 't' },
        { UPSTASH_REDIS_REST_URL: 'https://a.upstash.io' },                                  // بدون رمز
        { UPSTASH_REDIS_REST_TOKEN: 't' },                                                   // بدون عنوان
        { UPSTASH_REDIS_REST_URL: 'not a url', UPSTASH_REDIS_REST_TOKEN: 't' }
    ]) {
        const billing = loadConfig(env).billing;
        assert.equal(billing.upstash, null, JSON.stringify(env));
        assert.match(billing.upstashError, /غير صالح/);
    }
    assert.equal(loadConfig({}).billing.upstashError, '');
    assert.equal(loadConfig({}).billing.upstash, null);
});

// ---------------------------------------------------------------- من خلال الخادم الحقيقي

async function remoteEnv(fake, extra = {}) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-up-'));
    return {
        dir,
        cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
        env: {
            UPSTASH_REDIS_REST_URL: fake.url(), UPSTASH_REDIS_REST_TOKEN: TOKEN, LICENSE_SECRET: SECRET, DATA_DIR: dir,
            ADMINS: await adminEntry('musab', TEST_PASSWORD), ...extra
        }
    };
}

const fastRetry = config => { config.billing.retryMs = 40; };
const saleBody = (over = {}) => ({ customer: 'مكتب الأمل', tier: 'pro', days: 30, amount: 15000, currency: 'IQD', method: 'ZainCash', note: '', ...over });
const post = (app, cookie, p, body) => request(app, 'POST', p, { headers: { ...sameOrigin(app), Cookie: cookie }, body });
const overviewOf = (app, cookie, headers = {}) => request(app, 'GET', '/api/admin/licenses', { headers: { Cookie: cookie, ...headers } });

test('الخادم مع Upstash: البيع والإلغاء يُحفظان بالقاعدة وليس بالقرص، ويبقيان بعد إعادة التشغيل', () => withFake(async fake => {
    const { env, dir, cleanup } = await remoteEnv(fake);
    try {
        let key, id;
        await withServer(env, async app => {
            const cookie = cookieFrom(await login(app));
            const created = await post(app, cookie, '/api/admin/licenses', saleBody());
            assert.equal(created.status, 201);
            key = created.json.key;
            id = created.json.license.id;
            const overview = await overviewOf(app, cookie);
            assert.equal(overview.json.storage.backend, 'upstash');
            assert.equal(overview.json.storage.persistent, true);
            assert.equal(overview.json.storage.ephemeralRisk, false);
            assert.equal(fake.hashes.get('pd:sales').size, 1);
            assert.equal(fs.existsSync(path.join(dir, 'billing.json')), false, 'no local file when Upstash is used');
            assert.equal((await post(app, cookie, '/api/admin/licenses/revoke', { id })).status, 200);
            assert.ok(fake.sets.get('pd:revoked').has(id));
        }, fastRetry);

        // إعادة تشغيل كاملة: خادم جديد بنفس القاعدة
        await withServer(env, async app => {
            const cookie = cookieFrom(await login(app));
            const overview = await overviewOf(app, cookie);
            assert.equal(overview.json.licenses.length, 1);
            assert.equal(overview.json.licenses[0].status, 'revoked');
            const check = await request(app, 'POST', '/api/license/check', { headers: JSON_HEADERS, body: { key } });
            assert.equal(check.json.reason, 'revoked');
        }, fastRetry);
    } finally { cleanup(); }
}));

test('الخادم مع Upstash: الرمز السري لا يظهر بأي رد، والاتصال يستخدمه كما يجب', () => withFake(async fake => {
    const { env, cleanup } = await remoteEnv(fake);
    try {
        await withServer(env, async app => {
            const cookie = cookieFrom(await login(app));
            await post(app, cookie, '/api/admin/licenses', saleBody());
            const bodies = [
                (await overviewOf(app, cookie)).text,
                (await request(app, 'GET', '/api/admin/stats', { headers: { Cookie: cookie } })).text,
                (await request(app, 'GET', '/api/admin/export/backup.json', { headers: { Cookie: cookie } })).text,
                (await request(app, 'GET', '/api/pricing')).text,
                (await request(app, 'GET', '/')).text
            ];
            for (const text of bodies) {
                assert.ok(!text.includes(TOKEN), 'upstash token leaked');
                assert.ok(!text.includes(fake.url()), 'upstash url leaked');
            }
            assert.ok(fake.authHeaders.length > 0 && fake.authHeaders.every(h => h === 'Bearer ' + TOKEN));
        }, fastRetry);
    } finally { cleanup(); }
}));

test('انقطاع القاعدة أثناء التشغيل: البيع والإلغاء يُرفضان بـ503 بدون مفتاح، والتحقق والفحص يستمران، ثم يعود طبيعياً', () => withFake(async fake => {
    const { env, cleanup } = await remoteEnv(fake);
    try {
        await withServer(env, async app => {
            const cookie = cookieFrom(await login(app));
            const first = await post(app, cookie, '/api/admin/licenses', saleBody());
            assert.equal(first.status, 201);

            await fake.stop();                                                    // القاعدة طايحة
            const refused = await post(app, cookie, '/api/admin/licenses', saleBody({ customer: 'زبون أثناء الانقطاع' }));
            assert.equal(refused.status, 503);
            assert.match(refused.json.error, /لم يُسجَّل البيع/);
            assert.ok(!/PD1-/.test(refused.text), 'no key may be shown for an unrecorded sale');
            assert.equal((await post(app, cookie, '/api/admin/licenses/revoke', { id: first.json.license.id })).status, 503);

            const overview = await overviewOf(app, cookie);
            assert.equal(overview.json.licenses.length, 1);                       // البيع الفاشل لم يدخل
            assert.match(overview.json.storage.error, /فشلت آخر عملية كتابة/);
            // مفاتيح الزبائن الحاليين تستمر (التحقق من التوقيع + النسخة التي بالذاكرة)
            const check = await request(app, 'POST', '/api/license/check', { headers: JSON_HEADERS, body: { key: first.json.key } });
            assert.equal(check.status, 200);
            const scan = await request(app, 'POST', '/api/pro/scan-urls', { headers: { ...JSON_HEADERS, 'X-License-Key': first.json.key }, body: { urls: ['http://a.com'] } });
            assert.equal(scan.status, 200);

            await fake.start();                                                   // رجعت القاعدة
            const again = await post(app, cookie, '/api/admin/licenses', saleBody({ customer: 'بعد الرجوع' }));
            assert.equal(again.status, 201);
            assert.equal((await overviewOf(app, cookie)).json.storage.error, '');
            assert.equal(fake.hashes.get('pd:sales').size, 2);
        }, fastRetry);
    } finally { cleanup(); }
}));

test('الخادم يبدأ حتى لو القاعدة طايحة: يرفض البيع، ثم يتعافى تلقائياً بدون إعادة تشغيل', async () => {
    const fake = createFakeUpstash({ token: TOKEN });
    await fake.start();
    const { env, cleanup } = await remoteEnv(fake);
    await fake.stop();
    try {
        await withServer(env, async app => {
            assert.equal((await request(app, 'GET', '/healthz')).status, 200);       // الموقع نفسه يعمل
            const cookie = cookieFrom(await login(app));
            const overview = await overviewOf(app, cookie);
            assert.equal(overview.json.storage.persistent, false);
            assert.match(overview.json.storage.error, /تعذر الاتصال/);
            assert.equal((await post(app, cookie, '/api/admin/licenses', saleBody())).status, 503);

            await fake.start();
            let recovered = false;
            for (let i = 0; i < 40 && !recovered; i++) {
                await wait(30);
                recovered = (await overviewOf(app, cookie)).json.storage.persistent === true;
            }
            assert.equal(recovered, true, 'store did not recover');
            assert.equal((await post(app, cookie, '/api/admin/licenses', saleBody())).status, 201);
        }, fastRetry);
    } finally {
        cleanup();
        await fake.stop();
    }
});

test('إعداد Upstash غير صالح: يرجع لملف DATA_DIR بدون أن يتعطل', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-fallback-'));
    try {
        const env = { UPSTASH_REDIS_REST_URL: 'ftp://nope', UPSTASH_REDIS_REST_TOKEN: 't', LICENSE_SECRET: SECRET, DATA_DIR: dir, ADMINS: await adminEntry('musab', TEST_PASSWORD) };
        await withServer(env, async app => {
            const cookie = cookieFrom(await login(app));
            const overview = await overviewOf(app, cookie);
            assert.equal(overview.json.storage.backend, 'file');
            assert.equal(overview.json.storage.persistent, true);
            assert.equal((await post(app, cookie, '/api/admin/licenses', saleBody())).status, 201);
            assert.ok(fs.existsSync(path.join(dir, 'billing.json')));
        });
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('على Render بدون قاعدة خارجية: تحذير ظاهر أن الملف مؤقت', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-render-'));
    try {
        const env = { RENDER: 'true', LICENSE_SECRET: SECRET, DATA_DIR: dir, ADMINS: await adminEntry('musab', TEST_PASSWORD) };
        await withServer(env, async app => {
            const cookie = cookieFrom(await login(app, { headers: { 'X-Forwarded-Proto': 'https' } }));
            const overview = await overviewOf(app, cookie, { 'X-Forwarded-Proto': 'https' });
            assert.equal(overview.json.storage.ephemeralRisk, true);
        });
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
