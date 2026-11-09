'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const crypto = require('node:crypto');
const { createFakeUpstash } = require('./fake-upstash');
const { createUpstashClient, UpstashError, describeError } = require('../server/upstash');
const { loadConfig } = require('../server/config');
const { request, sameOrigin, cookieFrom, startServer } = require('./helpers');

const TOKEN = 'tok_' + crypto.randomBytes(12).toString('hex');

async function withFake(fn) {
    const fake = createFakeUpstash({ token: TOKEN });
    await fake.start();
    try { await fn(fake); } finally { await fake.stop(); }
}

const clientFor = (fake, extra = {}) => createUpstashClient({ url: fake.url(), token: TOKEN, ...extra });

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
    await assert.rejects(client.command(['FLUSHALL']), error => error.kind === 'command' && /unsupported command/.test(error.detail));
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

// ---------------------------------------------------------------- الخادم الحقيقي مع Upstash

const account = { email: 'persist@example.com', password: 'a long safe passphrase' };

test('الخادم مع Upstash: الحساب يبقى بعد إعادة التشغيل، والرمز السري لا يظهر بأي رد', () => withFake(async fake => {
    const env = { UPSTASH_REDIS_REST_URL: fake.url(), UPSTASH_REDIS_REST_TOKEN: TOKEN };
    let app = await startServer(env);
    try {
        const reg = await request(app, 'POST', '/api/auth/register', { headers: sameOrigin(app), body: account });
        assert.equal(reg.status, 201);
        assert.ok(!reg.text.includes(TOKEN));
        assert.ok(fake.commands.some(c => c[0] === 'SET' && /^pd:u:/.test(c[1])), 'user stored in Upstash');
        // كلمة السر لا تُخزَّن كما هي
        assert.ok(!fake.commands.some(c => c.join(' ').includes(account.password)), 'plain password stored');
    } finally {
        await app.close();
    }
    app = await startServer(env);     // نسخة جديدة تماماً (مثل نشر جديد على Render)
    try {
        const res = await request(app, 'POST', '/api/auth/login', { headers: sameOrigin(app), body: account });
        assert.equal(res.status, 200);
        const me = await request(app, 'GET', '/api/auth/me', { headers: { Cookie: cookieFrom(res) } });
        assert.equal(me.json.user.email, account.email);
        assert.ok(fake.authHeaders.every(h => h === 'Bearer ' + TOKEN));
    } finally {
        await app.close();
    }
}));

test('انقطاع القاعدة: الدخول يرد 503 برسالة واضحة بدون تفاصيل سرية، ثم يعود طبيعياً', () => withFake(async fake => {
    const app = await startServer({ UPSTASH_REDIS_REST_URL: fake.url(), UPSTASH_REDIS_REST_TOKEN: TOKEN });
    try {
        assert.equal((await request(app, 'POST', '/api/auth/register', { headers: sameOrigin(app), body: account })).status, 201);
        await fake.stop();
        const down = await request(app, 'POST', '/api/auth/login', { headers: sameOrigin(app), body: account });
        assert.equal(down.status, 503);
        assert.ok(!down.text.includes(TOKEN) && !down.text.includes('127.0.0.1'));
        // الصفحة الرئيسية بدون جلسة تحوّل للدخول بدل أن تنهار
        assert.equal((await request(app, 'GET', '/')).status, 302);
        await fake.start();
        assert.equal((await request(app, 'POST', '/api/auth/login', { headers: sameOrigin(app), body: account })).status, 200);
    } finally {
        await app.close();
    }
}));
