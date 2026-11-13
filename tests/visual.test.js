'use strict';

/* الكشف البصري: وكيل الحماية (SSRF)، مقارنة البصمات، دمج النتيجة بالفحص، المكتبة بلوحة الإدارة، وخصوصية اللقطات. */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const net = require('node:net');
const { createGuardProxy } = require('../visual-worker/guard-proxy');
const { compare, hamming, PAGE_PHASH_MAX } = require('../server/visual');
const { isPublicIp } = require('../server/inspect');
const { withServer, request, sameOrigin, registerUser, authed, adminEntry, login, cookieFrom } = require('./helpers');

const JPEG = Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0]), Buffer.alloc(400, 7)]).toString('base64');
const PAGE = { phash: 'f0f0f0f0a5a5a5a5', dhash: '0123456789abcdef' };
const flip = (hex, bits) => { let n = BigInt('0x' + hex); for (let i = 0; i < bits; i++) n ^= 1n << BigInt(i * 3); return n.toString(16).padStart(16, '0'); };

// ---------------------------------------------------------------- وكيل الحماية

function rawProxy(port, payload) {
    return new Promise(resolve => {
        const s = net.connect(port, '127.0.0.1', () => s.write(payload));
        let out = '';
        s.on('data', d => { out += d; });
        s.on('end', () => resolve(out));
        s.on('close', () => resolve(out));
        setTimeout(() => { s.destroy(); resolve(out); }, 3000);
    });
}

test('وكيل الحماية: يرفض العناوين الداخلية والمنافذ الغريبة والأسماء اللي تتحول لعنوان داخلي', async () => {
    const lookup = async host => (host === 'evil-rebind.test' ? [{ address: '10.0.0.5', family: 4 }] : host === 'mixed.test' ? [{ address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 }] : []);
    const px = createGuardProxy({ isAllowedIp: isPublicIp, lookup });
    const port = await px.listen();
    try {
        for (const target of ['http://169.254.169.254/latest/meta-data/', 'http://127.0.0.1/', 'http://[::1]/', 'http://10.1.2.3/', 'http://localhost/', 'http://evil-rebind.test/', 'http://mixed.test/', 'http://8.8.8.8:22/']) {
            const out = await rawProxy(port, `GET ${target} HTTP/1.1\r\nHost: x\r\n\r\n`);
            assert.match(out, /^HTTP\/1\.1 (403|400)/, target);
            assert.match(out, /x-pd-guard: blocked/i, target);
        }
        for (const target of ['169.254.169.254:443', '127.0.0.1:443', '10.0.0.1:443', 'evil-rebind.test:443', '8.8.8.8:25']) {
            const out = await rawProxy(port, `CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`);
            assert.match(out, /^HTTP\/1\.1 403/, target);
        }
        assert.ok(px.stats.blocked >= 13);
        assert.equal(px.stats.allowed, 0);
    } finally {
        await px.close();
    }
});

test('وكيل الحماية: يمرر الطلبات المسموحة للعنوان اللي فحصه بالضبط', async () => {
    const site = http.createServer((req, res) => res.end('hello ' + req.headers.host));
    await new Promise(r => site.listen(0, '127.0.0.1', r));
    const sitePort = site.address().port;
    const px = createGuardProxy({ isAllowedIp: ip => ip === '127.0.0.1', allowedPorts: new Set([sitePort]), lookup: async () => [{ address: '127.0.0.1', family: 4 }] });
    const port = await px.listen();
    try {
        const out = await rawProxy(port, `GET http://example.test:${sitePort}/ HTTP/1.1\r\nHost: example.test:${sitePort}\r\nConnection: close\r\n\r\n`);
        assert.match(out, /^HTTP\/1\.1 200/);
        assert.match(out, /hello example\.test/);
        const tunnel = await rawProxy(port, `CONNECT example.test:${sitePort} HTTP/1.1\r\n\r\nGET / HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n`);
        assert.match(tunnel, /200 Connection Established[\s\S]*hello example\.test/);
    } finally {
        await px.close();
        site.close();
    }
});

// ---------------------------------------------------------------- المقارنة

test('مقارنة البصمات: النسخة تطابق، الصفحة المختلفة ما تطابق، والأيقونة وحدها تحتاج حقل كلمة سر', () => {
    assert.equal(hamming('0000000000000000', 'ffffffffffffffff'), 64);
    assert.equal(hamming(PAGE.phash, PAGE.phash), 0);
    assert.equal(hamming('zz', PAGE.phash), 64);
    const ref = { brand: 'فيسبوك', domains: ['facebook.com'], hashes: { page: PAGE, favicon: { phash: 'aaaaaaaaaaaaaaaa', dhash: 'bbbbbbbbbbbbbbbb' } } };
    const near = compare({ page: { phash: flip(PAGE.phash, 3), dhash: flip(PAGE.dhash, 4) } }, [ref]);
    assert.equal(near.kind, 'page');
    assert.ok(near.similarity >= 90);
    assert.equal(compare({ page: { phash: flip(PAGE.phash, PAGE_PHASH_MAX + 6), dhash: PAGE.dhash } }, [ref]), null);
    const far = { phash: '0f0f0f0f5a5a5a5a', dhash: 'fedcba9876543210' };
    assert.equal(compare({ page: far, favicon: ref.hashes.favicon, hasPassword: false }, [ref]), null);
    assert.equal(compare({ page: far, favicon: ref.hashes.favicon, hasPassword: true }, [ref]).kind, 'favicon');
    assert.equal(compare({ page: { phash: 'nothex', dhash: 'x' } }, [ref]), null);
    assert.equal(compare({ page: PAGE }, [{ brand: 'x', domains: [], hashes: null }]), null);
});

// ---------------------------------------------------------------- الدمج بالموقع

const ENV = { VISUAL_WORKER_URL: 'https://visual.example', VISUAL_WORKER_TOKEN: 't'.repeat(32) };

function fakeInspector(finalUrl) {
    return {
        inspect: async () => ({ visited: true, exists: true, finalUrl, status: 200, signals: [], page: { title: 'Log in', fields: { password: 1 } } }),
        getSnapshot: () => null, status: () => ({ enabled: true })
    };
}

function fakeWorker(capture, calls = []) {
    return async (url, opts) => {
        calls.push({ url, opts });
        if (url.endsWith('/health')) return { ok: true, json: async () => ({ ok: true, queue: 0, captured: 1 }) };
        const body = JSON.parse(opts.body);
        return { ok: true, status: 200, text: async () => JSON.stringify(typeof capture === 'function' ? capture(body) : capture) };
    };
}

async function seedRef(app, hashes = { page: PAGE, favicon: null }) {
    await app.db.cmd(['SET', app.db.key('visualrefs'), JSON.stringify([{ id: 'r1', brand: 'فيسبوك', url: 'https://www.facebook.com/login/', domains: ['facebook.com'], hashes, updatedAt: 1, error: '' }])]);
}

async function pollUntilDone(app, cookie, job) {
    for (let i = 0; i < 50; i++) {
        const r = await request(app, 'GET', '/api/scan/visual/' + job, { headers: { Cookie: cookie } });
        if (r.json && r.json.status !== 'pending') return r;
        await new Promise(res => setTimeout(res, 20));
    }
    throw new Error('visual job never finished');
}

test('صفحة بدومين عشوائي شكلها نسخة من فيسبوك: الحكم يصير خطر واللقطة تنعرض لصاحب الفحص بس', async () => {
    const calls = [];
    const worker = fakeWorker({ ok: true, status: 200, finalUrl: 'https://x7k2.top/login', title: 'Log in', hasPassword: true, page: { phash: flip(PAGE.phash, 2), dhash: PAGE.dhash }, favicon: null, screenshot: JPEG }, calls);
    await withServer(ENV, async app => {
        await seedRef(app);
        const u = await registerUser(app, { email: 'vis1@example.com' });
        const scan = await request(app, 'POST', '/api/scan/url', { headers: authed(app, u.cookie), body: { url: 'https://x7k2.top/login' } });
        assert.equal(scan.status, 200);
        const job = scan.json.result.visual && scan.json.result.visual.job;
        assert.ok(job, 'الفحص يرجع رقم مهمة بصرية');
        const before = scan.json.result.score;
        const done = await pollUntilDone(app, u.cookie, job);
        assert.equal(done.json.status, 'ok');
        assert.equal(done.json.match.brand, 'فيسبوك');
        assert.equal(done.json.match.official, false);
        assert.equal(done.json.result.level, 'danger');
        assert.ok(done.json.result.score > before);
        assert.ok(done.json.result.checks.visual);
        assert.ok(done.json.result.reasons.some(r => /الفحص البصري: الصفحة نسخة من صفحة دخول فيسبوك/.test(r.text)));
        // الطلب للخدمة يحمل المفتاح ويطلب لقطة
        const cap = calls.find(c => c.url === 'https://visual.example/capture');
        assert.equal(cap.opts.headers.Authorization, 'Bearer ' + 't'.repeat(32));
        assert.equal(JSON.parse(cap.opts.body).kind, 'scan');
        // اللقطة: JPEG لصاحب الفحص، 404 لغيره
        const shot = await request(app, 'GET', '/api/scan/shot/' + done.json.shotId, { headers: { Cookie: u.cookie } });
        assert.equal(shot.status, 200);
        assert.equal(shot.headers['content-type'], 'image/jpeg');
        assert.match(shot.headers['cache-control'], /no-store/);
        const other = await registerUser(app, { email: 'vis2@example.com' });
        assert.equal((await request(app, 'GET', '/api/scan/shot/' + done.json.shotId, { headers: { Cookie: other.cookie } })).status, 404);
        assert.equal((await request(app, 'GET', '/api/scan/visual/' + job, { headers: { Cookie: other.cookie } })).status, 404);
        assert.equal((await request(app, 'GET', '/api/scan/shot/' + done.json.shotId)).status, 401);
    }, undefined, { inspector: fakeInspector('https://x7k2.top/login'), visualFetch: worker });
});

test('صفحة فيسبوك الحقيقية ما تنحسب تصيد، وصفحة ما تشبه شي تبقى على حكمها', async () => {
    await withServer(ENV, async app => {
        await seedRef(app);
        const u = await registerUser(app, { email: 'vis3@example.com' });
        const scan = await request(app, 'POST', '/api/scan/url', { headers: authed(app, u.cookie), body: { url: 'https://some-unknown-shop.example/' } });
        const done = await pollUntilDone(app, u.cookie, scan.json.result.visual.job);
        assert.equal(done.json.match, null);
        assert.equal(done.json.result.score, scan.json.result.score);
        assert.ok(done.json.result.reasons.some(r => /ما تشبه أي صفحة دخول/.test(r.text)));
    }, undefined, { inspector: fakeInspector('https://some-unknown-shop.example/'), visualFetch: fakeWorker({ ok: true, finalUrl: 'https://some-unknown-shop.example/', page: { phash: '0f0f0f0f5a5a5a5a', dhash: 'fedcba9876543210' }, screenshot: JPEG }) });

    await withServer(ENV, async app => {
        await seedRef(app);
        const u = await registerUser(app, { email: 'vis4@example.com' });
        // الرابط نفسه مو رسمي (حتى ينزار)، بس الصفحة النهائية على facebook.com
        const scan = await request(app, 'POST', '/api/scan/url', { headers: authed(app, u.cookie), body: { url: 'https://short.example/abc' } });
        const done = await pollUntilDone(app, u.cookie, scan.json.result.visual.job);
        assert.equal(done.json.match.official, true);
        assert.ok(!done.json.result.reasons.some(r => r.type === 'danger' && /الفحص البصري/.test(r.text)));
    }, undefined, { inspector: fakeInspector('https://www.facebook.com/login/'), visualFetch: fakeWorker({ ok: true, finalUrl: 'https://www.facebook.com/login/', page: PAGE, screenshot: JPEG }) });
});

test('بدون إعداد الخدمة أو مع إطفاء الميزة: ما اكو فحص بصري والفحص العادي يشتغل', async () => {
    await withServer({}, async app => {
        const u = await registerUser(app, { email: 'vis5@example.com' });
        const scan = await request(app, 'POST', '/api/scan/url', { headers: authed(app, u.cookie), body: { url: 'https://x7k2.top/login' } });
        assert.equal(scan.status, 200);
        assert.equal(scan.json.result.visual, undefined);
    }, undefined, { inspector: fakeInspector('https://x7k2.top/login') });
    await withServer(ENV, async app => {
        await app.settings.update({ features: { visual: false } });
        const u = await registerUser(app, { email: 'vis6@example.com' });
        const scan = await request(app, 'POST', '/api/scan/url', { headers: authed(app, u.cookie), body: { url: 'https://x7k2.top/login' } });
        assert.equal(scan.json.result.visual, undefined);
    }, undefined, { inspector: fakeInspector('https://x7k2.top/login'), visualFetch: fakeWorker({ ok: true }) });
});

test('خدمة معطلة أو رفضت الرابط: الفحص يكمل والنتيجة تقول السبب بدون ما يطيح شي', async () => {
    for (const [capture, status] of [[{ ok: false, error: 'blocked' }, 'blocked'], [{ ok: false, error: 'busy' }, 'busy'], [() => { throw new Error('down'); }, 'failed'], [{ ok: true, page: PAGE, screenshot: 'not-a-jpeg' }, 'ok']]) {
        await withServer(ENV, async app => {
            const u = await registerUser(app, { email: `vis-${status}-${Math.random()}@example.com` });
            const scan = await request(app, 'POST', '/api/scan/url', { headers: authed(app, u.cookie), body: { url: 'https://x7k2.top/login' } });
            const done = await pollUntilDone(app, u.cookie, scan.json.result.visual.job);
            assert.equal(done.json.status, status);
            if (status === 'ok') assert.equal(done.json.shotId, '', 'لقطة مو JPEG ما تنحفظ');
        }, undefined, { inspector: fakeInspector('https://x7k2.top/login'), visualFetch: fakeWorker(capture) });
    }
});

test('مكتبة الكشف البصري بلوحة الإدارة: للأدمن فقط، والرابط لازم يكون https ومن النطاقات الرسمية', async () => {
    const calls = [];
    const worker = fakeWorker(body => ({ ok: true, finalUrl: body.url, page: PAGE, favicon: { phash: 'aaaaaaaaaaaaaaaa', dhash: 'bbbbbbbbbbbbbbbb' } }), calls);
    await withServer({ ...ENV, ADMINS: await adminEntry('qa', 'QA-admin-pass-123') }, async app => {
        const u = await registerUser(app, { email: 'vis7@example.com' });
        assert.equal((await request(app, 'GET', '/api/admin/visual')).status, 401);
        assert.equal((await request(app, 'GET', '/api/admin/visual', { headers: { Cookie: u.cookie } })).status, 401);
        const l = await login(app, { username: 'qa', password: 'QA-admin-pass-123' });
        const admin = { ...sameOrigin(app), Cookie: cookieFrom(l) };
        const list = await request(app, 'GET', '/api/admin/visual', { headers: admin });
        assert.equal(list.status, 200);
        assert.ok(list.json.refs.some(r => r.brand === 'فيسبوك' && r.domains.includes('facebook.com')), 'مراجع أولية مع نطاقاتها الرسمية');
        assert.equal(list.json.health.configured, true);
        for (const bad of [{ brand: 'x', url: 'http://rafidain.iq/login', domains: 'rafidain.iq' }, { brand: 'x', url: 'https://evil.example/login', domains: 'rafidain.iq' }, { brand: '', url: 'https://rafidain.iq/', domains: '' }, { brand: 'x', url: 'javascript:alert(1)' }]) {
            assert.equal((await request(app, 'POST', '/api/admin/visual/add', { headers: admin, body: bad })).status, 400, JSON.stringify(bad));
        }
        const add = await request(app, 'POST', '/api/admin/visual/add', { headers: admin, body: { brand: 'مصرف الرافدين', url: 'https://www.rafidain-bank.iq/login', domains: 'rafidain-bank.iq, rafidain.iq' } });
        assert.equal(add.status, 201);
        const ref = add.json.refs.find(r => r.brand === 'مصرف الرافدين');
        assert.deepEqual(ref.domains, ['rafidain-bank.iq', 'rafidain.iq']);
        assert.equal(ref.ready, false);
        const refreshed = await request(app, 'POST', '/api/admin/visual/refresh', { headers: admin, body: { id: ref.id } });
        const after = refreshed.json.refs.find(r => r.id === ref.id);
        assert.equal(after.ready, true);
        assert.equal(after.hasIcon, true);
        assert.equal(JSON.parse(calls.find(c => c.url.endsWith('/capture')).opts.body).kind, 'reference');
        // CSRF
        assert.equal((await request(app, 'POST', '/api/admin/visual/remove', { headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example', Cookie: cookieFrom(l) }, body: { id: ref.id } })).status, 403);
        const removed = await request(app, 'POST', '/api/admin/visual/remove', { headers: admin, body: { id: ref.id } });
        assert.ok(!removed.json.refs.some(r => r.id === ref.id));
    }, undefined, { visualFetch: worker });
});
