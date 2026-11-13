'use strict';

/* مراقبة انتحال الدومين: التصنيف، الفحص من سجلات الشهادات، «مو تهديد»، الحدود، وPro فقط. */

const test = require('node:test');
const assert = require('node:assert/strict');
const { classify, searchVariants, createMonitor } = require('../server/monitor');
const { createMemoryDb } = require('../server/db');
const { withServer, request, registerUser, authed } = require('./helpers');

test('التصنيف: يكشف أساليب الانتحال ويتجاهل نطاقك ونطاقاتك الفرعية', () => {
    const domain = 'tu.edu.iq';
    assert.equal(classify('mail.tu.edu.iq', domain), null);
    assert.equal(classify('tu.edu.iq', domain), null);
    assert.match(classify('tu.edu.iq.login-portal.xyz', domain).reason, /يستخدم نطاقك/);
    assert.match(classify('tu-edu-iq.com', domain).reason, /يستخدم نطاقك/);
    const bank = 'rafidain-bank.gov.iq';
    assert.ok(classify('rafidain-bank-update.com', bank));
    assert.match(classify('paypal-secure.com', 'paypal.com').reason, /Combosquatting/);
    assert.match(classify('paypa1.com', 'paypal.com').reason, /قريب جداً/);
    assert.match(classify('paypal.net', 'paypal.com').reason, /امتداد ثاني/);
    assert.equal(classify('unrelated-shop.com', 'paypal.com'), null);
    assert.deepEqual(searchVariants('google').slice(0, 2), ['google', 'g0ogle']);
});

test('الفحص: يجيب النتائج من crt.sh، ما يكرر، و«مو تهديد» يخفيها', async () => {
    const db = createMemoryDb(); db.key = (...p) => ['pd', ...p].join(':');
    const queries = [];
    const fetchImpl = async url => {
        queries.push(new URL(url).searchParams.get('q'));
        return { ok: true, text: async () => JSON.stringify([
            { name_value: 'paypal-secure-login.xyz\n*.paypal-secure-login.xyz', not_before: '2026-11-10T00:00:00' },
            { name_value: 'www.paypal.com', not_before: '2026-01-01T00:00:00' },
            { name_value: 'paypa1.top', not_before: '2026-11-11T00:00:00' }
        ]) };
    };
    const sent = [];
    const user = { id: 'u1', email: 'owner@example.com' };
    const monitor = createMonitor({ db, users: { get: async () => user }, mailer: { enabled: true, send: async m => sent.push(m) }, appUrl: 'https://site.example', fetchImpl });
    await monitor.add(user, 'https://www.PayPal.com/login');
    await assert.rejects(monitor.add(user, 'paypal.com'), /مضاف مسبقاً/);
    const r = await monitor.check(user, 'paypal.com');
    assert.deepEqual(r.fresh.map(f => f.domain).sort(), ['paypa1.top', 'paypal-secure-login.xyz']);
    assert.ok(queries.includes('%paypal%'));
    assert.equal(sent.length, 1);
    assert.match(sent[0].subject, /2 نطاق جديد يشبه paypal\.com/);
    await assert.rejects(monitor.check(user, 'paypal.com'), /بعد 10 دقائق/);
    const again = await monitor.check(user, 'paypal.com', { manual: false });
    assert.equal(again.fresh.length, 0, 'ما يكرر نفس النتائج');
    const after = await monitor.dismiss(user, 'paypal.com', 'paypa1.top');
    assert.equal(after.domains[0].findings.find(f => f.domain === 'paypa1.top').dismissed, true);
    await monitor.add(user, 'b.com'); await monitor.add(user, 'c.com');
    await assert.rejects(monitor.add(user, 'd.com'), /الحد 3/);
});

test('تعطل crt.sh ما يكسر شي ويطلع رسالة واضحة', async () => {
    let calls = 0; let t = 1_000_000;
    const db = createMemoryDb(); db.key = (...p) => ['pd', ...p].join(':');
    const user = { id: 'u2', email: 'x@example.com' };
    const monitor = createMonitor({ db, users: { get: async () => user }, mailer: null, appUrl: 'https://s', fetchImpl: async () => { calls++; return { ok: false, status: 502, text: async () => '' }; }, now: () => t, retryDelayMs: 0 });
    await monitor.add(user, 'example.com');
    const r = await monitor.check(user, 'example.com');
    assert.equal(r.failed, true);
    assert.match(r.data.domains[0].lastError, /crt\.sh/);
    assert.equal(r.data.domains[0].lastCheck, 0, 'الفشل ما يُحسب كفحص ناجح');
    assert.equal(calls, 2, 'الاسم الأصلي ينعاد مرتين');
    // بعد الفشل: ما ننتظر 10 دقائق، بس دقيقة
    await assert.rejects(monitor.check(user, 'example.com'), /بعد دقيقة/);
    t += 61_000;
    await monitor.check(user, 'example.com');
    assert.equal(calls, 4);
});

test('واجهة المراقبة: Pro فقط، وتحتاج حساب', () => withServer({}, async app => {
    assert.equal((await request(app, 'GET', '/api/monitor')).status, 401);
    const { cookie, json } = await registerUser(app);   // تجربة Pro
    const add = await request(app, 'POST', '/api/monitor/add', { headers: authed(app, cookie), body: { domain: 'my-shop.example' } });
    assert.equal(add.status, 200);
    assert.equal(add.json.domains[0].domain, 'my-shop.example');
    // نخلّي الحساب مجاني
    await app.users.update(json.user.id, u => { u.trialEndsAt = 1; });
    await new Promise(r => setTimeout(r, 5));
    const free = await request(app, 'GET', '/api/monitor', { headers: { Cookie: cookie } });
    assert.equal(free.status, 403);
}, null, { monitor: createMonitor({ db: (() => { const d = createMemoryDb(); d.key = (...p) => ['pd', ...p].join(':'); return d; })(), users: { get: async () => null }, mailer: null, appUrl: 'https://s', fetchImpl: async () => ({ ok: true, text: async () => '[]' }) }) }));

test('صيغ الأرقام اختيارية: إذا فشلت والاسم الأصلي نجح، الفحص ينجح', async () => {
    const db = createMemoryDb(); db.key = (...p) => ['pd', ...p].join(':');
    const user = { id: 'u9', email: 'x@example.com' };
    const fetchImpl = async url => decodeURIComponent(url).includes('%google%')
        ? { ok: true, text: async () => JSON.stringify([{ name_value: 'google-login.xyz', not_before: '2026-11-10' }]) }
        : { ok: false, status: 503, text: async () => '<html>busy</html>' };
    const monitor = createMonitor({ db, users: { get: async () => user }, mailer: null, appUrl: 'https://s', fetchImpl, retryDelayMs: 0 });
    await monitor.add(user, 'google.com');
    const r = await monitor.check(user, 'google.com');
    assert.equal(r.failed, false);
    assert.equal(r.data.domains[0].lastError, '');
    assert.ok(r.data.domains[0].lastCheck > 0);
    assert.ok(r.data.domains[0].findings.some(f => f.domain === 'google-login.xyz'));
});
