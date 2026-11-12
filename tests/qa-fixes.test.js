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
