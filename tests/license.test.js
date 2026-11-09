'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createLicenseManager, dateToStamp, stampToExpiry } = require('../server/license');
const { createStore, MAX_SALES } = require('../server/store');
const { createBilling, summarize, csvCell, statusOf } = require('../server/billing');

const SECRET = 'k'.repeat(48);
const T0 = Date.UTC(2026, 10, 9, 12, 0, 0);       // 9 نوفمبر 2026 الظهر (UTC)
const DAY = 86_400_000;

// ---------------------------------------------------------------- مفاتيح الترخيص

test('مفتاح الترخيص: إصدار ثم تحقق، وشكله ثابت ومقروء', async () => {
    const lm = createLicenseManager(SECRET, { now: () => T0 });
    assert.equal(lm.enabled, true);
    const issued = lm.issue({ tier: 'pro', expiresAt: T0 + 30 * DAY });
    assert.match(issued.key, /^PD1-P-[0-9A-F]{8}-20261209-[A-Z2-7]{16}$/);
    const result = lm.verify(issued.key);
    assert.deepEqual({ ok: result.ok, tier: result.tier, id: result.id }, { ok: true, tier: 'pro', id: issued.id });
    assert.equal(result.expiresAt, Date.UTC(2026, 11, 9, 23, 59, 59, 999));
    assert.match(lm.issue({ tier: 'enterprise', expiresAt: T0 + DAY }).key, /^PD1-E-/);
});

test('المفتاح يقبل حالة الأحرف والمسافات الزائدة', async () => {
    const lm = createLicenseManager(SECRET, { now: () => T0 });
    const { key } = lm.issue({ tier: 'pro', expiresAt: T0 + 10 * DAY });
    assert.equal(lm.verify('  ' + key.toLowerCase() + '\n').ok, true);
    // مفتاح انكسر بسطرين عند اللصق من واتساب: المسافات والأسطر تُزال قبل التحقق، والتوقيع يبقى هو الحَكَم
    assert.equal(lm.verify(key.slice(0, 20) + '\r\n ' + key.slice(20)).ok, true);
    assert.equal(lm.verify(key.replace(/-/g, '_')).ok, false);                     // لكن استبدال الشرطات يكسره
});

test('لا يمكن تزوير المفتاح: تغيير الباقة أو التاريخ أو الرقم أو التوقيع أو السر', async () => {
    const lm = createLicenseManager(SECRET, { now: () => T0 });
    const { key } = lm.issue({ tier: 'pro', expiresAt: T0 + 30 * DAY });
    const parts = key.split('-');
    const forge = (index, value) => parts.map((p, i) => (i === index ? value : p)).join('-');
    const flip = text => text.slice(0, -1) + (text.endsWith('A') ? 'B' : 'A');

    for (const forged of [forge(1, 'E'), forge(2, '00000000'), forge(3, '20301231'), forge(4, flip(parts[4])), forge(4, 'A'.repeat(16))]) {
        const r = lm.verify(forged);
        assert.equal(r.ok, false, forged);
        assert.equal(r.reason, 'signature', forged);
    }
    const other = createLicenseManager('z'.repeat(48), { now: () => T0 });
    assert.equal(other.verify(key).reason, 'signature');
});

test('الصلاحية تنتهي بنهاية يوم الانتهاء (UTC) بالضبط', async () => {
    let now = T0;
    const lm = createLicenseManager(SECRET, { now: () => now });
    const { key, id } = lm.issue({ tier: 'pro', expiresAt: T0 + 5 * DAY });     // 14 نوفمبر
    now = Date.UTC(2026, 10, 14, 23, 59, 59, 999);
    assert.equal(lm.verify(key).ok, true);
    now += 1;
    const expired = lm.verify(key);
    assert.equal(expired.ok, false);
    assert.equal(expired.reason, 'expired');
    assert.equal(expired.id, id);
});

test('مدخلات غريبة وتواريخ غير حقيقية ترجع format بدون أخطاء', async () => {
    const lm = createLicenseManager(SECRET, { now: () => T0 });
    for (const input of [null, undefined, 123, '', 'PD1', 'x'.repeat(5000), "' OR 1=1 --", '<script>', 'PD1-P-ABCDEF12-20261301-' + 'A'.repeat(16), 'PD1-P-ABCDEF12-20260230-' + 'A'.repeat(16), 'PD1-X-ABCDEF12-20261209-' + 'A'.repeat(16)]) {
        const r = lm.verify(input);
        assert.equal(r.ok, false);
        assert.equal(r.reason, 'format');
    }
});

test('الإصدار يرفض الباقة المجهولة والتاريخ الماضي، وبدون سر الاشتراكات معطّلة', async () => {
    const lm = createLicenseManager(SECRET, { now: () => T0 });
    assert.throws(() => lm.issue({ tier: 'vip', expiresAt: T0 + DAY }));
    assert.throws(() => lm.issue({ tier: 'pro', expiresAt: T0 - DAY }));
    assert.throws(() => lm.issue({ tier: 'pro', expiresAt: NaN }));
    for (const secret of ['', undefined, 'short', 'x'.repeat(31)]) {
        const off = createLicenseManager(secret);
        assert.equal(off.enabled, false);
        assert.throws(() => off.issue({ tier: 'pro', expiresAt: Date.now() + DAY }));
        assert.equal(off.verify('PD1-P-ABCDEF12-20261209-' + 'A'.repeat(16)).reason, 'disabled');
    }
});

test('keyFor ثابت لنفس المدخلات، والأرقام لا تتكرر', async () => {
    const lm = createLicenseManager(SECRET, { now: () => T0 });
    const issued = lm.issue({ tier: 'pro', expiresAt: T0 + 3 * DAY });
    assert.equal(lm.keyFor({ tier: 'pro', id: issued.id, expiresAt: issued.expiresAt }), issued.key);
    const ids = new Set();
    for (let i = 0; i < 2000; i++) ids.add(lm.issue({ tier: 'pro', expiresAt: T0 + DAY }).id);
    assert.equal(ids.size, 2000);
});

test('أدوات التواريخ', async () => {
    assert.equal(dateToStamp(Date.UTC(2026, 0, 5)), '20260105');
    assert.equal(stampToExpiry('20260230'), null);
    assert.equal(stampToExpiry('20240229'), Date.UTC(2024, 1, 29, 23, 59, 59, 999));
});

// ---------------------------------------------------------------- التخزين

function tempDir() {
    return fs.mkdtempSync(path.join(os.tmpdir(), 'pd-store-'));
}
const sampleSale = (over = {}) => ({ id: 'ABCDEF12', createdAt: new Date(T0).toISOString(), customer: 'زبون', tier: 'pro', expiresAt: new Date(T0 + 30 * DAY).toISOString(), amount: 15000, currency: 'IQD', method: 'ZainCash', note: '', ...over });

test('التخزين: يحفظ ويقرأ من جديد، ولا يترك ملفاً مؤقتاً', async () => {
    const dir = tempDir();
    try {
        const a = createStore(dir);
        assert.equal(a.state.persistent, true);
        (await a.addSale(sampleSale()));
        (await a.revoke('ABCDEF12'));
        (await a.revoke('ABCDEF12'));                                         // مكرر: لا يتضاعف
        const b = createStore(dir);
        assert.equal(b.sales().length, 1);
        assert.equal(b.isRevoked('ABCDEF12'), true);
        assert.deepEqual(b.revokedIds(), ['ABCDEF12']);
        assert.deepEqual(fs.readdirSync(dir), ['billing.json']);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('التخزين: ملف تالف لا يُكتب فوقه، يُحفظ باسم آخر مع تنبيه', async () => {
    const dir = tempDir();
    try {
        fs.writeFileSync(path.join(dir, 'billing.json'), '{ not json ');
        const store = createStore(dir);
        assert.equal(store.sales().length, 0);
        assert.match(store.state.error, /تالفاً/);
        assert.ok(fs.readdirSync(dir).some(f => /^billing\.corrupt-\d+\.json$/.test(f)));
        assert.equal(fs.readFileSync(fs.readdirSync(dir).filter(f => f.includes('corrupt')).map(f => path.join(dir, f))[0], 'utf8'), '{ not json ');
        (await store.addSale(sampleSale()));
        assert.equal(createStore(dir).sales().length, 1);
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('التخزين: مجلد لا يمكن الكتابة فيه يعمل بالذاكرة مع تنبيه، ووضع بلا مجلد', async () => {
    const dir = tempDir();
    try {
        const blocker = path.join(dir, 'file-not-dir');
        fs.writeFileSync(blocker, 'x');
        const store = createStore(path.join(blocker, 'data'));          // مسار تحت ملف: لا يمكن إنشاؤه
        assert.equal(store.state.persistent, false);
        assert.match(store.state.error, /بالذاكرة/);
        (await store.addSale(sampleSale()));
        assert.equal(store.sales().length, 1);
        const memory = createStore(null);
        assert.equal(memory.state.persistent, false);
        assert.equal(memory.state.error, '');
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('التخزين: حد أقصى لعدد السجلات', async () => {
    const store = createStore(null);
    for (let i = 0; i < MAX_SALES; i++) (await store.addSale(sampleSale({ id: String(i) })));
    await assert.rejects(() => store.addSale(sampleSale()), /limit/);
});

// ---------------------------------------------------------------- الإيرادات

const sale = (over) => sampleSale(over);

test('الإيرادات: لكل عملة على حدة، الشهر الحالي، آخر 30 يوماً، الأشهر الستة', async () => {
    const sales = [
        sale({ id: 'A0000001', createdAt: new Date(T0 - 2 * DAY).toISOString(), amount: 15000, currency: 'IQD' }),         // هذا الشهر
        sale({ id: 'A0000002', createdAt: new Date(T0 - 20 * DAY).toISOString(), amount: 10, currency: 'USD', tier: 'enterprise' }),  // 20 أكتوبر: آخر 30 يوماً لكن شهر آخر
        sale({ id: 'A0000003', createdAt: new Date(T0 - 60 * DAY).toISOString(), amount: 70000, currency: 'IQD' }),        // قديم
        sale({ id: 'A0000004', createdAt: new Date(T0 - 1 * DAY).toISOString(), amount: 49.5, currency: 'USD' })
    ];
    const s = summarize(sales, () => false, T0);
    assert.deepEqual(s.revenue.IQD, { allTime: 85000, thisMonth: 15000, last30: 15000 });
    assert.deepEqual(s.revenue.USD, { allTime: 59.5, thisMonth: 49.5, last30: 59.5 });
    assert.equal(s.monthly.length, 6);
    assert.equal(s.monthly[5].month, '2026-11');
    assert.equal(s.monthly[5].IQD, 15000);
    assert.equal(s.monthly[4].month, '2026-10');
    assert.equal(s.monthly[4].USD, 10);
    assert.equal(s.monthly[3].month, '2026-09');
    assert.equal(s.monthly[3].IQD, 70000);
});

test('الإيرادات: الحالات والعدّ حسب الباقة والتي تنتهي قريباً', async () => {
    const sales = [
        sale({ id: 'B0000001', expiresAt: new Date(T0 + 30 * DAY).toISOString() }),                       // نشط
        sale({ id: 'B0000002', expiresAt: new Date(T0 + 3 * DAY).toISOString(), customer: 'قريب' }),      // ينتهي قريباً
        sale({ id: 'B0000003', expiresAt: new Date(T0 + 1 * DAY).toISOString(), tier: 'enterprise', customer: 'الأقرب' }),
        sale({ id: 'B0000004', expiresAt: new Date(T0 - 1 * DAY).toISOString() }),                        // منتهٍ
        sale({ id: 'B0000005', expiresAt: new Date(T0 + 90 * DAY).toISOString(), tier: 'enterprise' })    // سيُلغى
    ];
    const revoked = new Set(['B0000005']);
    const s = summarize(sales, id => revoked.has(id), T0);
    assert.deepEqual(s.counts, { total: 5, active: 1, expiring: 2, expired: 1, revoked: 1 });
    assert.deepEqual(s.activeByTier, { pro: 2, enterprise: 1 });
    assert.deepEqual(s.expiringSoon.map(e => e.id), ['B0000003', 'B0000002']);          // الأقرب أولاً
    assert.equal(statusOf(sales[0], false, T0), 'active');
    assert.equal(statusOf(sales[0], true, T0), 'revoked');
});

test('CSV: حماية المعادلات والاقتباس', async () => {
    assert.equal(csvCell('=HYPERLINK("http://x")'), `"'=HYPERLINK(""http://x"")"`);
    assert.equal(csvCell('+1'), "'+1");
    assert.equal(csvCell('-5'), "'-5");
    assert.equal(csvCell('@SUM(A1)'), "'@SUM(A1)");
    assert.equal(csvCell('a,b'), '"a,b"');
    assert.equal(csvCell('عادي'), 'عادي');
    assert.equal(csvCell(15000), '15000');
    assert.equal(csvCell(null), '');
});

// ---------------------------------------------------------------- منطق الإصدار

function newBilling(options = {}) {
    let now = T0;
    const events = [];
    const store = createStore(null);
    const license = createLicenseManager(options.secret === undefined ? SECRET : options.secret, { now: () => now });
    const billing = createBilling({ store, license, stats: { event: (...a) => events.push(a) }, now: () => now });
    return { billing, store, license, events, advance: ms => { now += ms; } };
}
const validInput = (over = {}) => ({ customer: '  شركة   الأمل  ', tier: 'pro', days: 30, amount: 15000, currency: 'IQD', method: 'ZainCash', note: 'ملاحظة', ...over });

test('الإصدار: يسجّل البيع ويرجع مفتاحاً صالحاً، ولا يكتب اسم الزبون بسجل التدقيق', async () => {
    const { billing, license, events, store } = newBilling();
    const result = (await billing.create(validInput(), '10.0.0.5'));
    assert.equal(result.status, 201);
    assert.equal(result.license.customer, 'شركة الأمل');               // مسافات منظّمة
    assert.equal(result.license.status, 'active');
    assert.equal(license.verify(result.key).ok, true);
    assert.equal(store.sales().length, 1);
    assert.equal(result.license.key, result.key);
    assert.equal(events.length, 1);
    assert.equal(events[0][0], 'license_created');
    assert.ok(!events[0][1].includes('الأمل'), 'customer name leaked to audit log');
    assert.equal(billing.overview().summary.revenue.IQD.thisMonth, 15000);
});

test('الإصدار: التحقق من كل حقل', async () => {
    const { billing, store } = newBilling();
    const bad = [
        { customer: '' }, { customer: '   ' }, { tier: 'vip' }, { tier: 'free' }, { days: 0 }, { days: 3661 }, { days: 1.5 }, { days: 'abc' },
        { amount: -1 }, { amount: 'abc' }, { amount: 1e10 }, { amount: Infinity }, { currency: 'EUR' }, { method: 'bitcoin' }, { renewalOf: 'not-an-id' }
    ];
    for (const patch of bad) {
        const r = (await billing.create(validInput(patch), '1.1.1.1'));
        assert.equal(r.status, 400, JSON.stringify(patch));
        assert.ok(r.error);
    }
    assert.equal((await billing.create(null, '1.1.1.1')).status, 400);
    assert.equal(store.sales().length, 0);
    assert.equal((await billing.create(validInput({ amount: 0 }), '1.1.1.1')).status, 201);            // مجاني/هدية مسموح
    assert.equal((await billing.create(validInput({ amount: 10.456, currency: 'USD' }), '1.1.1.1')).license.amount, 10.46);
    const long = (await billing.create(validInput({ customer: 'م'.repeat(500), note: 'ن'.repeat(900) }), '1.1.1.1'));
    assert.equal(long.license.customer.length, 80);
    assert.equal(long.license.note.length, 200);
});

test('الإصدار: بدون سر يرجع 503 ولا يسجّل شيئاً', async () => {
    const { billing, store } = newBilling({ secret: '' });
    assert.equal(billing.enabled, false);
    assert.equal((await billing.create(validInput(), '1.1.1.1')).status, 503);
    assert.equal(store.sales().length, 0);
});

test('الإلغاء: يغيّر الحالة، ويتحقق من الرقم، ولا يحذف الإيراد', async () => {
    const { billing, license, events } = newBilling();
    const { key, license: created } = (await billing.create(validInput(), '1.1.1.1'));
    assert.equal((await billing.revoke('zzz', '1.1.1.1')).status, 400);
    assert.equal((await billing.revoke('00000000', '1.1.1.1')).status, 404);
    assert.equal((await billing.revoke(created.id, '1.1.1.1')).status, 200);
    const overview = billing.overview();
    assert.equal(overview.licenses[0].status, 'revoked');
    assert.equal(overview.summary.revenue.IQD.allTime, 15000);
    assert.equal(overview.summary.counts.revoked, 1);
    assert.equal(license.verify(key).ok, true);                         // التوقيع وحده سليم؛ الإلغاء يُفحص بالسجل
    assert.ok(events.some(e => e[0] === 'license_revoked'));
});

test('التجديد: مفتاح جديد بتاريخ جديد ويرتبط بالسابق، والقديم يبقى صالحاً حتى ينتهي', async () => {
    const { billing, license, advance } = newBilling();
    const first = (await billing.create(validInput({ days: 30 }), '1.1.1.1'));
    advance(25 * DAY);
    const renewal = (await billing.create(validInput({ days: 30, renewalOf: first.license.id }), '1.1.1.1'));
    assert.notEqual(renewal.key, first.key);
    assert.equal(renewal.license.renewalOf, first.license.id);
    assert.equal(license.verify(first.key).ok, true);
    assert.equal(license.verify(renewal.key).ok, true);
    advance(10 * DAY);
    assert.equal(license.verify(first.key).reason, 'expired');
    assert.equal(license.verify(renewal.key).ok, true);
});

test('التصدير: CSV بترويسة BOM وحماية المعادلات، والنسخة الاحتياطية JSON', async () => {
    const { billing } = newBilling();
    (await billing.create(validInput({ customer: '=HYPERLINK("http://evil")', note: 'a,"b"' }), '1.1.1.1'));
    const csv = billing.csv();
    assert.ok(csv.startsWith('﻿license_id,created_at,customer'));
    assert.ok(csv.includes(`"'=HYPERLINK(""http://evil"")"`));
    assert.ok(csv.includes('"a,""b"""'));
    const backup = billing.backup();
    assert.equal(backup.version, 1);
    assert.equal(backup.sales.length, 1);
    assert.deepEqual(backup.revoked, []);
});
