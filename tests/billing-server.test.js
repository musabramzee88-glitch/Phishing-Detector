'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { TEST_PASSWORD, adminEntry, request, JSON_HEADERS, sameOrigin, cookieFrom, login, withServer } = require('./helpers');

const SECRET = crypto.randomBytes(32).toString('hex');
const ROOT = path.resolve(__dirname, '..');

// بيئة اشتراكات كاملة: سر ترخيص + مجلد بيانات مؤقت + حساب أدمن
async function billingEnv(extra = {}) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-billing-'));
    const env = {
        DATA_DIR: dir, LICENSE_SECRET: SECRET, ADMINS: await adminEntry('musab', TEST_PASSWORD),
        CONTACT_WHATSAPP: '9647700000000', CONTACT_TELEGRAM: 'phish_detector', PAYMENT_NOTE: 'حوّل المبلغ ثم أرسل الإيصال', ...extra
    };
    return { env, dir, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

async function adminCookie(app) {
    return cookieFrom(await login(app));
}

function adminPost(app, cookie, pathName, body, headers = {}) {
    return request(app, 'POST', pathName, { headers: { ...sameOrigin(app), Cookie: cookie, ...headers }, body });
}

const saleBody = (over = {}) => ({ customer: 'مكتب الأمل', tier: 'pro', days: 30, amount: 15000, currency: 'IQD', method: 'ZainCash', note: '', ...over });

async function issue(app, cookie, over) {
    const res = await adminPost(app, cookie, '/api/admin/licenses', saleBody(over));
    assert.equal(res.status, 201, res.text);
    return res.json;
}

function scan(app, key, urls, headers = {}) {
    return request(app, 'POST', '/api/pro/scan-urls', { headers: { ...JSON_HEADERS, 'X-License-Key': key, ...headers }, body: { urls } });
}

// ---------------------------------------------------------------- الباقات العامة

test('/api/pricing: الباقات وبيانات التواصل من المتغيرات، وتُسقَط القيم غير الصالحة', async () => {
    const { env, cleanup } = await billingEnv({ CONTACT_WHATSAPP: 'abc', CONTACT_TELEGRAM: 'bad name!' });
    try {
        await withServer(env, async app => {
            const res = await request(app, 'GET', '/api/pricing');
            assert.equal(res.status, 200);
            assert.equal(res.json.licensingEnabled, true);
            assert.deepEqual(res.json.tiers.map(t => t.id), ['free', 'pro', 'enterprise']);
            assert.deepEqual(res.json.contact.whatsapp, '');
            assert.deepEqual(res.json.contact.telegram, '');
            assert.equal(res.json.contact.note, 'حوّل المبلغ ثم أرسل الإيصال');
            assert.equal(res.json.limits.pro.maxUrls, 50);
            assert.equal((await request(app, 'POST', '/api/pricing')).status, 405);
        });
    } finally { cleanup(); }
});

test('بدون LICENSE_SECRET: الاشتراكات مغلقة بكل المسارات ولا يُنشأ مجلد بيانات', async () => {
    const env = { ADMINS: await adminEntry('musab', TEST_PASSWORD) };
    await withServer(env, async app => {
        assert.equal((await request(app, 'GET', '/api/pricing')).json.licensingEnabled, false);
        const check = await request(app, 'POST', '/api/license/check', { headers: JSON_HEADERS, body: { key: 'PD1-P-ABCDEF12-20301209-' + 'A'.repeat(16) } });
        assert.equal(check.status, 503);
        assert.equal((await scan(app, 'x', ['http://a.com'])).status, 503);
        const cookie = await adminCookie(app);
        const created = await adminPost(app, cookie, '/api/admin/licenses', saleBody());
        assert.equal(created.status, 503);
        const overview = await request(app, 'GET', '/api/admin/licenses', { headers: { Cookie: cookie } });
        assert.equal(overview.json.enabled, false);
        assert.equal(fs.existsSync(path.join(ROOT, 'data')), false, 'data dir must not be created without a license secret');
    });
});

// ---------------------------------------------------------------- الرحلة الكاملة

test('الرحلة الكاملة: إصدار، تحقق، فحص جماعي، إيرادات، إلغاء', async () => {
    const { env, dir, cleanup } = await billingEnv();
    try {
        await withServer(env, async app => {
            const cookie = await adminCookie(app);
            const { license, key } = await issue(app, cookie);
            assert.match(key, /^PD1-P-[0-9A-F]{8}-\d{8}-[A-Z2-7]{16}$/);
            assert.equal(license.status, 'active');

            // التحقق من المفتاح
            const check = await request(app, 'POST', '/api/license/check', { headers: JSON_HEADERS, body: { key } });
            assert.equal(check.status, 200);
            assert.equal(check.json.valid, true);
            assert.equal(check.json.tier, 'pro');
            assert.equal(check.json.limits.maxUrls, 50);

            // الفحص الجماعي: بالترويسة وبـ Bearer
            const urls = ['https://tu.edu.iq', 'https://fasebook.com', 'https://paypal.com.secure-login.xyz/verify', 'not a url !!', 'https://tu.edu.iq'];
            const res = await scan(app, key, urls);
            assert.equal(res.status, 200);
            assert.equal(res.json.tier, 'pro');
            assert.equal(res.json.count, 4);                                  // المكرر يُحذف
            const byUrl = Object.fromEntries(res.json.results.map(r => [r.url, r]));
            assert.equal(byUrl['https://tu.edu.iq'].level, 'safe');
            assert.equal(byUrl['https://fasebook.com'].level, 'danger');
            assert.equal(byUrl['https://paypal.com.secure-login.xyz/verify'].level, 'danger');
            assert.ok(byUrl['https://fasebook.com'].reasons.length > 0 && byUrl['https://fasebook.com'].reasons.length <= 4);
            assert.ok(byUrl['https://fasebook.com'].reasons.every(r => r.type !== 'info'));
            assert.ok(byUrl['not a url !!'].error);                           // رابط معطوب لا يوقف الباقي
            const bearer = await request(app, 'POST', '/api/pro/scan-urls', { headers: { ...JSON_HEADERS, Authorization: 'Bearer ' + key }, body: { urls: ['http://a.com'] } });
            assert.equal(bearer.status, 200);

            // الإيرادات بلوحة الأدمن، والسجل محفوظ على القرص
            const overview = await request(app, 'GET', '/api/admin/licenses', { headers: { Cookie: cookie } });
            assert.equal(overview.status, 200);
            assert.equal(overview.json.storage.persistent, true);
            assert.equal(overview.json.summary.revenue.IQD.thisMonth, 15000);
            assert.equal(overview.json.summary.revenue.USD.thisMonth, 0);
            assert.equal(overview.json.summary.activeByTier.pro, 1);
            assert.equal(overview.json.licenses[0].key, key);
            assert.ok(fs.existsSync(path.join(dir, 'billing.json')));
            const stats = await request(app, 'GET', '/api/admin/stats', { headers: { Cookie: cookie } });
            assert.equal(stats.json.counters.proRequests, 2);
            const created = stats.json.events.find(e => e.type === 'license_created');
            assert.ok(created && !created.detail.includes('مكتب الأمل'), 'customer name must not be in audit log');

            // الإلغاء يوقف المفتاح فوراً
            const revoke = await adminPost(app, cookie, '/api/admin/licenses/revoke', { id: license.id });
            assert.equal(revoke.status, 200);
            const after = await request(app, 'POST', '/api/license/check', { headers: JSON_HEADERS, body: { key } });
            assert.equal(after.status, 401);
            assert.equal(after.json.reason, 'revoked');
            assert.equal((await scan(app, key, ['http://a.com'])).status, 401);
            const overview2 = await request(app, 'GET', '/api/admin/licenses', { headers: { Cookie: cookie } });
            assert.equal(overview2.json.licenses[0].status, 'revoked');
            assert.equal(overview2.json.summary.revenue.IQD.allTime, 15000);   // الإيراد لا يتغيّر بالإلغاء
        });
    } finally { cleanup(); }
});

test('حدود الباقات تُفرض على الخادم: Pro 50 رابطاً، Enterprise 500، وحد الطلبات بالدقيقة', async () => {
    const { env, cleanup } = await billingEnv();
    try {
        await withServer(env, async app => {
            const cookie = await adminCookie(app);
            const pro = (await issue(app, cookie)).key;
            const enterprise = (await issue(app, cookie, { tier: 'enterprise', customer: 'شركة' })).key;
            const many = n => Array.from({ length: n }, (_, i) => `http://site${i}.example.com`);

            assert.equal((await scan(app, pro, many(50))).status, 200);
            const tooMany = await scan(app, pro, many(51));
            assert.equal(tooMany.status, 413);
            assert.equal(tooMany.json.limit, 50);
            assert.equal((await scan(app, enterprise, many(500))).status, 200);
            assert.equal((await scan(app, enterprise, many(501))).status, 413);

            // 20 طلباً بالدقيقة للـ Pro. استُهلك منها طلبان (الـ50 رابطاً والـ51 المرفوض، فالمرفوض يُحسب أيضاً)
            // الباقي 18 طلباً ناجحاً، وبعدها 429
            const codes = [];
            for (let i = 0; i < 20; i++) codes.push((await scan(app, pro, ['http://a.com'])).status);
            assert.equal(codes.filter(c => c === 200).length, 18);
            assert.equal(codes.filter(c => c === 429).length, 2);
            assert.ok(codes.includes(429));
            assert.equal((await scan(app, enterprise, ['http://a.com'])).status, 200);   // الحد لكل ترخيص على حدة

            // مدخلات خاطئة
            for (const body of [{}, { urls: [] }, { urls: 'http://a.com' }, { urls: [1, 2, 3] }, 'null', '[]', 'nope']) {
                const res = await request(app, 'POST', '/api/pro/scan-urls', { headers: { ...JSON_HEADERS, 'X-License-Key': enterprise }, body });
                assert.equal(res.status, 400, JSON.stringify(body));
            }
        });
    } finally { cleanup(); }
});

// ---------------------------------------------------------------- الأمان

test('المفاتيح الخاطئة: رسالة مناسبة، وحظر التخمين بعد عدد محدود من المحاولات', async () => {
    const { env, cleanup } = await billingEnv();
    try {
        await withServer(env, async app => {
            const bad = ['', 'PD1-P-ABCDEF12-20301209-' + 'A'.repeat(16), 'garbage'];
            const reasons = [];
            for (const key of bad) {
                const res = await scan(app, key, ['http://a.com']);
                assert.equal(res.status, 401);
                reasons.push(res.json.reason);
                assert.ok(res.json.error);
            }
            assert.deepEqual(reasons, ['format', 'signature', 'format']);
            const blocked = await scan(app, 'PD1-P-ABCDEF12-20301209-' + 'A'.repeat(16), ['http://a.com']);
            assert.equal(blocked.status, 429);
            assert.ok(Number(blocked.headers['retry-after']) >= 1);
        }, config => { config.limits.badLicenseKeysPerWindow = 3; });
    } finally { cleanup(); }
});

test('الطلبات من مواقع أخرى ونوع المحتوى الخاطئ والجسم الكبير', async () => {
    const { env, cleanup } = await billingEnv();
    try {
        await withServer(env, async app => {
            const cookie = await adminCookie(app);
            const { key } = await issue(app, cookie);
            const evil = await request(app, 'POST', '/api/pro/scan-urls', { headers: { ...JSON_HEADERS, 'X-License-Key': key, Origin: 'https://evil.example' }, body: { urls: ['http://a.com'] } });
            assert.equal(evil.status, 403);
            const evilCheck = await request(app, 'POST', '/api/license/check', { headers: { ...JSON_HEADERS, Origin: 'https://evil.example' }, body: { key } });
            assert.equal(evilCheck.status, 403);
            const text = await request(app, 'POST', '/api/pro/scan-urls', { headers: { 'Content-Type': 'text/plain', 'X-License-Key': key }, body: 'x' });
            assert.equal(text.status, 403);
            const huge = await request(app, 'POST', '/api/pro/scan-urls', { headers: { ...JSON_HEADERS, 'X-License-Key': key }, body: { urls: ['http://a.com/' + 'x'.repeat(300_000)] } });
            assert.equal(huge.status, 400);
            assert.equal((await request(app, 'GET', '/api/pro/scan-urls')).status, 405);
            assert.equal((await request(app, 'GET', '/api/license/check')).status, 405);
        });
    } finally { cleanup(); }
});

test('مسارات الأدمن للاشتراكات: جلسة مطلوبة، وحماية CSRF، والتحقق من الحقول', async () => {
    const { env, cleanup } = await billingEnv();
    try {
        await withServer(env, async app => {
            for (const p of ['/api/admin/licenses', '/api/admin/export/sales.csv', '/api/admin/export/backup.json']) {
                assert.equal((await request(app, 'GET', p)).status, 401, p);
            }
            assert.equal((await request(app, 'POST', '/api/admin/licenses', { headers: sameOrigin(app), body: saleBody() })).status, 401);
            assert.equal((await request(app, 'POST', '/api/admin/licenses/revoke', { headers: sameOrigin(app), body: { id: 'ABCDEF12' } })).status, 401);
            assert.equal((await request(app, 'GET', '/admin/assets/licenses.js')).status, 404);

            const cookie = await adminCookie(app);
            assert.equal((await request(app, 'GET', '/admin/assets/licenses.js', { headers: { Cookie: cookie } })).status, 200);
            const crossSite = await request(app, 'POST', '/api/admin/licenses', { headers: { ...JSON_HEADERS, Origin: 'https://evil.example', Cookie: cookie }, body: saleBody() });
            assert.equal(crossSite.status, 403);
            const form = await request(app, 'POST', '/api/admin/licenses', { headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: `http://127.0.0.1:${app.base.port}`, Cookie: cookie }, body: 'customer=x' });
            assert.equal(form.status, 415);
            for (const body of [saleBody({ tier: 'vip' }), saleBody({ days: 0 }), saleBody({ amount: -5 }), saleBody({ customer: '' }), '[]', 'null', 'x']) {
                const res = await adminPost(app, cookie, '/api/admin/licenses', body);
                assert.equal(res.status, 400, JSON.stringify(body));
            }
            assert.equal((await adminPost(app, cookie, '/api/admin/licenses/revoke', { id: '00000000' })).status, 404);
            assert.equal((await adminPost(app, cookie, '/api/admin/licenses/revoke', { id: '<script>' })).status, 400);
            assert.equal((await request(app, 'DELETE', '/api/admin/licenses', { headers: { Cookie: cookie } })).status, 405);
            const overview = await request(app, 'GET', '/api/admin/licenses', { headers: { Cookie: cookie } });
            assert.equal(overview.json.licenses.length, 0);                   // لم يُنشأ شيء من الطلبات المرفوضة
        });
    } finally { cleanup(); }
});

test('التصدير: CSV محمي من المعادلات + BOM، ونسخة احتياطية JSON، ويُسجَّل بالتدقيق', async () => {
    const { env, cleanup } = await billingEnv();
    try {
        await withServer(env, async app => {
            const cookie = await adminCookie(app);
            await issue(app, cookie, { customer: '=HYPERLINK("http://evil.example")', note: '+cmd' });
            const csv = await request(app, 'GET', '/api/admin/export/sales.csv', { headers: { Cookie: cookie } });
            assert.equal(csv.status, 200);
            assert.match(csv.headers['content-type'], /text\/csv/);
            assert.match(csv.headers['content-disposition'], /attachment; filename="sales\.csv"/);
            assert.ok(csv.text.startsWith('﻿'));
            assert.ok(csv.text.includes(`"'=HYPERLINK(`));
            assert.ok(csv.text.includes(",'+cmd,"));
            const backup = await request(app, 'GET', '/api/admin/export/backup.json', { headers: { Cookie: cookie } });
            assert.equal(backup.json.version, 1);
            assert.equal(backup.json.sales.length, 1);
            const stats = await request(app, 'GET', '/api/admin/stats', { headers: { Cookie: cookie } });
            assert.equal(stats.json.events.filter(e => e.type === 'export').length, 2);
        });
    } finally { cleanup(); }
});

// ---------------------------------------------------------------- الاستمرارية

test('السجل يبقى بعد إعادة التشغيل (نفس المجلد)، والمفاتيح تبقى صالحة حتى لو ضاع القرص', async () => {
    const { env, dir, cleanup } = await billingEnv();
    try {
        let key, id;
        await withServer(env, async app => {
            const cookie = await adminCookie(app);
            const issued = await issue(app, cookie);
            key = issued.key;
            id = issued.license.id;
            await adminPost(app, cookie, '/api/admin/licenses/revoke', { id });
        });

        // 1) إعادة تشغيل بنفس المجلد: السجل والإلغاء محفوظان
        await withServer(env, async app => {
            const cookie = await adminCookie(app);
            const overview = await request(app, 'GET', '/api/admin/licenses', { headers: { Cookie: cookie } });
            assert.equal(overview.json.licenses.length, 1);
            assert.equal(overview.json.licenses[0].status, 'revoked');
            assert.equal((await request(app, 'POST', '/api/license/check', { headers: JSON_HEADERS, body: { key } })).json.reason, 'revoked');
        });

        // 2) ضاع القرص (مجلد فارغ جديد): السجل فارغ، لكن مفتاح زبون غير ملغى يبقى صالحاً لأنه موقَّع
        const second = await billingEnv({ DATA_DIR: fs.mkdtempSync(path.join(os.tmpdir(), 'pd-empty-')) });
        let liveKey;
        try {
            await withServer(env, async app => {
                liveKey = (await issue(app, await adminCookie(app), { customer: 'زبون ثانٍ' })).key;
            });
            await withServer(second.env, async app => {
                const check = await request(app, 'POST', '/api/license/check', { headers: JSON_HEADERS, body: { key: liveKey } });
                assert.equal(check.status, 200);
                assert.equal(check.json.valid, true);
                const overview = await request(app, 'GET', '/api/admin/licenses', { headers: { Cookie: await adminCookie(app) } });
                assert.equal(overview.json.licenses.length, 0);
            });
            // سر مختلف: كل المفاتيح السابقة تتوقف
            await withServer({ ...second.env, LICENSE_SECRET: crypto.randomBytes(32).toString('hex') }, async app => {
                const check = await request(app, 'POST', '/api/license/check', { headers: JSON_HEADERS, body: { key: liveKey } });
                assert.equal(check.status, 401);
                assert.equal(check.json.reason, 'signature');
            });
        } finally {
            second.cleanup();
            fs.rmSync(second.env.DATA_DIR, { recursive: true, force: true });
        }
    } finally { cleanup(); }
});

test('مجلد بيانات غير قابل للكتابة: تنبيه ظاهر بلوحة الأدمن والإصدار يستمر بالذاكرة', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-ro-'));
    const blocker = path.join(dir, 'blocker');
    fs.writeFileSync(blocker, 'x');
    try {
        const { env, cleanup } = await billingEnv({ DATA_DIR: path.join(blocker, 'data') });
        try {
            await withServer(env, async app => {
                const cookie = await adminCookie(app);
                const overview = await request(app, 'GET', '/api/admin/licenses', { headers: { Cookie: cookie } });
                assert.equal(overview.json.storage.persistent, false);
                assert.match(overview.json.storage.error, /بالذاكرة/);
                await issue(app, cookie);
                assert.equal((await request(app, 'GET', '/api/admin/licenses', { headers: { Cookie: cookie } })).json.licenses.length, 1);
            });
        } finally { cleanup(); }
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
