'use strict';

/*
  تدقيق أمني على نسخة حقيقية من الخادم (كل هجوم اختبار مستقل):
  تجاوز الدخول، وصول مستخدم عادي للإدارة، CSRF، قراءة ملفات الخادم، تلويث النموذج الأولي، تعيين حقول محمية،
  الوصول لبيانات مستخدم آخر، أجسام طلبات تالفة لكل مسار (لا خطأ 500)، طرق HTTP غريبة، القفل بعد محاولات خاطئة، ورؤوس الأمان.
*/

const test = require('node:test');
const assert = require('node:assert/strict');
const { startServer, request, sameOrigin, registerUser, authed, adminEntry } = require('./helpers');

const PROTECTED = [['GET', '/api/auth/me'], ['GET', '/api/account/history'], ['POST', '/api/account/name'], ['POST', '/api/account/password'], ['POST', '/api/account/api-key'], ['POST', '/api/account/delete'], ['GET', '/api/billing'], ['POST', '/api/billing/request'], ['POST', '/api/scan/url'], ['POST', '/api/scan/text'], ['POST', '/api/scan/file'], ['POST', '/api/scan/bulk'], ['POST', '/api/scan/record'], ['POST', '/api/chat'], ['POST', '/api/v1/scan-url']];
const ADMIN = [['GET', '/api/admin/stats'], ['GET', '/api/admin/users'], ['POST', '/api/admin/users/action'], ['GET', '/api/admin/payments'], ['POST', '/api/admin/payments/decide'], ['GET', '/api/admin/settings'], ['POST', '/api/admin/settings'], ['GET', '/api/admin/export/users.csv'], ['GET', '/api/admin/export/payments.csv'], ['GET', '/api/admin/ipcheck'], ['POST', '/api/admin/ai-test'], ['GET', '/admin/assets/dashboard.js'], ['GET', '/admin/assets/manage.js']];
const POSTS = ['/api/auth/register', '/api/auth/login', '/api/auth/mfa', '/api/auth/mfa/resend', '/api/auth/reset', '/api/auth/resend', '/api/auth/verify-code', '/api/auth/forgot', '/api/account/name', '/api/account/password', '/api/account/history-setting', '/api/account/history/clear', '/api/billing/request', '/api/scan/url', '/api/scan/text', '/api/scan/file', '/api/scan/record', '/api/scan/bulk', '/api/scan/clean', '/api/chat', '/api/event', '/api/client-error', '/api/admin/login', '/api/admin/email/start', '/api/admin/email/verify', '/api/admin/account/start'];
const JUNK = ['{}', '[]', 'null', '1', '"x"', '{"a":', '{"email":{"$ne":null},"password":{"$gt":""}}',
    '{"url":["a","b"],"text":{"x":1},"urls":"abc","message":123,"history":"x","code":[1],"months":"1e9","strict":"yes"}',
    '{"urls":[null,1,{},"https://a.com"],"kind":"file","level":"danger","score":"NaN"}', '{"text":"\\ud800\\udfff\\u0000"}', '\u0000\u0001',
    '{"months":-1,"method":"contact","reference":"12345"}', '{"username":null,"password":null,"ticket":{},"code":null}'];
const TRAVERSAL = ['/../server.js', '/%2e%2e/server.js', '/..%2fserver.js', '/.env', '/.git/config', '/server/config.js', '/package.json', '/js/../../server.js',
    '/%2e%2e%2f%2e%2e%2fetc%2fpasswd', '/css/..%5c..%5cserver.js', '/js/app.js%00.png', '/admin/assets/../admin.js', '/admin/assets/%2e%2e%2fadmin.js',
    '//etc/passwd', '/tests/helpers.js', '/Dockerfile', '/.github/workflows/test.yml', '/img/../../.env', '/server/admin/dashboard.js'];

test('تدقيق أمني على الخادم', async t => {
    const app = await startServer({ ADMINS: await adminEntry('qa', 'QA-admin-pass-123') });
    try {
        const O = sameOrigin(app);
        const alice = await registerUser(app, { email: 'alice@example.com' });
        const bob = await registerUser(app, { email: 'bob@example.com' });

        for (const [m, p] of [...PROTECTED, ...ADMIN]) {
            await t.test(`بدون جلسة ممنوع: ${m} ${p}`, async () => {
                const r = await request(app, m, p, { headers: O, body: m === 'POST' ? {} : undefined });
                assert.ok([401, 403, 404, 405].includes(r.status), String(r.status));
            });
        }
        for (const [m, p] of ADMIN) {
            await t.test(`مستخدم عادي لا يصل للإدارة: ${m} ${p}`, async () => {
                const r = await request(app, m, p, { headers: authed(app, alice.cookie), body: m === 'POST' ? {} : undefined });
                assert.ok([401, 403, 404, 405].includes(r.status), String(r.status));
            });
        }
        for (const p of ['/api/account/name', '/api/account/delete', '/api/billing/request', '/api/scan/url', '/api/chat', '/api/auth/logout', '/api/account/api-key']) {
            for (const origin of ['https://evil.example', 'null', `http://127.0.0.1.evil.example`]) {
                await t.test(`CSRF مرفوض: ${p} من ${origin}`, async () => {
                    const r = await request(app, 'POST', p, { headers: { 'Content-Type': 'application/json', Origin: origin, Cookie: alice.cookie }, body: { name: 'x', confirm: 'alice@example.com', url: 'https://a.com', message: 'hi' } });
                    assert.ok(r.status >= 400, String(r.status));
                });
            }
            await t.test(`CSRF بنموذج text/plain مرفوض: ${p}`, async () => {
                const r = await request(app, 'POST', p, { headers: { 'Content-Type': 'text/plain', Cookie: alice.cookie, 'Sec-Fetch-Site': 'cross-site' }, body: '{"name":"x"}' });
                assert.ok(r.status >= 400, String(r.status));
            });
        }
        for (const p of TRAVERSAL) {
            await t.test(`لا تسريب لملفات الخادم: ${p}`, async () => {
                const r = await request(app, 'GET', p);
                assert.ok(r.status < 500);
                assert.ok(!(r.status === 200 && /require\(|process\.env|root:|UPSTASH|"scripts"/.test(r.text)), r.text.slice(0, 80));
            });
        }
        for (const p of POSTS) {
            await t.test(`أجسام تالفة لا تسبب خطأ 500: ${p}`, async () => {
                for (const body of JUNK) for (const cookie of [alice.cookie, '']) {
                    const r = await request(app, 'POST', p, { headers: { ...O, ...(cookie ? { Cookie: cookie } : {}) }, body });
                    assert.ok(r.status < 500 || r.status === 503, `${r.status} on ${body.slice(0, 40)}`);
                }
            });
        }
        await t.test('طرق HTTP غريبة لا تسبب خطأ 500', async () => {
            for (const p of [...POSTS, '/', '/login', '/admin', '/healthz', '/api/site', '/robots.txt', '/api/auth/config']) {
                for (const m of ['PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE', 'HEAD']) {
                    const r = await request(app, m, p, { headers: { Cookie: alice.cookie } });
                    assert.ok(r.status < 500, `${m} ${p} → ${r.status}`);
                }
            }
        });
        await t.test('تلويث النموذج الأولي وتعيين حقول محمية عند التسجيل لا يعمل', async () => {
            const r = await request(app, 'POST', '/api/auth/register', { headers: O, body: '{"email":"pp@example.com","password":"a long safe passphrase","__proto__":{"isAdmin":true},"constructor":{"prototype":{"polluted":1}},"paidUntil":9999999999999,"trialEndsAt":9999999999999,"disabled":false}' });
            assert.equal(({}).isAdmin, undefined);
            assert.equal(({}).polluted, undefined);
            const until = r.json && r.json.user && r.json.user.planUntil;
            assert.ok(!until || new Date(until).getFullYear() < 2100);
        });
        await t.test('مستخدم لا يرى أو يحذف بيانات غيره', async () => {
            await request(app, 'POST', '/api/billing/request', { headers: authed(app, alice.cookie), body: { method: 'contact', months: 1, reference: 'ALICE-REF-777' } });
            const billing = await request(app, 'GET', '/api/billing', { headers: authed(app, bob.cookie) });
            assert.doesNotMatch(JSON.stringify(billing.json), /ALICE-REF-777/);
            const del = await request(app, 'POST', '/api/account/delete', { headers: authed(app, bob.cookie), body: { confirm: 'alice@example.com' } });
            assert.notEqual(del.status, 200);
        });
        await t.test('مدة اشتراك سالبة مرفوضة', async () => {
            const r = await request(app, 'POST', '/api/billing/request', { headers: authed(app, alice.cookie), body: { method: 'contact', months: -12, reference: '99999999' } });
            assert.ok(r.status >= 400);
        });
        await t.test('الاسم المخزّن ينظَّف من HTML', async () => {
            await request(app, 'POST', '/api/account/name', { headers: authed(app, alice.cookie), body: { name: '<img src=x onerror=alert(1)>' } });
            const me = await request(app, 'GET', '/api/auth/me', { headers: { Cookie: alice.cookie } });
            assert.doesNotMatch(me.json.user.name, /[<>]/);
        });
        await t.test('رؤوس الأمان على كل الصفحات', async () => {
            for (const p of ['/login', '/', '/privacy', '/admin', '/api/site', '/js/app.js', '/nope']) {
                const r = await request(app, 'GET', p, { headers: { Cookie: alice.cookie } });
                for (const h of ['content-security-policy', 'x-content-type-options', 'x-frame-options', 'referrer-policy']) assert.ok(r.headers[h], `${h} on ${p}`);
            }
        });
        await t.test('قفل بعد محاولات دخول خاطئة (مستخدم وأدمن)', async () => {
            let user = false, admin = false;
            for (let i = 0; i < 20 && !user; i++) user = (await request(app, 'POST', '/api/auth/login', { headers: O, body: { email: 'alice@example.com', password: 'wrong' + i } })).status === 429;
            for (let i = 0; i < 10 && !admin; i++) admin = (await request(app, 'POST', '/api/admin/login', { headers: O, body: { username: 'qa', password: 'wrong' + i } })).status === 429;
            assert.ok(user && admin);
        });
    } finally {
        await app.close();
    }
});
