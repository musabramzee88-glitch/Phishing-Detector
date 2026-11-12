'use strict';

/* فحص الأرقام والحسابات: بصمة لا نص، مستخدم يُحسب مرة، لا أحكام، اعتراض وحذف. */

const test = require('node:test');
const assert = require('node:assert/strict');
const { withServer, request, registerUser, authed, sameOrigin, adminEntry, cookieFrom } = require('./helpers');
const { normalize, mask } = require('../server/identifiers');

test('توحيد المعرّفات: صيغ الرقم العراقي كلها نفس البصمة، والحسابات بدون @ ورابط', () => {
    for (const v of ['07701234567', '+9647701234567', '009647701234567', '0770 123 4567', '7701234567']) assert.equal(normalize('phone', v), '9647701234567', v);
    assert.equal(normalize('instagram', 'https://www.instagram.com/Fake.Shop_IQ/'), 'fake.shop_iq');
    assert.equal(normalize('telegram', '@Seller_99'), 'seller_99');
    assert.equal(normalize('phone', 'abc'), '');
    assert.equal(mask('phone', '9647701234567'), '964770•••4567');
});

test('بلاغ وبحث: يُخزن كبصمة، كل مستخدم مرة وحدة، ونفس الرقم بأي صيغة', async () => {
    await withServer({}, async app => {
        const a = await registerUser(app), b = await registerUser(app);
        const r1 = await request(app, 'POST', '/api/identifier/report', { headers: authed(app, a.cookie), body: { kind: 'phone', value: '07701234567', category: 'transfer', note: 'طلب رصيد' } });
        assert.equal(r1.status, 201);
        assert.equal(r1.json.result.reporters, 1);
        const again = await request(app, 'POST', '/api/identifier/report', { headers: authed(app, a.cookie), body: { kind: 'whatsapp', value: '+964 770 123 4567', category: 'transfer' } });
        assert.equal(again.status, 409, 'نفس المستخدم ما ينحسب مرتين حتى بنوع واتساب');
        await request(app, 'POST', '/api/identifier/report', { headers: authed(app, b.cookie), body: { kind: 'phone', value: '009647701234567', category: 'fake_seller' } });
        const look = await request(app, 'POST', '/api/identifier/lookup', { headers: authed(app, b.cookie), body: { kind: 'phone', value: '0770-123-4567' } });
        assert.equal(look.json.result.reporters, 2);
        assert.deepEqual(look.json.result.categories, { fake_seller: 1, transfer: 1 });
        assert.doesNotMatch(JSON.stringify(look.json), /7701234567|طلب رصيد|@example/, 'لا رقم ولا ملاحظة ولا هوية مبلّغ بالرد');
        // القاعدة ما بيها الرقم كنص
        const dump = JSON.stringify([...app.db._data].map(([k, v]) => [k, v.value instanceof Map ? [...v.value] : v.value instanceof Set ? [...v.value] : v.value]));
        assert.doesNotMatch(dump, /7701234567/);
        // بدون حساب: ممنوع البحث
        assert.equal((await request(app, 'POST', '/api/identifier/lookup', { headers: sameOrigin(app), body: { kind: 'phone', value: '07701234567' } })).status, 401);
    });
});

test('اعتراض من أي شخص ← الأدمن يقبل ← البلاغات تنحذف ويمنع بلاغات جديدة', async () => {
    await withServer({ ADMINS: await adminEntry('qa', 'QA-admin-pass-123') }, async app => {
        const a = await registerUser(app), b = await registerUser(app);
        await request(app, 'POST', '/api/identifier/report', { headers: authed(app, a.cookie), body: { kind: 'instagram', value: '@innocent.shop', category: 'fake_seller' } });
        const dispute = await request(app, 'POST', '/api/identifier/dispute', { headers: sameOrigin(app), body: { kind: 'instagram', value: 'innocent.shop', contact: 'me@shop.example', reason: 'هذا حسابي الحقيقي وانسرق مني الشهر الماضي' } });
        assert.equal(dispute.status, 201);
        const short = await request(app, 'POST', '/api/identifier/dispute', { headers: sameOrigin(app), body: { kind: 'instagram', value: 'innocent.shop', reason: 'لا' } });
        assert.equal(short.status, 400);
        const admin = cookieFrom(await request(app, 'POST', '/api/admin/login', { headers: sameOrigin(app), body: { username: 'qa', password: 'QA-admin-pass-123' } }));
        const view = await request(app, 'GET', '/api/admin/identifiers', { headers: { Cookie: admin } });
        assert.equal(view.json.top[0].masked, 'inn••••••••op');
        assert.equal(view.json.top[0].h.length, 64);
        const d = view.json.disputes[0];
        assert.equal(d.h, undefined);
        assert.equal((await request(app, 'POST', '/api/admin/identifiers/dispute', { headers: authed(app, admin), body: { id: d.id, remove: true } })).status, 200);
        const look = await request(app, 'POST', '/api/identifier/lookup', { headers: authed(app, b.cookie), body: { kind: 'instagram', value: 'innocent.shop' } });
        assert.equal(look.json.result.reporters, 0);
        const blocked = await request(app, 'POST', '/api/identifier/report', { headers: authed(app, b.cookie), body: { kind: 'instagram', value: 'innocent.shop' } });
        assert.equal(blocked.status, 409);
        assert.equal((await request(app, 'GET', '/dispute')).status, 200);
    });
});

test('حد البلاغات اليومي وحد الاعتراضات بالساعة', () => withServer({}, async app => {
    const a = await registerUser(app);
    let last;
    for (let i = 0; i < 11; i++) last = await request(app, 'POST', '/api/identifier/report', { headers: authed(app, a.cookie), body: { kind: 'phone', value: '0770100000' + i } });
    assert.equal(last.status, 429);
    for (let i = 0; i < 6; i++) last = await request(app, 'POST', '/api/identifier/dispute', { headers: sameOrigin(app), body: { kind: 'phone', value: '07701000001', reason: 'هذا رقمي والبلاغ غلط والله' } });
    assert.equal(last.status, 429);
}));
