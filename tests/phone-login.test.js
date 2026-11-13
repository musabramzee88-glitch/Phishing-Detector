'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { withServer, request, sameOrigin, cookieFrom, registerUser, authed } = require('./helpers');
const { normalizeIraqiMobile, maskPhone, createPhoneAuth } = require('../server/phone-auth');
const { parseSms, createSms } = require('../server/sms');
const { createMemoryDb } = require('../server/db');

// مزوّد رسائل وهمي يحفظ آخر رمز لكل رقم
function fakeSms({ fail = false, cap = 300 } = {}) {
    const box = new Map();
    return {
        enabled: true, dailyCap: cap, box, sent: 0,
        async sendCode(phone, code) { if (fail) throw new Error('sms_failed'); this.sent++; box.set(phone, code); },
        status: () => ({ enabled: true, provider: 'fake', dailyCap: cap, sent: 0, lastError: '' })
    };
}

test('تطبيع الأرقام العراقية: يقبل الصيغ الشائعة ويرفض الدولية والأرضي', () => {
    for (const v of ['07701234567', '0770 123 4567', '+9647701234567', '009647701234567', '7701234567', '٠٧٧٠١٢٣٤٥٦٧', '(0770)-123-4567']) {
        assert.equal(normalizeIraqiMobile(v), '9647701234567', v);
    }
    for (const v of ['', '0123', '+12025550123', '+447700900123', '0770123456', '077012345678', '9641234567', '07201234567', 'abc', null, {}]) {
        assert.equal(normalizeIraqiMobile(v), '', String(v));
    }
    assert.equal(maskPhone('9647701234567'), '0770 ••• 4567');
});

test('إعداد المزوّد من متغيرات البيئة', () => {
    assert.equal(parseSms({}).enabled, false);
    assert.equal(parseSms({ TELEGRAM_GATEWAY_TOKEN: 'abc' }).provider, 'telegram');
    assert.equal(parseSms({ TWILIO_ACCOUNT_SID: 'AC' + 'a'.repeat(32), TWILIO_AUTH_TOKEN: 'x', TWILIO_FROM: '+1555' }).enabled, true);
    assert.equal(parseSms({ TWILIO_ACCOUNT_SID: 'bad', TWILIO_AUTH_TOKEN: 'x', TWILIO_FROM: '+1555' }).enabled, false);
    assert.equal(parseSms({ SMS_WEBHOOK_URL: 'http://insecure.example' }).enabled, false, 'لازم https');
    assert.equal(parseSms({ SMS_WEBHOOK_URL: 'https://sms.example/send' }).enabled, true);
    assert.equal(parseSms({ SMS_DAILY_CAP: '50' }).dailyCap, 50);
});

test('المزوّدات ترسل الطلب الصحيح ولا تسرّب المفتاح بالخطأ', async () => {
    const calls = [];
    const fetchImpl = async (url, opts) => { calls.push({ url, opts }); return { ok: true, text: async () => '{"ok":true,"result":{}}' }; };
    await createSms(parseSms({ TELEGRAM_GATEWAY_TOKEN: 'SECRET-T' }), { fetchImpl }).sendCode('9647701234567', '123456');
    assert.match(calls[0].url, /gatewayapi\.telegram\.org\/sendVerificationMessage/);
    assert.deepEqual(JSON.parse(calls[0].opts.body), { phone_number: '+9647701234567', code: '123456', ttl: 300 });
    assert.equal(calls[0].opts.headers.Authorization, 'Bearer SECRET-T');

    const tw = createSms(parseSms({ TWILIO_ACCOUNT_SID: 'AC' + '1'.repeat(32), TWILIO_AUTH_TOKEN: 'SECRET-W', TWILIO_FROM: '+15550001111' }), { fetchImpl });
    await tw.sendCode('9647701234567', '654321');
    assert.match(calls[1].url, /api\.twilio\.com\/2010-04-01\/Accounts\/AC1+\/Messages\.json/);
    const form = new URLSearchParams(calls[1].opts.body);
    assert.equal(form.get('To'), '+9647701234567');
    assert.match(form.get('Body'), /654321/);

    const failing = createSms(parseSms({ TELEGRAM_GATEWAY_TOKEN: 'SECRET-T' }), { fetchImpl: async () => ({ ok: false, status: 401, text: async () => 'SECRET-T' }) });
    await assert.rejects(failing.sendCode('9647701234567', '111111'), /sms_failed/);
    assert.doesNotMatch(JSON.stringify(failing.status()), /SECRET/);
});

test('منطق الرمز: انتظار دقيقة، 5 محاولات، صلاحية، وحدود يومية', async () => {
    const db = createMemoryDb(); db.key = (...p) => ['pd', ...p].join(':');
    const sms = fakeSms();
    let t = Date.parse('2026-11-13T10:00:00Z');
    const pa = createPhoneAuth({ db, sms, now: () => t });
    const r = await pa.start({ phone: '07701234567', ip: '1.1.1.1' });
    assert.equal(r.masked, '0770 ••• 4567');
    const code = sms.box.get('9647701234567');
    assert.match(code, /^\d{6}$/);
    await assert.rejects(pa.start({ phone: '07701234567', ip: '1.1.1.1' }), e => e.code === 'wait');
    // رمز غلط 5 مرات ثم ينلغي حتى لو جاي الصح
    const wrong = code === '000000' ? '111111' : '000000';
    for (let i = 0; i < 5; i++) await assert.rejects(pa.verify({ challenge: r.challenge, code: wrong }), e => e.code === 'bad_code');
    await assert.rejects(pa.verify({ challenge: r.challenge, code }), e => e.code === 'too_many');
    await assert.rejects(pa.verify({ challenge: r.challenge, code }), e => e.code === 'expired');
    // تحدي جديد، والرمز الصح يشتغل مرة وحدة بس
    await db.cmd(['DEL', db.key('otpwait', '9647701234567')]);
    const r2 = await pa.start({ phone: '0770 123 4567', ip: '1.1.1.1' });
    const ok = await pa.verify({ challenge: r2.challenge, code: '  ' + sms.box.get('9647701234567') });
    assert.equal(ok.phone, '9647701234567');
    await assert.rejects(pa.verify({ challenge: r2.challenge, code: sms.box.get('9647701234567') }), e => e.code === 'expired');
    // تحدي «ربط» ما ينفع للدخول
    await db.cmd(['DEL', db.key('otpwait', '9647701234567')]);
    const link = await pa.start({ phone: '07701234567', ip: '1.1.1.1', purpose: 'link', uid: 'abc' });
    await assert.rejects(pa.verify({ challenge: link.challenge, code: sms.box.get('9647701234567'), purpose: 'login' }), e => e.code === 'expired');
    // حد الرقم اليومي (5)
    for (let i = 0; i < 2; i++) { await db.cmd(['DEL', db.key('otpwait', '9647701234567')]); await pa.start({ phone: '07701234567', ip: '2.2.2.' + i }); }
    await db.cmd(['DEL', db.key('otpwait', '9647701234567')]);
    await assert.rejects(pa.start({ phone: '07701234567', ip: '3.3.3.3' }), e => e.code === 'phone_limit');
    // حد الـ IP (20 بالساعة)
    for (let i = 0; i < 20; i++) await pa.start({ phone: '0780' + String(1000000 + i), ip: '9.9.9.9' }).catch(e => assert.fail(e.message));
    await assert.rejects(pa.start({ phone: '07811111111', ip: '9.9.9.9' }), e => e.code === 'ip_limit');
    // رقم دولي مرفوض قبل أي إرسال
    const before = sms.sent;
    await assert.rejects(pa.start({ phone: '+447700900123', ip: '5.5.5.5' }), e => e.code === 'bad_phone');
    assert.equal(sms.sent, before);
});

test('الحد اليومي لكل الموقع، وفشل الإرسال ما يترك تحدي معلّق', async () => {
    const db = createMemoryDb(); db.key = (...p) => ['pd', ...p].join(':');
    const pa = createPhoneAuth({ db, sms: fakeSms({ cap: 2 }) });
    await pa.start({ phone: '07701111111', ip: 'a' });
    await pa.start({ phone: '07702222222', ip: 'b' });
    await assert.rejects(pa.start({ phone: '07703333333', ip: 'c' }), e => e.code === 'global_limit');
    const pf = createPhoneAuth({ db: Object.assign(createMemoryDb(), { key: (...p) => p.join(':') }), sms: fakeSms({ fail: true }) });
    await assert.rejects(pf.start({ phone: '07701111111', ip: 'a' }), e => e.code === 'send_failed');
    // بعد الفشل ما ننتظر دقيقة
    await assert.rejects(pf.start({ phone: '07701111111', ip: 'a' }), e => e.code === 'send_failed');
});

test('الواجهة: مخفية بدون مزوّد رسائل', () => withServer({}, async app => {
    const cfg = await request(app, 'GET', '/api/auth/config');
    assert.equal(cfg.json.phone, false);
    const r = await request(app, 'POST', '/api/auth/phone/start', { headers: sameOrigin(app), body: { phone: '07701234567' } });
    assert.equal(r.status, 503);
}));

test('الدخول بالرقم: حساب جديد، ثم دخول لنفس الحساب، وحذف بالرقم', async () => {
    const sms = fakeSms();
    await withServer({}, async app => {
        assert.equal((await request(app, 'GET', '/api/auth/config')).json.phone, true);
        const start = await request(app, 'POST', '/api/auth/phone/start', { headers: sameOrigin(app), body: { phone: '0770 123 4567' } });
        assert.equal(start.status, 200);
        assert.equal(start.json.masked, '0770 ••• 4567');
        assert.equal(start.json.code, undefined, 'الرمز ما يرجع بالرد أبداً');
        assert.doesNotMatch(start.text, new RegExp(sms.box.get('9647701234567')));
        // CSRF
        const evil = await request(app, 'POST', '/api/auth/phone/verify', { headers: { 'Content-Type': 'application/json', Origin: 'https://evil.example' }, body: { challenge: start.json.challenge, code: sms.box.get('9647701234567') } });
        assert.equal(evil.status, 403);
        const v = await request(app, 'POST', '/api/auth/phone/verify', { headers: sameOrigin(app), body: { challenge: start.json.challenge, code: sms.box.get('9647701234567') } });
        assert.equal(v.status, 201);
        assert.equal(v.json.created, true);
        assert.equal(v.json.user.phone, '9647701234567');
        assert.equal(v.json.user.email, '');
        assert.equal(v.json.user.plan, 'pro', 'الشهر المجاني للحساب الجديد');
        const cookie = cookieFrom(v);
        const me = await request(app, 'GET', '/api/auth/me', { headers: { Cookie: cookie } });
        assert.equal(me.json.user.phone, '9647701234567');

        // دخول ثاني لنفس الرقم = نفس الحساب
        await app.db.cmd(['DEL', app.db.key('otpwait', '9647701234567')]);
        const s2 = await request(app, 'POST', '/api/auth/phone/start', { headers: sameOrigin(app), body: { phone: '+9647701234567' } });
        const v2 = await request(app, 'POST', '/api/auth/phone/verify', { headers: sameOrigin(app), body: { challenge: s2.json.challenge, code: sms.box.get('9647701234567') } });
        assert.equal(v2.status, 200);
        assert.equal(v2.json.created, false);
        assert.equal(v2.json.user.id, v.json.user.id);

        // حساب الرقم ما يكدر يشيل رقمه (هو طريقة دخوله الوحيدة)
        const rm = await request(app, 'POST', '/api/account/phone/remove', { headers: authed(app, cookie), body: {} });
        assert.equal(rm.status, 400);
        // الحذف يتأكد بالرقم
        const bad = await request(app, 'POST', '/api/account/delete', { headers: authed(app, cookie), body: { confirm: '07709999999' } });
        assert.equal(bad.status, 400);
        const del = await request(app, 'POST', '/api/account/delete', { headers: authed(app, cookie), body: { confirm: '07701234567' } });
        assert.equal(del.status, 200);
        assert.equal(await app.db.cmd(['GET', app.db.key('phone', '9647701234567')]), null, 'الرقم يتحرر بعد الحذف');
    }, undefined, { sms });
});

test('ربط رقم بحساب بريد، ثم الدخول بيه، ومنع ربط نفس الرقم بحسابين', async () => {
    const sms = fakeSms();
    await withServer({}, async app => {
        const a = await registerUser(app, { email: 'phone-a@example.com' });
        const b = await registerUser(app, { email: 'phone-b@example.com' });
        // بدون حساب: ممنوع
        assert.equal((await request(app, 'POST', '/api/account/phone/start', { headers: sameOrigin(app), body: { phone: '07801234567' } })).status, 401);
        const s = await request(app, 'POST', '/api/account/phone/start', { headers: authed(app, a.cookie), body: { phone: '07801234567' } });
        assert.equal(s.status, 200);
        // تحدي حساب A ما ينفع لحساب B
        const steal = await request(app, 'POST', '/api/account/phone/verify', { headers: authed(app, b.cookie), body: { challenge: s.json.challenge, code: sms.box.get('9647801234567') } });
        assert.equal(steal.status, 400);
        const v = await request(app, 'POST', '/api/account/phone/verify', { headers: authed(app, a.cookie), body: { challenge: s.json.challenge, code: sms.box.get('9647801234567') } });
        assert.equal(v.status, 200);
        assert.equal(v.json.user.phone, '9647801234567');
        // B يحاول يربط نفس الرقم
        const taken = await request(app, 'POST', '/api/account/phone/start', { headers: authed(app, b.cookie), body: { phone: '07801234567' } });
        assert.equal(taken.status, 409);
        // الدخول بالرقم يفتح حساب A
        await app.db.cmd(['DEL', app.db.key('otpwait', '9647801234567')]);
        const ls = await request(app, 'POST', '/api/auth/phone/start', { headers: sameOrigin(app), body: { phone: '07801234567' } });
        const lv = await request(app, 'POST', '/api/auth/phone/verify', { headers: sameOrigin(app), body: { challenge: ls.json.challenge, code: sms.box.get('9647801234567') } });
        assert.equal(lv.json.user.email, 'phone-a@example.com');
        // إزالة الرقم من حساب البريد مسموحة
        const rm = await request(app, 'POST', '/api/account/phone/remove', { headers: authed(app, a.cookie), body: {} });
        assert.equal(rm.status, 200);
        assert.equal(rm.json.user.phone, '');
    }, undefined, { sms });
});

test('إيقاف الميزة من لوحة الإدارة، وإيقاف التسجيل يمنع حسابات الرقم الجديدة', async () => {
    const sms = fakeSms();
    await withServer({}, async app => {
        await app.settings.update({ features: { phoneLogin: false } });
        assert.equal((await request(app, 'GET', '/api/auth/config')).json.phone, false);
        assert.equal((await request(app, 'POST', '/api/auth/phone/start', { headers: sameOrigin(app), body: { phone: '07501234567' } })).status, 503);
        await app.settings.update({ features: { phoneLogin: true, registration: false } });
        const s = await request(app, 'POST', '/api/auth/phone/start', { headers: sameOrigin(app), body: { phone: '07501234567' } });
        const v = await request(app, 'POST', '/api/auth/phone/verify', { headers: sameOrigin(app), body: { challenge: s.json.challenge, code: sms.box.get('9647501234567') } });
        assert.equal(v.status, 403);
        assert.equal(v.json.code, 'registration_closed');
    }, undefined, { sms });
});

test('مدخلات خربانة ما توقع الخادم', async () => {
    await withServer({}, async app => {
        for (const p of ['/api/auth/phone/start', '/api/auth/phone/verify']) {
            for (const body of ['{}', '[]', 'null', '{"phone":{"$ne":1}}', '{"phone":"' + '7'.repeat(5000) + '"}', '{"challenge":["x"],"code":{}}', '{"challenge":"' + 'A'.repeat(32) + '","code":"123456"}']) {
                const r = await request(app, 'POST', p, { headers: sameOrigin(app), body });
                assert.ok(r.status < 500, `${p} ${body.slice(0, 30)} → ${r.status}`);
            }
        }
    }, undefined, { sms: fakeSms() });
});
