'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const totp = require('../server/totp');
const { parseAdmins } = require('../server/config');
const { maskIp, createStats } = require('../server/stats');
const { createRateLimiter, createFailureLimiter } = require('../server/rate-limit');
const { parseCookies, isSameOrigin } = require('../server/http');

// ---------------------------------------------------------------- TOTP

// قيم الاختبار الرسمية من RFC 6238 (السر: "12345678901234567890" بصيغة ASCII)
const RFC_SECRET = totp.base32Encode(Buffer.from('12345678901234567890'));

test('TOTP يطابق قيم RFC 6238 الرسمية', () => {
    assert.equal(RFC_SECRET, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
    const key = Buffer.from('12345678901234567890');
    assert.equal(totp.hotp(key, Math.floor(59 / 30), 8), '94287082');
    assert.equal(totp.hotp(key, Math.floor(1111111109 / 30), 8), '07081804');
    assert.equal(totp.hotp(key, Math.floor(1111111111 / 30), 8), '14050471');
    assert.equal(totp.hotp(key, Math.floor(1234567890 / 30), 8), '89005924');
    assert.equal(totp.totp(RFC_SECRET, 59_000, { digits: 6 }), '287082');
});

test('Base32 يرجع القيمة الأصلية، ويتجاهل المسافات وحالة الأحرف', () => {
    const secret = totp.generateSecret();
    assert.match(secret, /^[A-Z2-7]{32}$/);
    assert.deepEqual(totp.base32Decode(secret.toLowerCase().replace(/(.{4})/g, '$1 ')), totp.base32Decode(secret));
    assert.throws(() => totp.base32Decode('abc!'));
});

test('التحقق من الرمز: نافذة ±30 ثانية، ويرفض الأطوال والمحارف الخاطئة', () => {
    const now = 1_700_000_000_000;
    const good = totp.totp(RFC_SECRET, now);
    assert.ok(totp.verify(RFC_SECRET, good, { time: now }) >= 0);
    assert.ok(totp.verify(RFC_SECRET, good, { time: now + 30_000 }) >= 0);          // خطوة بعد
    assert.equal(totp.verify(RFC_SECRET, good, { time: now + 120_000 }), -1);       // خارج النافذة
    assert.equal(totp.verify(RFC_SECRET, '12345', { time: now }), -1);
    assert.equal(totp.verify(RFC_SECRET, 'abcdef', { time: now }), -1);
    assert.equal(totp.verify(RFC_SECRET, '', { time: now }), -1);
    assert.equal(totp.verify('not base32 !!', good, { time: now }), -1);
});

test('TOTP: نفس الرمز لا يُقبل مرتين (منع إعادة الاستخدام)', () => {
    const now = 1_700_000_000_000;
    const code = totp.totp(RFC_SECRET, now);
    const counter = totp.verify(RFC_SECRET, code, { time: now });
    assert.ok(counter >= 0);
    assert.equal(totp.verify(RFC_SECRET, code, { time: now, lastCounter: counter }), -1);
});

test('رابط otpauth صحيح', () => {
    const uri = totp.otpauthUri('ABC234', 'musab', 'Phishing Detector');
    assert.match(uri, /^otpauth:\/\/totp\/Phishing%20Detector:musab\?secret=ABC234&issuer=Phishing%20Detector/);
});

// ---------------------------------------------------------------- الإعدادات

test('parseAdmins يتجاهل الإدخالات التالفة', () => {
    const hash = 'a'.repeat(64);
    const admins = parseAdmins(`Musab:abcd:${hash}:SECRET2, bad, x:y:short, ali:salt:${hash}`);
    assert.deepEqual([...admins.keys()].sort(), ['ali', 'musab']);
    assert.equal(admins.get('musab').totpSecret, 'SECRET2');
    assert.equal(admins.get('ali').totpSecret, '');
    assert.equal(admins.get('musab').hash.length, 32);
    assert.equal(parseAdmins('').size, 0);
    assert.equal(parseAdmins(undefined).size, 0);
});

// ---------------------------------------------------------------- الإحصاءات

test('maskIp يخفي آخر جزء من العنوان', () => {
    assert.equal(maskIp('203.0.113.77'), '203.0.113.x');
    assert.equal(maskIp('::ffff:203.0.113.77'), '203.0.113.x');
    assert.match(maskIp('2001:db8:85a3:8d3:1319:8a2e:370:7348'), /^2001:db8:85a3:…$/);
    assert.equal(maskIp(''), '');
});

test('الإحصاءات تقبل فقط الأنواع والنتائج المعروفة وتنظّف النصوص', () => {
    const stats = createStats();
    assert.equal(stats.scan('url', 'danger'), true);
    assert.equal(stats.scan('url', 'DROP TABLE'), false);
    assert.equal(stats.scan('__proto__', 'safe'), false);
    assert.equal(stats.scan('constructor', 'safe'), false);
    stats.count('loginFailed');
    stats.count('toString');                      // عدّاد غير موجود: يُتجاهل
    stats.event('x‮', 'bad\u0000 text', '10.0.0.5');
    const snap = stats.snapshot();
    assert.equal(snap.scans.url.danger, 1);
    assert.equal(snap.counters.loginFailed, 1);
    assert.equal(snap.events[0].ip, '10.0.0.x');
    assert.ok(!/[\u0000‮]/.test(snap.events[0].type + snap.events[0].detail));
    for (let i = 0; i < 300; i++) stats.event('e', String(i), '1.1.1.1');
    assert.equal(stats.snapshot(500).events.length, 200);   // الحد الأقصى للسجل
});

// ---------------------------------------------------------------- محددات الطلبات

test('محدد الطلبات: حد لكل مفتاح وسقف عام ونافذة زمنية', () => {
    const limiter = createRateLimiter({ windowMs: 1000, max: 3, globalMax: 5 });
    const t = 1_000_000;
    assert.deepEqual([1, 2, 3, 4].map(() => limiter.take('a', t)), [true, true, true, false]);
    assert.equal(limiter.take('b', t), true);
    assert.equal(limiter.take('b', t), true);
    assert.equal(limiter.take('c', t), false);                 // السقف العام (5) انتهى
    assert.equal(limiter.take('a', t + 1500), true);           // نافذة جديدة
});

test('محدد الطلبات لا يكبر بلا حد', () => {
    const limiter = createRateLimiter({ windowMs: 60_000, max: 5, maxKeys: 100 });
    for (let i = 0; i < 1000; i++) limiter.take('ip-' + i);
    assert.ok(limiter.size() <= 100);
});

test('محدد الفشل: يحظر بعد الحد، ويفك الحظر بالنجاح أو بانتهاء المدة', () => {
    const limiter = createFailureLimiter({ windowMs: 1000, max: 3 });
    const t = 5_000_000;
    for (let i = 0; i < 3; i++) {
        assert.equal(limiter.isBlocked('ip', t), false);
        limiter.fail('ip', t);
    }
    assert.equal(limiter.isBlocked('ip', t), true);
    assert.ok(limiter.retryAfterSeconds('ip', t) >= 1);
    assert.equal(limiter.isBlocked('other', t), false);
    assert.equal(limiter.isBlocked('ip', t + 1500), false);    // انتهت المدة
    limiter.fail('ip', t + 2000); limiter.fail('ip', t + 2000); limiter.fail('ip', t + 2000);
    assert.equal(limiter.isBlocked('ip', t + 2000), true);
    limiter.clear('ip');
    assert.equal(limiter.isBlocked('ip', t + 2000), false);
});

// ---------------------------------------------------------------- أدوات HTTP

test('parseCookies', () => {
    assert.deepEqual(parseCookies('a=1; b=hello world; =bad; c'), { a: '1', b: 'hello world' });
    assert.deepEqual(parseCookies(''), {});
    assert.equal(parseCookies('sid=first; sid=second').sid, 'first');   // نأخذ أول قيمة
});

test('isSameOrigin يقارن Origin بعنوان الموقع', () => {
    const req = (headers) => ({ headers });
    assert.equal(isSameOrigin(req({ origin: 'https://site.example', host: 'site.example' })), true);
    assert.equal(isSameOrigin(req({ origin: 'https://evil.example', host: 'site.example' })), false);
    assert.equal(isSameOrigin(req({ origin: 'null', host: 'site.example' })), false);
    assert.equal(isSameOrigin(req({ origin: 'https://site.example.evil.com', host: 'site.example' })), false);
    assert.equal(isSameOrigin(req({ host: 'site.example', 'sec-fetch-site': 'cross-site' })), false);
    assert.equal(isSameOrigin(req({ host: 'site.example', 'sec-fetch-site': 'same-origin' })), true);
    assert.equal(isSameOrigin(req({ host: 'site.example' })), true);   // أدوات بلا متصفح (لا كوكيز عندها)
});
