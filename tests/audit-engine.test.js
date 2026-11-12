'use strict';

/*
  تدقيق شامل لدقة المحرك ومتانته (مئات الحالات، كل حالة اختبار مستقل):
  - روابط حقيقية شائعة (عالمية وعراقية) يجب أن تكون «آمنة» ⇠ يقيس الإنذارات الكاذبة
  - روابط احتيال مولّدة (أخطاء إملائية، أرقام بدل حروف، نطاقات فرعية مضللة، IP، Punycode...) يجب ألا تكون «آمنة»
  - رسائل احتيال ورسائل عادية
  - مدخلات عشوائية وخبيثة: لا استثناء، ولا بطء (يحمي الخادم من ReDoS)
*/

const test = require('node:test');
const assert = require('node:assert/strict');
const engine = require('../public/js/detection-engine.js');
const { analyzeHtml, isPublicIp } = require('../server/inspect');
const { normalizeEmail, passwordProblem, cleanName } = require('../server/users');
const { LEGIT: LEGIT_URLS, PHISH } = require('./fixtures/url-corpus');
const { SCAM, LEGIT: LEGIT_TEXT } = require('./fixtures/text-corpus');

const why = r => (r.reasons || []).filter(x => x.type !== 'info').map(x => x.text).join(' | ');

test('روابط حقيقية: لا إنذار كاذب', async t => {
    for (const url of LEGIT_URLS) {
        await t.test(url, () => {
            const r = engine.analyzeUrl(url);
            assert.equal(r.error, undefined);
            assert.equal(r.level, 'safe', `${r.score}% ${why(r)}`);
        });
    }
});

test('روابط احتيال: لا تمر كآمنة', async t => {
    for (const url of PHISH) {
        await t.test(url, () => {
            const r = engine.analyzeUrl(url);
            assert.notEqual(r.level, 'safe', `${url} scored ${r.score}`);
        });
    }
});

// الوضع المشدد (الأكاديمي والحكومي) يطلب التحقق من النطاقات الرسمية غير المدرجة ومن منصات المحتوى العام (Google Docs)،
// فيعطيها «تنبيه» عن قصد، لكن لا يتهم أي موقع حقيقي بأنه «خطر»
test('الوضع المشدد يبقى يكشف الاحتيال ولا يتهم المواقع الحقيقية بالخطر', async t => {
    for (const url of PHISH.slice(0, 60)) await t.test('phish ' + url, () => assert.notEqual(engine.analyzeUrl(url, { strict: true }).level, 'safe'));
    for (const url of LEGIT_URLS) {
        await t.test('legit ' + url, () => assert.notEqual(engine.analyzeUrl(url, { strict: true }).level, 'danger'));
    }
});

test('رسائل احتيال: تُكشف', async t => {
    for (const msg of SCAM) await t.test(msg.slice(0, 60), () => {
        const r = engine.analyzeText(msg);
        assert.notEqual(r.level, 'safe', `${r.score}%`);
    });
});

test('رسائل عادية: لا تُتهم (رمز تحقق حقيقي، إشعار راتب، رسائل يومية)', async t => {
    for (const msg of LEGIT_TEXT) await t.test(msg.slice(0, 60), () => {
        const r = engine.analyzeText(msg);
        assert.equal(r.level, 'safe', `${r.score}% ${why(r)}`);
    });
});

test('انتحال على الاستضافة المجانية يبقى خطراً رغم تخفيف وزن الشرطات', () => {
    assert.equal(engine.analyzeUrl('https://paypal-login-secure.netlify.app').level, 'danger');
    assert.equal(engine.analyzeUrl('https://ali-hassan-portfolio.netlify.app').level, 'safe');
});

// ------------------------------------------------------------ المتانة
let seed = 7;
const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
const ALPH = 'aA0.-_/:?#@%&=+~ \t\n\u0000​‮ءابتعكلمنوي١٢٣😀ЀаοxnN-<>"\'\\[]{}()*$!';
const randomString = n => Array.from({ length: n }, () => ALPH[Math.floor(rnd() * ALPH.length)]).join('');

const ADVERSARIAL = [
    'a'.repeat(100000), 'http://' + 'a.'.repeat(30000) + 'com', 'https://' + '-'.repeat(50000) + '.com', 'https://x.com/' + '%'.repeat(60000),
    '"' + 'A'.repeat(500000) + '"', 'á'.repeat(80000), 'كلمه '.repeat(20000), 'رمز '.repeat(15000) + 'تحقق', 'http://a.com '.repeat(5000),
    '​'.repeat(80000), 'https://%E0@a.com/', 'شوف https://%E0%A4@a.com/x هسه', 'https://a.com/%E0%A4%A', 'xn--' + 'a'.repeat(5000) + '.com'
];
const HTML_ATTACKS = ['<!--'.repeat(80000), '<script '.repeat(40000), '<style>'.repeat(40000), '<svg'.repeat(70000), '<input type=password '.repeat(20000),
    '<form '.repeat(20000), '<'.repeat(300000), '<title>' + 'x'.repeat(200000), '<meta http-equiv=refresh content="0;url=' + 'a'.repeat(100000), '"' + 'A'.repeat(600000) + '"'];

function timed(fn) {
    const start = process.hrtime.bigint();
    fn();
    return Number(process.hrtime.bigint() - start) / 1e6;
}

test('مدخلات عشوائية: لا استثناءات بأي خوارزمية', async t => {
    const fns = {
        analyzeUrl: s => engine.analyzeUrl(s), analyzeText: s => engine.analyzeText(s), extractUrls: s => engine.extractUrls(s),
        analyzeHtml: s => analyzeHtml(s, new URL('https://a.example/')), isPublicIp: s => isPublicIp(s),
        normalizeEmail: s => normalizeEmail(s), passwordProblem: s => passwordProblem(s, 'a@b.com'), cleanName: s => cleanName(s)
    };
    const inputs = Array.from({ length: 300 }, () => randomString(1 + Math.floor(rnd() * 300)));
    for (const [name, fn] of Object.entries(fns)) {
        await t.test(name, () => { for (const s of inputs) assert.doesNotThrow(() => fn(s), JSON.stringify(s.slice(0, 40))); });
    }
});

test('مدخلات خبيثة طويلة: لا استثناء ولا بطء (حماية من ReDoS)', async t => {
    for (const s of ADVERSARIAL) {
        await t.test(`url/text len=${s.length} ${JSON.stringify(s.slice(0, 20))}`, () => {
            assert.ok(timed(() => engine.analyzeUrl(s)) < 1500);
            assert.ok(timed(() => engine.analyzeText(s)) < 1500);
        });
    }
    for (const html of HTML_ATTACKS) {
        await t.test(`html len=${html.length} ${JSON.stringify(html.slice(0, 16))}`, () => {
            assert.ok(timed(() => analyzeHtml(html, new URL('https://a.example/'))) < 1000);
        });
    }
});

test('الرابط بترميز % تالف داخل رسالة لا يكسر فحص الرسالة', () => {
    assert.doesNotThrow(() => engine.analyzeUrl('https://%E0@a.com/'));
    const r = engine.analyzeText('شوف https://%E0%A4@a.com/login هسه');
    assert.ok(typeof r.score === 'number');
});

test('استخراج النص من HTML بمرور خطي يبقى صحيحاً', () => {
    const r = analyzeHtml('<title>T</title><style>.a{}</style><script>var x="<b>"</script><!-- c --><p>Hello <b>world</b></p><svg><text>no</text></svg><scripty>keep</scripty>', new URL('https://a.example/'));
    assert.equal(r.excerpt, 'Hello world keep');
});

test('تقليد اسم موقعنا نفسه = خطر، والموقع الحقيقي آمن', async t => {
    engine.setSiteHosts(['phishing-detector-x1-iq.onrender.com']);
    try {
        for (const url of ['https://evil-phishing-detector-x1-iq.onrender.com', 'https://phishing-detect0r-x1-iq.onrender.com', 'https://phishing-detector-x1-iq.onrender.com.evil.com/login']) {
            await t.test(url, () => assert.equal(engine.analyzeUrl(url).level, 'danger'));
        }
        await t.test('الموقع الحقيقي', () => assert.equal(engine.analyzeUrl('https://phishing-detector-x1-iq.onrender.com/admin').level, 'safe'));
        await t.test('موقع آخر عادي على نفس الاستضافة', () => assert.equal(engine.analyzeUrl('https://my-shop.onrender.com').level, 'safe'));
    } finally {
        engine.setSiteHosts([]);
    }
});
