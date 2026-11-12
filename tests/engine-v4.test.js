'use strict';
// اختبارات محرك v4: مقاومة التمويه، عدم تطابق الهوية، بريد الضحية بالرابط، وقابلية التفسير
const test = require('node:test');
const assert = require('node:assert/strict');
const E = require('../public/js/detection-engine.js');

test('كل نتيجة تحمل مؤشرات قابلة للقراءة آلياً ودرجة ثقة ورقم إصدار', () => {
    const r = E.analyzeUrl('https://paypa1-login.xyz/verify');
    assert.equal(r.engineVersion, E.ENGINE_VERSION);
    assert.ok(['low', 'medium', 'high'].includes(r.confidence));
    assert.ok(r.indicators.length >= 2);
    for (const i of r.indicators) {
        assert.ok(i.weight > 0 && i.weight <= 100);
        assert.ok(i.impact >= 0 && i.impact <= r.score);
        assert.equal(typeof i.text, 'string');
    }
    assert.deepEqual(E.analyzeUrl('https://facebook.com').indicators, []);
});

test('مساهمة المؤشرات (leave-one-out) تطابق noisy-OR', () => {
    const impact = E.contributions([{ weight: 0.5 }, { weight: 0.5 }, { weight: 0 }]);
    // بالاثنين: 75%، بواحد: 50% ⇒ مساهمة كل واحد 25 نقطة، والمعلوماتي صفر
    assert.deepEqual(impact, [25, 25, 0]);
});

test('درجة الثقة: عالية بعيداً عن العتبات، ومنخفضة قربها', () => {
    assert.equal(E.confidenceFor(95, E.THRESHOLDS, 4), 'high');
    assert.equal(E.confidenceFor(0, E.THRESHOLDS, 0), 'high');
    assert.equal(E.confidenceFor(53, E.THRESHOLDS, 2), 'low');
    assert.equal(E.confidenceFor(40, E.THRESHOLDS, 2), 'medium');
});

test('كشف الحروف الكيريلية المدسوسة بالكلمات الإنجليزية', () => {
    assert.deepEqual(E.mixedScriptWords('Your PаyPаl account'), ['PаyPаl']);
    assert.deepEqual(E.mixedScriptWords('Normal English text and نص عربي'), []);
    const r = E.analyzeText('Your PаyPаl account is locked. Verify now: https://secure-check-center.com/login');
    assert.equal(r.level, 'danger');
    assert.ok(r.categories.includes('obfuscation'));
    // بعد فك التمويه يتعرف المحرك على التهديد نفسه
    assert.ok(r.categories.includes('threat'));
});

test('المحارف الخفية داخل الكلمات تُكشف وتُزال قبل التحليل', () => {
    const r = E.analyzeText('pay​pal ac​count sus​pended, click here http://a.com');
    assert.equal(r.level, 'danger');
    assert.ok(r.categories.includes('obfuscation'));
    assert.ok(r.categories.includes('threat'), 'التهديد يُكتشف بعد إزالة المحارف الخفية');
    // ZWJ في الإيموجي و LRM/RLM بالنص المختلط ليست تمويهاً
    const benign = E.analyzeText('عائلتي 👨‍👩‍👧 بخير، والاجتماع ‏بكرة‎ الساعة 10');
    assert.equal(benign.level, 'safe');
});

test('رسالة باسم جهة معروفة ورابطها لنطاق غريب', () => {
    const ar = E.analyzeText('تنبيه من مصرف الرافدين: حدث بياناتك عبر الرابط https://update-center.top/x');
    assert.equal(ar.level, 'danger');
    assert.ok(ar.categories.includes('brand_mismatch'));
    const en = E.analyzeText('Netflix: your payment failed, update your details at https://billing-help-desk.com');
    assert.ok(en.categories.includes('brand_mismatch'));
    assert.equal(en.level, 'danger');
});

test('ذكر جهة مع رابطها الرسمي أو رابط جهة رسمية أخرى ليس عدم تطابق', () => {
    const yt = E.analyzeText('شوف هذا الفيديو على يوتيوب https://youtube.com/watch?v=1');
    assert.ok(!yt.categories.includes('brand_mismatch'));
    assert.equal(yt.level, 'safe');
    const wa = E.analyzeText('تابع صفحتنا على فيسبوك أو راسلنا https://wa.me/9647700000000');
    assert.ok(!wa.categories.includes('brand_mismatch'));
});

test('بريد الضحية داخل الرابط (عادي أو Base64)', () => {
    const plain = E.analyzeUrl('https://office-docs-share.com/auth/?email=ali@company.iq');
    assert.ok(plain.reasons.some(r => /بريداً إلكترونياً/.test(r.text)));
    assert.notEqual(plain.level, 'safe');
    const b64 = E.analyzeUrl('https://xyz-portal.com/index.html#' + Buffer.from('ali@company.iq').toString('base64'));
    assert.ok(b64.reasons.some(r => /Base64/.test(r.text)));
    // الروابط الرسمية لا تتأثر، ونص Base64 عشوائي ليس بريداً
    assert.equal(E.analyzeUrl('https://accounts.google.com/signin?email=ali@gmail.com').level, 'safe');
    assert.equal(E.analyzeUrl('https://example.com/?token=dGhpcyBpcyBub3QgYW4gZW1haWw').level, 'safe');
});
