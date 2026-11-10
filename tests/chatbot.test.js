'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { offlineReply } = require('../server/chat');
const { pickTopics } = require('../server/chat-topics');
const engine = require('../public/js/detection-engine.js');

const topic = q => pickTopics(engine.normalizeArabic(q)).map(t => t.id);

test('CyberBot يفهم أسئلة بلهجة عراقية ويختار الموضوع الصحيح', () => {
    const cases = [
        ['حسابي بالفيسبوك انهكر شسوي', 'hacked'], ['واحد يكلي دزلي الكود اللي وصلك', 'otp'], ['كالولي ربحت جايزة ايفون', 'prize'],
        ['شغل من البيت بدون خبرة صادق؟', 'jobs'], ['شلون اسوي باسورد قوي', 'password'], ['واحد يهددني بصوري', 'blackmail'],
        ['اتصال من رقم مجهول يكول انا من البنك', 'remote'], ['ملفاتي انقفلت وطالبين بتكوين', 'ransomware'], ['شلون اعرف اذا بياناتي تسربت', 'breach'],
        ['شنو الفرق بين التصيد والتصيد الموجه', 'spear'], ['القفل الاخضر يعني الموقع آمن؟', 'https'], ['رسالة من اسياسيل', 'telecom'],
        ['شكد الاشتراك', 'pro'], ['هل ملفي ينرفع للسيرفر', 'privacy'], ['ولدي يلعب فري فاير ويطلب جواهر', 'kids'], ['ادخل بنكي من المطعم', 'wifi']
    ];
    for (const [q, want] of cases) assert.ok(topic(q).includes(want), `${q} -> ${topic(q)}`);
});

test('CyberBot ما يقول "ما فهمت" أبداً ويعطي رداً مفيداً لأي مدخل', () => {
    const inputs = ['شنو رايك بالطقس', 'لوووووول', '12345', '؟', 'ممكن تساعدني', 'صار شي غريب بحسابي', 'asdkjh qwe', 'خايف من رسالة جاتني', 'x'.repeat(500)];
    for (const q of inputs) {
        const reply = offlineReply(q, [], 'مصعب');
        assert.ok(reply.length > 40, q);
        assert.ok(!/ما فهمت/.test(reply), q);
        assert.ok(!reply.includes('{name}'), q);
    }
});

test('رسالة احتيال طويلة تُحلَّل، ورسالة الواتساب مع اختراق تعرض الموضوعين', () => {
    assert.match(offlineReply('وصلتني رسالة: حسابك سيتم ايقافه خلال 24 ساعة اضغط هنا وارسل رمز التحقق فورا', [], 'x'), /حلّلت النص/);
    assert.ok(topic('حسابي بالانستغرام انسرق').includes('hacked'));
});

test('المتابعة القصيرة ترجع لآخر موضوع بالمحادثة', () => {
    const history = [{ role: 'user', content: 'واحد يهددني بصوري' }, { role: 'assistant', content: 'ok' }];
    assert.match(offlineReply('وبعدين شسوي', [], 'x', history), /الابتزاز/);
    assert.ok(!/ما فهمت/.test(offlineReply('وبعدين شسوي', [], 'x', [])));
});

test('مواضيع عراقية: منح، مخالفات، امتحانات، علاقات، تبرعات، بلاغات', () => {
    const cases = [['سلفة بدون كفيل', 'grant'], ['رسالة مخالفة مرورية', 'gov'], ['اسئلة الوزاري مسربة', 'exam'], ['تعرفت على بنت من النت تريد فلوس', 'romance'],
        ['حملة تبرع مشبوهة', 'charity'], ['وين اشتكي على النصاب', 'report'], ['شنو افضل vpn', 'vpn'], ['لكيت فلاشة بالشارع', 'usb']];
    for (const [q, want] of cases) assert.ok(pickTopics(engine.normalizeArabic(q)).some(t => t.id === want), q);
    assert.ok(!pickTopics(engine.normalizeArabic('شكرا حبيبي')).some(t => t.id === 'romance'));
});

test('أسئلة بالإنجليزية تُفهم أيضاً، والرد بالعربي مع سطر توضيحي', () => {
    for (const [q, want] of [['my account got hacked what do i do', 'hacked'], ['what is two factor authentication', 'twofa'], ['someone is blackmailing me with photos', 'blackmail'], ['how to report cyber crime', 'report']]) {
        assert.ok(pickTopics(engine.normalizeArabic(q)).some(t => t.id === want), q);
    }
    assert.match(offlineReply('what is ransomware', [], 'x'), /I answer in Arabic/);
});

test('معالجة نصوص ضخمة بالبوت سريعة', () => {
    const start = Date.now();
    offlineReply('اضغط على '.repeat(3000), [], 'x');
    offlineReply('م '.repeat(15000), [], 'x');
    assert.ok(Date.now() - start < 1500);
});

test('الموجّه (قواعد + مصنّف أمثلة) يفهم صياغات جديدة ولا يجيب على الخارج عن الاختصاص كأنه أمني', () => {
    const { route } = require('../server/chat-router');
    const ok = [['شخص يطلب رقم يوصلني برسالة', 'otp'], ['ملفاتي مشفرة ويطلبون فدية', 'ransomware'], ['مرفق ورد يطلب تشغيل الماكرو', 'files'], ['اكو فرق بين الرسالة النصية وتطبيق المصادقة', 'twofa']];
    for (const [q, want] of ok) assert.ok(route(q).topics.some(t => t.id === want), q);
    for (const q of ['شنو رايك بالطقس', 'احتاج وصفة كبة', 'تمام', 'شنو اسم عاصمة فرنسا']) assert.equal(route(q).topics.length, 0, q);
});
