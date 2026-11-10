'use strict';
/* حالات العرض: ما يُتوقع أن يجربه أي زائر أو مسؤول أمامه */
const test = require('node:test');
const assert = require('node:assert/strict');
const e = require('../public/js/detection-engine.js');

const SAFE_URLS = ['https://google.com', 'https://www.facebook.com', 'https://moi.gov.iq', 'https://tu.edu.iq', 'https://www.rafidain-bank.gov.iq', 'https://rasheedbank.gov.iq', 'https://fib.iq', 'https://zaincash.iq', 'https://github.com/login', 'https://accounts.google.com/signin'];
const BAD_URLS = ['http://paypa1-account-verify.xyz/login', 'https://faceb00k-security.com/login', 'https://zaincash-iq.com/wallet/update', 'http://rafidain-update.top', 'https://rasheedbank-iq.com/login', 'https://fib-iq.app/verify', 'https://qicard-iq.net/activate', 'https://www.paypal.com.verify-account.info', 'https://xn--pple-43d.com', 'https://login.microsoftonline.com.secure-auth.ru/'];

test('روابط رسمية معروفة: آمنة', () => {
    for (const u of SAFE_URLS) assert.equal(e.analyzeUrl(u).level, 'safe', u);
});

test('روابط تصيد شائعة (ومنها المصارف العراقية): خطر', () => {
    for (const u of BAD_URLS) assert.equal(e.analyzeUrl(u).level, 'danger', u);
});

test('رسالة رمز تحقق حقيقية ليست احتيالاً، وطلب إرسال الرمز احتيال', () => {
    assert.equal(e.analyzeText('رمز التحقق الخاص بك هو 482913 لا تشاركه مع أحد').level, 'safe');
    assert.equal(e.analyzeText('Your verification code is 552910. Do not share it with anyone.').level, 'safe');
    assert.equal(e.analyzeText('ارسلي رمز التحقق 482913 ولا تشاركه مع احد غيري').level, 'danger');
    assert.equal(e.analyzeText('اخي دزلي الكود اللي وصلك برسالة غلط وصلك').level, 'danger');
    assert.equal(e.analyzeText('رمز التحقق 1234 لا تشاركه، اضغط الرابط http://x-verify.top').level, 'danger');
});

test('رسائل احتيال وعادية', () => {
    assert.equal(e.analyzeText('تهانينا! لقد تم اختيار رقمك للفوز بسيارة. اتصل بنا لاستلام الجائزة').level, 'danger');
    assert.equal(e.analyzeText('تم قبولك في التعيين يرجى دفع 50 الف رسوم تسجيل عبر زين كاش').level, 'danger');
    assert.equal(e.analyzeText('هلا حبيبي شلونك اليوم نتلاقى بالكلية؟').level, 'safe');
    assert.equal(e.analyzeText('موعد استلام الشهادات يوم الاحد').level, 'safe');
    assert.equal(e.analyzeText('اجتماع القسم غداً الساعة 10 صباحاً في القاعة 3').level, 'safe');
});
