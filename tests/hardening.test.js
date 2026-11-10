'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const engine = require('../public/js/detection-engine.js');
const { passwordProblem } = require('../server/users');

test('analyzeFile لا ينهار مع مدخلات غير سليمة', () => {
    for (const bad of [null, undefined, 5, 'x']) assert.equal(engine.analyzeFile(bad).error, 'invalid');
});

test('النصوص الضخمة لا تبطّئ الفحص (ReDoS)', () => {
    for (const text of ['a.'.repeat(50000), 'م'.repeat(100000), 'اضغط '.repeat(20000), 'x'.repeat(200000)]) {
        const start = Date.now();
        engine.analyzeText(text);
        assert.ok(Date.now() - start < 1000, 'slow input');
    }
});

test('احتيال الميراث 419 وطلب تفعيل الماكرو يُكتشفان', () => {
    const macro = engine.analyzeText('Invoice attached. Enable macros to view the content urgently');
    assert.notEqual(macro.level, 'safe');
    const scam = engine.analyzeText('Hello, I am Prince Abubakar. I need your help to transfer $25 million USD. You will get 30% share. Reply to my private email.');
    assert.notEqual(scam.level, 'safe');
});

test('التهنئة العادية ليست جائزة، والجائزة مع رابط تبقى خطرة', () => {
    assert.equal(engine.analyzeText('عيد مبارك وكل عام وانتم بخير').level, 'safe');
    assert.equal(engine.analyzeText('مبروك النجاح يا بطل').level, 'safe');
    assert.equal(engine.analyzeText('مبروك ربحت جايزه اضغط على الرابط').level, 'danger');
});

test('انتحال كورك يُكتشف', () => {
    assert.notEqual(engine.analyzeUrl('https://korek-prize.net/claim').level, 'safe');
});

test('ملفات scr و pif التنفيذية خطرة', () => {
    const head = new Uint8Array([0x4d, 0x5a, 0x90, 0, 3, 0, 0, 0]);
    for (const name of ['screen.scr', 'a.pif']) {
        const result = engine.analyzeFile({ name, size: 8, head, tail: new Uint8Array(0) });
        assert.equal(result.level, 'danger');
    }
});

test('كلمات السر الضعيفة (حتى مع رموز وأرقام) تُرفض والقوية تُقبل', () => {
    for (const weak of ['letmein1', '12345678910', 'p@ssw0rd', 'Password123!', 'Welcome2024', '98765432']) assert.ok(passwordProblem(weak, 'a@b.c'), weak);
    for (const good of ['a long safe passphrase', 'correct horse battery', 'xk29!Lmq83']) assert.equal(passwordProblem(good, 'a@b.c'), '', good);
});
