'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createMemoryDb } = require('../server/db');
const { createStats } = require('../server/stats');
const { createVisitorCounter } = require('../server/visitors');

function makeDb() {
    const db = createMemoryDb();
    db.prefix = 'pd';
    db.key = (...parts) => ['pd', ...parts].join(':');
    return db;
}

test('الإحصاءات تبقى بعد إعادة التشغيل (نسخة جديدة على نفس القاعدة)', async () => {
    const db = makeDb();
    const a = createStats();
    assert.equal((await a.attach(db, { intervalMs: 0 })).ok, true);
    a.count('registrations'); a.count('registrations'); a.count('bulkScans');
    a.scan('url', 'danger'); a.scan('file', 'safe');
    a.event('login_ok', 'دخول', '10.0.0.5');
    await a.close();

    const b = createStats();
    await b.attach(db, { intervalMs: 0 });
    b.count('registrations');
    const snap = b.snapshot();
    assert.equal(snap.counters.registrations, 3);
    assert.equal(snap.counters.bulkScans, 1);
    assert.equal(snap.scans.url.danger, 1);
    assert.equal(snap.scans.file.safe, 1);
    assert.equal(snap.events[0].type, 'login_ok');
    assert.equal(snap.events[0].ip, '10.0.0.x');
    await b.close();

    const c = createStats();
    await c.attach(db, { intervalMs: 0 });
    assert.equal(c.snapshot().counters.registrations, 3);   // لا عدّ مزدوج
    assert.equal(c.snapshot().scans.url.danger, 1);
    await c.close();
});

test('نسختان تعملان معاً أثناء النشر: الفروقات تُجمع ولا تُكتب فوق بعضها', async () => {
    const db = makeDb();
    const oldApp = createStats(); await oldApp.attach(db, { intervalMs: 0 });
    const newApp = createStats(); await newApp.attach(db, { intervalMs: 0 });
    oldApp.count('userLogins'); oldApp.count('userLogins');
    newApp.count('userLogins');
    await oldApp.close(); await newApp.close();
    const check = createStats(); await check.attach(db, { intervalMs: 0 });
    assert.equal(check.snapshot().counters.userLogins, 3);
});

test('سجل الأحداث المحفوظ لا يتجاوز 200 ويبقى الأحدث', async () => {
    const db = makeDb();
    const a = createStats(); await a.attach(db, { intervalMs: 0 });
    for (let i = 0; i < 260; i++) a.event('e', 'n' + i, '1.1.1.1');
    await a.close();
    const b = createStats(); await b.attach(db, { intervalMs: 0 });
    const events = b.snapshot(500).events;
    assert.equal(events.length, 200);
    assert.equal(events[0].detail, 'n259');
});

test('فشل القاعدة لا يفقد العدّ: يُعاد حفظه لاحقاً', async () => {
    const db = makeDb();
    const a = createStats(); await a.attach(db, { intervalMs: 0 });
    const realPipe = db.pipe;
    db.pipe = async () => { throw new Error('down'); };
    a.count('chatOk'); a.count('chatOk');
    assert.equal(await a.flush(), false);
    db.pipe = realPipe;
    a.count('chatOk');
    assert.equal(await a.flush(), true);
    const b = createStats(); await b.attach(db, { intervalMs: 0 });
    assert.equal(b.snapshot().counters.chatOk, 3);
});

test('عدّاد الزوار يبقى بعد إعادة التشغيل ولا يعدّ نفس الزائر مرتين في اليوم', async () => {
    const db = makeDb();
    const t = Date.UTC(2026, 10, 10, 12, 0, 0);
    const a = createVisitorCounter(); await a.attach(db, { intervalMs: 0, now: t });
    a.hit('203.0.113.5', 'Chrome', t); a.hit('203.0.113.6', 'Chrome', t + 10);
    await a.close();

    const b = createVisitorCounter(); await b.attach(db, { intervalMs: 0, now: t });
    b.hit('203.0.113.5', 'Chrome', t + 1000);       // نفس الزائر بعد النشر
    b.hit('203.0.113.7', 'Chrome', t + 2000);       // زائر جديد
    const snap = b.snapshot(t + 3000);
    assert.equal(snap.uniqueToday, 3);
    assert.equal(snap.viewsToday, 4);
    assert.equal(snap.totalViews, 4);
    assert.ok(!JSON.stringify(snap).includes('203.0.113'));
    await b.close();

    const c = createVisitorCounter(); await c.attach(db, { intervalMs: 0, now: t });
    assert.equal(c.snapshot(t + 5000).uniqueToday, 3);
    assert.equal(c.snapshot(t + 5000).totalViews, 4);
    // المخزَّن في القاعدة بصمات مجزّأة فقط
    const dump = JSON.stringify([...db._data.entries()].map(([k, v]) => [k, v.value instanceof Map ? [...v.value] : v.value instanceof Set ? [...v.value] : v.value]));
    assert.ok(!dump.includes('203.0.113'));
});

test('بدون attach (تشغيل محلي) تعمل الإحصاءات بالذاكرة كما كانت', async () => {
    const s = createStats();
    s.count('requests');
    assert.equal(s.snapshot().counters.requests, 1);
    assert.equal(await s.flush(), false);
    await s.close();
});
