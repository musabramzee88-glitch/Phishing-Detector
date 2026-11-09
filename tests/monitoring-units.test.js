'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createStats } = require('../server/stats');
const { createVisitorCounter } = require('../server/visitors');
const { createHealthMonitor } = require('../server/health');

test('عدّاد الزوار: فريدون لكل يوم، ولا يخزّن العنوان ولا المتصفح', () => {
    const counter = createVisitorCounter();
    const t = Date.UTC(2026, 10, 9, 12, 0, 0);
    counter.hit('203.0.113.5', 'Chrome', t);
    counter.hit('203.0.113.5', 'Chrome', t + 1000);       // نفس الزائر
    counter.hit('203.0.113.6', 'Chrome', t + 2000);
    counter.hit('203.0.113.5', 'Firefox', t + 3000);      // متصفح آخر = بصمة أخرى
    const snap = counter.snapshot(t + 4000);
    assert.equal(snap.uniqueToday, 3);
    assert.equal(snap.viewsToday, 4);
    assert.equal(snap.activeNow, 3);
    assert.equal(snap.series.length, 7);
    assert.equal(snap.series[6].unique, 3);
    assert.ok(!JSON.stringify(snap).includes('203.0.113'), 'raw IP leaked');
    // بعد 6 دقائق لا يوجد نشطون، وبيوم جديد يبدأ العدّ من الصفر
    assert.equal(counter.snapshot(t + 6 * 60_000).activeNow, 0);
    const nextDay = t + 24 * 3600_000;
    counter.hit('203.0.113.5', 'Chrome', nextDay);
    assert.equal(counter.snapshot(nextDay).uniqueToday, 1);
    assert.equal(counter.snapshot(nextDay).series[5].unique, 3);
});

test('عدّاد الزوار يحسب أعداداً كبيرة بدقة', () => {
    const counter = createVisitorCounter();
    const t = Date.now();
    for (let i = 0; i < 1500; i++) counter.hit('10.0.' + (i >> 8) + '.' + (i & 255), 'x', t);
    assert.equal(counter.snapshot(t).uniqueToday, 1500);
});

test('مراقب الصحة: سليم، متدهور بسبب أخطاء الزوار، وحرج فقط بعد عينات متتالية', async () => {
    const ok = createHealthMonitor({ sampleMs: 20 });
    assert.equal(ok.evaluate(0).status, 'ok');
    const degraded = ok.evaluate(25);
    assert.equal(degraded.status, 'degraded');
    assert.match(degraded.reasons.join(' '), /أخطاء كثيرة/);
    ok.stop();

    const strict = createHealthMonitor({ criticalRssMb: 1, degradedRssMb: 1, sampleMs: 20, criticalSamples: 3 });
    assert.notEqual(strict.evaluate(0).status, 'critical');      // عينة واحدة لا تكفي
    await new Promise(resolve => setTimeout(resolve, 200));
    assert.equal(strict.evaluate(0).status, 'critical');
    strict.stop();
});

test('stats.recent يعدّ أحداث النوع بنافذة زمنية، وسجل التدقيق الخارجي لا يعطّل شيئاً', () => {
    const audited = [];
    const stats = createStats({ audit: entry => audited.push(entry) });
    stats.event('client_error', 'a', '1.2.3.4');
    stats.event('client_error', 'b', '1.2.3.4');
    stats.event('login_ok', 'c', '1.2.3.4');
    assert.equal(stats.recent('client_error', 60_000), 2);
    assert.equal(stats.recent('client_error', 60_000, Date.now() + 120_000), 0);
    assert.equal(audited.length, 3);
    assert.equal(audited[0].ip, '1.2.3.x');
    const broken = createStats({ audit: () => { throw new Error('disk full'); } });
    assert.doesNotThrow(() => broken.event('x', 'y', ''));
});
