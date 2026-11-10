'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createVisitorCounter } = require('../server/visitors');

test('أدوات المراقبة والزواحف لا تُحسب كزوار', () => {
    const v = createVisitorCounter();
    for (const ua of ['Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)', 'Googlebot/2.1', 'curl/8.4.0', 'Render/1.0']) v.hit('9.9.9.9', ua);
    assert.equal(v.snapshot().viewsToday, 0);
    v.hit('1.1.1.1', 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile Safari/604.1');
    assert.equal(v.snapshot().viewsToday, 1);
    assert.equal(v.snapshot().uniqueToday, 1);
});
