'use strict';
// الضغط والتخزين، صفحات الخصوصية/الشروط/404، robots و sitemap، وقراءة عنوان الزائر
const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('node:zlib');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { request, withServer } = require('./helpers');
const { loadConfig } = require('../server/config');
const { getClientIp } = require('../server/http');

const loadConfigFor = env => loadConfig({ HOST: '127.0.0.1', ...env });

// طلب يرجع البايتات الخام (للتحقق من الضغط)
function rawGet(app, path, headers = {}) {
    return new Promise((resolve, reject) => {
        http.get({ host: '127.0.0.1', port: app.base.port, path, headers }, res => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
        }).on('error', reject);
    });
}

test('ملفات CSS/JS تُضغط بـ Brotli أو gzip وتطابق الأصل', () => withServer({}, async app => {
    const plain = await rawGet(app, '/js/app.js');
    const br = await rawGet(app, '/js/app.js', { 'Accept-Encoding': 'br, gzip' });
    const gz = await rawGet(app, '/js/app.js', { 'Accept-Encoding': 'gzip' });
    assert.equal(br.headers['content-encoding'], 'br');
    assert.equal(gz.headers['content-encoding'], 'gzip');
    assert.equal(plain.headers['content-encoding'], undefined);
    assert.ok(br.body.length < plain.body.length / 2, 'الضغط يقلل الحجم للنصف على الأقل');
    assert.deepEqual(zlib.brotliDecompressSync(br.body), plain.body);
    assert.deepEqual(zlib.gunzipSync(gz.body), plain.body);
    assert.equal(br.headers.vary, 'Accept-Encoding');
}));

test('ETag يرجع 304، والملفات برقم نسخة تُخزَّن سنة', () => withServer({}, async app => {
    const first = await rawGet(app, '/css/style.css');
    assert.ok(first.headers.etag);
    assert.match(first.headers['cache-control'], /max-age=86400/);
    const again = await rawGet(app, '/css/style.css', { 'If-None-Match': first.headers.etag });
    assert.equal(again.status, 304);
    assert.equal(again.body.length, 0);
    const versioned = await rawGet(app, '/css/style.css?v=4.0.0');
    assert.match(versioned.headers['cache-control'], /max-age=31536000, immutable/);
    const img = await rawGet(app, '/img/logo-256.jpg');
    assert.equal(img.headers['content-type'], 'image/jpeg');
    assert.equal((await rawGet(app, '/img/logo-256.jpg', { 'If-None-Match': img.headers.etag })).status, 304);
}));

test('صفحة الدخول تُضغط وروابطها المطلقة تحمل عنوان الموقع', () => withServer({ APP_URL: 'http://localhost:8080' }, async app => {
    const br = await rawGet(app, '/login', { 'Accept-Encoding': 'br' });
    assert.equal(br.headers['content-encoding'], 'br');
    const html = zlib.brotliDecompressSync(br.body).toString('utf8');
    assert.ok(!html.includes('%APP_URL%'));
    assert.match(html, /og:image" content="http:\/\/localhost:8080\/img\/icon-512\.png"/);
    assert.match(html, /href="\/privacy"/);
}));

test('صفحات الخصوصية والشروط بروابط قصيرة، و404 مفهومة للمتصفح', () => withServer({}, async app => {
    for (const p of ['/privacy', '/terms', '/privacy.html']) {
        const res = await request(app, 'GET', p);
        assert.equal(res.status, 200, p);
        assert.match(res.headers['content-type'], /text\/html/);
    }
    const browser = await request(app, 'GET', '/no-such-page', { headers: { Accept: 'text/html,application/xhtml+xml' } });
    assert.equal(browser.status, 404);
    assert.match(browser.text, /الصفحة غير موجودة/);
    const apiClient = await request(app, 'GET', '/no-such-page');
    assert.equal(apiClient.status, 404);
    assert.deepEqual(apiClient.json, { error: 'Not found' });
    assert.equal((await request(app, 'GET', '/favicon.ico')).status, 200);
}));

test('robots.txt و sitemap.xml مبنية من عنوان الموقع', () => withServer({ APP_URL: 'http://localhost:8080' }, async app => {
    const robots = await request(app, 'GET', '/robots.txt');
    assert.match(robots.text, /Disallow: \/admin/);
    assert.match(robots.text, /Sitemap: http:\/\/localhost:8080\/sitemap\.xml/);
    const sitemap = await request(app, 'GET', '/sitemap.xml');
    assert.match(sitemap.headers['content-type'], /xml/);
    assert.match(sitemap.text, /<loc>http:\/\/localhost:8080\/privacy<\/loc>/);
}));

test('عنوان الزائر: الترويسة المضبوطة فقط، والقيم غير الصالحة تُتجاهل', () => {
    const req = (headers, remoteAddress = '10.0.0.1') => ({ headers, socket: { remoteAddress } });
    const behind = loadConfigFor({ TRUST_PROXY: '1' });
    assert.equal(getClientIp(req({ 'true-client-ip': '203.0.113.7' }), behind), '203.0.113.7');
    assert.equal(getClientIp(req({ 'true-client-ip': '<script>' }), behind), '10.0.0.1');
    const cf = loadConfigFor({ TRUST_PROXY: '1', CLIENT_IP_HEADER: 'CF-Connecting-IP' });
    assert.equal(getClientIp(req({ 'true-client-ip': '9.9.9.9', 'cf-connecting-ip': '198.51.100.4' }), cf), '198.51.100.4');
    // بدون وسيط موثوق لا نصدّق أي ترويسة
    const direct = loadConfigFor({ TRUST_PROXY: '0' });
    assert.equal(getClientIp(req({ 'true-client-ip': '9.9.9.9' }), direct), '10.0.0.1');
});

test('صفحة دخول الأدمن تعرض حقل التحقق الثنائي وترسله', () => {
    const dir = path.join(__dirname, '..', 'server', 'admin');
    assert.match(fs.readFileSync(path.join(dir, 'login.html'), 'utf8'), /id="code"/);
    assert.match(fs.readFileSync(path.join(dir, 'login.js'), 'utf8'), /code: \$\("code"\)\.value/);
});
