'use strict';

/* المرحلة ب: تحليل ترويسة البريد، استضافة عناوين IP، ومكتبات QR و OCR المستضافة محلياً. */

const test = require('node:test');
const assert = require('node:assert/strict');
const EH = require('../public/js/email-headers.js');
const { withServer, request, registerUser, authed } = require('./helpers');

const SPOOFED = `Delivered-To: victim@gmail.com
Received: by 2002:a05:6a10:1:b0:5c4 with SMTP id x; Tue, 11 Nov 2026 10:00:03 -0800
Received: from mail.cheap-sender.top (mail.cheap-sender.top [45.77.12.3])
        by mx.google.com with ESMTP id abc; Tue, 11 Nov 2026 10:00:02 -0800
Received: from localhost (unknown [10.0.0.5]) by mail.cheap-sender.top; Tue, 11 Nov 2026 10:00:01 -0800
Authentication-Results: mx.google.com;
       spf=softfail (google.com: domain of transitioning alert@paypal.com does not designate 45.77.12.3 as permitted sender) smtp.mailfrom=alert@paypal.com;
       dkim=none;
       dmarc=fail (p=REJECT sp=REJECT dis=QUARANTINE) header.from=paypal.com
From: "PayPal Security" <alert@paypal.com>
Reply-To: support@paypal-help-center.top
Return-Path: <bounce@cheap-sender.top>
Subject: =?UTF-8?B?2KrZhtio2YrZhyDYo9mF2YbZig==?=
Date: Tue, 11 Nov 2026 10:00:00 -0800

body here`;

const LEGIT = `Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])
        by mx.google.com with SMTPS id x; Tue, 11 Nov 2026 09:00:01 -0800
Authentication-Results: mx.google.com;
       dkim=pass header.i=@accounts.google.com header.s=20230601 header.b=abc;
       spf=pass (google.com: domain of 3abc@accounts.google.com designates 209.85.220.41 as permitted sender) smtp.mailfrom=3abc@accounts.google.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=accounts.google.com
From: Google <no-reply@accounts.google.com>
Subject: Security alert
`;

test('ترويسة منتحَلة: DMARC فشل + Reply-To لنطاق ثاني + اسم يدّعي PayPal ⇠ خطر', () => {
    const r = EH.analyze(SPOOFED);
    assert.equal(r.level, 'danger');
    assert.equal(r.auth.spf, 'softfail');
    assert.equal(r.auth.dmarc, 'fail');
    assert.equal(r.from.address, 'alert@paypal.com');
    assert.equal(r.replyTo.domain, 'paypal-help-center.top');
    assert.equal(r.subject, 'تنبيه أمني');
    const text = r.reasons.map(x => x.text).join('\n');
    assert.match(text, /DMARC فشل/);
    assert.match(text, /الرد يروح لعنوان ثاني/);
    // المسار من الأقدم للأحدث، والعناوين الخاصة مستبعدة من البحث
    assert.equal(r.path[0].from, 'localhost');
    assert.deepEqual(r.publicIps, ['45.77.12.3']);
});

test('ترويسة حقيقية من Google: كل المصادقات ناجحة ⇠ آمن', () => {
    const r = EH.analyze(LEGIT);
    assert.equal(r.level, 'safe', JSON.stringify(r.reasons));
    assert.equal(r.auth.dkim, 'pass');
    assert.equal(r.auth.dkimDomain, 'accounts.google.com');
});

test('الاسم الظاهر بيه بريد ثاني، ونص فارغ أو تالف لا يكسر المحلل', () => {
    const r = EH.analyze('From: "support@apple.com" <x@evil-mail.example>\nAuthentication-Results: x; dmarc=none\n');
    assert.match(r.reasons.map(x => x.text).join(' '), /عنوان بريد \(support@apple\.com\) يختلف/);
    assert.equal(EH.analyze('').error, 'empty');
    for (const junk of ['\u0000'.repeat(1000), 'Received: '.repeat(50000), 'a: b\n'.repeat(100000)]) assert.doesNotThrow(() => EH.analyze(junk));
});

test('استضافة IP: عامة فقط، بحد 8، وتحتاج حساب', async () => {
    const inspector = { hosting: async ip => ({ asn: 1, country: 'NL', countryName: 'هولندا', org: 'TEST-NET' }), inspect: async () => null };
    await withServer({}, async app => {
        assert.equal((await request(app, 'POST', '/api/scan/ip-hosting', { headers: { 'Content-Type': 'application/json', Origin: `http://127.0.0.1:${app.base.port}` }, body: { ips: ['8.8.8.8'] } })).status, 401);
        const { cookie } = await registerUser(app);
        const priv = await request(app, 'POST', '/api/scan/ip-hosting', { headers: authed(app, cookie), body: { ips: ['10.0.0.1', '127.0.0.1', '192.168.1.1'] } });
        assert.equal(priv.status, 400);
        const ips = Array.from({ length: 12 }, (_, i) => `8.8.8.${i + 1}`);
        const ok = await request(app, 'POST', '/api/scan/ip-hosting', { headers: authed(app, cookie), body: { ips: [...ips, '10.0.0.1', 'x'] } });
        assert.equal(ok.status, 200);
        assert.equal(ok.json.results.length, 8);
        assert.equal(ok.json.results[0].country, 'NL');
    }, null, { inspector });
});

test('مكتبات QR و OCR تُخدم من الموقع، والسياسات تسمح بالكاميرا وWebAssembly بأمان', () => withServer({}, async app => {
    for (const p of ['/vendor/jsqr/jsQR.js', '/vendor/tesseract/tesseract.min.js', '/vendor/tesseract/worker.min.js', '/vendor/tesseract/core/tesseract-core-simd-lstm.wasm.js', '/vendor/tesseract/core/tesseract-core-lstm.wasm.js']) {
        assert.equal((await request(app, 'HEAD', p)).status, 200, p);
    }
    const lang = await request(app, 'HEAD', '/vendor/tesseract/lang/ara.traineddata.gz');
    assert.equal(lang.status, 200);
    assert.equal(lang.headers['content-type'], 'application/gzip');
    const page = await request(app, 'GET', '/login');
    assert.match(page.headers['content-security-policy'], /script-src 'self' 'wasm-unsafe-eval';/);
    assert.doesNotMatch(page.headers['content-security-policy'], /'unsafe-eval'/);
    assert.match(page.headers['permissions-policy'], /camera=\(self\)/);
}));
