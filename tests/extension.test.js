'use strict';

/* إضافة المتصفح: البناء، الأذونات، الخصوصية (ما ترسل الروابط)، والـ ZIP، وقائمة الاحتيال العامة. */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const { build, crc32, siteOrigin } = require('../tools/build-extension');
const { withServer, request } = require('./helpers');

test('البناء: يعوّض عنوان الموقع، يضم المحرك، ويرفض عناوين غير آمنة', () => {
    const out = fs.mkdtempSync(path.join(os.tmpdir(), 'pd-ext-build-'));
    try {
        assert.throws(() => build('http://evil.example', out));
        assert.equal(siteOrigin('https://my-site.onrender.com/path?x=1'), 'https://my-site.onrender.com');
        const r = build('https://my-site.onrender.com', out);
        const manifest = JSON.parse(fs.readFileSync(path.join(r.dir, 'manifest.json'), 'utf8'));
        assert.equal(manifest.manifest_version, 3);
        assert.deepEqual(manifest.host_permissions, ['https://my-site.onrender.com/*'], 'إذن الوصول لموقعنا فقط، مو لكل المواقع');
        assert.deepEqual(manifest.permissions.sort(), ['activeTab', 'alarms', 'contextMenus', 'storage', 'webNavigation']);
        assert.match(fs.readFileSync(path.join(r.dir, 'config.js'), 'utf8'), /site: 'https:\/\/my-site\.onrender\.com'/);
        assert.ok(fs.existsSync(path.join(r.dir, 'detection-engine.js')));
        assert.ok(!r.files.some(f => fs.readFileSync(path.join(r.dir, f)).includes('__SITE_ORIGIN__')));

        // ZIP صالح: نقرأ الدليل المركزي ونفك كل ملف ونتأكد من CRC
        const zip = fs.readFileSync(r.zipPath);
        const end = zip.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
        const count = zip.readUInt16LE(end + 10);
        let p = zip.readUInt32LE(end + 16);
        assert.equal(count, r.files.length);
        for (let i = 0; i < count; i++) {
            const nameLen = zip.readUInt16LE(p + 28), crc = zip.readUInt32LE(p + 16), size = zip.readUInt32LE(p + 20), local = zip.readUInt32LE(p + 42);
            const name = zip.subarray(p + 46, p + 46 + nameLen).toString();
            const dataStart = local + 30 + zip.readUInt16LE(local + 26) + zip.readUInt16LE(local + 28);
            const data = zlib.inflateRawSync(zip.subarray(dataStart, dataStart + size));
            assert.equal(crc32(data), crc, name);
            p += 46 + nameLen;
        }
    } finally {
        fs.rmSync(out, { recursive: true, force: true });
    }
});

test('الخصوصية: الإضافة ما ترسل الروابط اللي يزورها المستخدم لأي خادم', () => {
    const bg = fs.readFileSync(path.join(__dirname, '..', 'extension', 'background.js'), 'utf8');
    const fetches = bg.match(/fetch\([^)]*\)/g) || [];
    assert.equal(fetches.length, 1);
    assert.match(fetches[0], /\/api\/blocklist/);
    assert.match(bg, /credentials: 'omit'/);
    // الروابط تروح للموقع فقط عبر فتح تبويب بطلب صريح من المستخدم (الكلك اليمين)
    assert.match(bg, /contextMenus\.onClicked[\s\S]*chrome\.tabs\.create/);
});

test('قائمة الاحتيال العامة: بيها النطاقات المؤكدة فقط وقابلة للتخزين المؤقت', () => withServer({}, async app => {
    await app.db.cmd(['SADD', app.db.key('blocklist'), 'bad-shop.example']);
    const r = await request(app, 'GET', '/api/blocklist');
    assert.equal(r.status, 200);
    assert.deepEqual(r.json.domains, ['bad-shop.example']);
    assert.equal(r.headers['cache-control'], 'public, max-age=600');
}));
