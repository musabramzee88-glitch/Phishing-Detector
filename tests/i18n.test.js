'use strict';

/* اللغات: القواميس مبنية ومحدّثة، وكل نص ظاهر بالصفحات إله ترجمة بالفصحى والكردية والإنكليزية. */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { parse, norm } = require('../tools/build-i18n');
const { withServer, request } = require('./helpers');

const ROOT = path.join(__dirname, '..');
const rows = parse(fs.readFileSync(path.join(ROOT, 'i18n', 'strings.tsv'), 'utf8'));
const dicts = Object.fromEntries(['ar', 'ku', 'en'].map(l => [l, JSON.parse(fs.readFileSync(path.join(ROOT, 'public', 'i18n', l + '.json'), 'utf8'))]));

const decode = s => s.replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>');

// النصوص الظاهرة بصفحة HTML (بين الوسوم + الخصائص اللي تنترجم)
function visibleStrings(file) {
    const html = fs.readFileSync(path.join(ROOT, 'public', file), 'utf8')
        .replace(/<script[\s\S]*?<\/script>/g, '').replace(/<style[\s\S]*?<\/style>/g, '').replace(/<!--[\s\S]*?-->/g, '')
        .replace(/<textarea[\s\S]*?<\/textarea>/g, '');
    const body = html.slice(html.indexOf('<body'));
    const out = new Set();
    for (const seg of body.split(/<[^>]*>/)) {
        const t = norm(decode(seg));
        if (/[؀-ۿ]/.test(t)) out.add(t);
    }
    for (const m of body.matchAll(/\s(?:placeholder|title|aria-label|alt|data-title)="([^"]*)"/g)) {
        const t = norm(decode(m[1]));
        if (/[؀-ۿ]/.test(t)) out.add(t);
    }
    return [...out];
}

test('القواميس مبنية من آخر نسخة لـ i18n/strings.tsv (شغّل npm run build-i18n بعد أي تعديل)', () => {
    for (const [lang, d] of Object.entries(dicts)) {
        const j = ['ar', 'ku', 'en'].indexOf(lang) + 1;
        const expected = rows.filter(r => !/\{\d\}/.test(r[0]));
        assert.equal(Object.keys(d.dict).length, new Set(expected.map(r => r[0])).size, lang);
        for (const r of expected) assert.equal(d.dict[r[0]], r[j], `${lang}: ${r[0]}`);
        assert.equal(d.patterns.length, rows.filter(r => /\{\d\}/.test(r[0])).length);
    }
    const runtime = fs.readFileSync(path.join(ROOT, 'public', 'js', 'i18n.js'), 'utf8');
    assert.match(runtime, /const DICT_VERSION = '[0-9a-f]{10}';/);
});

test('كل نص ظاهر بالتطبيق وصفحة الدخول إله ترجمة', () => {
    const missing = [];
    for (const file of ['index.html', 'login.html']) {
        for (const s of visibleStrings(file)) if (!(s in dicts.en.dict)) missing.push(`${file}: ${s}`);
    }
    assert.deepEqual(missing, [], 'نصوص بدون ترجمة. أضفها لـ i18n/strings.tsv وشغّل npm run build-i18n');
});

test('الترجمات: ما بيها وسوم HTML ولا روابط مخفية، والإنكليزية فعلاً إنكليزية', () => {
    for (const r of rows) {
        for (const t of r.slice(1)) {
            assert.doesNotMatch(t, /<|javascript:|on\w+=/i, r[0]);
        }
        // الإنكليزية ما تحتوي حروف عربية إلا أسماء اللغات
        if (!/اللهجة|العربية|کوردی/.test(r[3])) assert.doesNotMatch(r[3], /[؀-ۿ]/, `en: ${r[0]}`);
    }
});

test('الصفحات تحمّل i18n.js بالـ head وقائمة اللغة موجودة، والقاموس يُخدم', () => withServer({}, async app => {
    const login = await request(app, 'GET', '/login');
    assert.match(login.text, /<head>[\s\S]*<script src="\/js\/i18n\.js\?v=[\w.-]+"><\/script>[\s\S]*<\/head>/);
    assert.match(login.text, /data-lang-menu/);
    for (const l of ['ar', 'ku', 'en']) {
        const r = await request(app, 'GET', `/i18n/${l}.json?v=x`);
        assert.equal(r.status, 200);
        assert.equal(r.json.lang, l);
    }
}));

test('CyberBot يستلم لغة الواجهة من قائمة ثابتة فقط', () => {
    const src = fs.readFileSync(path.join(ROOT, 'server', 'chat.js'), 'utf8');
    assert.match(src, /const UI_LANG = \{ ar: .*ku: .*en: /);
    assert.match(src, /if \(UI_LANG\[body\.lang\]\)/);
});
