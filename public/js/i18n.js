/*
  اللغات: اللهجة العراقية (الأصل) + العربية الفصحى + الكردية (سۆرانی) + الإنكليزية.

  الفكرة: نصوص الموقع مكتوبة باللهجة العراقية، والقاموس مفتاحه النص الأصلي نفسه. نمر على النصوص بالصفحة
  (وأي نص يضاف بعدين عبر MutationObserver) ونبدلها بالترجمة. هيج أي رسالة أو زر يطلع من الكود ينترجم
  تلقائياً بدون ما نغيّر كل ملف. النص اللي ما إله ترجمة يبقى بالأصل (ما ينكسر شي).
  القواميس تُبنى بـ npm run build-i18n من i18n/strings.tsv.

  يُحمّل بـ <head> قبل باقي السكربتات حتى يضبط اتجاه الصفحة (RTL / LTR) قبل الرسم.
*/
(function () {
    'use strict';

    const DICT_VERSION = '17617faa20';
    const LANGS = {
        iq: { name: 'اللهجة العراقية', short: 'عراقي', html: 'ar-IQ', dir: 'rtl' },
        ar: { name: 'العربية الفصحى', short: 'فصحى', html: 'ar', dir: 'rtl' },
        ku: { name: 'کوردی', short: 'کوردی', html: 'ckb', dir: 'rtl' },
        en: { name: 'English', short: 'EN', html: 'en', dir: 'ltr' }
    };
    const ATTRS = ['placeholder', 'title', 'aria-label', 'alt', 'data-title'];
    // ما نترجم: الكود، حقول الإدخال، المحادثة (كلام المستخدم والبوت)، وأي عنصر عليه data-no-i18n
    const SKIP = 'script,style,textarea,code,pre,kbd,[contenteditable],[data-no-i18n],.chat-history,#ocrText';

    let lang = 'iq';
    try { lang = localStorage.getItem('pd_lang') || ''; } catch { /* اختياري */ }
    if (!lang) {
        const m = /(?:^|;\s*)pd_lang=([a-z]{2})/.exec(document.cookie);
        lang = m ? m[1] : 'iq';
    }
    if (!LANGS[lang]) lang = 'iq';

    const root = document.documentElement;
    root.lang = LANGS[lang].html;
    root.dir = LANGS[lang].dir;
    root.dataset.lang = lang;

    let dict = null;
    let patterns = [];
    const norm = s => s.replace(/\s+/g, ' ').trim();

    function compile(list) {
        return list.map(([src, tr]) => {
            const names = [];
            const re = src.split(/(\{\d\})/).map(part => {
                const m = /^\{(\d)\}$/.exec(part);
                if (m) { names.push(m[1]); return '(.*?)'; }
                return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            }).join('');
            return { re: new RegExp('^' + re + '$'), names, tr };
        });
    }

    // يترجم نصاً كاملاً. يرجع null إذا ما إله ترجمة
    function lookup(text) {
        if (!dict) return null;
        const key = norm(text);
        if (!key) return null;
        if (Object.prototype.hasOwnProperty.call(dict, key)) return dict[key];
        for (const p of patterns) {
            const m = p.re.exec(key);
            if (!m) continue;
            let out = p.tr;
            p.names.forEach((n, i) => {
                const part = m[i + 1];
                const inner = Object.prototype.hasOwnProperty.call(dict, part) ? dict[part] : part;
                out = out.replace('{' + n + '}', inner);
            });
            return lang === 'en' ? out.replace(/،/g, ',').replace(/؛/g, ';') : out;
        }
        return null;
    }

    function t(text) {
        const tr = lookup(String(text));
        return tr === null ? String(text) : tr;
    }

    function translateText(node) {
        const value = node.nodeValue;
        if (!value || !/[؀-ۿ]/.test(value)) return;
        const tr = lookup(value);
        if (tr === null) return;
        const lead = /^\s*/.exec(value)[0];
        const tail = /\s*$/.exec(value)[0];
        const next = lead + tr + tail;
        if (next !== value) node.nodeValue = next;
    }

    function translateAttrs(el) {
        for (const a of ATTRS) {
            const v = el.getAttribute(a);
            if (!v || !/[؀-ۿ]/.test(v)) continue;
            const tr = lookup(v);
            if (tr !== null && tr !== v) el.setAttribute(a, tr);
        }
    }

    function skipped(el) {
        return el && el.closest && el.closest(SKIP);
    }

    function translateTree(start) {
        if (!dict || !start) return;
        if (start.nodeType === 3) {
            if (!skipped(start.parentElement)) translateText(start);
            return;
        }
        if (start.nodeType !== 1 || skipped(start)) return;
        translateAttrs(start);
        const walker = document.createTreeWalker(start, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT, {
            acceptNode: n => (n.nodeType === 1 && n.matches(SKIP)) ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT
        });
        let n;
        while ((n = walker.nextNode())) {
            if (n.nodeType === 3) translateText(n);
            else translateAttrs(n);
        }
    }

    // قائمة اللغات: أي عنصر عليه data-lang-menu يصير أزرار اختيار
    function renderMenus() {
        document.querySelectorAll('[data-lang-menu]').forEach(box => {
            if (box.dataset.ready) return;
            box.dataset.ready = '1';
            box.setAttribute('data-no-i18n', '');
            Object.entries(LANGS).forEach(([code, info]) => {
                const b = document.createElement('button');
                b.type = 'button';
                b.className = 'lang-option' + (code === lang ? ' active' : '');
                b.lang = info.html;
                b.dir = info.dir;
                b.textContent = info.name;
                b.setAttribute('aria-pressed', String(code === lang));
                b.addEventListener('click', () => setLang(code));
                box.appendChild(b);
            });
        });
    }

    function setLang(code) {
        if (!LANGS[code] || code === lang) return;
        try { localStorage.setItem('pd_lang', code); } catch { /* اختياري */ }
        document.cookie = 'pd_lang=' + code + '; Path=/; Max-Age=31536000; SameSite=Lax' + (location.protocol === 'https:' ? '; Secure' : '');
        // نعيد تحميل الصفحة: أبسط وأضمن طريقة حتى كل المحتوى (حتى المولّد بالكود) يطلع باللغة الجديدة
        location.reload();
    }

    function start() {
        renderMenus();
        if (!dict) return;
        translateTree(document.body);
        if (document.title) document.title = t(document.title);
        new MutationObserver(records => {
            for (const r of records) {
                if (r.type === 'characterData') translateTree(r.target);
                else if (r.type === 'attributes') { if (!skipped(r.target)) translateAttrs(r.target); }
                else r.addedNodes.forEach(translateTree);
            }
        }).observe(document.body, { subtree: true, childList: true, characterData: true, attributes: true, attributeFilter: ATTRS });
    }

    function reveal() { root.classList.remove('i18n-loading'); }

    window.PDI18N = { lang, langs: LANGS, t, setLang };

    // بالإنكليزية: التواريخ والأرقام اللي الكود يكتبها بـ 'ar-IQ' تطلع بصيغة إنكليزية
    if (lang === 'en') {
        const swap = loc => (typeof loc === 'string' && /^ar/i.test(loc) ? 'en-GB' : loc);
        for (const [proto, names] of [[Date.prototype, ['toLocaleString', 'toLocaleDateString', 'toLocaleTimeString']], [Number.prototype, ['toLocaleString']]]) {
            for (const name of names) {
                const original = proto[name];
                proto[name] = function (loc, opts) { return original.call(this, swap(loc), opts); };
            }
        }
    }

    if (lang === 'iq') {
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', renderMenus);
        else renderMenus();
        return;
    }

    // نخفي الصفحة لحظة لحد ما تنترجم (حتى ما تطلع اللهجة ثم تتبدل). حد أقصى ثانيتين حتى ما تعلق
    root.classList.add('i18n-loading');
    const failsafe = setTimeout(reveal, 2000);
    const ready = new Promise(r => {
        if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', r);
        else r();
    });
    const loaded = fetch('/i18n/' + lang + '.json?v=' + DICT_VERSION, { credentials: 'same-origin' })
        .then(r => (r.ok ? r.json() : null))
        .then(data => {
            if (data && data.dict) { dict = data.dict; patterns = compile(data.patterns || []); }
        })
        .catch(() => { /* بدون قاموس: يبقى النص الأصلي */ });
    Promise.all([ready, loaded]).then(() => {
        try { start(); } finally { clearTimeout(failsafe); reveal(); }
    });
})();
