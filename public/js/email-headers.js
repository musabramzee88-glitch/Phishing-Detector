/*
  محلل ترويسات البريد (Email Header Analyzer). يعمل بالكامل داخل المتصفح:
  الترويسات بيها بريد المستخدم نفسه، فما نرسلها للخادم. (عناوين IP العامة فقط تُرسل لو المستخدم طلب معلومات استضافتها.)

  يستخرج: نتيجة SPF و DKIM و DMARC من Authentication-Results، والمرسل الظاهر مقابل العنوان الحقيقي و Reply-To و Return-Path،
  توافق نطاق DKIM مع نطاق المرسل، ومسار السيرفرات من سطور Received (من الأقدم للأحدث)، ومؤشرات انتحال.
*/
(function (root, factory) {
    const api = factory(root.PhishingEngine || (typeof require === 'function' ? require('./detection-engine.js') : null));
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.EmailHeaders = api;
})(typeof self !== 'undefined' ? self : this, function (engine) {
    'use strict';

    const MAX_INPUT = 200 * 1024;

    // يجمع الأسطر المكسورة (السطر الذي يبدأ بمسافة يكمل اللي قبله) ويرجع [{name, value}]
    function parseHeaders(raw) {
        const text = String(raw || '').slice(0, MAX_INPUT).replace(/\r\n?/g, '\n');
        const end = text.search(/\n\s*\n/);
        const head = end > 0 ? text.slice(0, end) : text;
        const out = [];
        for (const line of head.split('\n')) {
            if (/^[ \t]/.test(line) && out.length) { out[out.length - 1].value += ' ' + line.trim(); continue; }
            const m = /^([A-Za-z0-9-]{1,80}):\s?(.*)$/.exec(line);
            if (m) out.push({ name: m[1].toLowerCase(), value: m[2].trim() });
        }
        return out;
    }

    const all = (headers, name) => headers.filter(h => h.name === name).map(h => h.value);
    const first = (headers, name) => (headers.find(h => h.name === name) || {}).value || '';

    // ترويسة بصيغة RFC 2047 (=?UTF-8?B?...?=) تُفك حتى يظهر الاسم العربي صحيحاً
    function decodeWords(value) {
        return String(value).replace(/=\?([\w-]+)\?([BbQq])\?([^?]*)\?=/g, (m, charset, enc, data) => {
            try {
                let bytes;
                if (enc.toUpperCase() === 'B') bytes = Uint8Array.from(atob(data), c => c.charCodeAt(0));
                else bytes = Uint8Array.from(data.replace(/_/g, ' ').replace(/=([0-9A-F]{2})/gi, (x, h) => String.fromCharCode(parseInt(h, 16))), c => c.charCodeAt(0));
                return new TextDecoder(charset.toLowerCase()).decode(bytes);
            } catch { return m; }
        });
    }

    // «الاسم» <user@domain>  →  { name, address, domain }
    function parseAddress(value) {
        const v = decodeWords(value || '');
        const angle = /<\s*([^<>\s]+@[^<>\s]+)\s*>/.exec(v);
        const bare = /([^\s<>"']+@[^\s<>"']+)/.exec(v);
        const address = ((angle && angle[1]) || (bare && bare[1]) || '').toLowerCase().replace(/[>;,]+$/, '');
        const name = angle ? v.slice(0, angle.index).replace(/^["'\s]+|["'\s]+$/g, '').trim() : '';
        const domain = address.includes('@') ? address.split('@').pop() : '';
        return { name, address, domain };
    }

    const registrable = host => {
        if (!host) return '';
        try { return engine ? engine.splitDomain(host.toLowerCase()).registrable : host.toLowerCase(); } catch { return host.toLowerCase(); }
    };

    function authResults(headers) {
        const text = all(headers, 'authentication-results').concat(all(headers, 'arc-authentication-results')).join(' ; ');
        const pick = re => { const m = re.exec(text); return m ? m[1].toLowerCase() : ''; };
        const spfHeader = first(headers, 'received-spf');
        return {
            spf: pick(/\bspf=(\w+)/i) || ((/^(pass|fail|softfail|neutral|none|temperror|permerror)\b/i.exec(spfHeader) || [])[1] || '').toLowerCase(),
            dkim: pick(/\bdkim=(\w+)/i),
            dmarc: pick(/\bdmarc=(\w+)/i),
            dkimDomain: pick(/\bdkim=\w+[^;]*?header\.(?:d|i)=@?([\w.-]+)/i) || ((/\bd=([\w.-]+)/.exec(first(headers, 'dkim-signature')) || [])[1] || '').toLowerCase(),
            mailFrom: pick(/smtp\.mailfrom=(?:[^@\s;]+@)?([\w.-]+)/i),
            raw: text.slice(0, 2000)
        };
    }

    const IPV4 = /\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b/g;
    function isPrivate(ip) {
        const p = ip.split('.').map(Number);
        return p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) || (p[0] === 192 && p[1] === 168) || (p[0] === 169 && p[1] === 254) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) || p[0] >= 224;
    }

    // سطور Received من الأقدم (أول سيرفر) للأحدث (سيرفر المستلم)
    function receivedPath(headers) {
        return all(headers, 'received').slice(0, 30).reverse().map(v => {
            const from = (/\bfrom\s+([^\s;()]+)/i.exec(v) || [])[1] || '';
            const by = (/\bby\s+([^\s;()]+)/i.exec(v) || [])[1] || '';
            const ips = [...new Set((v.match(IPV4) || []))];
            const when = v.includes(';') ? v.slice(v.lastIndexOf(';') + 1).trim() : '';
            const t = Date.parse(when);
            return { from: from.slice(0, 120), by: by.slice(0, 120), ips, publicIps: ips.filter(ip => !isPrivate(ip)), time: Number.isFinite(t) ? new Date(t).toISOString() : '' };
        });
    }

    function analyze(raw) {
        const headers = parseHeaders(raw);
        if (!headers.length) return { error: 'empty' };
        const signals = [];
        const add = (weight, type, text) => signals.push({ weight, type, text });

        const from = parseAddress(first(headers, 'from'));
        const replyTo = parseAddress(first(headers, 'reply-to'));
        const returnPath = parseAddress(first(headers, 'return-path'));
        const auth = authResults(headers);
        const path = receivedPath(headers);
        const fromReg = registrable(from.domain);

        // 1. نتائج المصادقة
        if (auth.spf === 'fail') add(0.35, 'danger', 'SPF فشل: السيرفر اللي أرسل الرسالة غير مسموح له يرسل باسم هذا النطاق.');
        else if (auth.spf === 'softfail') add(0.18, 'warning', 'SPF «softfail»: السيرفر المرسل مو من السيرفرات المعتمدة للنطاق.');
        else if (auth.spf === 'pass') add(0, 'safe', 'SPF نجح: السيرفر المرسل مسموح له يرسل باسم نطاق المرسل الفعلي.');
        if (auth.dkim === 'fail') add(0.3, 'danger', 'DKIM فشل: التوقيع الرقمي للرسالة غير صحيح (ممكن تعدّلت أو التوقيع مزيف).');
        else if (auth.dkim === 'pass') add(0, 'safe', `DKIM نجح: الرسالة موقّعة رقمياً من نطاق ${auth.dkimDomain || 'معروف'}.`);
        else if (!auth.dkim) add(0.1, 'warning', 'ما اكو توقيع DKIM بالرسالة.');
        if (auth.dmarc === 'fail') add(0.5, 'danger', 'DMARC فشل: الرسالة ما تثبت إنها فعلاً من نطاق المرسل الظاهر. هذا أقوى مؤشر على انتحال المرسل.');
        else if (auth.dmarc === 'pass') add(0, 'safe', 'DMARC نجح: الرسالة مطابقة لسياسة نطاق المرسل.');
        if (!auth.spf && !auth.dkim && !auth.dmarc) add(0, 'info', 'ما لكينا نتائج SPF/DKIM/DMARC. تأكد إنك نسخت الترويسات كاملة (من «Show original»).');

        // 2. توافق النطاقات
        if (auth.dkim === 'pass' && auth.dkimDomain && fromReg && registrable(auth.dkimDomain) !== fromReg) {
            add(0.15, 'warning', `التوقيع DKIM من نطاق (${auth.dkimDomain}) غير نطاق المرسل الظاهر (${from.domain}). شائع بخدمات الإرسال، بس ممكن يكون انتحال.`);
        }
        if (replyTo.domain && fromReg && registrable(replyTo.domain) !== fromReg) {
            add(0.35, 'danger', `الرد يروح لعنوان ثاني (${replyTo.address}) غير المرسل (${from.address}). المحتال يستلم ردك على بريده هو.`);
        }
        if (returnPath.domain && fromReg && registrable(returnPath.domain) !== fromReg) {
            add(0.08, 'warning', `عنوان الإرجاع (Return-Path) من نطاق ثاني: ${returnPath.domain}.`);
        }

        // 3. الاسم الظاهر يدّعي جهة مختلفة عن العنوان الحقيقي
        if (engine && from.name) {
            const lower = from.name.toLowerCase();
            const claimed = engine.brandsMentioned(lower, engine.normalizeArabic(from.name)).find(b => b.domains.length && !b.domains.some(d => from.domain === d || from.domain.endsWith('.' + d)));
            if (claimed) add(0.45, 'danger', `الاسم الظاهر «${from.name.slice(0, 60)}» يدّعي إنه ${claimed.name}، بس البريد الحقيقي من ${from.domain}.`);
            const shownAddress = /[\w.+-]+@[\w-]+(\.[\w-]+)+/.exec(from.name);
            if (shownAddress && shownAddress[0].toLowerCase() !== from.address) add(0.4, 'danger', `الاسم الظاهر مكتوب بيه عنوان بريد (${shownAddress[0]}) يختلف عن العنوان الحقيقي (${from.address}). خدعة شائعة.`);
        }
        // 4. نطاق المرسل نفسه (تشابه مع علامات معروفة، نطاق جديد/مشبوه)
        if (engine && from.domain) {
            const r = engine.analyzeUrl('https://' + from.domain);
            if (!r.error && r.level !== 'safe') {
                const why = (r.reasons.find(x => x.type === 'danger' || x.type === 'warning') || {}).text || '';
                add(Math.min(0.7, r.score / 100), r.level === 'danger' ? 'danger' : 'warning', `نطاق المرسل ${from.domain} مشبوه: ${why}`);
            }
        }
        if (path.length > 12) add(0.08, 'warning', `الرسالة مرت بعدد كبير من السيرفرات (${path.length}).`);

        let keep = 1;
        for (const s of signals) if (s.weight > 0) keep *= 1 - Math.min(s.weight, 0.99);
        const score = Math.round((1 - keep) * 100);
        const level = score >= 55 ? 'danger' : score >= 25 ? 'warning' : 'safe';
        const order = { danger: 0, warning: 1, info: 2, safe: 3 };
        signals.sort((a, b) => order[a.type] - order[b.type] || b.weight - a.weight);
        return {
            score, level, reasons: signals.map(({ type, text }) => ({ type, text })),
            from, replyTo, returnPath, auth, path,
            subject: decodeWords(first(headers, 'subject')).slice(0, 200),
            date: first(headers, 'date').slice(0, 80),
            publicIps: [...new Set(path.flatMap(h => h.publicIps))].slice(0, 10)
        };
    }

    return { analyze, parseHeaders, parseAddress, decodeWords, receivedPath, authResults };
});
