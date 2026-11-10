/*
 * محرك الكشف لمنظومة كشف ومكافحة التصيد الإلكتروني.
 *
 * يحلل الروابط والرسائل والملفات بقواعد ساكنة (Heuristics) ويرجع درجة خطورة مع أسباب مفهومة.
 * لا يتصل بالإنترنت ولا يرسل أي بيانات. يعمل داخل المتصفح (window.PhishingEngine)
 * وداخل Node (require) حتى تشتغل عليه الاختبارات: node --test
 *
 * طريقة حساب الدرجة: كل مؤشر له وزن بين 0 و 1، وتُجمع الأوزان بطريقة noisy-OR:
 *   الدرجة = 1 - (1 - w1)(1 - w2)...
 * فكل مؤشر إضافي يرفع الخطورة، لكن الدرجة ما تتجاوز 100% ولا تتضخم من تكرار مؤشرات ضعيفة.
 */
(function (root, factory) {
    const engine = factory();
    if (typeof module === 'object' && module.exports) module.exports = engine;
    else root.PhishingEngine = engine;
})(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    // ------------------------------------------------------------------
    // أدوات عامة
    // ------------------------------------------------------------------

    const THRESHOLDS = { warning: 25, danger: 55 };
    const STRICT_THRESHOLDS = { warning: 15, danger: 45 };

    function combineSignals(signals) {
        let keep = 1;
        for (const s of signals) {
            if (s.weight > 0) keep *= 1 - Math.min(s.weight, 0.99);
        }
        return Math.round((1 - keep) * 100);
    }

    function levelFor(score, thresholds) {
        if (score >= thresholds.danger) return 'danger';
        if (score >= thresholds.warning) return 'warning';
        return 'safe';
    }

    function finish(signals, thresholds, extra) {
        const score = combineSignals(signals);
        const order = { danger: 0, warning: 1, info: 2, safe: 3 };
        const reasons = signals
            .slice()
            .sort((a, b) => (order[a.type] - order[b.type]) || (b.weight - a.weight))
            .map(s => ({ type: s.type, text: s.text }));
        return Object.assign({ score, level: levelFor(score, thresholds), reasons }, extra);
    }

    // مسافة Damerau-Levenshtein: تحسب الإضافة والحذف والاستبدال وتبديل حرفين متجاورين كتعديل واحد
    function editDistance(a, b) {
        const d = [];
        for (let i = 0; i <= a.length; i++) d.push([i]);
        for (let j = 1; j <= b.length; j++) d[0][j] = j;
        for (let i = 1; i <= a.length; i++) {
            for (let j = 1; j <= b.length; j++) {
                const cost = a[i - 1] === b[j - 1] ? 0 : 1;
                d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
                if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
                    d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
                }
            }
        }
        return d[a.length][b.length];
    }

    function similarity(a, b) {
        const max = Math.max(a.length, b.length);
        return max === 0 ? 1 : 1 - editDistance(a, b) / max;
    }

    // ------------------------------------------------------------------
    // الأحرف المتشابهة (Homoglyphs)
    // ------------------------------------------------------------------

    const CONFUSABLES = {
        'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c',
        'т': 't', 'у': 'y', 'х': 'x', 'і': 'i', 'ї': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
        'ӏ': 'l', 'ɡ': 'g', 'ɑ': 'a', 'ο': 'o', 'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v',
        'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w', 'ı': 'i', 'ł': 'l', 'ø': 'o', 'ß': 'b'
    };

    // يحول أي نص يحتوي أحرفاً مشابهة للاتينية (كيريلية، يونانية، أحرف بعلامات) إلى "هيكل" لاتيني
    function asciiSkeleton(text) {
        return Array.from(text.normalize('NFKD').replace(/[̀-ͯ]/g, ''))
            .map(ch => CONFUSABLES[ch] || ch)
            .join('');
    }

    // استبدال الأرقام والرموز التي تشبه الحروف (g00gle, paypa1, faceb00k)
    function deLeetVariants(text) {
        const base = text.replace(/rn/g, 'm').replace(/vv/g, 'w');
        const map = { '0': 'o', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g', '$': 's', '@': 'a' };
        const swap = s => s.replace(/[0345789$@]/g, c => map[c] || c);
        const variants = new Set([text, swap(base.replace(/1/g, 'l')), swap(base.replace(/1/g, 'i'))]);
        return Array.from(variants);
    }

    function scriptsOf(label) {
        const scripts = new Set();
        for (const ch of label) {
            if (/[a-z]/i.test(ch)) scripts.add('latin');
            else if (/[Ѐ-ӿ]/.test(ch)) scripts.add('cyrillic');
            else if (/[Ͱ-Ͽ]/.test(ch)) scripts.add('greek');
            else if (/[؀-ۿ]/.test(ch)) scripts.add('arabic');
            else if (/[0-9-]/.test(ch)) continue;
            else if (ch.charCodeAt(0) > 127) scripts.add('other');
        }
        return scripts;
    }

    // فك ترميز Punycode (RFC 3492) لأسماء النطاقات الدولية مثل xn--pple-43d
    function punycodeDecode(input) {
        const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
        const output = [];
        let basic = input.lastIndexOf('-');
        if (basic < 0) basic = 0;
        for (let j = 0; j < basic; j++) {
            if (input.charCodeAt(j) >= 0x80) throw new Error('invalid punycode');
            output.push(input.charCodeAt(j));
        }
        let n = 128, bias = 72, i = 0;
        for (let index = basic > 0 ? basic + 1 : 0; index < input.length;) {
            const oldi = i;
            let w = 1;
            for (let k = base; ; k += base) {
                if (index >= input.length) throw new Error('invalid punycode');
                const cp = input.charCodeAt(index++);
                let digit = base;
                if (cp >= 48 && cp <= 57) digit = cp - 22;
                else if (cp >= 65 && cp <= 90) digit = cp - 65;
                else if (cp >= 97 && cp <= 122) digit = cp - 97;
                if (digit >= base) throw new Error('invalid punycode');
                i += digit * w;
                const t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias);
                if (digit < t) break;
                w *= base - t;
            }
            const points = output.length + 1;
            let delta = oldi === 0 ? Math.floor((i - oldi) / damp) : Math.floor((i - oldi) / 2);
            delta += Math.floor(delta / points);
            let k = 0;
            while (delta > ((base - tMin) * tMax) >> 1) {
                delta = Math.floor(delta / (base - tMin));
                k += base;
            }
            bias = Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
            n += Math.floor(i / points);
            i %= points;
            output.splice(i++, 0, n);
        }
        return String.fromCodePoint(...output);
    }

    function hostToUnicode(host) {
        return host.split('.').map(label => {
            if (!label.startsWith('xn--')) return label;
            try { return punycodeDecode(label.slice(4)); } catch { return label; }
        }).join('.');
    }

    // ------------------------------------------------------------------
    // قواعد بيانات الروابط
    // ------------------------------------------------------------------

    const BRANDS = [
        { name: 'فيسبوك', keys: ['facebook'], domains: ['facebook.com', 'fb.com', 'fb.me', 'messenger.com', 'facebook.net', 'fbcdn.net'] },
        { name: 'جوجل', keys: ['google'], domains: ['google.com', 'google.iq', 'google.com.iq', 'googleapis.com', 'gstatic.com', 'goo.gl', 'forms.gle', 'g.co', 'android.com', 'youtube.com', 'gmail.com'] },
        { name: 'Gmail', keys: ['gmail'], domains: ['gmail.com', 'google.com'] },
        { name: 'يوتيوب', keys: ['youtube'], domains: ['youtube.com', 'youtu.be'] },
        { name: 'إنستغرام', keys: ['instagram'], domains: ['instagram.com', 'instagr.am', 'cdninstagram.com'] },
        { name: 'واتساب', keys: ['whatsapp'], domains: ['whatsapp.com', 'whatsapp.net', 'wa.me'] },
        { name: 'تيليجرام', keys: ['telegram'], domains: ['telegram.org', 'telegram.me', 't.me', 'telegra.ph'] },
        { name: 'تيك توك', keys: ['tiktok'], domains: ['tiktok.com', 'tiktokcdn.com'] },
        { name: 'سناب شات', keys: ['snapchat'], domains: ['snapchat.com'] },
        { name: 'تويتر / X', keys: ['twitter'], domains: ['twitter.com', 'x.com', 't.co'] },
        { name: 'مايكروسوفت', keys: ['microsoft', 'outlook', 'office365', 'hotmail', 'onedrive'], domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'microsoftonline.com', 'hotmail.com', 'sharepoint.com', 'onedrive.com', 'msn.com'] },
        { name: 'آبل', keys: ['apple', 'icloud'], generic: ['apple'], domains: ['apple.com', 'icloud.com', 'apple.co'] },
        { name: 'أمازون', keys: ['amazon'], domains: ['amazon.com', 'amazon.ae', 'amazon.sa', 'amazon.eg', 'amazon.de', 'amazon.co.uk', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.ca', 'amazon.in', 'amazon.co.jp', 'amazon.com.tr', 'amazonaws.com', 'amzn.to'] },
        { name: 'نتفليكس', keys: ['netflix'], domains: ['netflix.com'] },
        { name: 'باي بال', keys: ['paypal'], domains: ['paypal.com', 'paypal.me'] },
        { name: 'بينانس', keys: ['binance'], domains: ['binance.com'] },
        { name: 'دي إتش إل', keys: ['dhl'], domains: ['dhl.com', 'dhl.de'] },
        { name: 'فيديكس', keys: ['fedex'], domains: ['fedex.com'] },
        { name: 'أرامكس', keys: ['aramex'], domains: ['aramex.com'] },
        { name: 'كي كارد (Qi Card)', keys: ['kicard', 'qicard'], domains: ['qi.iq'] },
        { name: 'لينكدإن', keys: ['linkedin'], domains: ['linkedin.com', 'lnkd.in'] },
        { name: 'غيت هب', keys: ['github'], domains: ['github.com', 'githubusercontent.com'] },
        { name: 'ياهو', keys: ['yahoo'], domains: ['yahoo.com'] },
        { name: 'دروب بوكس', keys: ['dropbox'], domains: ['dropbox.com'] },
        { name: 'ستيم', keys: ['steamcommunity', 'steampowered'], domains: ['steamcommunity.com', 'steampowered.com'] },
        { name: 'زين كاش', keys: ['zaincash'], domains: ['zaincash.iq'] },
        { name: 'آسياسيل', keys: ['asiacell'], domains: ['asiacell.com'] },
        { name: 'أدوبي', keys: ['adobe'], domains: ['adobe.com', 'adobe.io', 'adobelogin.com'] },
        { name: 'DocuSign', keys: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
        { name: 'ديسكورد', keys: ['discord'], domains: ['discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net', 'discord.media'] },
        { name: 'سبوتيفاي', keys: ['spotify'], domains: ['spotify.com', 'spotify.link', 'scdn.co'] },
        { name: 'روبلوكس', keys: ['roblox'], domains: ['roblox.com', 'rbxcdn.com'] },
        { name: 'Coinbase', keys: ['coinbase'], domains: ['coinbase.com'] },
        { name: 'MetaMask', keys: ['metamask'], domains: ['metamask.io'] },
        { name: 'Trust Wallet', keys: ['trustwallet'], domains: ['trustwallet.com', 'link.trustwallet.com'] },
        { name: 'جامعة تكريت', keys: [], domains: ['tu.edu.iq'] },
        { name: 'وزارة التعليم العالي والبحث العلمي', keys: ['mohesr'], domains: ['mohesr.gov.iq'] }
    ];

    // نطاقات حقيقية تشبه أسماء علامات لكنها ليست انتحالاً
    const LOOKALIKE_ALLOWLIST = new Set(['telegraph.co.uk', 'paypay.ne.jp']);

    // كلمات إذا جاءت مع اسم علامة عامة (مثل apple) صار النطاق مريباً: appleid-apple.com / apple-id-locked.online
    const BRAND_HELPER_WORDS = new Set(['id', 'support', 'care', 'login', 'signin', 'secure', 'security', 'verify', 'account', 'billing', 'unlock', 'locked', 'help', 'service', 'pay', 'store']);

    // منصات رسمية لكنها تستضيف صفحات ونماذج وملفات يكتبها أي شخص، فالنطاق وحده لا يثبت صاحب المحتوى
    const USER_CONTENT_HOSTS = [
        'sites.google.com', 'forms.gle', 'docs.google.com', 'drive.google.com', 'script.google.com', 'storage.googleapis.com',
        'firebasestorage.googleapis.com', 'sharepoint.com', '1drv.ms', 'onedrive.live.com', 'forms.office.com', 'dropbox.com',
        'githubusercontent.com', 'amazonaws.com', 't.me', 'wa.me', 'telegra.ph', 'canva.com'
    ];

    const MULTI_PART_SUFFIXES = new Set([
        'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'edu.au', 'co.jp', 'ne.jp', 'or.jp',
        'com.br', 'com.tr', 'co.in', 'com.sa', 'gov.sa', 'edu.sa', 'com.eg', 'gov.eg', 'edu.eg', 'com.iq',
        'edu.iq', 'gov.iq', 'org.iq', 'net.iq', 'co.kr', 'com.cn', 'com.mx', 'co.za', 'com.jo', 'gov.jo',
        'com.kw', 'com.qa', 'co.ae', 'gov.ae', 'ac.ae', 'com.lb', 'com.sy', 'com.om', 'com.bh', 'co.il'
    ]);

    // استضافات مجانية وأنفاق: أي شخص يقدر يفتح عليها موقعاً خلال دقائق
    const HOSTING_SUFFIXES = new Set([
        'github.io', 'netlify.app', 'vercel.app', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com',
        'glitch.me', 'herokuapp.com', 'onrender.com', 'repl.co', 'replit.app', 'replit.dev', '000webhostapp.com',
        'weebly.com', 'wixsite.com', 'blogspot.com', 'ngrok.io', 'ngrok-free.app', 'ngrok.app',
        'trycloudflare.com', 'duckdns.org', 'no-ip.org', 'ddns.net', 'azurewebsites.net', 'appspot.com',
        'surge.sh', 'fly.dev', 'railway.app', 'godaddysites.com', 'square.site', 'webflow.io', 'framer.website'
    ]);

    const SHORTENERS = new Set([
        'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'v.gd', 'buff.ly', 'cutt.ly',
        'rebrand.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 's.id', 't.ly', 'shorte.st', 'adf.ly', 'tr.im', 'qr.ae'
    ]);

    const RISKY_TLDS = new Set([
        'zip', 'mov', 'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'country', 'kim', 'work', 'support',
        'rest', 'fit', 'loan', 'men', 'cam', 'quest', 'icu', 'buzz', 'monster', 'cyou', 'sbs', 'cfd', 'bond',
        'win', 'bid', 'review', 'party', 'stream', 'download', 'racing', 'date', 'faith', 'link', 'live', 'online', 'site'
    ]);

    const SENSITIVE_KEYWORDS = [
        'login', 'log-in', 'signin', 'sign-in', 'verify', 'verification', 'validate', 'update', 'secure', 'security',
        'account', 'banking', 'wallet', 'password', 'confirm', 'unlock', 'suspend', 'billing', 'payment', 'otp',
        'recover', 'webscr', 'auth', 'session', 'invoice', 'bonus', 'prize', 'reward', 'claim', 'gift'
    ];

    const REDIRECT_PARAMS = /^(url|u|q|r|redirect|redirect_uri|redirect_url|redir|next|target|dest|destination|continue|return|returnurl|return_to|goto|link|out|to)$/i;

    // لا نضع js و com هنا: node.js اسم وسم/مكتبة، و amazon.com قد يظهر في نهاية مسار عادي، فيعطيان إنذارات كاذبة
    const DANGEROUS_DOWNLOADS = ['exe', 'scr', 'pif', 'msi', 'bat', 'cmd', 'vbs', 'vbe', 'wsf', 'hta', 'ps1', 'jar', 'apk', 'lnk', 'iso', 'img', 'dll'];
    const ARCHIVE_DOWNLOADS = ['zip', 'rar', '7z', 'gz', 'tar', 'cab'];

    // يكشف الأسماء العشوائية (DGA): عشوائية عالية + سلاسل حروف ساكنة طويلة + خلط أرقام وحروف
    function looksRandom(label) {
        const clean = String(label || '').toLowerCase().replace(/-/g, '');
        if (clean.length < 10 || !/^[a-z0-9]+$/.test(clean)) return false;
        const counts = {};
        for (const ch of clean) counts[ch] = (counts[ch] || 0) + 1;
        let entropy = 0;
        for (const n of Object.values(counts)) { const p = n / clean.length; entropy -= p * Math.log2(p); }
        const vowels = (clean.match(/[aeiou]/g) || []).length / clean.length;
        const longestConsonants = Math.max(0, ...(clean.match(/[bcdfghjklmnpqrstvwxz]+/g) || ['']).map(r => r.length));
        const digitSwitches = (clean.match(/[a-z][0-9]|[0-9][a-z]/g) || []).length;
        let points = 0;
        if (entropy >= 3.5) points++;
        if (vowels < 0.22) points++;
        if (longestConsonants >= 5) points++;
        if (digitSwitches >= 3) points++;
        return points >= 3;
    }

    function splitDomain(host) {
        const labels = host.split('.').filter(Boolean);
        let suffixLength = 1;
        let isHosting = false;
        for (const k of [3, 2]) {
            if (labels.length <= k) continue;
            const suffix = labels.slice(-k).join('.');
            if (HOSTING_SUFFIXES.has(suffix)) { suffixLength = k; isHosting = true; break; }
            if (MULTI_PART_SUFFIXES.has(suffix)) { suffixLength = k; break; }
        }
        const suffix = labels.slice(-suffixLength).join('.');
        const registrable = labels.slice(-(suffixLength + 1)).join('.');
        const label = labels.length > suffixLength ? labels[labels.length - suffixLength - 1] : labels[0] || '';
        const subdomains = labels.slice(0, Math.max(0, labels.length - suffixLength - 1));
        return { labels, suffix, registrable, label, subdomains, isHosting };
    }

    function officialBrandFor(host) {
        for (const brand of BRANDS) {
            for (const domain of brand.domains) {
                if (host === domain || host.endsWith('.' + domain)) return { brand, domain };
            }
        }
        return null;
    }

    function isIPv4(host) {
        return /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(host) && host.split('.').every(p => Number(p) <= 255);
    }

    function isPrivateIPv4(host) {
        const [a, b] = host.split('.').map(Number);
        return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254);
    }

    function cleanUrlInput(raw) {
        let text = String(raw || '').trim().replace(/^[<"'(\[]+|[>"')\]]+$/g, '');
        let defanged = false;
        if (/^hxxps?:/i.test(text) || /\[\.\]|\(\.\)|\[dot\]/i.test(text)) {
            defanged = true;
            text = text.replace(/^hxxp/i, 'http').replace(/\[\.\]|\(\.\)|\[dot\]/gi, '.').replace(/\[:\]/g, ':');
        }
        return { text, defanged };
    }

    // يستخرج اسم المضيف كما كتبه المستخدم قبل أن يحوله المتصفح (حتى نكشف الأحرف الدولية والعناوين الرقمية المموهة)
    function rawHostOf(text) {
        const match = /^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i.exec(text);
        if (!match) return '';
        return match[1].replace(/^.*@/, '').replace(/:\d+$/, '').toLowerCase();
    }

    // ------------------------------------------------------------------
    // تحليل الروابط
    // ------------------------------------------------------------------

    function matchBrand(host, parts, pathAndQuery) {
        if (LOOKALIKE_ALLOWLIST.has(parts.registrable)) return null;
        let best = null;
        const consider = candidate => {
            if (!best || candidate.weight > best.weight) best = candidate;
        };
        const label = parts.label;
        const tokens = label.split('-').filter(t => t.length >= 3);
        const subdomainText = parts.subdomains.join('.');

        for (const brand of BRANDS) {
            // نطاق رسمي كامل موضوع كنطاق فرعي: paypal.com.secure-login.xyz
            for (const domain of brand.domains) {
                if (subdomainText && (subdomainText === domain || subdomainText.endsWith('.' + domain) || subdomainText.includes(domain + '.') || subdomainText.startsWith(domain))) {
                    consider({ brand, weight: 0.85, kind: 'subdomain', text: `اسم النطاق الرسمي (${domain}) موضوع في بداية الرابط لخداعك، بينما الموقع الحقيقي هو ${parts.registrable}.` });
                }
            }
            for (const key of brand.keys) {
                if (parts.subdomains.some(sub => sub.split('-').some(token => deLeetVariants(token).includes(key)))) {
                    consider({ brand, weight: 0.75, kind: 'subdomain', text: `اسم "${key}" مستخدم كنطاق فرعي على موقع لا علاقة له بـ${brand.name} (${parts.registrable}).` });
                }
                if (label === key) {
                    const ccLike = parts.suffix.length === 2 || parts.suffix.includes('.');
                    consider({
                        brand, weight: ccLike ? 0.15 : 0.45, kind: 'tld',
                        text: `الاسم مطابق لـ${brand.name} لكن بامتداد (.${parts.suffix}) غير مسجل لدينا كنطاق رسمي لها. بعض الشركات تملك نطاقات دولية، فتأكد قبل إدخال أي بيانات.`
                    });
                    continue;
                }
                const isGeneric = (brand.generic || []).includes(key);
                const flat = label.replace(/-/g, '');
                // الاسم العام (apple) ما نعلّمه إلا إذا رافقته كلمة مساعدة مثل id / support / locked
                const hasHelper = label.replace(key, '-').split('-').filter(Boolean).some(t => BRAND_HELPER_WORDS.has(t));
                const shortExact = key.length === 3 && tokens.includes(key) && label !== key;
                if ((!isGeneric && key.length >= 4 && flat.includes(key)) || (isGeneric && label.includes(key) && hasHelper) || shortExact) {
                    consider({ brand, weight: 0.75, kind: 'combo', text: `النطاق ${parts.registrable} يدمج اسم ${brand.name} مع كلمات إضافية (Combosquatting)، وهو ليس نطاقها الرسمي.` });
                }
                for (const candidate of [label.replace(/-/g, ''), ...tokens]) {
                    for (const variant of deLeetVariants(candidate)) {
                        if (variant === key && candidate !== key) {
                            consider({ brand, weight: 0.88, kind: 'homoglyph', text: `النطاق يستبدل حروفاً بأرقام أو رموز مشابهة ("${candidate}" بدلاً من "${key}") لانتحال ${brand.name}.` });
                            continue;
                        }
                        if (key.length < 5 || variant === key) continue;
                        const distance = editDistance(variant, key);
                        const allowed = key.length >= 8 ? 2 : 1;
                        if (distance > 0 && distance <= allowed) {
                            consider({
                                brand, weight: 0.8, kind: 'typo',
                                text: `النطاق "${candidate}" قريب جداً من "${key}" (فرق ${distance} حرف، تشابه ${Math.round(similarity(variant, key) * 100)}%). هذا انتحال لـ${brand.name} بالأخطاء الإملائية (Typosquatting).`
                            });
                        }
                    }
                }
                if (key.length >= 5 && pathAndQuery.includes(key)) {
                    consider({ brand, weight: 0.15, kind: 'path', text: `اسم ${brand.name} موجود في مسار الرابط على موقع لا يتبع لها (${parts.registrable}).` });
                }
            }
        }
        return best;
    }

    function analyzeUrl(rawInput, options = {}) {
        const strict = Boolean(options.strict);
        const depth = options.depth || 0;
        const thresholds = strict ? STRICT_THRESHOLDS : THRESHOLDS;
        const signals = [];
        const add = (weight, type, text) => signals.push({ weight, type, text });

        const cleaned = cleanUrlInput(rawInput);
        let text = cleaned.text;
        if (!text) return { error: 'empty' };
        if (cleaned.defanged) add(0, 'info', 'الرابط مكتوب بصيغة معطّلة (hxxp أو [.]) وتمت إعادته لصيغته الأصلية لغرض الفحص.');

        const scheme = (/^([a-z][a-z0-9+.-]*):/i.exec(text) || [])[1];
        if (scheme && /^(javascript|data|vbscript|file|blob)$/i.test(scheme)) {
            add(0.9, 'danger', `الرابط يستخدم بروتوكول ${scheme}: الذي يشغّل كوداً أو يفتح ملفات محلية مباشرة بدلاً من فتح موقع.`);
            return finish(signals, thresholds, { input: text, host: '', official: null });
        }
        if (!scheme || !/^https?$/i.test(scheme)) {
            if (scheme && !/^[a-z0-9-]+\.[a-z]/i.test(text)) {
                // مثل mailto: أو tel: : ليس رابط موقع
                add(0.1, 'warning', `الرابط من نوع ${scheme}: وليس صفحة ويب.`);
                return finish(signals, thresholds, { input: text, host: '', official: null });
            }
            text = (text.startsWith('//') ? 'http:' : 'http://') + text;
            add(0, 'info', 'لم يُذكر البروتوكول في الرابط، فافترضنا http:// لغرض الفحص.');
        }

        let url;
        try {
            url = new URL(text);
        } catch {
            return { error: 'invalid' };
        }

        // المتصفحات تختلف في قبول المسافات والرموز داخل اسم النطاق (Chrome يحوّلها إلى %20 وNode يرفضها)،
        // فنتحقق بأنفسنا حتى يكون السلوك واحداً في كل بيئة.
        const rawHost = rawHostOf(text);
        if (/\s/.test(rawHost) || !/^(\[[0-9a-f:.]+\]|[a-z0-9_.\-¡-￿]+)$/i.test(url.hostname)) return { error: 'invalid' };
        const host = url.hostname.toLowerCase().replace(/\.$/, '');
        const unicodeHost = hostToUnicode(host);
        const parts = splitDomain(host);
        const official = officialBrandFor(host);
        const pathAndQuery = (url.pathname + url.search).toLowerCase();

        // 1. البروتوكول
        if (url.protocol === 'http:') add(0.2, 'warning', 'الاتصال غير مشفر (HTTP)، ويمكن اعتراض أو تعديل ما ترسله للموقع.');
        else add(0, 'info', 'الاتصال مشفر (HTTPS). تنبيه: معظم مواقع التصيد اليوم تستخدم HTTPS أيضاً، فوجود القفل لا يعني أن الموقع موثوق.');

        // 2. بيانات قبل علامة @
        if (url.username || url.password) {
            const fake = decodeURIComponent(url.username + (url.password ? ':' + url.password : ''));
            add(official ? 0.3 : 0.6, 'danger', `الرابط يحتوي "${fake}@" في بدايته. المتصفح يتجاهل كل ما قبل @، والموقع الذي سيفتح فعلاً هو ${host}.`);
        }

        // 3. المنفذ
        if (url.port && !['80', '443'].includes(url.port)) add(0.2, 'warning', `الرابط يستخدم منفذاً غير معتاد (${url.port})، وهذا شائع في الخوادم المؤقتة.`);

        // 4. الإعادة التوجيه داخل الرابط
        for (const [key, value] of url.searchParams) {
            if (!REDIRECT_PARAMS.test(key) || !/^(https?:)?\/\//i.test(value)) continue;
            let target;
            try { target = new URL(value.startsWith('//') ? 'http:' + value : value); } catch { continue; }
            if (target.hostname === host) continue;
            add(0.3, 'warning', `الرابط يعيد توجيهك تلقائياً إلى موقع آخر: ${target.hostname} (عبر المعامل ${key}).`);
            if (depth < 1) {
                const nested = analyzeUrl(value, { strict, depth: depth + 1 });
                if (!nested.error && nested.level === 'danger') {
                    add(0.6, 'danger', `الوجهة النهائية ${target.hostname} نفسها تحمل مؤشرات تصيد (${nested.score}%).`);
                }
            }
            break;
        }

        // 5. التنزيلات الخطرة
        const fileExt = (/\.([a-z0-9]{1,5})$/i.exec(url.pathname) || [])[1];
        if (fileExt && DANGEROUS_DOWNLOADS.includes(fileExt.toLowerCase())) {
            add(official ? 0.1 : 0.5, 'warning', `الرابط يُنزّل ملفاً تنفيذياً مباشرة (.${fileExt.toLowerCase()}). نزّل البرامج من موقعها الرسمي فقط.`);
        } else if (fileExt && ARCHIVE_DOWNLOADS.includes(fileExt.toLowerCase())) {
            add(0.15, 'warning', `الرابط يُنزّل ملفاً مضغوطاً (.${fileExt.toLowerCase()})، وقد يحتوي برامج تنفيذية.`);
        }

        if (official) {
            const userContent = USER_CONTENT_HOSTS.find(d => host === d || host.endsWith('.' + d));
            if (userContent) {
                // نطاق رسمي لكن المحتوى لأي شخص: لا نعلّمه آمناً، ونفحص المسار
                add(0.2, 'warning', `${host} منصة رسمية، لكنها تسمح لأي شخص بنشر صفحات ونماذج وملفات عليها. الرابط يثبت المنصة فقط، وليس صاحب المحتوى.`);
                const other = BRANDS.find(b => b !== official.brand && b.keys.some(k => k.length >= 5 && pathAndQuery.includes(k)));
                if (other) add(0.2, 'warning', `الصفحة تذكر اسم ${other.name} بينما هي منشورة على منصة طرف ثالث.`);
                const pathKeywords = SENSITIVE_KEYWORDS.filter(k => pathAndQuery.includes(k)).slice(0, 3);
                if (pathKeywords.length) add(0.15, 'warning', `كلمات حساسة في المسار: ${pathKeywords.join('، ')}.`);
                if (other && pathKeywords.length) add(0.3, 'danger', `صفحة تدّعي أنها تتبع ${other.name} وتطلب تسجيل دخول أو بيانات، وهي منشورة على منصة طرف ثالث.`);
            } else {
                add(0, 'safe', `النطاق ${official.domain} من النطاقات الرسمية المعروفة لـ${official.brand.name}.`);
            }
            return finish(signals, thresholds, { input: url.href, host, unicodeHost, registrable: parts.registrable, official: official.brand.name });
        }

        // 6. عنوان IP بدلاً من اسم نطاق
        if (host.startsWith('[')) {
            add(0.45, 'danger', 'الرابط يستخدم عنوان IPv6 مباشر بدلاً من اسم نطاق.');
        } else if (isIPv4(host)) {
            const obfuscated = rawHost && rawHost !== host;
            if (obfuscated) add(0.7, 'danger', `عنوان IP مموّه (${rawHost}) يتحول فعلياً إلى ${host}. هذا تمويه متعمد.`);
            else add(0.45, 'danger', 'الرابط يستخدم عنوان IP مباشر بدلاً من اسم نطاق، وهذا نادر في المواقع الرسمية.');
            if (isPrivateIPv4(host)) add(0, 'info', 'العنوان من نطاق شبكة داخلية (مثل الراوتر أو جهاز محلي).');
        }

        // 7. أحرف دولية وانتحال بالأحرف المتشابهة
        if (unicodeHost !== host || /[^\x00-\x7f]/.test(rawHost)) {
            const shown = /[^\x00-\x7f]/.test(rawHost) ? rawHost : unicodeHost;
            const labelsUnicode = shown.split('.');
            const mixed = labelsUnicode.some(l => {
                const s = scriptsOf(l);
                return s.has('latin') && (s.has('cyrillic') || s.has('greek'));
            });
            const skeleton = asciiSkeleton(shown);
            const skeletonOfficial = officialBrandFor(skeleton);
            const skeletonParts = splitDomain(skeleton);
            const skeletonBrand = skeletonOfficial
                ? { brand: skeletonOfficial.brand }
                : BRANDS.find(b => b.keys.includes(skeletonParts.label)) ? { brand: BRANDS.find(b => b.keys.includes(skeletonParts.label)) } : null;
            if (skeletonBrand) {
                add(0.92, 'danger', `النطاق ${shown} مكتوب بأحرف غير لاتينية تشبه تماماً اسم ${skeletonBrand.brand.name} (هجوم Homograph). شكله في المتصفح: ${host}.`);
            } else if (mixed) {
                add(0.7, 'danger', `النطاق يخلط أحرفاً لاتينية مع أحرف كيريلية أو يونانية متشابهة الشكل (${shown}).`);
            } else {
                add(0.2, 'warning', `النطاق يستخدم أحرفاً دولية (${shown}). تأكد أنه الموقع المقصود.`);
            }
        }

        // 8. انتحال العلامات التجارية
        const brandMatch = matchBrand(host, parts, pathAndQuery);
        if (brandMatch) add(brandMatch.weight, brandMatch.weight >= 0.45 ? 'danger' : 'warning', brandMatch.text);

        // امتداد نطاق داخل النطاق الفرعي (bankofamerica.com.verify.cf): أسلوب لتقليد موقع لا نعرفه مسبقاً
        const embeddedTld = parts.subdomains.find(s => ['com', 'net', 'org', 'gov', 'edu', 'info'].includes(s));
        if (embeddedTld && !brandMatch) {
            add(0.45, 'danger', `النطاق الفرعي يحتوي (.${embeddedTld}) كأنه عنوان موقع آخر، بينما الموقع الفعلي هو ${parts.registrable}.`);
        }

        // 9. انتحال النطاقات الجامعية والحكومية العراقية
        const isIraqiOfficialSuffix = parts.suffix === 'edu.iq' || parts.suffix === 'gov.iq';
        if (!isIraqiOfficialSuffix && /(edu|gov)[.-]?iq/.test(host)) {
            add(0.8, 'danger', `الرابط يقلّد نطاقاً جامعياً أو حكومياً عراقياً، لكن النطاق الحقيقي هو ${parts.registrable} وليس .edu.iq أو .gov.iq.`);
        } else if (isIraqiOfficialSuffix && strict) {
            add(0.2, 'warning', `النطاق ${parts.registrable} عراقي رسمي لكنه غير موجود في قائمة النطاقات المعتمدة لدينا. تأكد أنه للجهة الصحيحة.`);
        }

        // 10. اختصار الروابط والاستضافة المجانية والامتدادات الخطرة
        if (SHORTENERS.has(parts.registrable) || SHORTENERS.has(host)) {
            add(0.3, 'warning', 'رابط مختصر يخفي الوجهة الحقيقية. افتحه بخدمة توسيع الروابط قبل الدخول.');
        }
        if (parts.isHosting) {
            add(0.15, 'warning', `الموقع مستضاف على خدمة مجانية (${parts.suffix}) يستطيع أي شخص فتح موقع عليها خلال دقائق.`);
        }
        const tld = parts.labels[parts.labels.length - 1] || '';
        if (RISKY_TLDS.has(tld)) {
            const confusing = tld === 'zip' || tld === 'mov' ? ' هذا الامتداد يشبه اسم ملف، ويُستغل لخداع المستخدمين.' : '';
            add(0.25, 'warning', `امتداد النطاق (.${tld}) منخفض التكلفة ويكثر استخدامه في حملات التصيد.${confusing}`);
        }

        // 11. كلمات حساسة في رابط غير رسمي
        const haystack = host + pathAndQuery;
        const keywords = SENSITIVE_KEYWORDS.filter(k => haystack.includes(k)).slice(0, 4);
        if (keywords.length) {
            add(Math.min(0.12 + 0.06 * (keywords.length - 1), 0.35), 'warning', `كلمات تُستخدم عادة في صفحات سرقة البيانات: ${keywords.join('، ')}.`);
            if (brandMatch && brandMatch.kind === 'path') {
                add(0.4, 'danger', `الصفحة تحمل اسم ${brandMatch.brand.name} وتطلب (${keywords.slice(0, 2).join('، ')}) لكنها ليست على موقعها الرسمي.`);
            }
        }

        // 12. بنية النطاق والرابط
        if (parts.subdomains.length >= 3) add(0.2, 'warning', `عدد كبير من النطاقات الفرعية (${parts.subdomains.length})، وهي طريقة لإخفاء النطاق الحقيقي في نهاية الرابط.`);
        const hyphens = (parts.label.match(/-/g) || []).length;
        if (hyphens >= 2) add(hyphens >= 3 ? 0.2 : 0.12, 'warning', `اسم النطاق فيه ${hyphens} شرطات (-)، وهذا شائع في نطاقات التصيد.`);
        if ((parts.label.match(/\d/g) || []).length >= 4) add(0.1, 'warning', 'اسم النطاق يحتوي أرقاماً كثيرة.');
        if (host.length > 45) add(0.1, 'warning', `اسم المضيف طويل بشكل غير معتاد (${host.length} حرفاً).`);
        // اسم عشوائي المظهر (مولَّد آلياً): شائع في نطاقات الحملات المؤقتة والبرمجيات الخبيثة
        if (!isIPv4(host) && looksRandom(parts.label)) add(0.2, 'warning', `اسم النطاق "${parts.label}" يبدو عشوائياً ومولَّداً آلياً، وهذا شائع في النطاقات المؤقتة للحملات الخبيثة.`);
        if (url.href.length > 120) add(0.1, 'warning', `الرابط طويل جداً (${url.href.length} حرفاً)، وقد يكون لإخفاء الجزء المهم.`);
        if (/\/\//.test(url.pathname)) add(0.1, 'warning', 'المسار يحتوي "//" إضافية، وتُستخدم أحياناً لإعادة التوجيه.');
        if ((url.pathname.match(/%[0-9a-f]{2}/gi) || []).length >= 6) add(0.1, 'warning', 'المسار مليء بالترميز (%xx)، وقد يكون لإخفاء محتواه.');

        if (!signals.some(s => s.weight >= 0.1)) {
            add(0, 'safe', 'لم تُرصد مؤشرات خطر في بنية الرابط. هذا لا يضمن أن محتوى الموقع نفسه آمن.');
        }

        return finish(signals, thresholds, {
            input: url.href, host, unicodeHost, registrable: parts.registrable, official: null,
            brand: brandMatch ? brandMatch.brand.name : null
        });
    }

    // ------------------------------------------------------------------
    // تحليل الرسائل والنصوص
    // ------------------------------------------------------------------

    function normalizeArabic(text) {
        return String(text || '')
            .toLowerCase()
            .replace(/[ً-ٰٟ]/g, '')
            .replace(/ـ/g, '')
            .replace(/[أإآٱ]/g, 'ا')
            .replace(/ى/g, 'ي')
            .replace(/ة/g, 'ه')
            .replace(/ؤ/g, 'و')
            .replace(/ئ/g, 'ي')
            .replace(/[٠-٩]/g, d => String(d.charCodeAt(0) - 0x0660))
            .replace(/[۰-۹]/g, d => String(d.charCodeAt(0) - 0x06F0))
            .replace(/\s+/g, ' ')
            .trim();
    }

    const W = '(?:\\S+\\s+)'; // كلمة واحدة بين العبارات
    const rx = (source) => new RegExp(source, 'i');

    const TEXT_RULES = [
        {
            id: 'credentials', label: 'طلب بيانات سرية', weight: 0.5, patterns: [
                rx('(رمز|كود|رقم)\\s*(ال)?(تحقق|تفعيل|تاكيد|امان|سري)'),
                rx(`(دز|دزلي|ارسل|ارسلي|ارسلها|ابعث|ابعتلي|ابعثلي|شارك|اعطيني|انطيني|زودنا|زودني)\\s*${W}{0,3}?(ال)?(رمز|كود|otp|باسورد|كلمه)`),
                rx(`(الرمز|الكود)\\s*${W}{0,2}?(اللي|الذي|الي)\\s*(وصلك|وصل|اجاك|راح يوصلك|سيصلك)`),
                rx('كلمه\\s*(ال)?(سر|مرور)'), rx('الرقم السري'), rx('\\b(otp|pin|cvv|cvc|password|passcode)\\b'),
                rx('verification code|security code|one[- ]time (pass)?code'),
                rx('رقم\\s*(ال)?بطاق'), rx('(تاريخ|سنه)\\s*(ال)?(انتهاء|صلاحيه)'), rx('بيانات\\s*(ال)?(بطاق|دخول|حساب)'),
                rx('credit card|card number|login details|bank details')
            ]
        },
        {
            id: 'threat', label: 'تهديد بإيقاف أو إغلاق', weight: 0.35, patterns: [
                rx(`(تجميد|ايقاف|توقيف|تعليق|اغلاق|غلق|حظر|قفل|تعطيل|الغاء|حذف)\\s*${W}{0,2}?(ال)?(حساب|بطاق|محفظ|خط|رقم|اشتراك|راتب|رصيد)`),
                rx('(سيتم|راح|رح|حيتم|سوف)\\s*(يتم\\s*)?(حذف|اغلاق|ايقاف|حظر|تجميد|تعطيل|قطع|الغاء|ينقفل|ينحظر|ينغلق|ينحذف)'),
                rx('(محاوله|محاولات)\\s*(دخول|تسجيل)\\s*(مشبوه|غير)'), rx('نشاط\\s*(مشبوه|غير طبيعي|غير معتاد)'),
                rx('(account|card)\\s+(has been\\s+|was\\s+|is\\s+|will be\\s+)?(suspended|locked|disabled|blocked|limited|restricted|closed|deactivated)'),
                rx('unusual (activity|sign[- ]?in)|suspicious (activity|login)'),
                rx('legal action|عقوبه|غرامه|مساءله قانونيه')
            ]
        },
        {
            id: 'urgency', label: 'استعجال وضغط زمني', weight: 0.25, patterns: [
                rx('عاجل'), rx('فورا|فوري'), rx('خلال\\s*\\d+\\s*(ساعه|ساعات|دقيقه|دقايق|دقائق|يوم|ايام)'),
                rx('(اخر|نهائي)\\s*(فرصه|موعد|تنبيه|انذار|اشعار)'), rx('قبل فوات'), rx('لا\\s*(تتاخر|تتجاهل)'),
                rx('سارع|بادر'), rx('بسرعه|ضروري|حالا'), rx('ينتهي\\s*(اليوم|الليله|قريبا)'), rx('(الوقت|العرض)\\s*(محدود|ينتهي)'),
                rx('\\burgent\\b|immediately|right away|within \\d+ (hours?|minutes?|days?)|act now|final (notice|warning)|expires? (today|soon)|limited time|\\basap\\b')
            ]
        },
        {
            id: 'prize', label: 'وعد بجائزة أو ربح', weight: 0.35, patterns: [
                rx('مبروك|مبارك'), rx('ربحت|فزت|كسبت'), rx('جايزه|جوايز|جائزه'), rx('سحب\\s*(على|ال)'),
                rx('(هديه|هدايا|رصيد|انترنت|باقه)\\s*مجاني'), rx('مكافاه|مكافيه'), rx('تم\\s*اختيار(ك|كم)'), rx('الفايز|الفائز|الرابح'),
                rx('ايفون\\s*\\d*\\s*مجان|مجانا'),
                rx('you (have )?won|\\bwinner\\b|congratulations|\\bprize\\b|free gift|claim (your|now)|\\breward\\b|lottery|giveaway')
            ]
        },
        {
            id: 'payment', label: 'طلب دفع أو تحويل أموال', weight: 0.4, patterns: [
                rx(`(حول|حولي|حوللي|تحويل|ارسل|ادفع|دفع|اشحن|اشحنلي)\\s*${W}{0,2}?(مبلغ|رصيد|فلوس|اموال|دولار|دينار|رسوم|\\d+\\s*(\\$|دولار|الف|دينار))`),
                rx('رسوم\\s*(رمزيه|الشحن|شحن|تسجيل|التسجيل|تفعيل|جمرك|كمرك|توصيل|التوصيل|اداريه|معامله)'),
                rx('(كارت|بطاقه|بطاقات)\\s*(شحن|ايتونز|هدايا|جوجل بلاي|ستيم)'),
                rx('gift ?cards?|wire transfer|western union|moneygram|bitcoin|\\bbtc\\b|\\busdt\\b|crypto|processing fee|delivery fee|customs fee|pay (a|the) fee'),
                rx('(محفظه|محافظ)\\s*(رقميه|الكترونيه)')
            ]
        },
        {
            id: 'impersonation', label: 'انتحال جهة رسمية أو شركة', weight: 0.2, patterns: [
                rx('مصرف|بنك'), rx('الرافدين|الرشيد|كي كارد|\\b(ki|qi) ?card\\b|ماستر ?كارد|فيزا كارد'),
                rx('زين ?كاش|اسيا ?حواله|اسياسيل|كورك'), rx('وزاره|الشرطه|الامن الوطني|المحكمه|الضرايب|الضرائب|الكمارك|الجمارك'),
                rx('(فريق|قسم|اداره)\\s*(الدعم|الامان|الحمايه|الامن)'), rx('الدعم الفني'),
                rx('(اداره|فريق|دعم)\\s*(فيسبوك|فيس بوك|انستغرام|انستا|واتساب|تيك ?توك|تلكرام|تيليجرام)'),
                rx('\\b(dhl|aramex|fedex)\\b'),
                rx('(paypal|apple|microsoft|amazon|netflix|facebook|meta|whatsapp|instagram|bank) (support|security|team|service)')
            ]
        },
        {
            id: 'action', label: 'دفعك للضغط على رابط أو تسجيل الدخول', weight: 0.2, patterns: [
                rx(`(اضغط|انقر|دوس|اكبس|ادخل|افتح|زور)\\s*${W}{0,2}?(على\\s*)?(ال)?(رابط|لينك|هنا)`),
                rx('(سجل|تسجيل)\\s*(ال)?دخول'), rx(`(حدث|تحديث)\\s*${W}{0,1}?(ال)?(بيانات|معلومات|حساب)`),
                rx(`(تاكيد|اكد|تحقق من)\\s*${W}{0,1}?(ال)?(هويت|حساب|بيانات|معلومات)`),
                rx('click (here|the link|below|on the link)|log ?in (now|here|to)|sign ?in to|verify (your )?(account|identity|information)|update your (details|information|account|payment)|confirm your (account|identity|details)')
            ]
        },
        {
            id: 'greeting', label: 'تحية عامة مجهولة', weight: 0.1, patterns: [
                rx('عزيزي\\s*(ال)?(عميل|مستخدم|مشترك|زبون|مواطن)'),
                rx('dear (customer|user|client|member|valued|account holder)')
            ]
        },
        {
            id: 'job', label: 'عرض عمل أو استثمار مشبوه', weight: 0.35, patterns: [
                rx('(عمل|شغل|وظيفه)\\s*(من|بال)\\s*(المنزل|البيت)'), rx('(ربح|دخل|راتب)\\s*(يومي|خيالي|مغري|مضمون)'),
                rx('بدون\\s*(خبره|راس مال|شهاده)'), rx('(استثمار|ارباح|عوايد|عوائد|عايد|عائد)\\s*(مضمون|يومي|اسبوعي)'),
                rx('ضاعف\\s*(اموالك|فلوسك|رصيدك|راس مالك)'), rx('\\d+\\s*%\\s*(ربح|ارباح|فايده|فائده|عايد|عائد)'),
                rx('work from home|guaranteed (profit|returns?|income)|double your (money|investment)|earn \\$?\\d+ (per|a) (day|week)|investment opportunity|no experience (needed|required)')
            ]
        },
        {
            id: 'grant', label: 'منحة أو سلفة أو قرض عبر رابط', weight: 0.3, patterns: [
                rx('(منحه|منح)\\s*(ماليه|نقديه|حكوميه|الطلبه|للطلبه|العاطلين|الشباب)'),
                rx('(سلفه|سلف|قرض|قروض)\\s*(بدون|بلا)\\s*(فوايد|فوائد|كفيل|ضمان)'),
                rx(`(رابط|استماره)\\s*${W}{0,1}?(التقديم|التسجيل)\\s*${W}{0,2}?(على|ب)?\\s*(ال)?(منحه|سلفه|قرض|وظايف|وظائف|التعيين)`),
                rx('(التقديم|التسجيل)\\s*على\\s*(ال)?(منحه|سلفه|القرض)'),
                rx('government grant|free grant|loan without (interest|guarantor)')
            ]
        },
        {
            id: 'secrecy', label: 'طلب السرية أو العزل', weight: 0.25, patterns: [
                rx(`لا\\s*(تخبر|تقول|تكول|تحجي|تشارك)\\s*${W}{0,1}?(احد|اي شخص|لاحد|هذه|هاي)`),
                rx('سري\\s*(للغايه|جدا)|بيني وبينك'),
                rx("keep (this|it) (secret|confidential|between us)|do ?n[o']?t tell (anyone|anybody)")
            ]
        },
        {
            id: 'channel', label: 'نقل المحادثة إلى قناة أخرى', weight: 0.15, patterns: [
                rx(`(تواصل|راسل|كلم|احجي)\\s*${W}{0,1}?(عبر|على|ب)\\s*(ال)?(واتساب|واتس|تليجرام|تلكرام|تلغرام|الخاص)`),
                rx('contact (us|me) (on|via) (whatsapp|telegram)')
            ]
        }
    ];

    const TEXT_COMBOS = [
        { all: 'credentials', any: ['threat', 'urgency', 'impersonation'], weight: 0.4, text: 'طلب بيانات سرية مع تهديد أو استعجال أو باسم جهة رسمية: هذا نمط التصيد الكلاسيكي.' },
        { all: 'prize', any: ['payment', 'credentials', 'action'], weight: 0.35, text: 'وعد بجائزة يتطلب دفع رسوم أو إدخال بيانات: أسلوب احتيال معروف.' },
        { all: 'threat', any: ['action'], weight: 0.3, text: 'تهديد بإيقاف الحساب مع دفعك للضغط على رابط أو تسجيل الدخول.' },
        { all: 'job', any: ['payment'], weight: 0.35, text: 'عرض عمل أو استثمار يطلب دفع مبلغ مقدماً (Advance-fee scam).' },
        { all: 'impersonation', any: ['payment'], weight: 0.25, text: 'جهة تدّعي أنها رسمية وتطلب تحويل أموال.' },
        { all: 'grant', any: ['action', 'credentials', 'payment', 'link'], weight: 0.35, text: 'منحة أو قرض يُطلب التقديم عليه عبر رابط أو بإدخال بيانات: من أكثر أساليب الاحتيال انتشاراً بالعراق.' }
    ];

    const TEXT_ADVICE = {
        credentials: 'لا تشارك أي رمز تحقق أو كلمة سر مع أي شخص، حتى لو قال إنه من الدعم الفني أو البنك.',
        payment: 'لا تحوّل أي مبلغ قبل التحقق من الجهة عبر قناتها الرسمية.',
        threat: 'تواصل مع الجهة عبر رقمها أو تطبيقها الرسمي، وليس عبر الرابط أو الرقم الموجود في الرسالة.',
        prize: 'المسابقات الحقيقية لا تطلب رسوماً أو رمز تحقق لاستلام الجائزة.',
        job: 'الشركات الحقيقية لا تطلب من المتقدم دفع رسوم.',
        link: 'لا تفتح الرابط الموجود في الرسالة.'
    };

    const URL_IN_TEXT = /((?:hxxps?|https?):\/\/[^\s<>"'،]+|www\.[^\s<>"'،]+|(?:[a-z0-9-]+\.)+(?:com|net|org|info|xyz|top|iq|io|me|co|app|site|online|shop|click|link|ly|gl|tk|ml|ga|cf|gq|ru|cn|ws|cc|biz|live|support)(?:\/[^\s<>"'،]*)?)/gi;

    function extractUrls(text) {
        const found = [];
        for (const match of String(text).matchAll(URL_IN_TEXT)) {
            const url = match[0].replace(/[.,!?؟،)\]]+$/, '');
            if (!found.includes(url)) found.push(url);
            if (found.length >= 5) break;
        }
        return found;
    }

    function analyzeText(rawText) {
        const original = String(rawText || '').trim();
        if (!original) return { error: 'empty' };
        const normalized = normalizeArabic(original);
        const signals = [];
        const add = (weight, type, text) => signals.push({ weight, type, text });
        const hits = new Set();

        for (const rule of TEXT_RULES) {
            const matches = [];
            for (const pattern of rule.patterns) {
                const m = pattern.exec(normalized);
                if (m && !matches.includes(m[0].trim())) matches.push(m[0].trim());
                if (matches.length >= 2) break;
            }
            if (matches.length) {
                hits.add(rule.id);
                const weight = Math.min(rule.weight + 0.1 * (matches.length - 1), 0.6);
                add(weight, weight >= 0.35 ? 'danger' : 'warning', `${rule.label}: «${matches.join('»، «')}»`);
            }
        }

        // الروابط داخل الرسالة تُفحص بمحرك الروابط
        const urls = extractUrls(original).map(url => ({ url, result: analyzeUrl(url) })).filter(u => !u.result.error);
        if (urls.length) {
            hits.add('link');
            add(0.1, 'warning', `الرسالة تحتوي ${urls.length === 1 ? 'رابطاً' : urls.length + ' روابط'}.`);
            const worst = urls.reduce((a, b) => (b.result.score > a.result.score ? b : a));
            if (worst.result.level === 'danger') {
                const why = (worst.result.reasons.find(r => r.type === 'danger') || {}).text || '';
                add(0.6, 'danger', `الرابط ${worst.url} خطِر (${worst.result.score}%). ${why}`);
            } else if (worst.result.level === 'warning') {
                add(0.25, 'warning', `الرابط ${worst.url} عليه مؤشرات مخاطرة (${worst.result.score}%).`);
            }
        }

        // الأنماط المركّبة (بعد فحص الروابط حتى تدخل الروابط ضمنها)
        for (const combo of TEXT_COMBOS) {
            if (hits.has(combo.all) && combo.any.some(id => hits.has(id))) add(combo.weight, 'danger', combo.text);
        }

        const compact = normalized.replace(/(\d)[\s-](?=\d)/g, '$1');
        if (/(\+?964|00964|0)7[3-9]\d{8}/.test(compact)) {
            add(0.05, 'info', 'الرسالة تحتوي رقم هاتف. لا تتصل برقم موجود داخل رسالة مشبوهة؛ استخدم الرقم الرسمي للجهة.');
        }

        if (!signals.some(s => s.weight >= 0.1)) {
            add(0, 'safe', 'لم تُرصد أساليب هندسة اجتماعية معروفة في النص.');
        }

        const advice = [];
        for (const id of ['credentials', 'payment', 'threat', 'prize', 'job']) if (hits.has(id)) advice.push(TEXT_ADVICE[id]);
        if (urls.some(u => u.result.level !== 'safe')) advice.push(TEXT_ADVICE.link);

        return finish(signals, THRESHOLDS, {
            categories: Array.from(hits),
            urls: urls.map(u => ({ url: u.url, score: u.result.score, level: u.result.level })),
            advice
        });
    }

    // ------------------------------------------------------------------
    // تحليل الملفات
    // ------------------------------------------------------------------

    const EXT_FAMILIES = {
        executable: ['exe', 'dll', 'scr', 'pif', 'com', 'cpl', 'sys', 'msi', 'msix', 'appx', 'apk', 'jar', 'app', 'elf'],
        script: ['bat', 'cmd', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh', 'ps1', 'psm1', 'hta', 'sh', 'reg', 'scf', 'inf'],
        shortcut: ['lnk', 'url'],
        disk: ['iso', 'img', 'vhd', 'vhdx'],
        office: ['doc', 'docx', 'docm', 'dot', 'dotm', 'xls', 'xlsx', 'xlsm', 'xlsb', 'xlam', 'ppt', 'pptx', 'pptm', 'rtf', 'odt', 'ods', 'odp'],
        pdf: ['pdf'],
        archive: ['zip', 'rar', '7z', 'gz', 'tgz', 'tar', 'cab'],
        image: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'ico', 'svg'],
        audio: ['mp3', 'wav', 'ogg', 'oga', 'opus', 'flac', 'm4a', 'aac', 'wma', 'amr'],
        video: ['mp4', 'm4v', 'mov', 'webm', 'mkv', 'avi', 'wmv', '3gp'],
        web: ['html', 'htm', 'shtml', 'xhtml', 'mht', 'mhtml'],
        text: ['txt', 'csv', 'json', 'xml', 'md', 'log', 'ini', 'cfg', 'yml', 'yaml']
    };
    const MACRO_EXTENSIONS = ['docm', 'dotm', 'xlsm', 'xlam', 'pptm'];
    const SUSPICIOUS_NAME_WORDS = ['crack', 'keygen', 'patch', 'activator', 'loader', 'hack', 'cheat', 'injector', 'stealer', 'trojan', 'payload', 'exploit', 'free-robux', 'robux', 'generator', 'kms'];

    function familyOfExtension(ext) {
        for (const [family, list] of Object.entries(EXT_FAMILIES)) if (list.includes(ext)) return family;
        return 'other';
    }

    function hexAt(bytes, start, length) {
        let out = '';
        for (let i = start; i < start + length && i < bytes.length; i++) out += bytes[i].toString(16).toUpperCase().padStart(2, '0');
        return out;
    }

    function asciiAt(bytes, start, length) {
        let out = '';
        for (let i = start; i < start + length && i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
        return out;
    }

    function containsAscii(bytes, needle) {
        if (!bytes || !bytes.length) return false;
        const first = needle.charCodeAt(0);
        outer: for (let i = 0; i <= bytes.length - needle.length; i++) {
            if (bytes[i] !== first) continue;
            for (let j = 1; j < needle.length; j++) if (bytes[i + j] !== needle.charCodeAt(j)) continue outer;
            return true;
        }
        return false;
    }

    function containsUtf16(bytes, needle) {
        let encoded = '';
        for (const ch of needle) encoded += ch + '\0';
        return containsAscii(bytes, encoded);
    }

    function decodeText(bytes, limit) {
        const slice = bytes.subarray ? bytes.subarray(0, limit) : bytes.slice(0, limit);
        if (typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8', { fatal: false }).decode(slice);
        return Array.from(slice, b => String.fromCharCode(b)).join('');
    }

    function looksLikeText(bytes) {
        const sample = bytes.subarray ? bytes.subarray(0, 4096) : bytes.slice(0, 4096);
        if (!sample.length) return false;
        let control = 0;
        for (const b of sample) {
            if (b === 0) return false;
            if (b < 9 || (b > 13 && b < 32)) control++;
        }
        return control / sample.length < 0.02;
    }

    function shannonEntropy(bytes) {
        if (!bytes.length) return 0;
        const counts = new Array(256).fill(0);
        for (const b of bytes) counts[b]++;
        let entropy = 0;
        for (const c of counts) {
            if (!c) continue;
            const p = c / bytes.length;
            entropy -= p * Math.log2(p);
        }
        return entropy;
    }

    // قراءة ترويسة ملفات ويندوز التنفيذية (PE) لمعرفة: هل الملف موقّع؟ مضغوط؟ 32 أو 64 بت؟ .NET؟
    function parsePE(bytes) {
        try {
            if (bytes.length < 64 || bytes[0] !== 0x4D || bytes[1] !== 0x5A) return null;
            const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
            const peOffset = view.getUint32(0x3C, true);
            if (peOffset + 24 > bytes.length || asciiAt(bytes, peOffset, 4) !== 'PE\0\0') return { valid: false };
            const coff = peOffset + 4;
            const numberOfSections = view.getUint16(coff + 2, true);
            const timestamp = view.getUint32(coff + 4, true);
            const optionalSize = view.getUint16(coff + 16, true);
            const characteristics = view.getUint16(coff + 18, true);
            const optional = coff + 20;
            const magic = view.getUint16(optional, true);
            const is64 = magic === 0x20B;
            const dirBase = optional + (is64 ? 112 : 96);
            const dirCount = view.getUint32(optional + (is64 ? 108 : 92), true);
            const dir = index => (index < dirCount && dirBase + index * 8 + 8 <= bytes.length)
                ? { rva: view.getUint32(dirBase + index * 8, true), size: view.getUint32(dirBase + index * 8 + 4, true) }
                : { rva: 0, size: 0 };
            const security = dir(4);
            const clr = dir(14);
            const sections = [];
            const sectionTable = optional + optionalSize;
            for (let i = 0; i < Math.min(numberOfSections, 64); i++) {
                const start = sectionTable + i * 40;
                if (start + 8 > bytes.length) break;
                sections.push(asciiAt(bytes, start, 8).replace(/\0+$/, ''));
            }
            return {
                valid: true,
                is64,
                isDll: Boolean(characteristics & 0x2000),
                isDotNet: clr.size > 0,
                signed: security.size > 0 && security.rva > 0,
                timestamp,
                sections
            };
        } catch {
            return { valid: false };
        }
    }

    // تحديد نوع الملف الحقيقي من بايتاته الأولى (Magic Bytes)
    // يرجع البايتات التي تلي نهاية الصورة الفعلية (PNG: بعد IEND، JPEG: بعد EOI، GIF: بعد 0x3B)
    function imageTrailingData(bytes) {
        if (!bytes || bytes.length < 12) return null;
        const find = (marker, fromEnd) => {
            for (let i = bytes.length - marker.length; i >= 0; i--) {
                let ok = true;
                for (let j = 0; j < marker.length; j++) if (bytes[i + j] !== marker[j]) { ok = false; break; }
                if (ok) return i;
            }
            return -1;
        };
        const isPng = bytes[0] === 0x89 && bytes[1] === 0x50 || find([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]) >= 0;
        if (isPng) {
            const i = find([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]);   // IEND + CRC
            return i >= 0 ? bytes.subarray(i + 8) : null;
        }
        if (bytes[0] === 0xFF && bytes[1] === 0xD8) {
            const i = find([0xFF, 0xD9]);
            return i >= 0 ? bytes.subarray(i + 2) : null;
        }
        return null;
    }

    function hasEmbeddedPayloadMarkers(bytes) {
        const text = decodeText(bytes, 64 * 1024).toLowerCase();
        if (/<script|<\?php|powershell|cmd\.exe|eval\(|wscript|javascript:/.test(text)) return 'كوداً برمجياً (سكربت)';
        if (bytes[0] === 0x4D && bytes[1] === 0x5A) return 'برنامجاً تنفيذياً';
        if (containsAscii(bytes, 'MZ') && containsAscii(bytes, 'This program')) return 'برنامجاً تنفيذياً';
        if (bytes[0] === 0x50 && bytes[1] === 0x4B) return 'أرشيفاً مضغوطاً';
        return '';
    }

    function detectFileType(bytes, tail) {
        const head = bytes || new Uint8Array(0);
        const names = (needle) => containsAscii(head, needle) || containsAscii(tail, needle);
        if (head.length < 4) return { kind: 'unknown', label: 'ملف فارغ أو صغير جداً بلا بصمة معروفة' };
        const h2 = hexAt(head, 0, 2), h4 = hexAt(head, 0, 4);

        if (h2 === '4D5A') return { kind: 'executable', label: 'ملف تنفيذي لنظام Windows (EXE / DLL)' };
        if (h4 === '7F454C46') return { kind: 'executable', label: 'ملف تنفيذي لنظام Linux (ELF)' };
        if (['FEEDFACE', 'FEEDFACF', 'CEFAEDFE', 'CFFAEDFE', 'CAFEBABE'].includes(h4)) return { kind: 'executable', label: 'ملف تنفيذي (macOS Mach-O أو Java Class)' };
        if (hexAt(head, 0, 8) === '4C00000001140200') return { kind: 'shortcut', label: 'اختصار ويندوز (LNK)' };
        if (hexAt(head, 0, 8) === 'D0CF11E0A1B11AE1') return { kind: 'ole', label: 'مستند Office قديم (DOC/XLS/PPT) أو حزمة MSI' };
        if (h4 === '504B0304' || h4 === '504B0506' || h4 === '504B0708') {
            if (names('AndroidManifest.xml')) return { kind: 'executable', label: 'تطبيق أندرويد (APK)' };
            if (names('META-INF/MANIFEST.MF')) return { kind: 'executable', label: 'برنامج Java (JAR)' };
            if (names('[Content_Types].xml')) return { kind: 'ooxml', label: 'مستند Office حديث (DOCX / XLSX / PPTX)' };
            if (names('mimetypeapplication/vnd.oasis')) return { kind: 'ooxml', label: 'مستند OpenDocument' };
            return { kind: 'archive', label: 'أرشيف مضغوط (ZIP)' };
        }
        if (asciiAt(head, 0, 4) === 'Rar!') return { kind: 'archive', label: 'أرشيف مضغوط (RAR)' };
        if (hexAt(head, 0, 6) === '377ABCAF271C') return { kind: 'archive', label: 'أرشيف مضغوط (7z)' };
        if (h2 === '1F8B') return { kind: 'archive', label: 'أرشيف مضغوط (GZIP)' };
        if (asciiAt(head, 0, 4) === 'MSCF') return { kind: 'archive', label: 'أرشيف ويندوز (CAB)' };
        if (h4 === '25504446') return { kind: 'pdf', label: 'مستند PDF' };
        if (asciiAt(head, 0, 5) === '{\\rtf') return { kind: 'rtf', label: 'مستند RTF' };
        if (head.length > 0x8006 && asciiAt(head, 0x8001, 5) === 'CD001') return { kind: 'disk', label: 'صورة قرص (ISO)' };
        if (hexAt(head, 0, 3) === 'FFD8FF') return { kind: 'image', label: 'صورة JPG' };
        if (h4 === '89504E47') return { kind: 'image', label: 'صورة PNG' };
        if (asciiAt(head, 0, 4) === 'GIF8') return { kind: 'image', label: 'صورة GIF' };
        if (asciiAt(head, 0, 4) === 'RIFF' && asciiAt(head, 8, 4) === 'WEBP') return { kind: 'image', label: 'صورة WEBP' };
        if (asciiAt(head, 0, 5) === '#!AMR') return { kind: 'audio', label: 'صوت AMR' };
        if (asciiAt(head, 0, 3) === 'ID3') return { kind: 'audio', label: 'صوت MP3 (يحتوي وسم ID3)' };
        if (head[0] === 0xFF && (head[1] & 0xF6) === 0xF0) return { kind: 'audio', label: 'صوت AAC (ADTS)' };
        if (head[0] === 0xFF && (head[1] & 0xE0) === 0xE0) return { kind: 'audio', label: 'صوت MP3 (إطارات MPEG)' };
        if (asciiAt(head, 0, 4) === 'RIFF') {
            const riffType = asciiAt(head, 8, 4);
            if (riffType === 'WAVE') return { kind: 'audio', label: 'صوت WAV' };
            if (riffType === 'AVI ') return { kind: 'video', label: 'فيديو AVI' };
            return { kind: 'unknown', label: 'حاوية RIFF غير معروفة' };
        }
        if (asciiAt(head, 0, 4) === 'OggS') return { kind: 'media', label: 'حاوية Ogg (صوت أو فيديو)' };
        if (asciiAt(head, 0, 4) === 'fLaC') return { kind: 'audio', label: 'صوت FLAC' };
        if (asciiAt(head, 4, 4) === 'ftyp') {
            const brand = asciiAt(head, 8, 4);
            if (brand.startsWith('M4A') || brand.startsWith('M4B')) return { kind: 'audio', label: 'صوت M4A' };
            if (brand === 'qt  ') return { kind: 'video', label: 'فيديو QuickTime (MOV)' };
            if (brand.startsWith('3g')) return { kind: 'video', label: 'فيديو 3GP' };
            return { kind: 'media', label: 'حاوية MP4 (فيديو أو صوت)' };
        }
        if (h4 === '1A45DFA3') return { kind: 'media', label: 'حاوية WebM / MKV' };
        if (h4 === '3026B275') return { kind: 'media', label: 'حاوية Windows Media (WMA / WMV)' };

        if (looksLikeText(head)) {
            const start = decodeText(head, 2048).replace(/^﻿/, '').trimStart().toLowerCase();
            if (start.startsWith('#!')) return { kind: 'script', label: 'سكربت نصي (Shell / Python)' };
            if (/^(<!doctype html|<html|<head|<body|<script|<meta|<form)/.test(start) || /<html[\s>]/.test(start)) return { kind: 'html', label: 'صفحة ويب (HTML)' };
            if (/^(<\?xml[^>]*>\s*)?<svg[\s>]/.test(start)) return { kind: 'svg', label: 'صورة SVG (نص قابل لاحتواء سكربت)' };
            return { kind: 'text', label: 'ملف نصي' };
        }
        return { kind: 'unknown', label: 'بصمة غير مطابقة لأي صيغة معروفة' };
    }

    const EXPECTED_KINDS = {
        executable: ['executable'],
        script: ['text', 'script', 'html'],
        shortcut: ['shortcut', 'text'],
        disk: ['disk', 'unknown'],
        office: ['ole', 'ooxml', 'rtf', 'archive'],
        pdf: ['pdf'],
        archive: ['archive'],
        image: ['image', 'svg'],
        audio: ['audio', 'media'],
        video: ['video', 'media'],
        web: ['html', 'text'],
        text: ['text', 'html', 'script']
    };

    const SCRIPT_PATTERNS = [
        { re: /powershell(\.exe)?[^\n]*\s-(e|en|enc|encodedcommand)\s/i, weight: 0.6, text: 'يشغّل PowerShell بأوامر مشفرة (-EncodedCommand).' },
        { re: /\b(iex|invoke-expression)\b/i, weight: 0.4, text: 'ينفّذ نصاً كأوامر برمجية (Invoke-Expression).' },
        { re: /downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|start-bitstransfer|bitsadmin/i, weight: 0.45, text: 'ينزّل ملفات أو أوامر من الإنترنت.' },
        { re: /frombase64string|\[convert\]::/i, weight: 0.3, text: 'يفك ترميز Base64 أثناء التشغيل.' },
        { re: /wscript\.shell|shell\.application|activexobject|createobject\s*\(/i, weight: 0.4, text: 'يستخدم كائنات ويندوز لتنفيذ أوامر على الجهاز (WScript.Shell / ActiveX).' },
        { re: /certutil[^\n]*-(decode|urlcache)|mshta\s|regsvr32[^\n]*\/i:|rundll32[^\n]*,/i, weight: 0.5, text: 'يستغل أدوات ويندوز الأصلية لتمرير برمجيات (LOLBins).' },
        { re: /add-mppreference[^\n]*exclusion|set-mppreference[^\n]*disable/i, weight: 0.6, text: 'يحاول تعطيل Windows Defender أو إضافة استثناءات له.' },
        { re: /schtasks[^\n]*\/create|currentversion\\run/i, weight: 0.4, text: 'يضيف نفسه للتشغيل التلقائي مع ويندوز.' },
        { re: /vssadmin[^\n]*delete\s+shadows|bcdedit[^\n]*recoveryenabled/i, weight: 0.8, text: 'يحذف النسخ الاحتياطية للنظام، وهذا سلوك برامج الفدية.' },
        { re: /\beval\s*\(|unescape\s*\(|string\.fromcharcode|\batob\s*\(/i, weight: 0.25, text: 'يحتوي كوداً مموّهاً يُفك أثناء التشغيل (eval / atob / unescape).' },
        { re: /[A-Za-z0-9+/]{300,}={0,2}/, weight: 0.3, text: 'يحتوي كتلة طويلة مرمّزة بـ Base64.' }
    ];

    // fileInfo = { name, size, head: Uint8Array (أول 1MB تقريباً), tail: Uint8Array (آخر 64KB) }
    function analyzeFile(fileInfo) {
        const name = String(fileInfo.name || '');
        const lower = name.toLowerCase().trim();
        const head = fileInfo.head || new Uint8Array(0);
        const tail = fileInfo.tail || new Uint8Array(0);
        const size = fileInfo.size != null ? fileInfo.size : head.length;
        const signals = [];
        const add = (weight, type, text) => signals.push({ weight, type, text });

        const type = detectFileType(head, tail);
        const parts = lower.split('.');
        const ext = parts.length > 1 ? parts.pop().trim() : '';
        const innerExts = parts.slice(1).map(p => p.trim());
        const family = familyOfExtension(ext);
        const dangerousFamilies = ['executable', 'script', 'shortcut'];
        const lureFamilies = ['office', 'pdf', 'image', 'audio', 'video', 'text', 'archive', 'web'];

        if (size === 0) add(0, 'info', 'الملف فارغ.');

        // 1. حيل اسم الملف
        if (/[‪-‮⁦-⁩]/.test(name)) {
            add(0.95, 'danger', 'اسم الملف يحتوي محارف خفية تعكس اتجاه النص (RLO) لإخفاء امتداده الحقيقي.');
        }
        if (/\s{3,}\.[a-z0-9]+$/i.test(name) || /\.[a-z0-9]{2,4}\s{3,}/i.test(name)) {
            add(0.6, 'danger', 'اسم الملف يحتوي مسافات كثيرة لإبعاد الامتداد الحقيقي عن نظرك.');
        }
        if (dangerousFamilies.includes(family) && innerExts.some(e => lureFamilies.includes(familyOfExtension(e)))) {
            add(0.95, 'danger', `امتداد مزدوج مخادع: الاسم يوحي بملف عادي لكن امتداده الحقيقي .${ext}.`);
        }

        // 2. الامتداد نفسه
        if (family === 'script') add(0.55, 'danger', `ملف سكربت (.${ext}) ينفّذ أوامر على الجهاز مباشرة عند فتحه.`);
        else if (family === 'shortcut') add(0.6, 'danger', `ملف اختصار (.${ext}) يمكنه تشغيل أي أمر، ويكثر استخدامه في المرفقات الخبيثة.`);
        else if (family === 'disk') add(0.35, 'warning', `صورة قرص (.${ext}): تُستخدم لتمرير برامج خبيثة وتجاوز تحذيرات ويندوز للملفات المنزّلة.`);
        else if (family === 'executable') add(0.3, 'warning', `ملف تنفيذي (.${ext}). شغّله فقط إذا نزّلته بنفسك من الموقع الرسمي للبرنامج.`);
        if (MACRO_EXTENSIONS.includes(ext)) add(0.4, 'warning', `مستند Office يدعم الماكرو (.${ext})، والماكرو من أشهر طرق نشر البرمجيات الخبيثة.`);

        const nameWord = SUSPICIOUS_NAME_WORDS.find(w => lower.includes(w));
        if (nameWord && (dangerousFamilies.includes(family) || family === 'archive' || type.kind === 'executable')) {
            add(0.35, 'danger', `اسم الملف يحتوي كلمة ترتبط كثيراً بالبرمجيات الخبيثة ("${nameWord}").`);
        }

        // 3. تطابق الامتداد مع المحتوى الحقيقي
        const expected = EXPECTED_KINDS[family];
        const realIsDangerous = ['executable', 'shortcut', 'script'].includes(type.kind);
        if (expected && !expected.includes(type.kind) && type.kind !== 'unknown') {
            if (realIsDangerous && !dangerousFamilies.includes(family)) {
                add(0.95, 'danger', `الملف متنكر: امتداده .${ext} لكن محتواه الحقيقي ${type.label}.`);
            } else {
                add(0.4, 'warning', `امتداد الملف (.${ext}) لا يطابق محتواه الحقيقي (${type.label}).`);
            }
        } else if (!ext && realIsDangerous) {
            add(0.5, 'danger', `الملف بلا امتداد لكن محتواه ${type.label}.`);
        } else if (expected && expected.includes(type.kind)) {
            add(0, 'safe', `نوع الملف الحقيقي (${type.label}) يطابق امتداده.`);
        } else if (type.kind === 'unknown' && size > 0) {
            add(0.15, 'warning', 'لم نتعرف على نوع الملف من بصمته الثنائية.');
        }

        // 4. فحص عميق حسب النوع
        const entropy = shannonEntropy(head);
        let pe = null;
        let trustFactor = 1;
        if (type.kind === 'executable' && head[0] === 0x4D) {
            pe = parsePE(head);
            if (pe && pe.valid) {
                const bits = pe.is64 ? '64 بت' : '32 بت';
                add(0, 'info', `${pe.isDll ? 'مكتبة DLL' : 'برنامج'} ويندوز ${bits}${pe.isDotNet ? ' مكتوب بـ .NET' : ''}، عدد الأقسام ${pe.sections.length}.`);
                if (pe.signed) {
                    trustFactor = 0.7;
                    add(0, 'safe', 'الملف يحمل توقيعاً رقمياً (Authenticode). لم نتحقق من صحة التوقيع أو هوية الجهة الموقّعة؛ تحقق منها من خصائص الملف في ويندوز.');
                } else {
                    add(0.25, 'warning', 'الملف التنفيذي غير موقّع رقمياً، فلا يمكن معرفة الجهة التي أنتجته.');
                }
                const packer = pe.sections.find(s => /^(upx\d|\.aspack|\.adata|\.mpress\d|\.themida|\.vmp\d|\.enigma\d|\.petite|\.nsp\d)$/i.test(s));
                if (packer) add(0.35, 'warning', `الملف مضغوط أو محمي بأداة تغليف (القسم ${packer})، وهي طريقة شائعة لإخفاء الكود الخبيث.`);
                else if (entropy > 7.2) add(0.25, 'warning', `عشوائية بيانات الملف عالية (${entropy.toFixed(2)} من 8)، وقد يدل ذلك على تشفير أو ضغط لإخفاء الكود.`);
            } else {
                add(0.3, 'warning', 'ترويسة الملف التنفيذي تالفة أو غير مكتملة.');
            }
        }

        // بيانات ملحقة بعد نهاية الصورة: طريقة معروفة لإخفاء كود أو ملف تنفيذي داخل صورة عادية
        if (type.kind === 'image') {
            const trailing = imageTrailingData(tail.length ? tail : head);
            if (trailing && trailing.length > 16) {
                const hidden = hasEmbeddedPayloadMarkers(trailing);
                if (hidden) add(0.7, 'danger', `الصورة تحمل بعد نهايتها ${trailing.length} بايت إضافية تبدو ${hidden}. هذه حيلة لإخفاء كود داخل صورة عادية.`);
                else add(0.35, 'warning', `الصورة تحمل بعد نهايتها ${trailing.length} بايت إضافية غير ظاهرة. قد تكون بيانات مخفية؛ يمكن تنظيفها (Pro) بإعادة بناء الصورة.`);
            }
        }

        if (type.kind === 'ooxml' && (containsAscii(head, 'vbaProject.bin') || containsAscii(tail, 'vbaProject.bin'))) {
            add(0.5, 'danger', 'المستند يحتوي ماكرو VBA (vbaProject.bin). لا تضغط "تمكين المحتوى" إذا لم تكن تثق بالمرسل.');
        }
        if (type.kind === 'ole' && (containsUtf16(head, '_VBA_PROJECT') || containsUtf16(head, 'Macros') || containsAscii(head, 'VBA'))) {
            add(0.5, 'danger', 'المستند القديم يحتوي ماكرو VBA. لا تفعّل المحتوى إذا لم تكن تثق بالمرسل.');
        }
        if (type.kind === 'pdf') {
            const has = needle => containsAscii(head, needle) || containsAscii(tail, needle);
            if (has('/Launch')) add(0.5, 'danger', 'ملف PDF يحتوي أمر Launch لتشغيل برامج خارجية.');
            if (has('/JavaScript') || has('/JS')) add(0.35, 'warning', 'ملف PDF يحتوي كود JavaScript.');
            if (has('/EmbeddedFile')) add(0.25, 'warning', 'ملف PDF يحتوي ملفات مدمجة بداخله.');
            if (has('/OpenAction') || has('/AA')) add(0.1, 'warning', 'ملف PDF ينفّذ إجراءً تلقائياً عند فتحه.');
        }
        if (type.kind === 'rtf' && (containsAscii(head, '\\objdata') || containsAscii(head, '\\object'))) {
            add(0.35, 'warning', 'مستند RTF يحتوي كائنات مدمجة، وهي طريقة معروفة لاستغلال ثغرات Office.');
        }

        if (['text', 'script', 'html', 'svg'].includes(type.kind)) {
            const content = decodeText(head, 256 * 1024);
            let shown = 0;
            for (const p of SCRIPT_PATTERNS) {
                if (p.re.test(content)) {
                    add(p.weight, p.weight >= 0.45 ? 'danger' : 'warning', p.text);
                    if (++shown >= 6) break;
                }
            }
            if (type.kind === 'html' || type.kind === 'svg') {
                const lowerContent = content.toLowerCase();
                const hasPassword = /type\s*=\s*["']?password/.test(lowerContent);
                const externalForm = /<form[^>]+action\s*=\s*["']?https?:\/\//.test(lowerContent);
                if (hasPassword) add(0.35, 'warning', 'الصفحة تحتوي حقل كلمة سر. صفحات تسجيل الدخول لا تُرسل كمرفقات.');
                if (externalForm) add(0.3, 'warning', 'الصفحة ترسل ما تكتبه إلى خادم خارجي.');
                if (hasPassword && externalForm) add(0.4, 'danger', 'نموذج تسجيل دخول محلي يرسل كلمة السر لخادم خارجي: هذا أسلوب تصيد معروف بالمرفقات.');
                if (/http-equiv\s*=\s*["']?refresh|window\.location|location\.href\s*=/.test(lowerContent)) add(0.2, 'warning', 'الصفحة تعيد توجيهك تلقائياً لموقع آخر.');
                if (type.kind === 'svg' && /<script|onload\s*=|javascript:/.test(lowerContent)) add(0.5, 'danger', 'صورة SVG تحتوي كوداً برمجياً، والصور العادية لا تحتاج ذلك.');
            }
        }

        if (!signals.some(s => s.weight >= 0.1)) {
            add(0, 'safe', 'لم تُرصد مؤشرات خطر في بنية الملف أو اسمه.');
        }

        const result = finish(signals, THRESHOLDS, { type, entropy: Number(entropy.toFixed(2)), pe });
        if (trustFactor < 1) {
            result.score = Math.round(result.score * trustFactor);
            result.level = levelFor(result.score, THRESHOLDS);
        }
        return result;
    }

    return {
        analyzeUrl,
        analyzeText,
        analyzeFile,
        detectFileType,
        parsePE,
        extractUrls,
        normalizeArabic,
        editDistance,
        similarity,
        punycodeDecode,
        hostToUnicode,
        asciiSkeleton,
        shannonEntropy,
        splitDomain,
        looksRandom,
        THRESHOLDS,
        STRICT_THRESHOLDS,
        BRANDS
    };
});
