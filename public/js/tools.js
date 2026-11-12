/*
  أدوات إضافية بالمتصفح:
  1) فحص QR Code: من صورة أو من الكاميرا. نفك المحتوى، ونعرضه كنص فقط (ما نفتح أي رابط تلقائياً)، والروابط تنفحص بمحرك الروابط.
  2) فحص لقطة الشاشة (OCR): Tesseract.js بالعربي والإنكليزي داخل المتصفح. الصورة ما تنرفع؛ المستخدم يصحح النص ثم يفحصه.
  3) تحليل ترويسة الإيميل: بالمتصفح بالكامل (email-headers.js)، وعناوين IP العامة فقط تُرسل للخادم إذا المستخدم طلب معلومات استضافتها.
  مكتبات jsQR و Tesseract تُحمَّل فقط عند أول استخدام.
*/
(function () {
    'use strict';
    const $ = id => document.getElementById(id);

    function loadScript(src) {
        return new Promise((resolve, reject) => {
            if (document.querySelector(`script[data-src="${src}"]`)) return resolve();
            const s = document.createElement('script');
            s.src = src;
            s.dataset.src = src;
            s.onload = resolve;
            s.onerror = () => reject(new Error('تعذر تحميل ' + src));
            document.head.appendChild(s);
        });
    }

    function el(tag, cls, text) {
        const n = document.createElement(tag);
        if (cls) n.className = cls;
        if (text !== undefined) n.textContent = text;
        return n;
    }

    async function imageToCanvas(file, maxSide = 1800, minSide = 0) {
        const url = URL.createObjectURL(file);
        try {
            const img = await new Promise((resolve, reject) => {
                const i = new Image();
                i.onload = () => resolve(i);
                i.onerror = () => reject(new Error('الصورة غير صالحة'));
                i.src = url;
            });
            let scale = Math.min(1, maxSide / Math.max(img.naturalWidth, img.naturalHeight));
            if (minSide && Math.max(img.naturalWidth, img.naturalHeight) * scale < minSide) scale = minSide / Math.max(img.naturalWidth, img.naturalHeight);
            const canvas = document.createElement('canvas');
            canvas.width = Math.max(1, Math.round(img.naturalWidth * scale));
            canvas.height = Math.max(1, Math.round(img.naturalHeight * scale));
            const ctx = canvas.getContext('2d', { willReadFrequently: true });
            ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
            return canvas;
        } finally {
            URL.revokeObjectURL(url);
        }
    }

    // ================================================================ QR
    // نوع محتوى الباركود
    function classifyQr(raw) {
        const text = String(raw || '').trim();
        if (/^https?:\/\//i.test(text)) return { type: 'url', label: 'رابط', value: text };
        if (/^www\.[^\s]+\.[a-z]{2,}/i.test(text)) return { type: 'url', label: 'رابط', value: 'https://' + text };
        if (/^WIFI:/i.test(text)) {
            const field = k => { const m = new RegExp('[:;]' + k + ':((?:\\\\.|[^;])*)', 'i').exec(text); return m ? m[1].replace(/\\(.)/g, '$1') : ''; };
            return { type: 'wifi', label: 'شبكة WiFi', ssid: field('S'), security: (field('T') || 'nopass').toUpperCase(), hasPassword: Boolean(field('P')), hidden: /true/i.test(field('H')) };
        }
        if (/^(tel:|\+?\d[\d\s-]{7,}$)/i.test(text)) return { type: 'phone', label: 'رقم هاتف', value: text.replace(/^tel:/i, '') };
        if (/^smsto?:/i.test(text)) return { type: 'sms', label: 'رسالة SMS جاهزة', value: text };
        if (/^mailto:/i.test(text)) return { type: 'email', label: 'بريد إلكتروني', value: text.replace(/^mailto:/i, '') };
        if (/^(bitcoin|ethereum|litecoin|tron|usdt|bnb|solana):/i.test(text) || /^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$/.test(text) || /^0x[a-fA-F0-9]{40}$/.test(text)) return { type: 'crypto', label: 'عنوان دفع عملات رقمية', value: text };
        if (/^BEGIN:VCARD/i.test(text) || /^MECARD:/i.test(text)) return { type: 'contact', label: 'جهة اتصال', value: text };
        if (/^geo:/i.test(text)) return { type: 'geo', label: 'موقع جغرافي', value: text };
        return { type: 'text', label: 'نص', value: text };
    }

    async function decodeCanvas(canvas) {
        if ('BarcodeDetector' in window) {
            try {
                const detector = new BarcodeDetector({ formats: ['qr_code'] });
                const found = await detector.detect(canvas);
                if (found.length && found[0].rawValue) return found[0].rawValue;
            } catch { /* نكمل بـ jsQR */ }
        }
        await loadScript('/vendor/jsqr/jsQR.js?v=1');
        const ctx = canvas.getContext('2d', { willReadFrequently: true });
        const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const code = window.jsQR(data.data, canvas.width, canvas.height, { inversionAttempts: 'attemptBoth' });
        return code ? code.data : '';
    }

    async function showQrResult(raw) {
        stopCamera();
        const box = $('qrReportBox');
        const info = classifyQr(raw);
        const wrap = el('div', 'qr-content');
        wrap.append(el('strong', '', `محتوى الباركود (${info.label}):`));
        const pre = el('pre', 'qr-raw');
        pre.textContent = String(raw).slice(0, 2000);
        pre.dir = 'auto';
        wrap.append(pre, el('p', 'muted qr-note', 'ما فتحنا أي شي تلقائياً. هذا المحتوى كما هو داخل الباركود.'));
        const notes = el('ul', 'report-details-list');
        const note = (type, text) => notes.append(el('li', 'li-' + type, text));
        if (info.type === 'wifi') {
            note(info.security === 'NOPASS' ? 'warning' : 'info', info.security === 'NOPASS' ? `شبكة «${info.ssid}» مفتوحة بدون كلمة سر: أي شخص قريب يكدر يراقب اتصالك. لا تدخل بيانات حساسة عليها.` : `شبكة «${info.ssid}» بتشفير ${info.security}${info.hasPassword ? ' وكلمة سر' : ''}.`);
            note('warning', 'تأكد من صاحب المكان إن هذا اسم شبكته الحقيقي: المحتالين يسوون شبكات بأسماء تشبه شبكات المقاهي والمطاعم.');
        } else if (info.type === 'crypto') {
            note('danger', 'هذا الباركود يطلب دفع بالعملات الرقمية. التحويلات بيها ما ترجع أبداً: لا تحوّل إلا لجهة تعرفها وتأكدت منها بنفسك.');
        } else if (info.type === 'phone' || info.type === 'sms') {
            note('info', 'الباركود يفتح اتصال أو رسالة. تأكد من الرقم قبل ما تتصل، ولا ترسل رموز أو بيانات.');
        } else if (info.type === 'email') {
            note('info', 'الباركود يفتح رسالة بريد جاهزة. تأكد من العنوان قبل الإرسال.');
        }
        if (notes.children.length) wrap.append(notes);
        box.style.display = 'block';
        box.replaceChildren(wrap);

        if (info.type === 'url') {
            const sub = el('div', 'report-box');
            sub.id = 'qrUrlReport';
            sub.style.display = 'block';
            sub.innerHTML = loadingHtml('جارٍ فحص الرابط المخفي بالباركود...');
            box.append(sub);
            const { ok, data } = await api('/api/scan/url', { url: info.value });
            if (!ok) { sub.innerHTML = data.code === 'quota' ? quotaHtml(data.error) : errorHtml(data.error || 'تعذر الفحص.'); return; }
            const r = data.result;
            const meta = `<strong>الرابط المخفي:</strong> <code style="direction:ltr; display:inline-block;">${escapeHtml(r.input)}</code>`;
            renderReport(sub, 'url', 'مؤشر الخطورة', r, meta, inspectionHtml(r));
            addToHistory(info.value, 'QR', r.score, LEVEL_STATUS[r.level]);
        } else if (info.type === 'text' && info.value.length >= 15) {
            const btn = el('button', 'app-btn small', 'افحص هذا النص كرسالة');
            btn.type = 'button';
            btn.addEventListener('click', () => {
                switchPage('textScannerPage', 'فحص النصوص والرسائل', 'fa-solid fa-comment-sms');
                $('textInput').value = info.value.slice(0, 10000);
                analyzeText();
            });
            box.append(btn);
        }
    }

    async function scanQrImage(input) {
        const file = input && input.files && input.files[0];
        if (!file) return;
        const box = $('qrReportBox');
        box.style.display = 'block';
        box.innerHTML = loadingHtml('جارٍ قراءة الباركود من الصورة...');
        try {
            const canvas = await imageToCanvas(file, 1600);
            const raw = await decodeCanvas(canvas);
            if (!raw) { box.innerHTML = errorHtml('ما لكينا باركود QR واضح بالصورة. قرّب الصورة أو صوّره بإضاءة أحسن.'); return; }
            await showQrResult(raw);
        } catch (error) {
            box.innerHTML = errorHtml(error.message || 'تعذر قراءة الصورة.');
        } finally {
            input.value = '';
        }
    }

    let stream = null, scanning = false;
    async function startCamera() {
        const box = $('qrReportBox');
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
            box.style.display = 'block';
            box.innerHTML = errorHtml('متصفحك ما يدعم الكاميرا. ارفع صورة للباركود بدلاً من ذلك.');
            return;
        }
        try {
            stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' }, audio: false });
        } catch {
            box.style.display = 'block';
            box.innerHTML = errorHtml('ما سمحت للموقع يستخدم الكاميرا، أو الكاميرا مشغولة. تكدر ترفع صورة بدلها.');
            return;
        }
        const video = $('qrVideo');
        video.srcObject = stream;
        $('qrCamera').hidden = false;
        await video.play().catch(() => {});
        scanning = true;
        const canvas = document.createElement('canvas');
        const tick = async () => {
            if (!scanning) return;
            if (video.readyState >= 2 && video.videoWidth) {
                canvas.width = Math.min(960, video.videoWidth);
                canvas.height = Math.round(video.videoHeight * (canvas.width / video.videoWidth));
                canvas.getContext('2d', { willReadFrequently: true }).drawImage(video, 0, 0, canvas.width, canvas.height);
                try {
                    const raw = await decodeCanvas(canvas);
                    if (raw) { await showQrResult(raw); return; }
                } catch { /* نكمل */ }
            }
            setTimeout(() => requestAnimationFrame(tick), 250);
        };
        tick();
    }

    function stopCamera() {
        scanning = false;
        if (stream) stream.getTracks().forEach(t => t.stop());
        stream = null;
        const cam = $('qrCamera');
        if (cam) cam.hidden = true;
    }

    // ================================================================ OCR
    let ocrWorker = null;
    async function getOcrWorker(progress) {
        if (ocrWorker) return ocrWorker;
        progress('جارٍ تحميل قارئ النصوص (مرة وحدة فقط، قرابة 12MB)...');
        await loadScript('/vendor/tesseract/tesseract.min.js?v=1');
        ocrWorker = await window.Tesseract.createWorker(['ara', 'eng'], 1, {
            workerPath: '/vendor/tesseract/worker.min.js',
            corePath: '/vendor/tesseract/core',
            langPath: '/vendor/tesseract/lang',
            gzip: true,
            workerBlobURL: false,
            logger: m => { if (m && m.status === 'recognizing text') progress(`جارٍ قراءة النص... ${Math.round((m.progress || 0) * 100)}%`); }
        });
        return ocrWorker;
    }

    async function scanScreenshot(input) {
        const file = input && input.files && input.files[0];
        if (!file) return;
        const status = $('ocrStatus');
        const progress = text => { status.hidden = false; status.textContent = text; };
        $('ocrEditor').hidden = true;
        $('ocrReportBox').style.display = 'none';
        try {
            const canvas = await imageToCanvas(file, 2400, 1400);
            const worker = await getOcrWorker(progress);
            progress('جارٍ قراءة النص من الصورة...');
            const { data } = await worker.recognize(canvas);
            // نحذف علامات الاتجاه الخفية اللي يضيفها القارئ حول الروابط والأرقام
            const text = String(data && data.text || '').replace(/[\u200e\u200f\u202a-\u202e\u2066-\u2069]/g, '').replace(/[ \t]+\n/g, '\n').trim();
            status.hidden = true;
            if (!text) { progress('ما كدرنا نقرأ نص من الصورة. جرّب صورة أوضح أو اكتب النص بنفسك.'); return; }
            $('ocrText').value = text.slice(0, 10000);
            $('ocrEditor').hidden = false;
            $('ocrText').focus();
        } catch (error) {
            progress('تعذر قراءة الصورة: ' + (error && error.message ? error.message : 'خطأ غير معروف'));
        } finally {
            input.value = '';
        }
    }

    const PHONE_RE = /(?:\+?964|00964|0)7[3-9]\d[\s-]?\d{3}[\s-]?\d{4}|\+\d{8,15}/g;
    async function analyzeOcrText() {
        const text = $('ocrText').value.trim();
        const box = $('ocrReportBox');
        box.style.display = 'block';
        if (!text) { box.innerHTML = errorHtml('ما اكو نص للفحص.'); return; }
        box.innerHTML = loadingHtml('جارٍ تحليل الرسالة وروابطها...');
        const { ok, data } = await api('/api/scan/text', { text: text.slice(0, 10000) });
        if (!ok) { box.innerHTML = data.code === 'quota' ? quotaHtml(data.error) : errorHtml(data.error || 'تعذر الفحص.'); return; }
        $('textInput').value = text.slice(0, 10000);   // لزر «حذّر أهلك» و«بلّغ»
        const urls = PhishingEngine.extractUrls(text).slice(0, 10);
        const phones = [...new Set((text.match(PHONE_RE) || []).map(p => p.replace(/[\s-]/g, '')))].slice(0, 10);
        let extra = '';
        if (urls.length || phones.length) {
            extra = '<div class="ocr-found">';
            if (urls.length) extra += `<strong>روابط بالصورة (${urls.length}):</strong><ul>${urls.map(u => `<li><code dir="ltr">${escapeHtml(u)}</code> <button type="button" class="btn-quick" data-action="scanFoundUrl" data-arg="${escapeHtml(u)}">افحص بالتفصيل</button></li>`).join('')}</ul>`;
            if (phones.length) extra += `<strong>أرقام هواتف بالصورة (${phones.length}):</strong><ul>${phones.map(p => `<li><code dir="ltr">${escapeHtml(p)}</code> ${ACTIONS.lookupIdentifier ? `<button type="button" class="btn-quick" data-action="lookupIdentifier" data-arg="${escapeHtml(p)}">هل انبلغ عنه؟</button>` : ''}</li>`).join('')}</ul>`;
            extra += '</div>';
        }
        const preview = text.length > 140 ? text.slice(0, 140) + '…' : text;
        renderReport(box, 'text', 'مؤشر المخاطر', data.result, `<strong>النص المقروء من الصورة:</strong> <p style="margin-top:4px; color:var(--text-main); font-style:italic;">"${escapeHtml(preview)}"</p>`, extra);
        addToHistory('لقطة شاشة', 'صورة رسالة', data.result.score, LEVEL_STATUS[data.result.level]);
    }

    function scanFoundUrl(url) {
        switchPage('scannerPage', 'فحص الروابط', 'fa-solid fa-link');
        $('urlInput').value = String(url).slice(0, 2048);
        analyzeUrl();
    }

    // ================================================================ ترويسة البريد
    let lastHeaders = null;
    function analyzeHeaders() {
        const raw = $('headersInput').value;
        const box = $('headersReportBox');
        box.style.display = 'block';
        const r = window.EmailHeaders.analyze(raw);
        if (r.error) { box.innerHTML = errorHtml('الصق الترويسات كاملة (من «Show original» بجيميل أو «View message details» بآوتلوك).'); return; }
        lastHeaders = r;
        const AUTH = { pass: ['نجح', 'ok'], fail: ['فشل', 'bad'], softfail: ['فشل جزئي', 'warn'], neutral: ['محايد', 'warn'], none: ['غير موجود', 'warn'], temperror: ['خطأ مؤقت', 'warn'], permerror: ['خطأ دائم', 'bad'] };
        const chip = v => { const [t, c] = AUTH[v] || ['غير معروف', 'warn']; return `<span class="auth-chip ${c}">${t}</span>`; };
        const addr = a => a.address ? `${a.name ? escapeHtml(a.name) + ' ' : ''}<code dir="ltr">${escapeHtml(a.address)}</code>` : '—';
        const hops = r.path.map((h, i) => `<li class="hop" style="--hop:var(--accent-blue)"><span class="hop-dot"></span><span class="hop-host" dir="ltr">${escapeHtml(h.from || '?')} → ${escapeHtml(h.by || '?')}${h.publicIps.length ? ' [' + escapeHtml(h.publicIps.join(', ')) + ']' : ''}</span><span class="hop-status">${i + 1}</span></li>`).join('');
        const extra = `
            <div class="live-card">
                <div class="live-row"><span>SPF</span><b>${chip(r.auth.spf)}</b></div>
                <div class="live-row"><span>DKIM</span><b>${chip(r.auth.dkim)}${r.auth.dkimDomain ? ' <code dir="ltr">' + escapeHtml(r.auth.dkimDomain) + '</code>' : ''}</b></div>
                <div class="live-row"><span>DMARC</span><b>${chip(r.auth.dmarc)}</b></div>
                <div class="live-row"><span>المرسل الظاهر</span><b>${addr(r.from)}</b></div>
                <div class="live-row"><span>الرد يروح إلى</span><b>${addr(r.replyTo)}</b></div>
                <div class="live-row"><span>عنوان الإرجاع</span><b>${addr(r.returnPath)}</b></div>
                ${r.subject ? `<div class="live-row"><span>الموضوع</span><b>${escapeHtml(r.subject)}</b></div>` : ''}
            </div>
            ${hops ? `<div class="hop-chain"><strong>مسار السيرفرات (من المرسل للمستلم):</strong><ol>${hops}</ol></div>` : ''}
            ${r.publicIps.length ? `<button type="button" class="app-btn small secondary" data-action="lookupHeaderIps"><i class="fa-solid fa-globe"></i> اعرض استضافة السيرفرات (${r.publicIps.length})</button><p class="muted" style="font-size:.78rem">نرسل عناوين IP العامة فقط للخادم، مو الترويسات.</p><div id="headerIpsBox"></div>` : ''}`;
        const meta = `<strong>من:</strong> ${addr(r.from)}${r.date ? ' · ' + escapeHtml(r.date) : ''}`;
        renderReport(box, 'email', 'مؤشر الانتحال', { ...r, confidence: null, indicators: [] }, meta, extra);
    }

    async function lookupHeaderIps() {
        if (!lastHeaders) return;
        const box = $('headerIpsBox');
        box.innerHTML = loadingHtml('جارٍ جلب معلومات الاستضافة...');
        const { ok, data } = await api('/api/scan/ip-hosting', { ips: lastHeaders.publicIps });
        if (!ok) { box.innerHTML = errorHtml(data.error || 'تعذر الجلب.'); return; }
        box.innerHTML = '<div class="live-card">' + data.results.map(h => `<div class="live-row"><span dir="ltr">${escapeHtml(h.ip)}</span><b>${h.country ? flagEmoji(h.country) + ' ' + escapeHtml(h.countryName || h.country) : '—'}${h.org ? ' · <span dir="ltr">' + escapeHtml(h.org.split(',')[0]) + '</span>' : ''}</b></div>`).join('') + '<p class="live-note">دولة الاستضافة هي مكان تسجيل السيرفر، مو بالضرورة مكان المرسل.</p></div>';
    }

    // ================================================================ فحص رقم أو حساب
    const CATEGORY_NAMES = { fake_seller: 'بائع أو متجر وهمي', transfer: 'طلب تحويل رصيد أو فلوس', impersonation: 'انتحال جهة أو شخص', otp: 'طلب رمز تحقق أو بيانات', blackmail: 'ابتزاز أو تهديد', investment: 'استثمار أو ربح وهمي', other: 'أخرى' };
    async function lookupIdentifierForm() {
        const kind = $('idKind').value, value = $('idValue').value.trim();
        const box = $('idResult');
        box.style.display = 'block';
        if (!value) { box.innerHTML = errorHtml('اكتب الرقم أو الحساب.'); return; }
        box.innerHTML = loadingHtml('جارٍ البحث بالبلاغات...');
        const { ok, data } = await api('/api/identifier/lookup', { kind, value });
        if (!ok) { box.innerHTML = errorHtml(data.error || 'تعذر البحث.'); return; }
        const r = data.result;
        const card = el('div', 'id-card ' + (r.reporters >= 2 ? 'many' : r.reporters === 1 ? 'one' : 'none'));
        const shown = el('code', '', value);
        shown.dir = 'ltr';
        const head = el('p', 'id-head');
        head.append(shown);
        card.append(head);
        if (!r.reporters) {
            card.append(el('strong', '', 'ما انبلغ عنه بموقعنا.'), el('p', 'muted', 'هذا ما يعني إنه آمن: ممكن ما أحد بلّغ عنه بعد. لا تحوّل فلوس أو ترسل رموز لأي أحد ما تعرفه.'));
        } else {
            card.append(el('strong', '', r.reporters === 1 ? 'انبلغ عنه مرة وحدة.' : `انبلغ عنه ${r.reporters} مرات من ${r.reporters} مستخدمين مختلفين.`));
            card.append(el('p', 'muted', r.reporters === 1 ? 'بلاغ واحد مو حكم، بس كن حذر وتأكد بنفسك قبل أي تحويل.' : 'كن حذر جداً: لا تحوّل فلوس ولا ترسل رموز أو بيانات.'));
            const cats = Object.entries(r.categories).sort((a, b) => b[1] - a[1]).map(([c, n]) => `${CATEGORY_NAMES[c] || c} (${n})`);
            if (cats.length) card.append(el('p', '', 'نوع البلاغات: ' + cats.join('، ')));
            if (r.lastAt) card.append(el('p', 'muted', 'آخر بلاغ: ' + new Date(r.lastAt).toLocaleDateString('ar-IQ')));
        }
        box.replaceChildren(card);
    }

    async function reportIdentifierForm() {
        const msg = $('idrMsg');
        if (!$('idrConfirm').checked) { msg.textContent = 'أكّد إن البلاغ صحيح أولاً.'; return; }
        const { ok, data } = await api('/api/identifier/report', { kind: $('idrKind').value, value: $('idrValue').value.trim(), category: $('idrCategory').value, note: $('idrNote').value.trim() });
        msg.textContent = ok ? data.message : (data.error || 'تعذر الإرسال.');
        if (ok) { $('idrValue').value = ''; $('idrNote').value = ''; $('idrConfirm').checked = false; }
    }

    // من قارئ لقطة الشاشة: افحص الرقم مباشرة
    function lookupIdentifier(value) {
        switchPage('identifierPage', 'فحص رقم أو حساب', 'fa-solid fa-address-book');
        $('idKind').value = 'phone';
        $('idValue').value = String(value).slice(0, 200);
        lookupIdentifierForm();
    }

    // ================================================================ مراقبة انتحال الدومين
    function renderMonitor(data) {
        const box = $('monList');
        if (!box) return;
        box.replaceChildren(...(data.domains || []).map(d => {
            const card = el('div', 'mon-card');
            const head = el('div', 'mon-head');
            const name = el('strong', '', d.domain);
            name.dir = 'ltr';
            const actions = el('div', 'mon-actions');
            const check = el('button', 'app-btn small', 'افحص هسه');
            check.type = 'button';
            check.addEventListener('click', async () => {
                check.disabled = true;
                check.textContent = 'جارٍ الفحص...';
                const { ok, data: res } = await api('/api/monitor/check', { domain: d.domain });
                $('monMsg').textContent = ok ? (res.newFindings ? `لكينا ${res.newFindings} نطاق جديد.` : 'ما لكينا نطاقات جديدة.') : (res.error || 'تعذر الفحص.');
                if (ok) renderMonitor(res); else { check.disabled = false; check.textContent = 'افحص هسه'; }
            });
            const remove = el('button', 'app-btn small secondary', 'إزالة');
            remove.type = 'button';
            remove.addEventListener('click', async () => {
                if (!window.confirm(`إيقاف مراقبة ${d.domain}؟`)) return;
                const { ok, data: res } = await api('/api/monitor/remove', { domain: d.domain });
                if (ok) renderMonitor(res);
            });
            actions.append(check, remove);
            head.append(name, actions);
            card.append(head, el('p', 'muted mon-meta', d.lastCheck ? 'آخر فحص: ' + new Date(d.lastCheck).toLocaleString('ar-IQ') : 'ما انفحص بعد.'));
            if (d.lastError) card.append(el('p', 'mon-error', d.lastError));
            const active = d.findings.filter(f => !f.dismissed);
            if (!active.length) card.append(el('p', 'muted', d.lastCheck ? 'ما اكو نطاقات مشبوهة تشبه نطاقك حالياً.' : ''));
            for (const f of active) {
                const row = el('div', 'mon-finding');
                const host = el('code', '', f.domain);
                host.dir = 'ltr';
                const info = el('div');
                info.append(host, el('p', '', f.reason), el('small', 'muted', 'أول شهادة: ' + new Date(f.firstSeen).toLocaleDateString('ar-IQ') + (f.example && f.example !== f.domain ? ` · ${f.example}` : '')));
                const ok = el('button', 'btn-quick', 'مو تهديد');
                ok.type = 'button';
                ok.addEventListener('click', async () => {
                    const { ok: done, data: res } = await api('/api/monitor/dismiss', { domain: d.domain, finding: f.domain });
                    if (done) renderMonitor(res);
                });
                const scan = el('button', 'btn-quick', 'افحصه');
                scan.type = 'button';
                scan.addEventListener('click', () => scanFoundUrl('https://' + f.domain));
                const btns = el('div', 'mon-actions');
                btns.append(scan, ok);
                row.append(info, btns);
                card.append(row);
            }
            return card;
        }));
        if (!(data.domains || []).length) box.append(el('p', 'muted', 'ما أضفت أي نطاق بعد.'));
    }

    async function loadMonitor() {
        const { ok, data } = await api('/api/monitor');
        if (ok) renderMonitor(data);
        else $('monMsg').textContent = data.error || '';
    }

    async function monitorAdd() {
        const { ok, data } = await api('/api/monitor/add', { domain: $('monDomain').value });
        $('monMsg').textContent = ok ? 'انضاف. اضغط «افحص هسه» حتى نسوي أول فحص.' : (data.error || 'تعذر الإضافة.');
        if (ok) { $('monDomain').value = ''; renderMonitor(data); }
    }
    document.addEventListener('click', e => { if (e.target.closest('[data-page="monitorPage"]')) loadMonitor(); });

    Object.assign(ACTIONS, { monitorAdd });
    Object.assign(ACTIONS, { lookupIdentifierForm, reportIdentifierForm, lookupIdentifier });
    Object.assign(ACTIONS, { scanQrImage, startCamera, stopCamera, scanScreenshot, analyzeOcrText, scanFoundUrl, analyzeHeaders, lookupHeaderIps });
    // نوقف الكاميرا إذا المستخدم طلع من الصفحة
    document.addEventListener('click', e => { if (e.target.closest('[data-page]') && !e.target.closest('#qrPage')) stopCamera(); });
    window.PDTools = { classifyQr };
})();
