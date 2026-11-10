function switchPage(pageId, tabName, iconClasses) {
    document.querySelectorAll('.page-section').forEach(sec => sec.classList.remove('active'));
    document.getElementById(pageId).classList.add('active');

    // نبني الأيقونة كعنصر DOM (بدون innerHTML) حتى لا يمر أي نص عبر المحلل HTML
    const indicator = document.getElementById('currentTabIndicator');
    indicator.textContent = '';
    if (iconClasses) {
        const icon = document.createElement('i');
        icon.className = iconClasses;
        indicator.append(icon, ' ' + tabName);
    } else {
        indicator.textContent = tabName;
    }
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function openCyberBot() {
    switchPage('cyberBotPage', 'CyberBot AI', 'fa-solid fa-robot');
    checkUserSession();
}

function toggleThemeMenu() {
    const menu = document.getElementById('themeMenu');
    menu.classList.toggle('show');
}

function setTheme(themeName) {
    document.body.setAttribute('data-theme', themeName);
    localStorage.setItem('selected_theme', themeName);
    document.getElementById('themeMenu').classList.remove('show');
}

window.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('selected_theme') || 'dark';
    document.body.setAttribute('data-theme', savedTheme);
    loadSimulation(0);

    window.addEventListener('click', (e) => {
        if (!e.target.closest('.theme-selector-container')) {
            document.getElementById('themeMenu').classList.remove('show');
        }
    });
});

// ==========================================================
// اتصال بالخادم (مشترك مع account.js)
// ==========================================================
async function api(url, body, options = {}) {
    const init = { method: body === undefined ? (options.method || 'GET') : 'POST', credentials: 'same-origin', headers: {} };
    if (body !== undefined) {
        init.headers['Content-Type'] = 'application/json';
        init.body = JSON.stringify(body);
    }
    if (options.signal) init.signal = options.signal;
    const response = await fetch(url, init);
    let data = {};
    try { data = await response.json(); } catch { /* رد بدون JSON */ }
    // الجلسة انتهت: نرجع لصفحة الدخول
    if (response.status === 401 && data.code === 'login_required') {
        window.location.replace('/login');
        throw new Error('login required');
    }
    if (window.PDAccount && data && typeof data.used === 'number' && typeof data.limit === 'number') {
        window.PDAccount.noteUsage(url.includes('/chat') ? 'chat' : 'scan', data.used, data.limit);
    }
    return { ok: response.ok, status: response.status, data };
}

// رسالة الحد اليومي مع زر الترقية
function quotaHtml(message) {
    return `<div class="upgrade-callout"><span><i class="fa-solid fa-gauge-high"></i> ${escapeHtml(message)}</span>
        <button class="app-btn small" type="button" data-action="openUpgrade"><i class="fa-solid fa-crown"></i> الترقية إلى Pro</button></div>`;
}

function errorHtml(message) {
    return `<div style="color:var(--accent-red);"><i class="fa-solid fa-circle-exclamation"></i> ${escapeHtml(message)}</div>`;
}

function loadingHtml(text) {
    return `<div style="text-align:center; padding:1rem;"><i class="fa-solid fa-gear fa-spin" style="font-size:2rem; color:var(--accent-blue);"></i><br><br>${escapeHtml(text)}</div>`;
}

// ==========================================================
// CyberBot
// ==========================================================
const cyberBotHistory = [];
let cyberBotSending = false;
let cyberBotGreeted = false;

function setCyberBotStatus(message, connected = false) {
    const status = document.getElementById("chatConnectionStatus");
    if (!status) return;
    status.textContent = message;
    status.style.color = connected ? "var(--accent-green)" : "var(--text-muted)";
}

function currentUserName() {
    return (window.PDAccount && window.PDAccount.user && window.PDAccount.user.name) || "صديقي";
}

function appendCyberBotMessage(role, content, options = {}) {
    const history = document.getElementById("chatHistory");
    const bubble = document.createElement("div");
    bubble.className = "chat-bubble " + (role === "user" ? "chat-bubble-user" : "chat-bubble-assistant");
    if (options.typing) bubble.classList.add("chat-typing");
    const label = document.createElement("strong");
    label.className = "chat-bubble-label";
    label.textContent = role === "user" ? currentUserName() + ":" : "CyberBot AI:";
    bubble.appendChild(label);
    const body = document.createElement("span");
    body.textContent = String(content);
    bubble.appendChild(body);
    history.appendChild(bubble);
    history.scrollTop = history.scrollHeight;
    return bubble;
}

function initChatGreeting() {
    document.getElementById("chatHistory").replaceChildren();
    cyberBotHistory.length = 0;
    appendCyberBotMessage("assistant", "أهلاً " + currentUserName() + "! أنا CyberBot. ألصق أي رابط أو رسالة مشكوك بيها وأفحصها لك فوراً، أو اسألني عن أي شي بالأمن السيبراني.");
    setCyberBotStatus("جاهز.", true);
}

function openCyberBot() {
    switchPage('cyberBotPage', 'CyberBot AI', 'fa-solid fa-robot');
    if (!cyberBotGreeted) {
        cyberBotGreeted = true;
        initChatGreeting();
    }
    const input = document.getElementById("userChatInput");
    if (input) input.focus();
}

function clearCyberBotConversation() {
    initChatGreeting();
    document.getElementById("userChatInput").focus();
}

async function sendCyberBotMessage() {
    if (cyberBotSending) return;
    const inputField = document.getElementById("userChatInput");
    const sendButton = document.getElementById("chatSendButton");
    const userText = inputField.value.trim();
    if (!userText) return;

    appendCyberBotMessage("user", userText);
    const previous = cyberBotHistory.slice(-10).map(item => ({ role: item.role, content: item.content.slice(-1500) }));
    cyberBotHistory.push({ role: "user", content: userText });
    inputField.value = "";
    cyberBotSending = true;
    inputField.disabled = true;
    sendButton.disabled = true;
    const typingBubble = appendCyberBotMessage("assistant", "يكتب الآن...", { typing: true });
    let answer = "";
    let failed = false;

    const controller = new AbortController();
    const timeout = window.setTimeout(() => controller.abort(), 60000);
    try {
        const { ok, data } = await api("/api/chat", { message: userText, history: previous }, { signal: controller.signal });
        if (!ok) {
            failed = true;
            answer = data.error || "تعذر الحصول على رد. حاول مرة أخرى.";
            if (data.code === "quota") setCyberBotStatus("وصلت للحد اليومي. الترقية إلى Pro ترفع الحد.");
        } else {
            answer = String(data.reply || "").trim() || "لم يصل رد. حاول مرة أخرى.";
            if (data.mode === "ai") setCyberBotStatus("متصل بالذكاء الاصطناعي.", true);
            else if (data.mode === "fallback") setCyberBotStatus("المزوّد لم يرد الآن؛ هذه إجابة محلية مختصرة. حاول بعد قليل.");
            else setCyberBotStatus("يعمل بإجابات محلية (الذكاء الاصطناعي غير مفعّل على الخادم).");
        }
    } catch (error) {
        failed = true;
        answer = error && error.name === "AbortError" ? "استغرق الرد وقتاً طويلاً. حاول مرة أخرى." : "تعذر الاتصال بالخادم. تأكد من الإنترنت وحاول مرة أخرى.";
        setCyberBotStatus("غير متصل.");
    } finally {
        window.clearTimeout(timeout);
        typingBubble.remove();
        appendCyberBotMessage("assistant", answer);
        // ردود الأخطاء لا تدخل سياق المحادثة
        if (failed) cyberBotHistory.pop();
        else cyberBotHistory.push({ role: "assistant", content: answer });
        if (cyberBotHistory.length > 24) cyberBotHistory.splice(0, cyberBotHistory.length - 24);
        cyberBotSending = false;
        inputField.disabled = false;
        sendButton.disabled = false;
        inputField.focus();
    }
}
const phishingScenarios = [
    {
        id: 0,
        sender: "security-alert@faceb00k-verify.net",
        subject: "تنبيه عاجل: سيتم إغلاق حسابك خلال 24 ساعة!",
        body: "عزيزي المستخدم، تم رصد محاولة دخول مشبوهة لحسابك. يرجى الضغط على الرابط التالي لتأكيد هويتك وتجنب حظر الحساب فوراً:",
        link: "https://faceb00k-login-check.com",
        options: [
            { text: "النقر فوراً على الرابط وتحديث البيانات لتجنب إغلاق الحساب.", correct: false },
            { text: "كشف الرسالة كـ (تصيد): النطاق مزيف (faceb00k) وفيه لغة استعجال وتهديد.", correct: true },
            { text: "إرسال الرسالة لأصدقائك للتأكد منهم.", correct: false }
        ],
        explanation: "اسم النطاق يحتوي على استبدال حروف (faceb00k بدلاً من facebook) واستخدام لغة التهديد والاستعجال النفسي لإجبار الضحية على الاستجابة دون تفكير."
    },
    {
        id: 1,
        sender: "+964 770 000 0000 (رسالة SMS نصية)",
        subject: "إشعار مصرفي عاجل - تجميد الحساب",
        body: "عزيزي العميل، تم إيقاف بطاقتك البنكية مؤقتاً لعدم اكتمال التحديث السنوي. يرجى تأكيد معلوماتك عبر رابط البوابة الرسمية لتفادي الحظر:",
        link: "https://rafidain-bank-secure-update.com",
        options: [
            { text: "إدخال رقم البطاقة ورمز التحقق (OTP) المباشر عبر الرابط.", correct: false },
            { text: "تجاهل الرسالة تماماً والاتصال بالرقم الرسمي المسجل خلف البطاقة المصرفية.", correct: true },
            { text: "الرد على الرقم المرسل وطلب توضيح سبب إيقاف الحساب.", correct: false }
        ],
        explanation: "المصارف الرسمية لا تطلب أبداً تحديث البيانات عبر رسائل نصية قصيرة أو روابط خارجية، ورمز OTP سري للغاية ولا يُطلب في بوابات غير مسجلة."
    },
    {
        id: 2,
        sender: "hr-careers@remote-jobs-offer.org",
        subject: "مبروك! تم قبولك بوظيفة الأحلام براتب 2000$",
        body: "تم اختيارك للعمل معنا عن بعد براتب خيالي! لدفع رسوم الشحن الرمزية (25$) الخاصة بمعدات العمل، يرجى الدخول عبر رابط بوابة التوظيف:",
        link: "https://pay-fee-remote-jobs.net",
        options: [
            { text: "دفع الرسوم الرمزية عبر الرابط لضمان حجز الوظيفة فوراً.", correct: false },
            { text: "كشفها كنصب احتيالي: الشركات الحقيقية لا تطلب رسوماً مالية مسبقة من المتقدمين.", correct: true },
            { text: "مشاركة تفاصيل عرض العمل على وسائل التواصل الاجتماعي بفرحة.", correct: false }
        ],
        explanation: "هذا النوع يُعرف باحتيال رسوم التقدم المسبقة (Advance-fee scam)، حيث يطلب المخترقون مبالغ بسيطة بحجة الرسوم ليقوموا بسرقة بيانات بطاقتك الائتمانية."
    }
];

function loadSimulation(index) {
    const buttons = document.querySelectorAll('.sim-tab-btn');
    buttons.forEach((btn, idx) => {
        if(idx === index) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    const sc = phishingScenarios[index];
    const container = document.getElementById('simContentContainer');
    const optionsContainer = document.getElementById('simOptions');
    const feedback = document.getElementById('simFeedback');

    feedback.style.display = 'none';

    container.innerHTML = `
        <strong style="color: var(--accent-yellow);">المرسل:</strong> ${sc.sender}<br>
        <strong style="color: var(--accent-yellow);">الموضوع:</strong> ${sc.subject}<br><br>
        "${sc.body} <code style="color: var(--accent-blue); font-weight: bold;">${sc.link}</code>"
    `;

    let optionsHtml = '';
    sc.options.forEach((opt, optIdx) => {
        let iconClass = optIdx === 0 ? 'fa-arrow-pointer' : (optIdx === 1 ? 'fa-shield-halved' : 'fa-share');
        optionsHtml += `<button class="sim-option-btn" data-action="checkSimulation" data-arg="${index}" data-arg2="${optIdx}"><i class="fa-solid ${iconClass}"></i> ${opt.text}</button>`;
    });

    optionsContainer.innerHTML = optionsHtml;
}

function checkSimulation(scIndex, optIndex) {
    const sc = phishingScenarios[scIndex];
    const isCorrect = sc.options[optIndex].correct;
    const feedback = document.getElementById('simFeedback');
    feedback.style.display = 'block';

    if (isCorrect) {
        feedback.innerHTML = `
            <div style="color: var(--accent-green); font-weight: bold; font-size: 1.05rem;">
                <i class="fa-solid fa-circle-check"></i> إجابة نموذجية ممتازة!
            </div>
            <p style="margin-top: 8px; font-size: 0.9rem; color: var(--text-main);">
                ${sc.explanation}
            </p>
        `;
    } else {
        feedback.innerHTML = `
            <div style="color: var(--accent-red); font-weight: bold; font-size: 1.05rem;">
                <i class="fa-solid fa-triangle-exclamation"></i> خيار خاطئ وغير آمن!
            </div>
            <p style="margin-top: 8px; font-size: 0.9rem; color: var(--text-main);">
                وقعتا في فخ الاحتيال! ${sc.explanation} انتبه دائماً ولا تتفاعل مع هذه الروابط المشبوهة.
            </p>
        `;
    }
}

function testUrl(url) {
    document.getElementById('urlInput').value = url;
    analyzeUrl();
}

let scanHistory = [];

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

function addToHistory(target, type, score, statusText) {
    const now = new Date().toLocaleTimeString('ar-IQ');
    scanHistory.unshift({ time: now, target: target, type: type, score: score, status: statusText });

    const tbody = document.getElementById('historyTableBody');
    tbody.innerHTML = '';

    scanHistory.forEach(item => {
        let badgeStyle = item.score >= 55 ? 'color: var(--accent-red); font-weight:700;' : (item.score >= 25 ? 'color: var(--accent-yellow); font-weight:700;' : 'color: var(--accent-green); font-weight:700;');
        tbody.innerHTML += `
            <tr>
                <td>${item.time}</td>
                <td style="direction:ltr; max-width:250px; overflow:hidden; text-overflow:ellipsis;">${escapeHtml(item.target)}</td>
                <td>${item.type}</td>
                <td style="${badgeStyle}">${item.score}%</td>
                <td>${item.status}</td>
            </tr>
        `;
    });
}

// ---- ربط محرك الكشف (detection-engine.js) بالصفحة ----
const LEVEL_UI = {
    safe:    { badge: 'score-safe',    icon: 'fa-circle-check' },
    warning: { badge: 'score-warning', icon: 'fa-circle-exclamation' },
    danger:  { badge: 'score-danger',  icon: 'fa-triangle-exclamation' }
};
const LEVEL_TITLES = {
    url:  { safe: 'لم تُرصد مؤشرات خطر في الرابط (Low Risk)', warning: 'تنبيه: مؤشرات مخاطرة تستدعي الحذر (Medium Risk)', danger: 'تحذير شديد: رابط تصيد واحتيال محتمل (High Risk)' },
    text: { safe: 'لم تُرصد أساليب احتيال معروفة في النص (Low Risk)', warning: 'تنبيه: في الرسالة مؤشرات تستدعي الحذر (Medium Risk)', danger: 'تحذير: رسالة احتيال وهندسة اجتماعية محتملة (High Risk)' },
    file: { safe: 'لم تُرصد مؤشرات خطر في الملف (Low Risk)', warning: 'تنبيه: الملف فيه مؤشرات تستدعي الحذر (Medium Risk)', danger: 'تحذير شديد: ملف مشبوه أو خبيث محتمل (High Risk)' }
};
// يحفظ نتيجة فحص تم داخل المتصفح (ملف/وسائط) بسجل الحساب لمشتركي Pro
function recordScan(kind, label, score, level) {
    api('/api/scan/record', { kind, label: String(label).slice(0, 120), score, level }).catch(() => {});
}

const LEVEL_STATUS = { safe: 'لا مؤشرات', warning: 'تنبيه', danger: 'خطر' };
const SCAN_DISCLAIMER = 'الفحص يعتمد على قواعد وخوارزميات وقوائم تهديدات عامة. غياب المؤشرات لا يثبت أن الهدف آمن، ووجودها لا يثبت أنه خبيث.';

// يرسم تقرير الفحص. كل نص قادم من المستخدم أو من المحرك يمر عبر escapeHtml.
function renderReport(box, kind, scoreLabel, result, metaHtml, extraHtml) {
    const ui = LEVEL_UI[result.level];
    const items = result.reasons
        .map(r => `<li class="li-${r.type}">${escapeHtml(r.text)}</li>`)
        .join('');
    box.style.display = 'block';
    box.innerHTML = `
        <div class="report-header">
            <div>
                <strong style="font-size:1.1rem;"><i class="fa-solid ${ui.icon}"></i> ${LEVEL_TITLES[kind][result.level]}</strong>
            </div>
            <div class="risk-score-badge ${ui.badge}">
                ${scoreLabel}: ${result.score}%
            </div>
        </div>
        <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:8px;">${metaHtml}</div>
        <ul class="report-details-list">${items}</ul>
        ${extraHtml || ''}
        <p style="font-size:0.78rem; color:var(--text-muted); margin-top:12px;">${SCAN_DISCLAIMER}</p>
    `;
}

let urlScanBusy = false;
async function analyzeUrl() {
    const input = document.getElementById('urlInput').value.trim();
    const reportBox = document.getElementById('reportBox');
    const strict = document.getElementById('academicDefenseToggle').checked;

    if (!input) {
        reportBox.style.display = 'block';
        reportBox.innerHTML = errorHtml('اكتب الرابط أولاً.');
        return;
    }
    if (urlScanBusy) return;
    urlScanBusy = true;
    reportBox.style.display = 'block';
    reportBox.innerHTML = loadingHtml('جارٍ فحص الرابط بالمحرك وقوائم التهديدات...');

    let response;
    try {
        response = await api('/api/scan/url', { url: input, strict });
    } catch {
        reportBox.innerHTML = errorHtml('تعذر الاتصال بالخادم. حاول مرة أخرى.');
        return;
    } finally {
        urlScanBusy = false;
    }
    const { ok, data } = response;
    if (!ok) {
        reportBox.innerHTML = data.code === 'quota' ? quotaHtml(data.error) : errorHtml(data.error || 'تعذر الفحص.');
        return;
    }
    const result = data.result;

    let meta = `<strong>الرابط المحلل:</strong> <code style="direction:ltr; display:inline-block;">${escapeHtml(result.input)}</code>`;
    if (result.host) {
        meta += `<br><strong>النطاق الفعلي:</strong> <code style="direction:ltr; display:inline-block;">${escapeHtml(result.registrable || result.host)}</code>`;
        if (result.unicodeHost && result.unicodeHost !== result.host) {
            meta += ` &nbsp;<strong>يظهر بالأحرف:</strong> <code style="direction:ltr; display:inline-block;">${escapeHtml(result.unicodeHost)}</code>`;
        }
    }
    const checks = result.checks || {};
    const layers = ['محرك القواعد'];
    if (checks.feeds) layers.push('قوائم التهديدات (OpenPhish / URLhaus)');
    if (checks.deep) layers.push('عمر النطاق (RDAP)');
    meta += `<br><strong>طبقات الفحص:</strong> ${escapeHtml(layers.join(' + '))}`;
    if (strict) meta += '<br><strong>الوضع:</strong> حماية أكاديمية وحكومية مشددة (عتبات تنبيه أقل).';
    const extra = checks.deep ? '' : '<p style="font-size:0.8rem; color:var(--text-muted); margin-top:10px;"><i class="fa-solid fa-crown"></i> مشتركو Pro يحصلون على فحص عمر النطاق وتاريخ تسجيله أيضاً.</p>';
    renderReport(reportBox, 'url', 'مؤشر الخطورة', result, meta, extra);

    addToHistory(input, 'رابط URL', result.score, LEVEL_STATUS[result.level]);
}

let textScanBusy = false;
async function analyzeText() {
    const textInput = document.getElementById('textInput').value.trim();
    const textReportBox = document.getElementById('textReportBox');

    if (!textInput) {
        textReportBox.style.display = 'block';
        textReportBox.innerHTML = errorHtml('الصق نص الرسالة أولاً.');
        return;
    }
    if (textScanBusy) return;
    textScanBusy = true;
    textReportBox.style.display = 'block';
    textReportBox.innerHTML = loadingHtml('جارٍ تحليل الرسالة وروابطها...');

    let response;
    try {
        response = await api('/api/scan/text', { text: textInput.slice(0, 10000) });
    } catch {
        textReportBox.innerHTML = errorHtml('تعذر الاتصال بالخادم. حاول مرة أخرى.');
        return;
    } finally {
        textScanBusy = false;
    }
    const { ok, data } = response;
    if (!ok) {
        textReportBox.innerHTML = data.code === 'quota' ? quotaHtml(data.error) : errorHtml(data.error || 'تعذر الفحص.');
        return;
    }
    const result = data.result;
    const preview = textInput.length > 140 ? textInput.substring(0, 140) + '…' : textInput;
    const meta = `<strong>النص المحلل:</strong> <p style="margin-top:4px; color:var(--text-main); font-style:italic;">"${escapeHtml(preview)}"</p>`;

    let extra = '';
    if (result.advice && result.advice.length) {
        extra = `
            <div style="margin-top:14px; padding:12px 14px; border:1px dashed var(--border-color); border-radius:10px;">
                <strong><i class="fa-solid fa-shield-heart"></i> ماذا تفعل؟</strong>
                <ul class="report-details-list">${result.advice.map(a => `<li class="li-info">${escapeHtml(a)}</li>`).join('')}</ul>
            </div>`;
    }
    renderReport(textReportBox, 'text', 'مؤشر المخاطر', result, meta, extra);

    addToHistory(textInput.substring(0, 30) + (textInput.length > 30 ? '…' : ''), 'نص رسالة', result.score, LEVEL_STATUS[result.level]);
}

function updateFileName(input) {
    const label = document.getElementById('fileLabelText');
    if (input.files && input.files[0]) {
        label.innerHTML = `الملف المختار: <span style="color: var(--accent-blue);">${escapeHtml(input.files[0].name)}</span>`;
    }
}

const FILE_HEAD_BYTES = 1024 * 1024;       // أول 1MB: الترويسة ومحتوى السكربتات
const FILE_TAIL_BYTES = 256 * 1024;        // آخر 256KB: فهرس ملفات ZIP/DOCX وذيل PDF
const FILE_HASH_MAX_BYTES = 64 * 1024 * 1024;

// بصمة SHA-256 للملف كاملاً (تُحسب داخل المتصفح). تتوقف عند الملفات الكبيرة أو الصفحات غير الآمنة (غير https).
async function sha256Hex(file) {
    if (!window.crypto || !crypto.subtle || file.size > FILE_HASH_MAX_BYTES) return null;
    try {
        const digest = await crypto.subtle.digest('SHA-256', await file.arrayBuffer());
        return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
    } catch {
        return null;
    }
}

async function analyzeFile() {
    const fileInput = document.getElementById('fileInput');
    const reportBox = document.getElementById('fileReportBox');

    if (fileInput.files.length === 0) {
        alert('يرجى اختيار ملف أولاً لغرض الفحص الأمني.');
        return;
    }

    const file = fileInput.files[0];
    reportBox.style.display = 'block';
    // نحجز الفحص من حصة اليوم (الملف نفسه لا يُرسل للخادم)
    try {
        const { ok, data } = await api('/api/scan/file', { size: file.size });
        if (!ok) {
            reportBox.innerHTML = data.code === 'quota' ? quotaHtml(data.error) : errorHtml(data.error || 'تعذر بدء الفحص.');
            return;
        }
    } catch {
        reportBox.innerHTML = errorHtml('تعذر الاتصال بالخادم. حاول مرة أخرى.');
        return;
    }
    reportBox.innerHTML = loadingHtml('جاري قراءة البصمة الثنائية وترويسة الملف وفحص محتواه داخل جهازك...');

    let result, hash;
    try {
        const head = new Uint8Array(await file.slice(0, FILE_HEAD_BYTES).arrayBuffer());
        const tail = file.size > FILE_HEAD_BYTES
            ? new Uint8Array(await file.slice(Math.max(FILE_HEAD_BYTES, file.size - FILE_TAIL_BYTES)).arrayBuffer())
            : new Uint8Array(0);
        result = PhishingEngine.analyzeFile({ name: file.name, size: file.size, head, tail });
        hash = await sha256Hex(file);
    } catch {
        reportBox.innerHTML = '<div style="color:var(--accent-red);">تعذر قراءة الملف. قد يكون محذوفاً أو غير قابل للوصول.</div>';
        return;
    }

    const sizeText = file.size >= 1024 * 1024 ? (file.size / (1024 * 1024)).toFixed(2) + ' MB' : (file.size / 1024).toFixed(2) + ' KB';
    let meta = `<strong>اسم الملف:</strong> ${escapeHtml(file.name)} | <strong>النوع الفعلي:</strong> ${escapeHtml(result.type.label)} | <strong>الحجم:</strong> ${sizeText}`;
    if (file.size > 0) meta += ` | <strong>عشوائية البيانات:</strong> ${result.entropy} / 8`;

    let extra = '';
    if (hash) {
        extra = `
            <div style="margin-top:14px; padding:12px 14px; border:1px dashed var(--border-color); border-radius:10px;">
                <strong><i class="fa-solid fa-fingerprint"></i> بصمة الملف (SHA-256)</strong>
                <p style="font-size:0.78rem; direction:ltr; word-break:break-all; margin:6px 0; color:var(--text-main);">${hash}</p>
                <a href="https://www.virustotal.com/gui/file/${hash}" target="_blank" rel="noopener noreferrer" style="color:var(--accent-blue); font-size:0.85rem;">
                    <i class="fa-solid fa-magnifying-glass"></i> ابحث عن البصمة في VirusTotal
                </a>
                <span style="font-size:0.78rem; color:var(--text-muted);"> (يبحث بالبصمة فقط، والملف نفسه لا يُرفع. إذا كان الملف جديداً أو نادراً قد لا يظهر له نتيجة.)</span>
            </div>`;
    } else if (file.size > FILE_HASH_MAX_BYTES) {
        extra = '<p style="font-size:0.78rem; color:var(--text-muted); margin-top:10px;">لم تُحسب بصمة SHA-256 لأن حجم الملف يتجاوز 64MB.</p>';
    }

    cleanCandidate = result.type.kind === 'image' ? { file, type: result.type.label } : null;
    extra += cleanSectionHtml(result.type.kind);
    renderReport(reportBox, 'file', 'مؤشر الخطورة', result, meta, extra);
    addToHistory(file.name, 'فحص ملف', result.score, LEVEL_STATUS[result.level]);
    recordScan('file', file.name, result.score, result.level);
}

// ---- تنظيف الملفات (Pro) ----
// الصورة تُعاد رسمها وترميزها من البكسلات فقط، فتسقط كل البيانات المخفية (EXIF، تعليقات، أكواد ملحقة بنهاية الملف، ملفات متعددة الصيغ).
// الملفات التنفيذية لا يمكن تنظيفها بأمان: الخطر فيها هو الملف نفسه، فنوصي بحذفها.
let cleanCandidate = null;
const CLEAN_MAX_BYTES = 25 * 1024 * 1024;

function cleanSectionHtml(kind) {
    const box = 'margin-top:14px; padding:12px 14px; border:1px dashed var(--border-color); border-radius:10px;';
    if (kind === 'image') {
        return `<div style="${box}">
            <strong><i class="fa-solid fa-broom"></i> تنظيف الصورة <span class="pro-badge" style="color:#ffab00;">Pro</span></strong>
            <p style="font-size:0.85rem; color:var(--text-muted); margin:6px 0;">نعيد بناء الصورة من البكسلات فقط، فتُزال بيانات EXIF والموقع والتعليقات وأي كود مخفي ملحق بالملف، ونسلّمك نسخة سليمة. (الصور المتحركة تتحول لصورة ثابتة.)</p>
            <button class="app-btn small" type="button" data-action="cleanScannedFile"><i class="fa-solid fa-broom"></i> نظّف الصورة وحمّلها</button>
            <div id="cleanStatus" style="margin-top:10px; font-size:0.9rem;"></div>
        </div>`;
    }
    if (['executable', 'script', 'shortcut', 'disk'].includes(kind)) {
        return `<div style="${box}">
            <strong><i class="fa-solid fa-ban"></i> لا يمكن تنظيف هذا النوع من الملفات</strong>
            <p style="font-size:0.85rem; color:var(--text-muted); margin:6px 0;">الملف التنفيذي هو البرنامج نفسه، فلا يوجد جزء «مصاب» نشيله ونبقي الباقي. إذا كان الملف مشبوهاً: لا تشغّله، احذفه، واحصل على نسخة من المصدر الرسمي.</p>
        </div>`;
    }
    return '';
}

async function cleanScannedFile() {
    const status = document.getElementById('cleanStatus');
    if (!status || !cleanCandidate) return;
    const { file } = cleanCandidate;
    if (file.size > CLEAN_MAX_BYTES) { status.innerHTML = errorHtml('الحد الأقصى لحجم الصورة 25MB.'); return; }
    status.textContent = 'جارٍ التحقق من الخطة...';
    try {
        const { ok, data } = await api('/api/scan/clean', { kind: 'image', size: file.size });
        if (!ok) {
            status.innerHTML = data.code === 'pro_only' ? quotaHtml(data.error) : errorHtml(data.error || 'تعذر بدء التنظيف.');
            return;
        }
    } catch {
        status.innerHTML = errorHtml('تعذر الاتصال بالخادم.');
        return;
    }
    status.textContent = 'جارٍ تنظيف الصورة...';
    try {
        const bitmap = await createImageBitmap(file);
        if (bitmap.width * bitmap.height > 80_000_000) throw new Error('too large');
        const canvas = document.createElement('canvas');
        canvas.width = bitmap.width;
        canvas.height = bitmap.height;
        const context = canvas.getContext('2d');
        const isJpeg = /JPG|JPEG/i.test(cleanCandidate.type);
        if (isJpeg) { context.fillStyle = '#fff'; context.fillRect(0, 0, canvas.width, canvas.height); }
        context.drawImage(bitmap, 0, 0);
        bitmap.close();
        const mime = isJpeg ? 'image/jpeg' : 'image/png';
        const blob = await new Promise((resolve, reject) => canvas.toBlob(b => (b ? resolve(b) : reject(new Error('encode'))), mime, 0.95));
        const base = file.name.replace(/\.[^.\\/]*$/, '').replace(/[\u0000-\u001f\\/:*?"<>|\u202a-\u202e\u2066-\u2069]/g, '').slice(0, 80) || 'image';
        const link = document.createElement('a');
        link.href = URL.createObjectURL(blob);
        link.download = `${base}-clean.${isJpeg ? 'jpg' : 'png'}`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(link.href), 10_000);
        const saved = file.size - blob.size;
        status.innerHTML = `<span style="color:var(--accent-green);"><i class="fa-solid fa-circle-check"></i> تم التنظيف وتنزيل النسخة السليمة (${escapeHtml(link.download)}).</span>`
            + (saved > 0 ? ` أُزيل ${(saved / 1024).toFixed(1)} KB من البيانات الإضافية.` : '');
    } catch {
        status.innerHTML = errorHtml('تعذر تنظيف هذه الصورة: قد تكون تالفة أو بصيغة غير مدعومة في متصفحك.');
    }
}

function updateMediaFileName(input) {
    const label = document.getElementById('mediaLabelText');
    if (input.files && input.files[0]) {
        label.innerHTML = `الملف المختار: <span style="color: var(--accent-blue);">${escapeHtml(input.files[0].name)}</span>`;
    }
}

const MEDIA_EXTENSIONS = {
    audio: ['mp3', 'wav', 'ogg', 'oga', 'opus', 'flac', 'm4a', 'aac', 'wma', 'amr'],
    video: ['mp4', 'm4v', 'mov', 'webm', 'mkv', 'avi', 'wmv', '3gp']
};
const EXECUTABLE_EXTENSIONS = ['exe', 'scr', 'bat', 'cmd', 'com', 'pif', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'ps1', 'msi', 'hta', 'lnk', 'jar', 'dll', 'apk'];

// يقرأ أول بايتات الملف ويطابقها مع تواقيع الصيغ المعروفة (Magic Bytes)
function detectMediaSignature(bytes) {
    const hex = (start, length) => Array.from(bytes.slice(start, start + length))
        .map(b => b.toString(16).toUpperCase().padStart(2, '0')).join('');
    const ascii = (start, length) => String.fromCharCode(...bytes.slice(start, start + length));

    if (bytes.length < 4) return { kind: 'unknown', label: 'ملف فارغ أو صغير جداً بلا بصمة معروفة' };
    if (hex(0, 2) === '4D5A') return { kind: 'executable', label: 'ملف تنفيذي لنظام Windows (EXE / DLL)' };
    if (hex(0, 4) === '7F454C46') return { kind: 'executable', label: 'ملف تنفيذي لنظام Linux (ELF)' };
    if (['FEEDFACE', 'FEEDFACF', 'CEFAEDFE', 'CFFAEDFE', 'CAFEBABE'].includes(hex(0, 4))) {
        return { kind: 'executable', label: 'ملف تنفيذي (macOS Mach-O أو Java Class)' };
    }
    if (hex(0, 4) === '504B0304') return { kind: 'archive', label: 'أرشيف مضغوط (ZIP / JAR / APK / Office)' };
    if (ascii(0, 4) === 'Rar!') return { kind: 'archive', label: 'أرشيف مضغوط (RAR)' };
    if (hex(0, 6) === '377ABCAF271C') return { kind: 'archive', label: 'أرشيف مضغوط (7z)' };
    if (hex(0, 4) === '25504446') return { kind: 'document', label: 'مستند PDF' };
    if (hex(0, 3) === 'FFD8FF' || hex(0, 4) === '89504E47' || ascii(0, 4) === 'GIF8') {
        return { kind: 'image', label: 'صورة (JPG / PNG / GIF)' };
    }
    if (ascii(0, 5) === '#!AMR') return { kind: 'audio', label: 'صوت AMR' };
    if (ascii(0, 3) === 'ID3') return { kind: 'audio', label: 'صوت MP3 (يحتوي وسم ID3)' };
    if (bytes[0] === 0xFF && (bytes[1] & 0xF6) === 0xF0) return { kind: 'audio', label: 'صوت AAC (ADTS)' };
    if (bytes[0] === 0xFF && (bytes[1] & 0xE0) === 0xE0) return { kind: 'audio', label: 'صوت MP3 (إطارات MPEG)' };
    if (ascii(0, 4) === 'RIFF') {
        const riffType = ascii(8, 4);
        if (riffType === 'WAVE') return { kind: 'audio', label: 'صوت WAV' };
        if (riffType === 'AVI ') return { kind: 'video', label: 'فيديو AVI' };
        return { kind: 'unknown', label: 'حاوية RIFF غير معروفة' };
    }
    if (ascii(0, 4) === 'OggS') return { kind: 'media', label: 'حاوية Ogg (صوت أو فيديو)' };
    if (ascii(0, 4) === 'fLaC') return { kind: 'audio', label: 'صوت FLAC' };
    if (ascii(4, 4) === 'ftyp') {
        const brand = ascii(8, 4);
        if (brand.startsWith('M4A') || brand.startsWith('M4B')) return { kind: 'audio', label: 'صوت M4A' };
        if (brand === 'qt  ') return { kind: 'video', label: 'فيديو QuickTime (MOV)' };
        if (brand.startsWith('3g')) return { kind: 'video', label: 'فيديو 3GP' };
        return { kind: 'media', label: 'حاوية MP4 (فيديو أو صوت)' };
    }
    if (hex(0, 4) === '1A45DFA3') return { kind: 'media', label: 'حاوية WebM / MKV' };
    if (hex(0, 4) === '3026B275') return { kind: 'media', label: 'حاوية Windows Media (WMA / WMV)' };
    return { kind: 'unknown', label: 'بصمة غير مطابقة لأي صيغة وسائط معروفة' };
}

// يحاول المتصفح قراءة بيانات الملف (المدة والأبعاد) بدون تشغيله
function probeMediaPlayback(file) {
    return new Promise(resolve => {
        const objectUrl = URL.createObjectURL(file);
        const element = document.createElement('video');
        let finished = false;
        const finish = result => {
            if (finished) return;
            finished = true;
            clearTimeout(timer);
            element.removeAttribute('src');
            element.load();
            URL.revokeObjectURL(objectUrl);
            resolve(result);
        };
        const timer = setTimeout(() => finish({ ok: false }), 6000);
        element.preload = 'metadata';
        element.muted = true;
        element.onloadedmetadata = () => finish({
            ok: true,
            duration: element.duration,
            width: element.videoWidth,
            height: element.videoHeight
        });
        element.onerror = () => finish({ ok: false });
        element.src = objectUrl;
    });
}

function formatMediaDuration(seconds) {
    if (!Number.isFinite(seconds) || seconds <= 0) return 'غير معروفة';
    const total = Math.round(seconds);
    const minutes = Math.floor(total / 60);
    return minutes + ':' + String(total % 60).padStart(2, '0');
}

async function uploadAndScan() {
    const fileInput = document.getElementById('mediaUpload');
    const reportBox = document.getElementById('mediaReportBox');

    if (fileInput.files.length === 0) {
        alert('يرجى اختيار ملف صوت أو فيديو أولاً لغرض الفحص.');
        return;
    }

    const file = fileInput.files[0];
    reportBox.style.display = 'block';
    reportBox.innerHTML = '<div style="text-align:center; padding:1rem;"><i class="fa-solid fa-gear fa-spin" style="font-size:2rem; color:var(--accent-blue);"></i><br><br>جاري قراءة البصمة الثنائية للملف ومحاولة قراءة بياناته داخل المتصفح...</div>';

    const bytes = new Uint8Array(await file.slice(0, 64).arrayBuffer());
    const signature = detectMediaSignature(bytes);
    const isMediaContent = ['audio', 'video', 'media'].includes(signature.kind);

    const lowerName = file.name.toLowerCase();
    const nameParts = lowerName.split('.');
    const extension = nameParts.length > 1 ? nameParts.pop() : '';
    const innerExtensions = nameParts.slice(1);
    const isMediaExtension = ext => MEDIA_EXTENSIONS.audio.includes(ext) || MEDIA_EXTENSIONS.video.includes(ext);
    const extensionFamily = MEDIA_EXTENSIONS.audio.includes(extension) ? 'audio'
        : MEDIA_EXTENSIONS.video.includes(extension) ? 'video'
        : EXECUTABLE_EXTENSIONS.includes(extension) ? 'executable'
        : 'other';

    let riskScore = 0;
    const reasons = [];
    const raise = value => { riskScore = Math.max(riskScore, value); };

    if (/[‪-‮⁦-⁩]/.test(file.name)) {
        raise(100);
        reasons.push({ text: 'اسم الملف يحتوي محارف خفية تعكس اتجاه النص (RLO)، وهي حيلة معروفة لإخفاء الامتداد الحقيقي للملف.', type: 'danger' });
    }

    if (extensionFamily === 'executable') {
        if (innerExtensions.some(isMediaExtension)) {
            raise(100);
            reasons.push({ text: `امتداد مزدوج مخادع: الاسم يوحي بملف وسائط لكن امتداده الحقيقي هو .${escapeHtml(extension)} (ملف تنفيذي).`, type: 'danger' });
        } else {
            raise(90);
            reasons.push({ text: `امتداد الملف .${escapeHtml(extension)} امتداد تنفيذي وليس امتداد صوت أو فيديو.`, type: 'danger' });
        }
    }

    if (signature.kind === 'executable') {
        raise(100);
        reasons.push({ text: `البصمة الثنائية تكشف أن محتوى الملف هو ${signature.label} وليس صوتاً أو فيديو. لا تفتح هذا الملف.`, type: 'danger' });
    } else if (signature.kind === 'archive') {
        raise(75);
        reasons.push({ text: `محتوى الملف ${signature.label} وليس وسائط، وقد يحتوي ملفات أخرى مخفية.`, type: 'danger' });
    } else if (signature.kind === 'document' || signature.kind === 'image') {
        raise(45);
        reasons.push({ text: `محتوى الملف ${signature.label}، ولا يطابق ملف صوت أو فيديو.`, type: 'warning' });
    } else if (signature.kind === 'unknown') {
        raise(40);
        reasons.push({ text: `${signature.label}. قد يكون الملف تالفاً أو بصيغة نادرة أو مموهاً.`, type: 'warning' });
    } else {
        reasons.push({ text: `البصمة الثنائية تطابق ملف وسائط حقيقياً: ${signature.label}.`, type: 'safe' });
        if (extensionFamily === 'other') {
            raise(20);
            reasons.push({ text: `امتداد الملف ${extension ? '.' + escapeHtml(extension) : '(بلا امتداد)'} غير معتاد لملفات الوسائط رغم أن المحتوى وسائط.`, type: 'warning' });
        } else if ((signature.kind === 'audio' && extensionFamily === 'video') || (signature.kind === 'video' && extensionFamily === 'audio')) {
            raise(10);
            reasons.push({ text: 'نوع المحتوى (صوت/فيديو) لا يطابق الامتداد. هذا شائع ولا يدل على خطر بحد ذاته.', type: 'warning' });
        }
    }

    let durationText = '—';
    let dimensionsText = '—';
    if (isMediaContent) {
        const probe = await probeMediaPlayback(file);
        if (probe.ok) {
            durationText = formatMediaDuration(probe.duration);
            dimensionsText = probe.width > 0 ? `${probe.width}×${probe.height}` : 'صوت فقط';
            reasons.push({ text: `قرأ المتصفح الملف بنجاح (المدة ${durationText}${probe.width > 0 ? '، الدقة ' + dimensionsText : '، مسار صوتي بلا صورة'}).`, type: 'safe' });
        } else {
            raise(25);
            reasons.push({ text: 'لم يستطع المتصفح قراءة الملف. قد تكون صيغته غير مدعومة في هذا المتصفح، أو يكون الملف تالفاً.', type: 'warning' });
        }
    }

    let badgeClass = 'score-safe';
    let statusTitle = 'بنية الملف سليمة: ملف وسائط حقيقي';
    let statusIcon = 'fa-circle-check';
    let historyStatus = 'سليم';
    if (riskScore >= 70) {
        badgeClass = 'score-danger';
        statusTitle = 'خطر: الملف ليس صوتاً أو فيديو حقيقياً (High Risk)';
        statusIcon = 'fa-triangle-exclamation';
        historyStatus = 'خطر';
    } else if (riskScore >= 30) {
        badgeClass = 'score-warning';
        statusTitle = 'تنبيه: تعذّر التأكد من أن الملف وسائط سليمة';
        statusIcon = 'fa-circle-exclamation';
        historyStatus = 'تنبيه';
    }

    const listHtml = reasons.map(r => `<li class="li-${r.type}">${r.text}</li>`).join('');

    reportBox.innerHTML = `
        <div class="report-header">
            <div>
                <strong style="font-size:1.1rem;"><i class="fa-solid ${statusIcon}"></i> ${statusTitle}</strong>
            </div>
            <div class="risk-score-badge ${badgeClass}">
                مؤشر خطورة الملف: ${riskScore}%
            </div>
        </div>
        <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:8px;">
            <strong>اسم الملف:</strong> ${escapeHtml(file.name)} | <strong>المحتوى الفعلي:</strong> ${signature.label} | <strong>الحجم:</strong> ${(file.size / (1024 * 1024)).toFixed(2)} MB | <strong>المدة:</strong> ${durationText} | <strong>الأبعاد:</strong> ${dimensionsText}
        </div>
        <ul class="report-details-list">
            ${listHtml}
        </ul>
        <div style="margin-top:14px; padding:12px 14px; border:1px dashed var(--border-color); border-radius:10px;">
            <strong><i class="fa-solid fa-user-ninja"></i> التزييف العميق (Deepfake): يحتاج تحققاً يدوياً</strong>
            <p style="font-size:0.85rem; color:var(--text-muted); margin:6px 0;">هذا الفحص لا يحدد إن كان الصوت أو الفيديو مولداً بالذكاء الاصطناعي. سلامة بنية الملف لا تعني أن محتواه حقيقي.</p>
            <ul class="report-details-list">
                <li class="li-warning">قارن حركة الشفاه بالكلام، وراقب الرمش وحدود الوجه والشعر والإضاءة عند تحريك الرأس.</li>
                <li class="li-warning">استمع لنبرة رتيبة، أو غياب صوت التنفس والضوضاء الطبيعية، أو انتقالات مقطوعة بين الكلمات.</li>
                <li class="li-warning">تحقق من مصدر المقطع: من نشره أولاً؟ وهل نقلته جهة موثوقة؟</li>
                <li class="li-warning">إذا طلب المقطع مالاً أو بيانات، اتصل بالشخص على رقم تعرفه مسبقاً قبل أي تصرف.</li>
            </ul>
        </div>
    `;

    addToHistory(file.name, 'فحص سلامة ملف وسائط', riskScore, historyStatus);
    recordScan('media', file.name, riskScore, riskScore >= 70 ? 'danger' : (riskScore >= 30 ? 'warning' : 'safe'));
}

// ==========================================================
// موزّع الأحداث: بديل المعالجات المضمنة (onclick=...) حتى تعمل سياسة CSP الصارمة
// ==========================================================
const ACTIONS = {
    analyzeUrl, analyzeText, analyzeFile, uploadAndScan, toggleThemeMenu, openCyberBot,
    clearCyberBotConversation, sendCyberBotMessage, testUrl, loadSimulation, checkSimulation,
    updateFileName, updateMediaFileName, cleanScannedFile
};

// يبلّغ حارس الأخطاء (error-guard.js) ويبقي الصفحة تعمل
function reportError(label, error) {
    if (window.PDGuard) window.PDGuard.captureError(label, error);
    else console.error(label, error);
}

// ينفّذ أي أمر داخل try/catch (متزامن أو async): فشل أمر واحد لا يعطّل بقية الصفحة
function guarded(label, fn) {
    try {
        const result = fn();
        if (result && typeof result.catch === 'function') result.catch(error => reportError(label, error));
    } catch (error) {
        reportError(label, error);
    }
}

function runAction(name, ...args) {
    const action = Object.prototype.hasOwnProperty.call(ACTIONS, name) ? ACTIONS[name] : null;
    if (action) guarded(name, () => action(...args));
}

function actionArg(value) {
    return typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
}

document.addEventListener('click', event => {
    const el = event.target.closest('[data-page],[data-theme],[data-action],[data-click-target]');
    if (!el) return;
    if (el.dataset.page) {
        guarded('switchPage', () => switchPage(el.dataset.page, el.dataset.title || '', el.dataset.icon || ''));
    } else if (el.dataset.theme) {
        guarded('setTheme', () => setTheme(el.dataset.theme));
    } else if (el.dataset.action) {
        runAction(el.dataset.action, actionArg(el.dataset.arg), actionArg(el.dataset.arg2));
    } else if (el.dataset.clickTarget) {
        const target = document.getElementById(el.dataset.clickTarget);
        if (target && event.target !== target) target.click();
    }
});

document.addEventListener('change', event => {
    const name = event.target.dataset && event.target.dataset.change;
    if (name) runAction(name, event.target);
});

document.addEventListener('submit', event => {
    const name = event.target.dataset && event.target.dataset.submit;
    if (name) {
        event.preventDefault();
        runAction(name);
    }
});

document.addEventListener('keydown', event => {
    const name = event.target.dataset && event.target.dataset.enter;
    if (name && event.key === 'Enter') {
        event.preventDefault();
        runAction(name);
    }
});
