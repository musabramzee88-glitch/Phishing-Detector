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

const cyberBotHistory = [];
let activeCyberBotUser = "";
let cyberBotSending = false;

function normalizeCyberBotText(value) {
    return String(value || "").toLowerCase().normalize("NFKD")
        .replace(/[\u064B-\u065F\u0670\u0640]/g, "")
        .replace(/[أإآٱ]/g, "ا").replace(/ى/g, "ي").replace(/ة/g, "ه")
        .replace(/\s+/g, " ").trim();
}

function setCyberBotStatus(message, connected = false) {
    const status = document.getElementById("chatConnectionStatus");
    if (!status) return;
    status.textContent = message;
    status.style.color = connected ? "var(--accent-green)" : "var(--text-muted)";
}

function appendCyberBotMessage(role, content, options = {}) {
    const history = document.getElementById("chatHistory");
    const bubble = document.createElement("div");
    bubble.className = "chat-bubble " + (role === "user" ? "chat-bubble-user" : "chat-bubble-assistant");
    if (options.typing) bubble.classList.add("chat-typing");
    const label = document.createElement("strong");
    label.className = "chat-bubble-label";
    label.textContent = options.typing ? "CyberBot AI:" : (role === "user" ? (localStorage.getItem("cyber_bot_username") || "أنت") + ":" : "CyberBot AI:");
    bubble.appendChild(label);
    const body = document.createElement("span");
    body.textContent = String(content);
    bubble.appendChild(body);
    history.appendChild(bubble);
    history.scrollTop = history.scrollHeight;
    return bubble;
}

function initChatGreeting(userName) {
    document.getElementById("chatHistory").replaceChildren();
    cyberBotHistory.length = 0;
    appendCyberBotMessage("assistant", "أهلًا " + userName + ". أنا CyberBot، أستطيع متابعة سياق حديثنا ومساعدتك في الأسئلة العامة والأمن السيبراني. عند عدم اتصال نموذج الذكاء الاصطناعي ستكون إجاباتي المحلية محدودة. كيف أساعدك؟");
}

function checkUserSession() {
    const storedName = localStorage.getItem("cyber_bot_username");
    const promptCard = document.getElementById("namePromptCard");
    const chatCard = document.getElementById("chatInterfaceCard");
    if (storedName) {
        promptCard.style.display = "none";
        chatCard.style.display = "block";
        document.getElementById("greetingSubtitle").textContent = "المحادثة باسم: " + storedName;
        if (activeCyberBotUser !== storedName) {
            activeCyberBotUser = storedName;
            initChatGreeting(storedName);
        }
        const endpointField = document.getElementById("chatEndpointInput");
        endpointField.value = localStorage.getItem("cyber_bot_endpoint") ?? "/api/chat";
        setCyberBotStatus(endpointField.value.trim()
            ? "عنوان الخادم محفوظ. سيُفحص الاتصال عند إرسال رسالة."
            : "الوضع المحلي محدود؛ اربط خادمًا للحصول على إجابات عامة.");
    } else {
        promptCard.style.display = "block";
        chatCard.style.display = "none";
        activeCyberBotUser = "";
    }
}

function saveUserName() {
    const nameInput = document.getElementById("userNameInput");
    const name = nameInput.value.trim().slice(0, 50);
    if (!name) {
        alert("يرجى إدخال اسم صحيح للمتابعة");
        return;
    }
    localStorage.setItem("cyber_bot_username", name);
    nameInput.value = "";
    checkUserSession();
    document.getElementById("userChatInput").focus();
}

function resetUserName() {
    localStorage.removeItem("cyber_bot_username");
    checkUserSession();
}

function saveCyberBotEndpoint() {
    const input = document.getElementById("chatEndpointInput");
    const endpoint = input.value.trim();
    if (!endpoint) {
        localStorage.setItem("cyber_bot_endpoint", "");
        setCyberBotStatus("الوضع المحلي محدود؛ اربط خادمًا للحصول على إجابات عامة.");
        return;
    }
    try {
        const parsed = new URL(endpoint, window.location.href);
        const isLocalHost = ["localhost", "127.0.0.1", "[::1]"].includes(parsed.hostname);
        if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("invalid protocol");
        if (parsed.protocol === "http:" && !isLocalHost && window.location.protocol === "https:") throw new Error("insecure");
        if (parsed.username || parsed.password || parsed.hash) throw new Error("invalid URL parts");
        const savedValue = parsed.origin === window.location.origin ? parsed.pathname + parsed.search : parsed.href;
        localStorage.setItem("cyber_bot_endpoint", savedValue);
        input.value = savedValue;
        setCyberBotStatus("تم حفظ عنوان الخادم. سيُفحص الاتصال عند إرسال رسالة.");
    } catch {
        alert("أدخل رابط HTTP أو HTTPS صحيحًا. لا تضع مفتاح API في الرابط.");
    }
}

function clearCyberBotConversation() {
    const userName = localStorage.getItem("cyber_bot_username") || "صديقي";
    initChatGreeting(userName);
    setCyberBotStatus(document.getElementById("chatEndpointInput").value.trim()
        ? "عنوان الخادم محفوظ. سيُفحص الاتصال عند إرسال رسالة."
        : "الوضع المحلي محدود؛ اربط خادمًا للحصول على إجابات عامة.");
    document.getElementById("userChatInput").focus();
}

function buildOfflineCyberBotReply(userText, userName, disconnected = false) {
    const text = normalizeCyberBotText(userText);
    let answer = "";
    if (/(^|\s)(هلو|هلا|مرحبا|السلام|صباح|مساء|حيّاك)(\s|$)/.test(text)) {
        answer = "أهلًا " + userName + "، يسعدني الحديث معك. ما الموضوع الذي تريد أن نبدأ به؟";
    } else if (/(شلونك|كيف حالك|اخبارك|شخبارك|شكو ماكو)/.test(text)) {
        answer = "أنا جاهز لمساعدتك. أخبرني بما تحتاجه، وسأوضح لك ما أستطيع فعله.";
    } else if (/(شكرا|مشكور|تسلم|عاشت ايدك|كفو)/.test(text)) {
        answer = "العفو، أنا حاضر لمساعدتك.";
    } else if (/(من انت|منو انت|شنو انت|اسمك|ما هو اسمك)/.test(text)) {
        answer = "أنا CyberBot، مساعد المحادثة في هذا الموقع. عند ربط خادم نموذج لغوي أستطيع متابعة الحوار والإجابة عن نطاق أوسع من المواضيع.";
    } else if (/(من صمم|من برمج|من كتب الكود|المطور|مصعب|محمود|جامعه تكريت|كلية)/.test(text)) {
        answer = "بحسب المعلومات المعروضة في الموقع، أُعدّ المشروع في قسم الأمن السيبراني بكلية علوم الحاسوب والرياضيات في جامعة تكريت، ويظهر اسما مصعب رمزي ومحمود حكمت ضمن فريق التطوير.";
    } else if (/(رابط|url|http|www|موقع)/.test(text)) {
        answer = "لفحص رابط، افتح قسم «فحص الروابط» وأدخل العنوان كاملًا. النتيجة الحالية تحليل أولي قائم على قواعد داخل الصفحة؛ لا تثبت أن الرابط آمن، لذا لا تدخل بياناتك في موقع مشبوه.";
    } else if (/(رساله|رسائل|نص|تصيد|احتيال|بريد)/.test(text)) {
        answer = "يمكنك استخدام قسم «فحص النصوص والرسائل». يحلل أنماط الاحتيال (التهديد والاستعجال وطلب الرموز والدفع) بالعربية والإنكليزية، ويفحص الروابط داخل الرسالة. لكنه يعتمد على قواعد محددة، لذلك قد يفوّت أساليب جديدة أو يعطي إنذارًا خاطئًا.";
    } else if (/(ملف|فيروس|malware|exe|برنامج)/.test(text)) {
        answer = "فحص الملفات في الصفحة يقرأ النوع الحقيقي للملف من بصمته الثنائية ويفحص ترويسة الملفات التنفيذية (التوقيع الرقمي والتغليف) ومحتوى السكربتات والماكرو، ويعرض بصمة SHA-256. لكنه ليس مضاد فيروسات ولا تحليلًا سلوكيًا، فلا تشغّل ملفًا مجهولًا اعتمادًا على نتيجة هذه الصفحة وحدها.";
    } else if (/(صوت|فيديو|deepfake|تزييف|وسائط)/.test(text)) {
        answer = "قسم الصوت والفيديو في هذه الصفحة لا يشغّل نموذج كشف تزييف حقيقيًا؛ نتيجته الحالية تقديرية وبسيطة. لا تعتمد عليها لإثبات أصالة التسجيل.";
    } else if (/(كيف استخدم|كيف ابدأ|ماذا تستطيع|شنو تقدر|مساعده|مساعدة)/.test(text)) {
        answer = "يمكنني شرح صفحات الموقع وإرشادات الأمن الأساسية محليًا. للإجابة عن الأسئلة العامة ومواصلة حوار أوسع، شغّل خادم المحادثة واضبط بيانات مزود النموذج من جهة الخادم.";
    } else {
        answer = "لا أملك اتصالًا حاليًا بنموذج محادثة، لذلك لا أستطيع الإجابة بثقة عن هذا السؤال في الوضع المحلي. اربط خادم الذكاء الاصطناعي من الإعدادات، أو أعد صياغة السؤال حول وظائف الموقع.";
    }
    answer += disconnected
        ? "\n\nتعذر الاتصال بالخادم الآن؛ هذه إجابة محلية محدودة وليست إجابة نموذج لغوي."
        : "\n\nأعمل حاليًا بإجابات محلية محدودة. اربط خادم النموذج من إعدادات المحادثة للأسئلة العامة.";
    return answer;
}

async function sendCyberBotMessage() {
    if (cyberBotSending) return;
    const inputField = document.getElementById("userChatInput");
    const sendButton = document.getElementById("chatSendButton");
    const userText = inputField.value.trim();
    const userName = localStorage.getItem("cyber_bot_username") || "صديقي";
    if (!userText) return;

    appendCyberBotMessage("user", userText);
    cyberBotHistory.push({ role: "user", content: userText });
    inputField.value = "";
    cyberBotSending = true;
    inputField.disabled = true;
    sendButton.disabled = true;
    const typingBubble = appendCyberBotMessage("assistant", "يكتب الآن...", { typing: true });
    let answer = "";
    const endpoint = (localStorage.getItem("cyber_bot_endpoint") ?? "/api/chat").trim();

    try {
        if (!endpoint) {
            answer = buildOfflineCyberBotReply(userText, userName, false);
            setCyberBotStatus("الوضع المحلي محدود؛ لم يُضبط خادم ذكاء اصطناعي.");
        } else {
            const url = new URL(endpoint, window.location.href);
            const controller = new AbortController();
            const timeout = window.setTimeout(() => controller.abort(), 45000);
            let response;
            try {
                response = await fetch(url.href, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ message: userText, history: cyberBotHistory.slice(-9, -1).map(item => ({ role: item.role, content: item.content.slice(-1500) })), userName }),
                    signal: controller.signal
                });
            } finally {
                window.clearTimeout(timeout);
            }
            let payload = {};
            try { payload = await response.json(); } catch {}
            if (!response.ok) throw new Error("server error");
            const reply = typeof payload.reply === "string" ? payload.reply.trim() : "";
            if (!reply) throw new Error("empty reply");
            answer = reply;
            setCyberBotStatus("متصل بخادم نموذج الذكاء الاصطناعي.", true);
        }
    } catch {
        answer = buildOfflineCyberBotReply(userText, userName, true);
        setCyberBotStatus("تعذر الاتصال بالخادم؛ يعمل المساعد بإجابات محلية محدودة.");
    } finally {
        typingBubble.remove();
        appendCyberBotMessage("assistant", answer);
        cyberBotHistory.push({ role: "assistant", content: answer });
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
// يرسل للخادم نوع الفحص ونتيجته فقط (بدون الرابط أو النص أو الملف) لإحصاءات صفحة الأدمن
function reportScan(kind, level) {
    try {
        fetch('/api/event', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ kind, level }),
            keepalive: true
        }).catch(() => {});
    } catch {
        // الإحصاءات اختيارية ولا يجوز أن تعطّل الفحص
    }
}

const LEVEL_STATUS = { safe: 'لا مؤشرات', warning: 'تنبيه', danger: 'خطر' };
const SCAN_DISCLAIMER = 'هذا فحص بقواعد وخوارزميات محلية يعمل داخل متصفحك. غياب المؤشرات لا يثبت أن الهدف آمن، ووجودها لا يثبت أنه خبيث.';

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

function analyzeUrl() {
    const input = document.getElementById('urlInput').value.trim();
    const reportBox = document.getElementById('reportBox');
    const strict = document.getElementById('academicDefenseToggle').checked;

    if (!input) {
        alert('يرجى إدخال رابط للفحص');
        return;
    }

    const result = PhishingEngine.analyzeUrl(input, { strict });
    if (result.error) {
        reportBox.style.display = 'block';
        reportBox.innerHTML = '<div style="color:var(--accent-red);">عذراً، الرابط المدخل غير صالح هيكلياً. تأكد من كتابته بشكل صحيح.</div>';
        return;
    }

    let meta = `<strong>الرابط المحلل:</strong> <code style="direction:ltr; display:inline-block;">${escapeHtml(result.input)}</code>`;
    if (result.host) {
        meta += `<br><strong>النطاق الفعلي:</strong> <code style="direction:ltr; display:inline-block;">${escapeHtml(result.registrable || result.host)}</code>`;
        if (result.unicodeHost && result.unicodeHost !== result.host) {
            meta += ` &nbsp;<strong>يظهر بالأحرف:</strong> <code style="direction:ltr; display:inline-block;">${escapeHtml(result.unicodeHost)}</code>`;
        }
    }
    if (strict) meta += '<br><strong>الوضع:</strong> حماية أكاديمية وحكومية مشددة (عتبات تنبيه أقل).';
    renderReport(reportBox, 'url', 'مؤشر الخطورة', result, meta);

    addToHistory(input, 'رابط URL', result.score, LEVEL_STATUS[result.level]);
    reportScan('url', result.level);
}

function analyzeText() {
    const textInput = document.getElementById('textInput').value.trim();
    const textReportBox = document.getElementById('textReportBox');

    if (!textInput) {
        alert('يرجى إدخال النص أو محتوى الرسالة المراد فحصها');
        return;
    }

    const result = PhishingEngine.analyzeText(textInput);
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
    reportScan('text', result.level);
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
    reportBox.innerHTML = '<div style="text-align:center; padding:1rem;"><i class="fa-solid fa-gear fa-spin" style="font-size:2rem; color:var(--accent-blue);"></i><br><br>جاري قراءة البصمة الثنائية وترويسة الملف وفحص محتواه...</div>';

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

    renderReport(reportBox, 'file', 'مؤشر الخطورة', result, meta, extra);
    addToHistory(file.name, 'فحص ملف', result.score, LEVEL_STATUS[result.level]);
    reportScan('file', result.level);
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
    reportScan('media', riskScore >= 70 ? 'danger' : (riskScore >= 30 ? 'warning' : 'safe'));
}

// ==========================================================
// موزّع الأحداث: بديل المعالجات المضمنة (onclick=...) حتى تعمل سياسة CSP الصارمة
// ==========================================================
const ACTIONS = {
    analyzeUrl, analyzeText, analyzeFile, uploadAndScan, toggleThemeMenu, openCyberBot,
    saveUserName, resetUserName, saveCyberBotEndpoint, clearCyberBotConversation,
    sendCyberBotMessage, testUrl, loadSimulation, checkSimulation,
    updateFileName, updateMediaFileName
};

function runAction(name, ...args) {
    const action = Object.prototype.hasOwnProperty.call(ACTIONS, name) ? ACTIONS[name] : null;
    if (action) action(...args);
}

function actionArg(value) {
    return typeof value === 'string' && /^\d+$/.test(value) ? Number(value) : value;
}

document.addEventListener('click', event => {
    const el = event.target.closest('[data-page],[data-theme],[data-action],[data-click-target]');
    if (!el) return;
    if (el.dataset.page) {
        switchPage(el.dataset.page, el.dataset.title || '', el.dataset.icon || '');
    } else if (el.dataset.theme) {
        setTheme(el.dataset.theme);
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
