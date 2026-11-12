"use strict";

/*
  دخول الإدارة:
  - الحساب (الموصى به): اسم المستخدم ← البريد ← كلمة السر ← رمز من 6 أرقام يصل للبريد ← اللوحة.
    الخادم يفحص الثلاثة معاً بخطوة كلمة السر، فالخطوات الأولى لا تكشف هل الاسم أو البريد صحيح.
  - البريد فقط (ADMIN_EMAILS) أو كلمة السر القديمة، إذا كانت مضبوطة بدل الحسابات.
*/

const $ = id => document.getElementById(id);
const forms = { account: $("accountForm"), email: $("emailForm"), code: $("codeForm"), password: $("passwordForm") };
const message = $("message");
const otpInputs = Array.from(document.querySelectorAll("#otp input"));
const panels = Array.from(document.querySelectorAll("#accountForm .wiz-panel"));
const STEP_LABELS = {
    account: ["اسم المستخدم", "البريد", "كلمة السر", "التحقق"],
    email: ["البريد", "الرمز"]
};
let mode = "account";
let ticket = "";
let expiresAt = 0;
let resendAt = 0;
let timer = null;

function showError(text) {
    message.textContent = text;   // textContent: لا يُفسَّر كـ HTML أبداً
    message.hidden = false;
}

function clearError() {
    message.hidden = true;
}

// شريط الخطوات أعلى البطاقة
function renderSteps(index) {
    const list = $("steps");
    const labels = STEP_LABELS[mode];
    list.hidden = !labels;
    list.replaceChildren(...(labels || []).map((label, i) => {
        const li = document.createElement("li");
        li.textContent = label;
        if (i < index) li.className = "done";
        else if (i === index) li.className = "on";
        return li;
    }));
}

function showForm(name) {
    for (const [key, form] of Object.entries(forms)) form.hidden = key !== name;
    clearError();
}

const ACCOUNT_STEPS = ["username", "email", "password"];
const accountInput = { username: "accUser", email: "accEmail", password: "accPassword" };

function showAccountStep(step) {
    showForm("account");
    panels.forEach(panel => { panel.hidden = panel.dataset.step !== step; });
    renderSteps(ACCOUNT_STEPS.indexOf(step));
    const user = $("accUser").value.trim();
    $("whoUser").textContent = user;
    $("whoUser2").textContent = user;
    $("whoEmail").textContent = $("accEmail").value.trim();
    $(accountInput[step]).focus();
}

function currentAccountStep() {
    const panel = panels.find(p => !p.hidden);
    return panel ? panel.dataset.step : "username";
}

function showCodeStep() {
    showForm("code");
    renderSteps(mode === "account" ? 3 : 1);
    $("changeEmail").textContent = mode === "account" ? "البدء من جديد" : "تغيير البريد";
    otpInputs[0].focus();
}

async function post(url, body) {
    const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify(body)
    });
    const data = await response.json().catch(() => ({}));
    return { ok: response.ok, status: response.status, data };
}

function setBusy(button, busy, text) {
    button.disabled = busy;
    button.classList.toggle("loading", busy);
    if (text) button.querySelector("span").textContent = text;
}

const validEmail = value => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);

// ---------- مؤقت صلاحية الرمز وإعادة الإرسال ----------
function tick() {
    const now = Date.now();
    const left = Math.max(0, Math.round((expiresAt - now) / 1000));
    const mm = String(Math.floor(left / 60)).padStart(2, "0");
    const ss = String(left % 60).padStart(2, "0");
    $("timer").textContent = left > 0 ? `الرمز صالح لمدة ${mm}:${ss}` : "انتهت صلاحية الرمز. اطلب رمزاً جديداً.";
    $("timer").classList.toggle("expired", left === 0);
    const wait = Math.max(0, Math.ceil((resendAt - now) / 1000));
    const resend = $("resend");
    resend.disabled = wait > 0;
    resend.textContent = wait > 0 ? `إعادة الإرسال (${wait})` : "إعادة الإرسال";
    if (left === 0 && wait === 0) clearInterval(timer);
}

function startTimer(expiresIn, resendAfter) {
    expiresAt = Date.now() + expiresIn * 1000;
    resendAt = Date.now() + resendAfter * 1000;
    clearInterval(timer);
    tick();
    timer = setInterval(tick, 1000);
}

// ---------- خانات الرمز: تنقّل تلقائي ولصق الرمز كاملاً ----------
function fillCode(digits, from = 0) {
    const clean = digits.replace(/\D/g, "").slice(0, 6 - from);
    clean.split("").forEach((d, i) => { otpInputs[from + i].value = d; });
    const next = Math.min(from + clean.length, 5);
    otpInputs[next].focus();
    otpInputs.forEach(input => input.classList.toggle("filled", Boolean(input.value)));
    if (otpInputs.every(input => input.value)) forms.code.requestSubmit();
}

function currentCode() {
    return otpInputs.map(input => input.value).join("");
}

otpInputs.forEach((input, index) => {
    input.addEventListener("input", () => {
        clearError();
        const value = input.value.replace(/\D/g, "");
        input.value = "";
        if (value) fillCode(value, index);
        else input.classList.remove("filled");
    });
    input.addEventListener("keydown", event => {
        if (event.key === "Backspace" && !input.value && index > 0) {
            otpInputs[index - 1].value = "";
            otpInputs[index - 1].classList.remove("filled");
            otpInputs[index - 1].focus();
            event.preventDefault();
        } else if (event.key === "ArrowLeft" && index > 0) {
            otpInputs[index - 1].focus();      // الخانات من اليسار لليمين مثل أي رقم
        } else if (event.key === "ArrowRight" && index < 5) {
            otpInputs[index + 1].focus();
        }
    });
    input.addEventListener("paste", event => {
        const text = (event.clipboardData || window.clipboardData).getData("text");
        if (/\d/.test(text)) {
            event.preventDefault();
            fillCode(text, 0);
        }
    });
    input.addEventListener("focus", () => input.select());
});

function resetCode() {
    otpInputs.forEach(input => { input.value = ""; input.classList.remove("filled"); });
}

// النص حول البريد عربي والبريد إنجليزي: نعزل البريد بعنصر LTR حتى ما يتلخبط ترتيبه
function codeSent(data, before, email, after) {
    ticket = data.ticket;
    const b = document.createElement("b");
    b.dir = "ltr";
    b.textContent = email;
    $("sentText").replaceChildren(before, b, after);
    resetCode();
    startTimer(data.expiresIn || 600, data.resendAfter || 60);
}

// ---------- الحساب: اسم المستخدم ← البريد ← كلمة السر ----------
async function requestAccountCode() {
    const { ok, data } = await post("/api/admin/account/start", {
        username: $("accUser").value.trim(),
        email: $("accEmail").value.trim(),
        password: $("accPassword").value
    });
    if (!ok) {
        showError(data.error || "تعذر تسجيل الدخول.");
        return false;
    }
    codeSent(data, "تحققنا من بياناتك وأرسلنا رمز الدخول إلى ", data.sentTo || "بريدك", ". افتح بريدك واكتب الرمز هنا.");
    return true;
}

forms.account.addEventListener("submit", async event => {
    event.preventDefault();
    clearError();
    const step = currentAccountStep();
    if (step === "username") {
        const user = $("accUser").value.trim();
        if (!/^[A-Za-z0-9_.-]{1,64}$/.test(user)) {
            showError("اكتب اسم المستخدم (حروف إنجليزية وأرقام فقط).");
            return $("accUser").focus();
        }
        return showAccountStep("email");
    }
    if (step === "email") {
        if (!validEmail($("accEmail").value.trim())) {
            showError("اكتب بريداً إلكترونياً صحيحاً.");
            return $("accEmail").focus();
        }
        return showAccountStep("password");
    }
    if (!$("accPassword").value) {
        showError("اكتب كلمة السر.");
        return $("accPassword").focus();
    }
    const button = $("accountSubmit");
    if (button.disabled) return;
    setBusy(button, true, "جارٍ التحقق...");
    try {
        if (await requestAccountCode()) showCodeStep();
        else {
            $("accPassword").value = "";
            $("accPassword").focus();
        }
    } catch {
        showError("تعذر الاتصال بالخادم.");
    } finally {
        setBusy(button, false, "تحقق وأرسل الرمز");
    }
});

document.querySelectorAll("[data-back]").forEach(button => button.addEventListener("click", () => showAccountStep(button.dataset.back)));

$("pwToggle").addEventListener("click", () => {
    const input = $("accPassword");
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    $("pwToggle").textContent = show ? "إخفاء" : "إظهار";
    $("pwToggle").setAttribute("aria-pressed", String(show));
    $("pwToggle").setAttribute("aria-label", show ? "إخفاء كلمة السر" : "إظهار كلمة السر");
    input.focus();
});

// ---------- البريد فقط: طلب الرمز ----------
async function requestEmailCode() {
    const email = $("email").value.trim();
    if (!validEmail(email)) {
        showError("اكتب بريداً إلكترونياً صحيحاً.");
        $("email").focus();
        return false;
    }
    const { ok, data } = await post("/api/admin/email/start", { email });
    if (!ok) {
        showError(data.error || "تعذر إرسال الرمز. حاول مرة أخرى.");
        return false;
    }
    codeSent(data, "إذا كان ", email, " بريد أدمن مسجّل، فقد وصله رمز الدخول الآن. افتح بريدك واكتبه هنا.");
    return true;
}

forms.email.addEventListener("submit", async event => {
    event.preventDefault();
    clearError();
    const button = $("emailSubmit");
    setBusy(button, true, "جارٍ الإرسال...");
    try {
        if (await requestEmailCode()) showCodeStep();
    } catch {
        showError("تعذر الاتصال بالخادم.");
    } finally {
        setBusy(button, false, "أرسل رمز الدخول");
    }
});

// ---------- التحقق من الرمز ----------
forms.code.addEventListener("submit", async event => {
    event.preventDefault();
    const code = currentCode();
    if (code.length !== 6) {
        showError("اكتب الرمز كاملاً (6 أرقام).");
        return;
    }
    const button = $("codeSubmit");
    if (button.disabled) return;
    setBusy(button, true, "جارٍ التحقق...");
    try {
        const { ok, data } = await post("/api/admin/email/verify", { ticket, code });
        if (ok) {
            $("accPassword").value = "";
            button.querySelector("span").textContent = "تم، جارٍ فتح اللوحة...";
            window.location.replace("/admin");
            return;
        }
        resetCode();
        otpInputs[0].focus();
        forms.code.classList.remove("shake");
        void forms.code.offsetWidth;   // إعادة تشغيل حركة الاهتزاز
        forms.code.classList.add("shake");
        showError(data.error || "الرمز غير صحيح.");
        if (data.code === "expired") { expiresAt = Date.now(); tick(); }
    } catch {
        showError("تعذر الاتصال بالخادم.");
    } finally {
        setBusy(button, false, "دخول للوحة");
    }
});

$("resend").addEventListener("click", async () => {
    clearError();
    $("resend").disabled = true;
    try {
        const sent = mode === "account" ? await requestAccountCode() : await requestEmailCode();
        if (sent) otpInputs[0].focus();
        else tick();
    } catch {
        showError("تعذر الاتصال بالخادم.");
    }
});

$("changeEmail").addEventListener("click", () => {
    clearInterval(timer);
    ticket = "";
    if (mode === "account") {
        $("accPassword").value = "";
        showAccountStep("username");
    } else {
        showForm("email");
        renderSteps(0);
        $("email").focus();
    }
});

// ---------- الدخول بكلمة السر القديم (اختياري) ----------
forms.password.addEventListener("submit", async event => {
    event.preventDefault();
    clearError();
    const button = $("passwordSubmit");
    setBusy(button, true, "جارٍ الدخول...");
    try {
        const { ok, data } = await post("/api/admin/login", {
            username: $("username").value,
            password: $("password").value,
            code: $("code").value
        });
        if (ok) {
            window.location.replace("/admin");
            return;
        }
        showError(data.error || "تعذر تسجيل الدخول.");
    } catch {
        showError("تعذر الاتصال بالخادم.");
    } finally {
        setBusy(button, false, "دخول");
        $("password").value = "";   // لا نترك كلمة السر في الحقل
        $("code").value = "";
    }
});

// ---------- اختيار طريقة الدخول (فقط إذا لا توجد حسابات كاملة) ----------
function enterMode(name) {
    mode = name;
    if (name === "account") return showAccountStep("username");
    showForm(name);
    renderSteps(name === "email" ? 0 : -1);
    $(name === "email" ? "email" : "username").focus();
}

document.querySelectorAll(".seg-btn").forEach(button => button.addEventListener("click", () => {
    document.querySelectorAll(".seg-btn").forEach(b => {
        b.classList.toggle("active", b === button);
        b.setAttribute("aria-selected", String(b === button));
    });
    enterMode(button.dataset.method);
}));

(async function init() {
    let methods = { account: false, email: false, emailReady: false, password: true };
    try {
        const response = await fetch("/api/admin/methods", { credentials: "same-origin", cache: "no-store" });
        if (response.ok) methods = await response.json();
    } catch { /* نعرض كلمة السر احتياطاً */ }
    const warn = text => { $("unavailable").textContent = text; $("unavailable").hidden = false; };

    if (methods.account) {
        $("methodTabs").hidden = true;
        if (!methods.emailReady) warn("إرسال كود التحقق غير متاح: مزوّد البريد غير مضبوط على الخادم (BREVO_API_KEY و MAIL_FROM).");
        return enterMode("account");
    }
    const emailUsable = methods.email && methods.emailReady;
    $("methodTabs").hidden = !(emailUsable && methods.password);
    if (methods.email && !methods.emailReady) warn("الدخول برمز البريد غير متاح: مزوّد البريد غير مضبوط على الخادم (BREVO_API_KEY و MAIL_FROM).");
    enterMode(emailUsable ? "email" : "password");
})();
