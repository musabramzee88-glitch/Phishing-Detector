"use strict";

/* دخول الإدارة: البريد ← رمز من 6 أرقام يصل للبريد ← اللوحة. (أو اسم مستخدم + كلمة سر إذا كانت مفعّلة) */

const $ = id => document.getElementById(id);
const forms = { email: $("emailForm"), code: $("codeForm"), password: $("passwordForm") };
const message = $("message");
const otpInputs = Array.from(document.querySelectorAll("#otp input"));
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

function showStep(name) {
    for (const [key, form] of Object.entries(forms)) form.hidden = key !== name;
    clearError();
    if (name === "email") $("email").focus();
    if (name === "code") otpInputs[0].focus();
    if (name === "password") $("username").focus();
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

// ---------- الخطوة 1: طلب الرمز ----------
async function requestCode() {
    const email = $("email").value.trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        showError("اكتب بريداً إلكترونياً صحيحاً.");
        $("email").focus();
        return false;
    }
    const { ok, data } = await post("/api/admin/email/start", { email });
    if (!ok) {
        showError(data.error || "تعذر إرسال الرمز. حاول مرة أخرى.");
        return false;
    }
    ticket = data.ticket;
    $("sentTo").textContent = email;
    resetCode();
    startTimer(data.expiresIn || 600, data.resendAfter || 60);
    return true;
}

forms.email.addEventListener("submit", async event => {
    event.preventDefault();
    clearError();
    const button = $("emailSubmit");
    setBusy(button, true, "جارٍ الإرسال...");
    try {
        if (await requestCode()) showStep("code");
    } catch {
        showError("تعذر الاتصال بالخادم.");
    } finally {
        setBusy(button, false, "أرسل رمز الدخول");
    }
});

// ---------- الخطوة 2: التحقق من الرمز ----------
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
        if (await requestCode()) otpInputs[0].focus();
    } catch {
        showError("تعذر الاتصال بالخادم.");
    }
});

$("changeEmail").addEventListener("click", () => {
    clearInterval(timer);
    ticket = "";
    showStep("email");
});

// ---------- الدخول بكلمة السر (اختياري) ----------
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

// ---------- اختيار طريقة الدخول ----------
document.querySelectorAll(".seg-btn").forEach(button => button.addEventListener("click", () => {
    document.querySelectorAll(".seg-btn").forEach(b => {
        b.classList.toggle("active", b === button);
        b.setAttribute("aria-selected", String(b === button));
    });
    showStep(button.dataset.method);
}));

(async function init() {
    let methods = { email: false, emailReady: false, password: true };
    try {
        const response = await fetch("/api/admin/methods", { credentials: "same-origin", cache: "no-store" });
        if (response.ok) methods = await response.json();
    } catch { /* نعرض كلمة السر احتياطاً */ }
    const emailUsable = methods.email && methods.emailReady;
    $("methodTabs").hidden = !(emailUsable && methods.password);
    if (methods.email && !methods.emailReady) {
        $("unavailable").textContent = "الدخول برمز البريد غير متاح: مزوّد البريد غير مضبوط على الخادم (BREVO_API_KEY و MAIL_FROM).";
        $("unavailable").hidden = false;
    }
    showStep(emailUsable ? "email" : "password");
})();
