"use strict";

const form = document.getElementById("loginForm");
const message = document.getElementById("message");
const button = document.getElementById("submit");

function showError(text) {
    message.textContent = text;   // textContent: لا يُفسَّر كـ HTML أبداً
    message.hidden = false;
}

form.addEventListener("submit", async event => {
    event.preventDefault();
    message.hidden = true;
    button.disabled = true;
    try {
        const response = await fetch("/api/admin/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify({
                username: document.getElementById("username").value,
                password: document.getElementById("password").value,
                code: document.getElementById("code").value
            })
        });
        const data = await response.json().catch(() => ({}));
        if (response.ok) {
            window.location.replace("/admin");
            return;
        }
        showError(data.error || "تعذر تسجيل الدخول.");
    } catch {
        showError("تعذر الاتصال بالخادم.");
    } finally {
        button.disabled = false;
        document.getElementById("password").value = "";   // لا نترك كلمة السر في الحقل
        document.getElementById("code").value = "";
    }
});
