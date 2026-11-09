"use strict";

/*
  حارس الأخطاء بالمتصفح. يُحمَّل قبل أي سكربت آخر.
  - يلتقط أي خطأ غير متوقع (error / unhandledrejection) حتى لا يبقى صامتاً.
  - يبلّغ الخادم بنص قصير (بدون بيانات الزائر) ليظهر في لوحة الأدمن.
  - يعرض شريطاً هادئاً للزائر، وبقية الصفحة تبقى تعمل.
  لا يوجد كود يضمن "عدم حدوث أي خطأ". الهدف: خطأ واحد لا يوقف الموقع كله، ونعرف به فوراً.
*/

(function () {
    const MAX_REPORTS_PER_PAGE = 5;
    let reported = 0;
    let noticeShown = false;

    function fileName(source) {
        try {
            return String(source || "").split("/").pop().split("?")[0].slice(0, 60);
        } catch {
            return "";
        }
    }

    function report(kind, message, source, line) {
        if (reported >= MAX_REPORTS_PER_PAGE) return;
        reported += 1;
        try {
            fetch("/api/client-error", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    kind,
                    message: String(message || "").slice(0, 200),
                    source: fileName(source),
                    line: Number.isInteger(line) ? line : 0
                }),
                keepalive: true
            }).catch(() => {});
        } catch {
            // الإبلاغ نفسه لا يجوز أن يسبب خطأً جديداً
        }
    }

    function notify() {
        if (noticeShown || !document.body) return;
        noticeShown = true;
        const bar = document.createElement("div");
        bar.setAttribute("role", "alert");
        bar.style.cssText = "position:fixed;top:0;left:0;right:0;z-index:9999;padding:10px 16px;background:#7a1f2b;color:#fff;font:14px Tajawal,sans-serif;text-align:center;";
        bar.textContent = "حدث خطأ غير متوقع. أُبلغ النظام تلقائياً وبقية الميزات تعمل. إذا استمرت المشكلة أعد تحميل الصفحة. ";
        const close = document.createElement("button");
        close.type = "button";
        close.textContent = "إغلاق";
        close.style.cssText = "margin-inline-start:8px;padding:2px 10px;border:1px solid #fff;border-radius:6px;background:transparent;color:#fff;cursor:pointer;font:inherit;";
        close.addEventListener("click", () => bar.remove());
        bar.append(close);
        document.body.prepend(bar);
    }

    // أخطاء لا تهمنا (تحذيرات المتصفح المعروفة وغير الضارة)
    function ignorable(message) {
        return /ResizeObserver loop/i.test(String(message || ""));
    }

    window.addEventListener("error", event => {
        if (ignorable(event.message)) return;
        report("error", event.message, event.filename, event.lineno);
        notify();
    });

    window.addEventListener("unhandledrejection", event => {
        const reason = event.reason;
        const message = reason && reason.message ? reason.message : String(reason);
        if (ignorable(message)) return;
        report("promise", message, "", 0);
        notify();
    });

    // يستدعيه app.js عندما يلتقط خطأً بنفسه داخل أمر من أوامر الصفحة
    window.PDGuard = {
        captureError(label, error) {
            const message = (label ? label + ": " : "") + (error && error.message ? error.message : String(error));
            report("action", message, "", 0);
            notify();
        }
    };
})();
