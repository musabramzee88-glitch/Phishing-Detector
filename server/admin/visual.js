"use strict";

/* لوحة الأدمن: مكتبة الكشف البصري (صفحات الدخول الرسمية وبصماتها). كل القيم تُعرض بـ textContent فقط. */

(function () {
    const $ = id => document.getElementById(id);
    if (!$("visualAdmin")) return;

    function node(tag, className, text) {
        const n = document.createElement(tag);
        if (className) n.className = className;
        if (text !== undefined) n.textContent = String(text);
        return n;
    }

    async function call(url, body) {
        const init = { credentials: "same-origin", cache: "no-store" };
        if (body !== undefined) {
            init.method = "POST";
            init.headers = { "Content-Type": "application/json" };
            init.body = JSON.stringify(body);
        }
        const response = await fetch(url, init);
        if (response.status === 401) { window.location.replace("/admin"); throw new Error("unauthorized"); }
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.error || "خطأ");
        return data;
    }

    const msg = (text, tone) => { const b = $("visualMsg"); b.textContent = text || ""; b.className = "muted " + (tone || ""); };

    function renderStatus(health, status) {
        const box = $("visualStatus");
        box.replaceChildren();
        const row = (k, v) => { box.append(node("dt", "", k), node("dd", "", v)); };
        if (!health.configured) {
            row("الحالة", "غير مضبوطة: شغّل خدمة visual-worker وأضف VISUAL_WORKER_URL و VISUAL_WORKER_TOKEN بإعدادات الموقع (الشرح بـ README، القسم 5.7).");
            return;
        }
        row("الخدمة", health.reachable ? `تعمل (بالطابور: ${health.queue || 0}، التقطت: ${health.captured || 0})` : "ما ترد حالياً (ممكن نايمة بالخطة المجانية وتصحى مع أول طلب)");
        row("الميزة بالموقع", status.enabled ? "مفعّلة" : "مطفية من الإعدادات");
        row("منذ آخر تشغيل", `${status.jobs} فحص بصري، ${status.matches} تطابق مع صفحة رسمية، ${status.failures} تعذر`);
        if (status.lastError) row("آخر عطل", status.lastError);
    }

    function renderRefs(refs) {
        const table = $("visualRefs");
        const head = node("tr");
        for (const t of ["الجهة", "صفحة الدخول", "النطاقات الرسمية", "البصمة", "الإجراء"]) head.append(node("th", t === "الإجراء" ? "actions" : "", t));
        const rows = refs.map(r => {
            const tr = node("tr");
            const state = r.ready ? `جاهزة${r.hasIcon ? " + أيقونة" : ""} · ${new Date(r.updatedAt).toLocaleDateString("ar-IQ")}` : "لم تُلتقط بعد";
            const stateCell = node("td", "", state);
            if (r.error) stateCell.append(node("div", "badge warn", r.error));
            const actions = node("td", "actions");
            const refresh = node("button", "secondary", "التقط");
            refresh.type = "button";
            refresh.addEventListener("click", () => run(() => call("/api/admin/visual/refresh", { id: r.id }), "تم تحديث البصمة.", refresh));
            const remove = node("button", "secondary danger-outline", "حذف");
            remove.type = "button";
            remove.addEventListener("click", () => {
                if (window.confirm(`حذف ${r.brand} من مكتبة الكشف البصري؟`)) run(() => call("/api/admin/visual/remove", { id: r.id }), "انحذفت.", remove);
            });
            actions.append(refresh, " ", remove);
            const url = node("td", "ltr", r.url);
            const domains = node("td", "ltr", r.domains.slice(0, 3).join(", ") + (r.domains.length > 3 ? ` +${r.domains.length - 3}` : ""));
            domains.title = r.domains.join(", ");
            tr.append(node("td", "", r.brand), url, domains, stateCell, actions);
            return tr;
        });
        table.replaceChildren(head, ...rows);
    }

    async function run(fn, done, btn) {
        if (btn) btn.disabled = true;
        msg("جارٍ العمل... (الالتقاط ياخذ ثواني لكل صفحة)");
        try {
            const data = await fn();
            if (data.refs) renderRefs(data.refs);
            msg(done, "ok");
        } catch (error) {
            msg(error.message, "bad");
        } finally {
            if (btn) btn.disabled = false;
        }
    }

    async function load() {
        try {
            const data = await call("/api/admin/visual");
            renderStatus(data.health, data.status);
            renderRefs(data.refs);
        } catch (error) {
            msg(error.message, "bad");
        }
    }

    $("visualAddForm").addEventListener("submit", event => {
        event.preventDefault();
        run(async () => {
            const data = await call("/api/admin/visual/add", { brand: $("visualBrand").value, url: $("visualUrl").value, domains: $("visualDomains").value });
            $("visualAddForm").reset();
            return data;
        }, "انضافت. اضغط «التقط» حتى تنحسب بصمتها.");
    });
    $("visualRefreshAll").addEventListener("click", event => run(() => call("/api/admin/visual/refresh", {}), "تم تحديث كل البصمات.", event.currentTarget));
    document.addEventListener("click", event => {
        if (event.target.closest('[data-tab="security"]')) load();
    });
    if (location.hash === "#security") load();
})();
