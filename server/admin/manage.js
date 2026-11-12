"use strict";

/* إدارة المستخدمين وطلبات الدفع والإيرادات بلوحة الأدمن. كل القيم تُعرض بـ textContent فقط. */

(function () {
    const $ = id => document.getElementById(id);
    let methods = [];
    let offset = 0;
    let total = 0;
    let query = "";

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

    const date = iso => (iso ? new Date(iso).toLocaleString("ar-IQ") : "—");
    const shortDate = iso => (iso ? new Date(iso).toLocaleDateString("ar-IQ") : "—");
    const num = n => Number(n || 0).toLocaleString("ar-IQ");

    function notice(id, text, tone) {
        const box = $(id);
        box.replaceChildren();
        if (text) box.append(node("p", "badge " + (tone || ""), text));
    }

    // ---------------------------------------------------------------- الإيرادات والمدفوعات

    async function loadRevenue() {
        try {
            const r = await call("/api/admin/revenue");
            const cards = [
                ["طلبات بانتظار المراجعة", r.pendingCount, r.pendingCount ? "warn" : ""],
                ["إيراد هذا الشهر", `${num(r.monthUsd)}$ ≈ ${num(r.monthIqd)} د.ع`, "ok"],
                ["آخر 30 يوماً", `${num(r.last30Usd)}$ ≈ ${num(r.last30Iqd)} د.ع`, ""],
                ["الإجمالي", `${num(r.totalUsd)}$ ≈ ${num(r.totalIqd)} د.ع`, ""],
                ["اشتراكات مدفوعة مفعّلة", r.approvedCount, ""]
            ];
            const badge = $("pendingBadge");
            if (badge) { badge.textContent = String(r.pendingCount || 0); badge.hidden = !r.pendingCount; }
            $("revenue").replaceChildren(...cards.map(([label, value, tone]) => {
                const card = node("div", "stat " + tone);
                card.append(node("div", "value", value), node("div", "label", label));
                return card;
            }));
        } catch { /* يُعاد مع التحديث التالي */ }
    }

    async function loadPayments() {
        const table = $("paymentsTable");
        try {
            const data = await call("/api/admin/payments" + ($("showAllPayments").checked ? "" : "?status=pending"));
            methods = data.methods || [];
            const head = node("tr");
            for (const t of ["التاريخ", "المستخدم", "المدة / المبلغ", "الطريقة", "رقم العملية", "ملاحظة", "الحالة / الإجراء"]) head.append(node("th", t === "الحالة / الإجراء" ? "actions" : "", t));
            const rows = data.payments.map(p => {
                const tr = node("tr");
                const methodLabel = (methods.find(m => m.id === p.method) || {}).label || p.method;
                const action = node("td", "actions");
                if (p.status === "pending") {
                    const approve = node("button", "", "موافقة وتفعيل");
                    approve.type = "button";
                    approve.addEventListener("click", () => decide(p, true));
                    const reject = node("button", "secondary", "رفض");
                    reject.type = "button";
                    reject.addEventListener("click", () => decide(p, false));
                    action.append(approve, " ", reject);
                } else {
                    action.append(node("span", "badge " + (p.status === "approved" ? "ok" : "bad"), p.status === "approved" ? "مقبول" : "مرفوض"));
                    action.append(node("div", "muted", `${shortDate(new Date(p.decidedAt).toISOString())} — ${p.decidedBy}${p.reason ? " — " + p.reason : ""}`));
                }
                tr.append(
                    node("td", "num wrap", date(new Date(p.createdAt).toISOString())),
                    node("td", "ltr", p.email),
                    node("td", "wrap", `${p.months} شهر — ${p.amountUsd}$ (≈ ${num(p.amountIqd)} د.ع)`),
                    node("td", "", methodLabel),
                    node("td", "ltr", p.reference),
                    node("td", "detail", p.note || ""),
                    action
                );
                return tr;
            });
            if (!rows.length) {
                const tr = node("tr");
                const td = node("td", "empty", $("showAllPayments").checked ? "لا توجد طلبات بعد." : "لا توجد طلبات بانتظار المراجعة.");
                td.colSpan = 7;
                tr.append(td);
                rows.push(tr);
            }
            table.replaceChildren(node("thead"), node("tbody"));
            table.firstChild.append(head);
            table.lastChild.append(...rows);
        } catch { /* يُعاد مع التحديث التالي */ }
    }

    async function decide(p, approve) {
        let reason = "";
        if (approve) {
            if (!window.confirm(`تأكدت من وصول ${p.amountUsd}$ (≈ ${num(p.amountIqd)} د.ع) برقم العملية ${p.reference}؟ سيتفعّل Pro لـ ${p.email} لمدة ${p.months} شهر.`)) return;
        } else {
            reason = window.prompt("سبب الرفض (يظهر للمستخدم):", "لم يصلنا المبلغ برقم العملية المذكور.");
            if (reason === null) return;
        }
        try {
            await call("/api/admin/payments/decide", { id: p.id, approve, reason });
        } catch (error) {
            window.alert(error.message);
        }
        loadPayments();
        loadRevenue();
        loadUsers();
    }

    // ---------------------------------------------------------------- المستخدمون

    const PLAN_LABELS = { paid: "Pro مدفوع", trial: "Pro تجربة", trial_ended: "مجاني (انتهت التجربة)", free: "مجاني" };

    async function loadUsers() {
        const table = $("usersTable");
        try {
            const data = await call(`/api/admin/users?offset=${offset}&q=${encodeURIComponent(query)}`);
            total = data.total;
            $("usersTotal").textContent = `إجمالي المستخدمين: ${num(total)}`;
            const head = node("tr");
            for (const t of ["البريد", "الاسم", "الخطة", "حتى", "الدخول", "التسجيل / آخر دخول", "إجراءات"]) head.append(node("th", t === "إجراءات" ? "actions" : "", t));
            const rows = data.users.map(u => {
                const tr = node("tr");
                if (u.disabled) tr.className = "disabled-row";
                const actions = node("td", "actions");
                const grant = node("select");
                grant.append(new Option("منح Pro...", ""), ...[1, 3, 6, 12].map(m => new Option(`${m} شهر`, String(m))));
                grant.addEventListener("change", () => { if (grant.value) userAction(u, "grant", Number(grant.value)); grant.value = ""; });
                const toggle = node("button", "secondary", u.disabled ? "تفعيل" : "إيقاف");
                toggle.type = "button";
                toggle.addEventListener("click", () => userAction(u, u.disabled ? "enable" : "disable"));
                const reset = node("button", "secondary", "رابط كلمة سر");
                reset.type = "button";
                reset.addEventListener("click", () => userAction(u, "reset-link"));
                const revoke = node("button", "secondary", "خروج من كل الأجهزة");
                revoke.type = "button";
                revoke.title = "ينهي كل جلسات هذا المستخدم فوراً (مثلاً إذا أبلغ أن حسابه مخترق)";
                revoke.addEventListener("click", () => userAction(u, "revoke-sessions"));
                actions.append(grant, toggle, " ", reset, " ", revoke);
                tr.append(
                    node("td", "ltr", u.email + (u.disabled ? " (موقوف)" : "")),
                    node("td", "", u.name),
                    node("td", "", PLAN_LABELS[u.planSource] || u.plan),
                    node("td", "num", shortDate(u.planUntil)),
                    node("td", "", [u.hasPassword ? "بريد" : "", ...u.providers].filter(Boolean).join("، ")),
                    node("td", "num", `${shortDate(u.createdAt)} / ${shortDate(u.lastLoginAt)}`),
                    actions
                );
                return tr;
            });
            if (!rows.length) {
                const tr = node("tr");
                const td = node("td", "empty", "لا يوجد مستخدمون.");
                td.colSpan = 7;
                tr.append(td);
                rows.push(tr);
            }
            table.replaceChildren(node("thead"), node("tbody"));
            table.firstChild.append(head);
            table.lastChild.append(...rows);
            $("usersPrev").disabled = offset === 0 || Boolean(query);
            $("usersNext").disabled = offset + 50 >= total || Boolean(query);
        } catch { /* يُعاد لاحقاً */ }
    }

    async function userAction(u, action, months) {
        if (action === "disable" && !window.confirm(`إيقاف حساب ${u.email}؟ سيخرج من كل الأجهزة.`)) return;
        if (action === "revoke-sessions" && !window.confirm(`إنهاء كل جلسات ${u.email}؟ سيحتاج يسجّل دخوله من جديد على كل أجهزته.`)) return;
        if (action === "grant" && !window.confirm(`منح ${u.email} اشتراك Pro لمدة ${months} شهر بدون طلب دفع؟`)) return;
        try {
            const data = await call("/api/admin/users/action", { id: u.id, action, months });
            if (action === "reset-link") {
                const box = $("userNotice");
                box.replaceChildren(
                    node("p", "", `رابط إعادة تعيين كلمة السر لـ ${u.email} (صالح ساعة ولمرة واحدة). أرسله له بنفسك عبر قناة موثوقة:`),
                    node("code", "key", data.link)
                );
                return;
            }
            notice("userNotice", "تم.", "ok");
            loadUsers();
        } catch (error) {
            notice("userNotice", error.message, "bad");
        }
    }

    $("userSearch").addEventListener("submit", event => {
        event.preventDefault();
        query = $("userQuery").value.trim();
        offset = 0;
        loadUsers();
    });
    $("userReset").addEventListener("click", () => { query = ""; $("userQuery").value = ""; offset = 0; loadUsers(); });
    $("usersPrev").addEventListener("click", () => { offset = Math.max(0, offset - 50); loadUsers(); });
    $("usersNext").addEventListener("click", () => { offset += 50; loadUsers(); });
    $("showAllPayments").addEventListener("change", loadPayments);

    // التبويبات: القسم المفتوح يُحفظ بالرابط (#payments) فيبقى بعد التحديث
    const TABS = ["overview", "payments", "users", "settings", "security"];
    function showTab(name) {
        const tab = TABS.includes(name) ? name : "overview";
        document.querySelectorAll("[data-tab-panel]").forEach(el => { el.hidden = el.dataset.tabPanel !== tab; });
        document.querySelectorAll(".tab-btn").forEach(b => {
            const active = b.dataset.tab === tab;
            b.classList.toggle("active", active);
            if (active) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
            if (active) {
                document.getElementById("pageTitle").textContent = b.dataset.title;
                document.title = b.dataset.title + " | لوحة الإدارة";
            }
        });
        window.scrollTo({ top: 0 });
        if (window.location.hash.slice(1) !== tab) history.replaceState(null, "", "#" + tab);
    }
    document.querySelectorAll(".tab-btn").forEach(b => b.addEventListener("click", () => showTab(b.dataset.tab)));
    window.addEventListener("hashchange", () => showTab(window.location.hash.slice(1)));
    showTab(window.location.hash.slice(1));

    loadRevenue();
    loadPayments();
    loadUsers();
    // الطلبات الجديدة تظهر تلقائياً
    setInterval(() => { loadPayments(); loadRevenue(); }, 30_000);
})();
