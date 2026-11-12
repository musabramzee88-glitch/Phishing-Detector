"use strict";

/* لوحة الأدمن: بلاغات المستخدمين، تنبيهات الاحتيال، وقائمة النطاقات المؤكدة. كل القيم تُعرض بـ textContent فقط. */

(function () {
    const $ = id => document.getElementById(id);
    const SEVERITY = { danger: "خطر", warn: "تحذير", info: "معلومة" };
    const STATUS = { open: ["بانتظار المراجعة", "warn"], confirmed: ["مؤكد", "bad"], rejected: ["مرفوض", ""] };

    function node(tag, className, text) {
        const n = document.createElement(tag);
        if (className) n.className = className;
        if (text !== undefined) n.textContent = String(text);
        return n;
    }

    function button(text, cls, onClick) {
        const b = node("button", cls, text);
        b.type = "button";
        b.addEventListener("click", onClick);
        return b;
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

    function notice(id, text, tone) {
        const box = $(id);
        box.replaceChildren();
        if (text) box.append(node("span", "badge " + (tone || ""), text));
    }

    const date = ms => new Date(ms).toLocaleString("ar-IQ");

    function renderReports(reports) {
        const open = reports.filter(r => r.status === "open").length;
        const badge = $("reportsBadge");
        if (!$("showAllReports").checked) {
            badge.hidden = open === 0;
            badge.textContent = String(open);
        }
        const head = node("tr");
        for (const t of ["التاريخ", "المُبلِّغ", "النوع", "المحتوى", "ملاحظة", "الإجراء"]) head.append(node("th", t === "الإجراء" ? "actions" : "", t));
        const rows = reports.map(r => {
            const tr = node("tr");
            const action = node("td", "actions");
            if (r.status === "open") {
                action.append(
                    button(r.kind === "url" ? "تأكيد (حظر النطاق)" : "تأكيد", "", () => decide(r, true)), " ",
                    button("رفض", "secondary", () => decide(r, false))
                );
            } else {
                const [label, tone] = STATUS[r.status] || [r.status, ""];
                action.append(node("span", "badge " + tone, label), node("div", "muted", `${r.decidedBy} — ${date(r.decidedAt)}`));
            }
            tr.append(
                node("td", "num wrap", date(r.at)),
                node("td", "ltr", r.email || "—"),
                node("td", "", r.kind === "url" ? `رابط (${r.domain})` : "رسالة"),
                node("td", "content", r.content),
                node("td", "detail", r.note || ""),
                action
            );
            return tr;
        });
        if (!rows.length) {
            const tr = node("tr");
            const td = node("td", "empty", $("showAllReports").checked ? "لا توجد بلاغات بعد." : "لا توجد بلاغات بانتظار المراجعة.");
            td.colSpan = 6;
            tr.append(td);
            rows.push(tr);
        }
        const table = $("reportsTable");
        table.replaceChildren(node("thead"), node("tbody"));
        table.firstChild.append(head);
        table.lastChild.append(...rows);
    }

    function renderAlerts(alerts) {
        const box = $("alertsList");
        box.replaceChildren(...alerts.map(a => {
            const card = node("div", "alert-card " + a.severity);
            card.append(
                node("div", "muted", `${SEVERITY[a.severity] || ""} · ${date(a.at)} · ${a.by || ""}`),
                node("h3", "", a.title),
                node("p", "", a.body),
                button("حذف", "secondary", async () => {
                    if (!window.confirm("حذف هذا التنبيه من الموقع؟")) return;
                    try { await call("/api/admin/community/alert/delete", { id: a.id }); load(); } catch (e) { notice("alertNotice", e.message, "bad"); }
                })
            );
            return card;
        }));
        if (!alerts.length) box.append(node("p", "muted", "ما نشرت أي تنبيه بعد."));
    }

    function renderBlocklist(list) {
        const box = $("blocklist");
        box.replaceChildren(...list.map(domain => {
            const chip = node("span", "chip");
            chip.append(node("span", "", domain), button("إزالة", "secondary", async () => {
                if (!window.confirm(`إزالة ${domain} من قائمة الاحتيال المؤكدة؟`)) return;
                try { await call("/api/admin/community/unblock", { domain }); load(); } catch (e) { notice("reportsNotice", e.message, "bad"); }
            }));
            return chip;
        }));
        if (!list.length) box.append(node("p", "muted", "القائمة فارغة."));
    }

    async function decide(report, confirm) {
        const what = report.kind === "url" ? `النطاق ${report.domain}` : "هذه الرسالة";
        if (confirm && !window.confirm(`تأكيد أن ${what} احتيال؟${report.kind === "url" ? " كل فحص لاحق له راح يطلع «خطر»." : ""}`)) return;
        try {
            await call("/api/admin/community/report", { id: report.id, confirm });
            notice("reportsNotice", confirm ? "تم التأكيد." : "تم الرفض.", "ok");
            load();
        } catch (e) {
            notice("reportsNotice", e.message, "bad");
        }
    }

    // ---------- الأرقام والحسابات ----------
    const KIND_NAMES = { phone: "هاتف", telegram: "تيليجرام", instagram: "انستغرام", facebook: "فيسبوك", wallet: "محفظة" };
    async function loadIdentifiers() {
        try {
            const data = await call("/api/admin/identifiers");
            const disputes = $("idDisputes");
            disputes.replaceChildren(...data.disputes.map(d => {
                const card = node("div", "alert-card info");
                card.append(
                    node("div", "muted", `${KIND_NAMES[d.kind] || d.kind} · ${date(d.at)}${d.contact ? " · للتواصل: " + d.contact : ""}${d.hasReports ? "" : " · (ما عليه بلاغات حالياً)"}`),
                    node("h3", "ltr", d.masked),
                    node("p", "", d.reason),
                    button("قبول وحذف البلاغات", "", () => decideDispute(d, true)), " ",
                    button("رفض الاعتراض", "secondary", () => decideDispute(d, false))
                );
                return card;
            }));
            if (!data.disputes.length) disputes.append(node("p", "muted", "ما اكو اعتراضات مفتوحة."));
            const head = node("tr");
            for (const t of ["المعرّف (مموّه)", "النوع", "عدد المبلّغين", "آخر بلاغ", "آخر ملاحظة", "إجراء"]) head.append(node("th", t === "إجراء" ? "actions" : "", t));
            const rows = data.top.map(r => {
                const tr = node("tr");
                const act = node("td", "actions");
                act.append(button("حذف البلاغات", "secondary", async () => {
                    if (!window.confirm(`حذف كل البلاغات عن ${r.masked} ومنع بلاغات جديدة عنه؟`)) return;
                    try { await call("/api/admin/identifiers/remove", { h: r.h }); loadIdentifiers(); } catch (e) { notice("idNotice", e.message, "bad"); }
                }));
                tr.append(node("td", "ltr", r.masked), node("td", "", KIND_NAMES[r.kind] || r.kind), node("td", "num", r.reporters), node("td", "num wrap", r.lastAt ? date(r.lastAt) : "—"), node("td", "detail", r.lastNote), act);
                return tr;
            });
            if (!rows.length) { const tr = node("tr"); const td = node("td", "empty", "ما اكو بلاغات بعد."); td.colSpan = 6; tr.append(td); rows.push(tr); }
            const table = $("idTable");
            table.replaceChildren(node("thead"), node("tbody"));
            table.firstChild.append(head);
            table.lastChild.append(...rows);
        } catch { /* يُعاد لاحقاً */ }
    }

    async function decideDispute(d, remove) {
        if (remove && !window.confirm(`قبول الاعتراض وحذف كل البلاغات عن ${d.masked}؟`)) return;
        try {
            await call("/api/admin/identifiers/dispute", { id: d.id, remove });
            notice("idNotice", remove ? "حُذفت البلاغات." : "رُفض الاعتراض.", "ok");
            loadIdentifiers();
        } catch (e) {
            notice("idNotice", e.message, "bad");
        }
    }

    async function load() {
        loadIdentifiers();
        try {
            const data = await call("/api/admin/community" + ($("showAllReports").checked ? "?reports=all" : ""));
            renderReports(data.reports || []);
            renderAlerts(data.alerts || []);
            renderBlocklist(data.blocklist || []);
        } catch { /* يُعاد لاحقاً */ }
    }

    $("alertForm").addEventListener("submit", async event => {
        event.preventDefault();
        try {
            await call("/api/admin/community/alert", { title: $("alertTitle").value, body: $("alertBody").value, severity: $("alertSeverity").value });
            $("alertTitle").value = "";
            $("alertBody").value = "";
            notice("alertNotice", "نُشر التنبيه.", "ok");
            load();
        } catch (e) {
            notice("alertNotice", e.message, "bad");
        }
    });
    $("showAllReports").addEventListener("change", load);
    document.addEventListener("admin:tab", e => { if (e.detail === "reports") load(); });

    load();
    setInterval(load, 30_000);
})();
