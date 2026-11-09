"use strict";

/* لوحة الأدمن. كل ما يأتي من الخادم يُعرض بـ textContent فقط (لا innerHTML)، فلا يمكن لسجل أو قيمة تنفيذ كود. */

const REFRESH_MS = 10_000;
const KIND_LABELS = { url: "الروابط", text: "الرسائل والنصوص", file: "الملفات", media: "الصوت والفيديو" };
const EVENT_LABELS = {
    login_ok: ["دخول ناجح", "ok"],
    login_failed: ["دخول فاشل", "bad"],
    login_throttled: ["سقف محاولات الدخول", "warn"],
    blocked_origin: ["طلب من موقع غير مسموح", "bad"],
    logout: ["تسجيل خروج", ""]
};

function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = String(text);
    return node;
}

function formatDuration(totalSeconds) {
    const days = Math.floor(totalSeconds / 86400);
    const hours = Math.floor((totalSeconds % 86400) / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const parts = [];
    if (days) parts.push(days + " يوم");
    if (hours) parts.push(hours + " ساعة");
    parts.push(minutes + " دقيقة");
    return parts.join(" و ");
}

function renderCards(data) {
    const c = data.counters;
    const cards = [
        ["مدة التشغيل", formatDuration(data.uptimeSeconds), "ok"],
        ["كل الطلبات", c.requests, ""],
        ["رسائل CyberBot الناجحة", c.chatOk, "ok"],
        ["أخطاء CyberBot", c.chatErrors, c.chatErrors ? "warn" : ""],
        ["طلبات رُفضت بالحد", c.rateLimited, c.rateLimited ? "warn" : ""],
        ["طلبات حُجبت (مصدر غير مسموح)", c.blockedRequests, c.blockedRequests ? "bad" : ""],
        ["دخول ناجح", c.loginOk, "ok"],
        ["دخول فاشل", c.loginFailed, c.loginFailed ? "bad" : ""]
    ];
    const box = document.getElementById("cards");
    box.replaceChildren(...cards.map(([label, value, tone]) => {
        const card = el("div", "stat " + tone);
        card.append(el("div", "value", value), el("div", "label", label));
        return card;
    }));
}

function renderScans(data) {
    const table = document.getElementById("scans");
    const head = el("tr");
    for (const title of ["النوع", "لا مؤشرات", "تنبيه", "خطر", "المجموع"]) head.append(el("th", "", title));
    const rows = Object.keys(KIND_LABELS).map(kind => {
        const s = data.scans[kind] || { safe: 0, warning: 0, danger: 0 };
        const tr = el("tr");
        tr.append(el("td", "", KIND_LABELS[kind]), el("td", "num", s.safe), el("td", "num", s.warning), el("td", "num", s.danger), el("td", "num", s.safe + s.warning + s.danger));
        return tr;
    });
    table.replaceChildren(el("thead"), ...rows);
    table.firstChild.append(head);
}

function renderInfo(data) {
    const yesNo = value => (value ? "نعم" : "لا");
    const items = [
        ["المستخدم الحالي", data.user],
        ["بيئة التشغيل", data.server.platform],
        ["اتصال مشفّر (HTTPS)", yesNo(data.server.https)],
        ["إصدار Node.js", data.server.node],
        ["ذاكرة الخادم", data.server.memoryMb + " MB"],
        ["بدأ التشغيل", new Date(data.startedAt).toLocaleString("ar-IQ")],
        ["CyberBot مربوط بنموذج ذكاء اصطناعي", yesNo(data.config.chatConfigured)],
        ["البحث على الإنترنت بـ CyberBot", yesNo(data.config.webSearch)],
        ["حد CyberBot لكل زائر بالدقيقة", data.config.chatPerMinute],
        ["الحد العام لـ CyberBot بالدقيقة", data.config.globalChatPerMinute],
        ["عدد حسابات الأدمن", data.config.adminCount],
        ["رمز التحقق الثنائي لحسابك", yesNo(data.config.totpEnabled)],
        ["جلسات أدمن نشطة", data.config.activeSessions]
    ];
    document.getElementById("info").replaceChildren(...items.map(([label, value]) => {
        const row = el("div");
        row.append(el("dt", "", label), el("dd", "", value));
        return row;
    }));
}

function renderEvents(data) {
    const table = document.getElementById("events");
    if (!data.events.length) {
        table.replaceChildren(el("tbody"));
        const tr = el("tr");
        const td = el("td", "empty", "لا توجد أحداث بعد.");
        td.colSpan = 4;
        tr.append(td);
        table.firstChild.append(tr);
        return;
    }
    const head = el("tr");
    for (const title of ["الوقت", "الحدث", "التفاصيل", "العنوان (مخفي جزئياً)"]) head.append(el("th", "", title));
    const rows = data.events.map(event => {
        const [label, tone] = EVENT_LABELS[event.type] || [event.type, ""];
        const tr = el("tr");
        const kind = el("td");
        kind.append(el("span", "badge " + tone, label));
        tr.append(
            el("td", "num", new Date(event.time).toLocaleString("ar-IQ")),
            kind,
            el("td", "detail", event.detail),
            el("td", "ltr", event.ip)
        );
        return tr;
    });
    table.replaceChildren(el("thead"), el("tbody"));
    table.firstChild.append(head);
    table.lastChild.append(...rows);
}

async function refresh() {
    try {
        const response = await fetch("/api/admin/stats", { credentials: "same-origin", cache: "no-store" });
        if (response.status === 401) {
            window.location.replace("/admin");   // الجلسة انتهت: نرجع لصفحة الدخول
            return;
        }
        if (!response.ok) throw new Error("bad status");
        const data = await response.json();
        document.getElementById("user").textContent = "المستخدم: " + data.user;
        renderCards(data);
        renderScans(data);
        renderInfo(data);
        renderEvents(data);
        document.getElementById("updated").textContent = "آخر تحديث: " + new Date().toLocaleTimeString("ar-IQ");
    } catch {
        document.getElementById("updated").textContent = "تعذر التحديث، سأحاول مجدداً...";
    }
}

document.getElementById("logout").addEventListener("click", async () => {
    try {
        await fetch("/api/admin/logout", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", body: "{}" });
    } finally {
        window.location.replace("/admin");
    }
});

refresh();
setInterval(refresh, REFRESH_MS);
