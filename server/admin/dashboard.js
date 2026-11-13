"use strict";

/* لوحة الأدمن. كل ما يأتي من الخادم يُعرض بـ textContent فقط (لا innerHTML)، فلا يمكن لسجل أو قيمة تنفيذ كود. */

const REFRESH_MS = 10_000;
const KIND_LABELS = { url: "الروابط", text: "الرسائل والنصوص", file: "الملفات", media: "الصوت والفيديو" };
const EVENT_LABELS = {
    ssrf_blocked: ["محاولة SSRF مُنعت", "bad"],
    login_ok: ["دخول ناجح", "ok"],
    login_failed: ["دخول فاشل", "bad"],
    login_throttled: ["سقف محاولات الدخول", "warn"],
    blocked_origin: ["طلب من موقع غير مسموح", "bad"],
    logout: ["تسجيل خروج", ""],
    client_error: ["خطأ بمتصفح زائر", "warn"],
    server_error: ["خطأ بالخادم", "bad"],
    process_crash: ["انهيار العملية (تُعاد تلقائياً)", "bad"],
    register: ["حساب جديد", "ok"],
    register_throttled: ["حد إنشاء الحسابات", "warn"],
    password_reset: ["إعادة تعيين كلمة سر", ""],
    password_change: ["تغيير كلمة سر", ""],
    account_deleted: ["حذف حساب", "warn"],
    payment_request: ["طلب دفع جديد", "ok"],
    payment_decision: ["قرار على طلب دفع", ""],
    admin_user: ["إجراء أدمن على مستخدم", ""],
    oauth_failed: ["فشل دخول خارجي", "warn"],
    chat_error: ["عطل مزوّد CyberBot", "bad"],
    admin_ai_test: ["اختبار الذكاء الاصطناعي", ""],
    db_error: ["عطل قاعدة البيانات", "bad"],
    intel: ["قوائم التهديدات", "warn"],
    export: ["تصدير بيانات", ""],
    admin_code_sent: ["إرسال رمز دخول الإدارة", ""],
    admin_code_failed: ["فشل إرسال رمز الإدارة", "bad"],
    admin_code_unknown: ["طلب رمز لبريد غير أدمن", "warn"]
};
const HEALTH_LABELS = { ok: ["سليم", "ok"], degraded: ["متدهور (تحذير)", "warn"], critical: ["حرج (ستُعاد الخدمة تلقائياً)", "bad"] };

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
    const v = data.visitors || { uniqueToday: 0, activeNow: 0, viewsToday: 0 };
    const cards = [
        ["مدة تشغيل النسخة الحالية", formatDuration(data.uptimeSeconds), "ok"],
        ["حفظ الإحصائيات", data.persistent ? "دائم (تبقى بعد النشر)" : "مؤقت (تضيع عند النشر)", data.persistent ? "ok" : "bad"],
        ["زوار اليوم (تقريبي)", v.uniqueToday, ""],
        ["نشطون الآن (آخر 5 دقائق)", v.activeNow, "ok"],
        ["مشاهدات الصفحة اليوم", v.viewsToday, ""],
        ["كل الطلبات", c.requests, ""],
        ["أخطاء متصفحات الزوار", c.clientErrors, c.clientErrors ? "warn" : ""],
        ["أخطاء الخادم", c.serverErrors, c.serverErrors ? "bad" : ""],
        ["حسابات جديدة (إجمالي)", c.registrations, "ok"],
        ["تسجيلات دخول المستخدمين", c.userLogins, ""],
        ["طلبات دفع جديدة", c.paymentRequests, c.paymentRequests ? "ok" : ""],
        ["مرات الوصول للحد اليومي", c.quotaExceeded, ""],
        ["صور نُظّفت (Pro)", c.filesCleaned || 0, ""],
        ["رسائل CyberBot الناجحة", c.chatOk, "ok"],
        ["منها بالذكاء الاصطناعي", c.chatAi || 0, ""],
        ["أخطاء CyberBot", c.chatErrors, c.chatErrors ? "warn" : ""],
        ["طلبات رُفضت بالحد", c.rateLimited, c.rateLimited ? "warn" : ""],
        ["طلبات حُجبت (مصدر غير مسموح)", c.blockedRequests, c.blockedRequests ? "bad" : ""],
        ["دخول أدمن ناجح", c.loginOk, "ok"],
        ["دخول أدمن فاشل", c.loginFailed, c.loginFailed ? "bad" : ""],
        ["دخول مستخدم فاشل", c.userLoginFailed, c.userLoginFailed ? "warn" : ""]
    ];
    const box = document.getElementById("cards");
    box.replaceChildren(...cards.map(([label, value, tone]) => {
        const card = el("div", "stat " + tone);
        card.append(el("div", "value", value), el("div", "label", label));
        return card;
    }));
}

function renderHealth(data) {
    const box = document.getElementById("health");
    const health = data.health;
    if (!health) {
        box.replaceChildren(el("p", "muted", "مراقب الصحة غير مفعّل."));
        return;
    }
    const [label, tone] = HEALTH_LABELS[health.status] || [health.status, ""];
    const status = el("div", "stat " + tone);
    status.append(el("div", "value", label), el("div", "label", "الحالة العامة"));
    const metrics = [
        ["ذاكرة العملية", health.rssMb + " MB"],
        ["تأخر المعالجة (p99)", health.eventLoopP99Ms + " ms"]
    ].map(([title, value]) => {
        const card = el("div", "stat");
        card.append(el("div", "value ltr", value), el("div", "label", title));
        return card;
    });
    const wrap = el("div", "cards");
    wrap.append(status, ...metrics);
    const nodes = [wrap];
    if (health.reasons.length) {
        const list = el("ul", "reasons");
        for (const reason of health.reasons) list.append(el("li", "", reason));
        nodes.push(list);
    }
    box.replaceChildren(...nodes);
}

function renderVisitors(data) {
    const table = document.getElementById("visitors");
    const series = (data.visitors && data.visitors.series) || [];
    const head = el("tr");
    for (const title of ["اليوم (UTC)", "زوار فريدون تقريباً", "مشاهدات الصفحة"]) head.append(el("th", "", title));
    const rows = series.slice().reverse().map(day => {
        const tr = el("tr");
        tr.append(el("td", "ltr", day.day), el("td", "num", day.unique), el("td", "num", day.views));
        return tr;
    });
    table.replaceChildren(el("thead"), el("tbody"));
    table.firstChild.append(head);
    table.lastChild.append(...rows);
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
        ["عنوان الموقع (APP_URL)", data.config.appUrl],
        ["قاعدة البيانات", data.config.database ? (data.config.database.backend === "upstash" ? "Upstash (دائمة)" : "ذاكرة فقط") + (data.config.database.warning ? " ⚠ " + data.config.database.warning : "") : "—"],
        ["الدخول الخارجي المفعّل", (data.config.oauth || []).join("، ") || "لا شيء (بريد فقط)"],
        ["السعر الشهري / التجربة", data.config.plans ? `${data.config.plans.priceUsd}$ ≈ ${data.config.plans.priceIqd} د.ع / ${data.config.plans.trialDays} يوماً` : "—"],
        ["قوائم التهديدات", data.config.intel ? (data.config.intel.enabled ? `${data.config.intel.urls} رابط و ${data.config.intel.hosts || 0} نطاق` + Object.values(data.config.intel.feeds).map(f => ` | ${f.label}: ${f.count}${f.error ? " (خطأ: " + f.error + ")" : ""}`).join("") : "معطّلة") : "—"],
        ["CyberBot مربوط بنموذج ذكاء اصطناعي", yesNo(data.config.chatConfigured) + (data.config.chat && data.config.chat.model ? ` (${data.config.chat.model}, ${data.config.chat.style})` : "")],
        ["تأكيد البريد وإرسال الروابط", data.config.mail && data.config.mail.enabled ? "مفعّل (" + data.config.mail.provider + ")" + (data.config.mail.lastError ? " — آخر عطل: " + data.config.mail.lastError : "") : "غير مفعّل: أي شخص يسجّل ببريد غير مؤكَّد. أضف BREVO_API_KEY و MAIL_FROM"],
        ["آخر عطل بمزوّد CyberBot", data.config.chat && data.config.chat.lastError ? data.config.chat.lastError : "لا يوجد"],
        ["البحث على الإنترنت بـ CyberBot", yesNo(data.config.webSearch)],
        ["حد CyberBot لكل زائر بالدقيقة", data.config.chatPerMinute],
        ["الحد العام لـ CyberBot بالدقيقة", data.config.globalChatPerMinute],
        ["عدد حسابات الأدمن", data.config.adminCount],
        ["طريقة دخولك", data.config.loginMethod || (data.config.totpEnabled ? "كلمة سر + تطبيق مصادقة" : "كلمة سر فقط")],
        ["الدخول برمز البريد", yesNo(data.config.emailLogin)],
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

// ---------- لوحة تنفيذية: مؤشرات ورسوم ----------
const SVG_NS = "http://www.w3.org/2000/svg";
const OUTCOME = [
    { key: "safe", label: "لا مؤشرات خطر", color: "var(--green)" },
    { key: "warning", label: "تنبيه", color: "var(--yellow)" },
    { key: "danger", label: "خطر", color: "var(--red)" }
];
const nf = new Intl.NumberFormat("en-US");
const fmt = n => nf.format(Number(n) || 0);

function svg(tag, attrs = {}) {
    const node = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
    return node;
}

// تلميح واحد مشترك لكل الرسوم
const tip = el("div", "chart-tip");
tip.hidden = true;
document.body.append(tip);
function bindTip(target, lines) {
    const show = event => {
        tip.replaceChildren(...lines.map((line, i) => el(i === 0 ? "strong" : "div", "", line)));
        tip.hidden = false;
        const x = Math.min(window.innerWidth - tip.offsetWidth - 8, Math.max(8, event.clientX - tip.offsetWidth / 2));
        tip.style.left = x + "px";
        tip.style.top = Math.max(8, event.clientY - tip.offsetHeight - 14) + "px";
    };
    target.addEventListener("mousemove", show);
    target.addEventListener("mouseenter", show);
    target.addEventListener("mouseleave", () => { tip.hidden = true; });
}

function scanTotals(data) {
    const t = { safe: 0, warning: 0, danger: 0 };
    for (const kind of Object.keys(KIND_LABELS)) {
        const s = data.scans[kind] || {};
        for (const o of OUTCOME) t[o.key] += Number(s[o.key]) || 0;
    }
    t.total = t.safe + t.warning + t.danger;
    return t;
}

function renderKpis(data) {
    const t = scanTotals(data);
    const v = data.visitors || { uniqueToday: 0, activeNow: 0 };
    const c = data.counters;
    const intel = data.config.intel;
    const threatDb = intel && intel.enabled ? intel.urls + (intel.hosts || 0) : 0;
    const aiShare = c.chatOk ? Math.round(((c.chatAi || 0) / c.chatOk) * 100) : 0;
    const tiles = [
        { label: "إجمالي الفحوصات", value: fmt(t.total), sub: "روابط ورسائل وملفات ووسائط", tone: "accent" },
        { label: "تهديدات مكتشفة", value: fmt(t.warning + t.danger), sub: t.total ? `${Math.round(((t.warning + t.danger) / t.total) * 100)}% من الفحوصات (خطر ${fmt(t.danger)})` : "لا فحوصات بعد", tone: "bad" },
        { label: "المستخدمون المسجّلون", value: data.usersTotal === null || data.usersTotal === undefined ? "—" : fmt(data.usersTotal), sub: `${fmt(c.registrations)} حساب جديد منذ بدء الإحصاء`, tone: "ok" },
        { label: "زوار اليوم", value: fmt(v.uniqueToday), sub: `${fmt(v.activeNow)} نشط الآن`, tone: "" },
        { label: "محادثات CyberBot", value: fmt(c.chatOk), sub: c.chatOk ? `${aiShare}% بالذكاء الاصطناعي` : "لا محادثات بعد", tone: "" },
        { label: "قاعدة التهديدات", value: fmt(threatDb), sub: "رابط ونطاق تصيد محدّثة كل 3 ساعات", tone: "" },
        { label: "زيارات آمنة للروابط", value: fmt(c.liveVisits || 0), sub: `${fmt(c.snapshotViews || 0)} معاينة لشكل الصفحة`, tone: "accent" },
        { label: "دخول كضيف", value: fmt(c.guestEntries || 0), sub: (c.ssrfBlocked || 0) ? `⚠️ ${fmt(c.ssrfBlocked)} محاولة وصول لعنوان داخلي مُنعت` : "لا محاولات وصول لعناوين داخلية", tone: (c.ssrfBlocked || 0) ? "bad" : "" }
    ];
    document.getElementById("kpis").replaceChildren(...tiles.map(x => {
        const tile = el("div", "kpi " + x.tone);
        tile.append(el("div", "kpi-label", x.label), el("div", "kpi-value ltr", x.value), el("div", "kpi-sub", x.sub));
        return tile;
    }));
}

function renderVisitorsChart(data) {
    const box = document.getElementById("visitorsChart");
    const series = ((data.visitors && data.visitors.series) || []).slice(-14);
    if (!series.length) return box.replaceChildren(el("p", "empty", "لا بيانات زوار بعد."));
    const W = 520, H = 210, pad = { t: 16, r: 8, b: 30, l: 34 };
    const max = Math.max(4, ...series.map(d => d.unique));
    const raw = max / 4, p10 = Math.pow(10, Math.floor(Math.log10(raw))), n = raw / p10;
    const step = Math.max(1, (n <= 1 ? 1 : n <= 2 ? 2 : n <= 5 ? 5 : 10) * p10);
    const top = Math.ceil(max / step) * step;
    const iw = W - pad.l - pad.r, ih = H - pad.t - pad.b;
    const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": "رسم الزوار اليومي" });
    for (let y = 0; y <= top; y += step) {
        const py = pad.t + ih - (y / top) * ih;
        root.append(svg("line", { x1: pad.l, x2: W - pad.r, y1: py, y2: py, class: "grid" }));
        const label = svg("text", { x: pad.l - 6, y: py + 4, class: "axis", "text-anchor": "end" });
        label.textContent = fmt(y);
        root.append(label);
    }
    // ترتيب زمني من اليسار لليمين (الأقدم يسار) حتى يقرأ كخط زمني
    const slot = iw / series.length;
    const bw = Math.max(6, Math.min(34, slot - 6));
    series.forEach((d, i) => {
        const h = (d.unique / top) * ih;
        const x = pad.l + i * slot + (slot - bw) / 2;
        const y = pad.t + ih - h;
        const r = Math.min(4, bw / 2, h);
        const path = h > 0
            ? `M${x},${pad.t + ih} V${y + r} Q${x},${y} ${x + r},${y} H${x + bw - r} Q${x + bw},${y} ${x + bw},${y + r} V${pad.t + ih} Z`
            : `M${x},${pad.t + ih - 1} H${x + bw} V${pad.t + ih} H${x} Z`;
        const bar = svg("path", { d: path, class: "bar" + (i === series.length - 1 ? " today" : "") });
        root.append(bar);
        const hit = svg("rect", { x: pad.l + i * slot, y: pad.t, width: slot, height: ih, fill: "transparent" });
        bindTip(hit, [d.day, `زوار فريدون: ${fmt(d.unique)}`, `مشاهدات: ${fmt(d.views)}`]);
        root.append(hit);
        if (series.length <= 14 && (i % Math.ceil(series.length / 7) === 0 || i === series.length - 1)) {
            const label = svg("text", { x: x + bw / 2, y: H - 10, class: "axis", "text-anchor": "middle" });
            label.textContent = d.day.slice(5);
            root.append(label);
        }
    });
    root.append(svg("line", { x1: pad.l, x2: W - pad.r, y1: pad.t + ih, y2: pad.t + ih, class: "baseline" }));
    box.replaceChildren(root);
}

function legend(items) {
    const list = el("ul", "legend");
    for (const item of items) {
        const li = el("li");
        const sw = el("span", "swatch");
        sw.style.background = item.color;
        li.append(sw, el("span", "", item.label), el("b", "ltr", item.value));
        list.append(li);
    }
    return list;
}

function renderOutcome(data) {
    const box = document.getElementById("outcomeChart");
    const t = scanTotals(data);
    const size = 180, r = 70, stroke = 22, c = 2 * Math.PI * r;
    const root = svg("svg", { viewBox: `0 0 ${size} ${size}`, class: "donut", role: "img", "aria-label": "نتائج الفحوصات" });
    root.append(svg("circle", { cx: size / 2, cy: size / 2, r, class: "donut-track", "stroke-width": stroke, fill: "none" }));
    let offset = 0;
    const gap = t.total ? 2 : 0;
    for (const o of OUTCOME) {
        const value = t[o.key];
        if (!value) continue;
        const len = (value / t.total) * c;
        const arc = svg("circle", {
            cx: size / 2, cy: size / 2, r, fill: "none", "stroke-width": stroke,
            "stroke-dasharray": `${Math.max(0, len - gap)} ${c - Math.max(0, len - gap)}`,
            "stroke-dashoffset": -offset, transform: `rotate(-90 ${size / 2} ${size / 2})`
        });
        arc.style.stroke = o.color;
        bindTip(arc, [o.label, `${fmt(value)} فحص (${Math.round((value / t.total) * 100)}%)`]);
        root.append(arc);
        offset += len;
    }
    const total = svg("text", { x: size / 2, y: size / 2 + 2, class: "donut-total", "text-anchor": "middle" });
    total.textContent = fmt(t.total);
    const cap = svg("text", { x: size / 2, y: size / 2 + 24, class: "axis", "text-anchor": "middle" });
    cap.textContent = "فحص";
    root.append(total, cap);
    const wrap = el("div", "donut-wrap");
    wrap.append(root, legend(OUTCOME.map(o => ({ color: o.color, label: o.label, value: t.total ? `${fmt(t[o.key])} (${Math.round((t[o.key] / t.total) * 100)}%)` : "0" }))));
    box.replaceChildren(wrap);
}

function renderKinds(data) {
    const box = document.getElementById("kindsChart");
    const rows = Object.keys(KIND_LABELS).map(kind => {
        const s = data.scans[kind] || { safe: 0, warning: 0, danger: 0 };
        return { kind, s, total: s.safe + s.warning + s.danger };
    });
    const max = Math.max(1, ...rows.map(r => r.total));
    box.replaceChildren(...rows.map(r => {
        const row = el("div", "hbar");
        const track = el("div", "hbar-track");
        for (const o of OUTCOME) {
            if (!r.s[o.key]) continue;
            const seg = el("span", "hbar-seg");
            seg.style.width = (r.s[o.key] / max) * 100 + "%";
            seg.style.background = o.color;
            bindTip(seg, [KIND_LABELS[r.kind], `${o.label}: ${fmt(r.s[o.key])}`]);
            track.append(seg);
        }
        row.append(el("span", "hbar-label", KIND_LABELS[r.kind]), track, el("b", "hbar-value ltr", fmt(r.total)));
        return row;
    }), legend(OUTCOME.map(o => ({ color: o.color, label: o.label, value: "" }))));
}

function serviceRow(name, tone, detail) {
    const li = el("li", "svc " + tone);
    const text = { ok: "يعمل", warn: "تنبيه", bad: "عطل", off: "غير مفعّل" }[tone] || "";
    li.append(el("span", "svc-dot"), el("span", "svc-name", name), el("span", "svc-state", text), el("span", "svc-detail", detail));
    return li;
}

function renderServices(data) {
    const cfg = data.config;
    const chat = cfg.chat || {};
    const rows = [];
    if (!chat.configured) rows.push(serviceRow("CyberBot (ذكاء اصطناعي)", "off", "يرد بالمساعد المحلي. أضف GEMINI_API_KEY."));
    else if (chat.lastError) rows.push(serviceRow("CyberBot (ذكاء اصطناعي)", "bad", `${chat.model}: ${chat.lastError}`));
    else rows.push(serviceRow("CyberBot (ذكاء اصطناعي)", chat.lastOkAt ? "ok" : "warn", chat.lastOkAt ? `${chat.model}، آخر رد ناجح ${new Date(chat.lastOkAt).toLocaleTimeString("ar-IQ")}` : `${chat.model}، لم يُستخدم منذ آخر تشغيل. اضغط «اختبار».`));
    const db = cfg.database;
    rows.push(serviceRow("قاعدة البيانات", db && db.persistent ? "ok" : "bad", db ? (db.persistent ? "Upstash (دائمة)" : db.warning || "ذاكرة فقط") : "—"));
    rows.push(serviceRow("حفظ الإحصائيات", data.persistent ? "ok" : "warn", data.persistent ? "دائم، تبقى بعد النشر" : "مؤقت، تضيع عند النشر"));
    const mail = cfg.mail;
    const sms = cfg.sms;
    rows.push(serviceRow("رسائل التحقق للهاتف", sms && sms.enabled ? (sms.lastError ? "warn" : "ok") : "off", sms && sms.enabled ? `${sms.provider} · أُرسل ${sms.sent} منذ التشغيل · الحد اليومي ${sms.dailyCap}` + (sms.lastError ? " — آخر عطل: " + sms.lastError : "") : "غير مفعّل: أضف TELEGRAM_GATEWAY_TOKEN أو Twilio"));
    rows.push(serviceRow("البريد (تأكيد الحسابات)", mail && mail.enabled ? (mail.lastError ? "warn" : "ok") : "off", mail && mail.enabled ? mail.provider + (mail.lastError ? " — " + mail.lastError : "") : "غير مفعّل"));
    const intel = cfg.intel;
    if (intel && intel.enabled) {
        const feeds = Object.values(intel.feeds || {});
        const failed = feeds.filter(f => f.error);
        rows.push(serviceRow("قوائم التهديدات", failed.length === feeds.length && feeds.length ? "bad" : failed.length ? "warn" : "ok", feeds.map(f => `${f.label}: ${f.error ? "خطأ" : fmt(f.count)}`).join(" | ")));
    } else rows.push(serviceRow("قوائم التهديدات", "off", "معطّلة"));
    const health = data.health;
    if (health) rows.push(serviceRow("صحة الخادم", health.status === "ok" ? "ok" : health.status === "degraded" ? "warn" : "bad", `${health.rssMb} MB ذاكرة، تأخر ${health.eventLoopP99Ms} ms`));
    rows.push(serviceRow("اتصال مشفّر (HTTPS)", data.server.https ? "ok" : "warn", data.server.https ? "مفعّل" : "غير مشفّر (تشغيل محلي؟)"));
    document.getElementById("services").replaceChildren(...rows);
}

document.getElementById("aiTest").addEventListener("click", async event => {
    const button = event.currentTarget;
    const out = document.getElementById("aiTestResult");
    button.disabled = true;
    out.className = "muted";
    out.textContent = "جارٍ الاختبار...";
    try {
        const response = await fetch("/api/admin/ai-test", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", body: "{}" });
        const data = await response.json().catch(() => ({}));
        if (data.ok) {
            out.className = "ok-text";
            out.textContent = `يعمل ✓ (${data.model}، ${fmt(data.ms)} ms): ${data.reply}`;
        } else {
            out.className = "bad-text";
            out.textContent = "فشل: " + (data.error || "خطأ غير معروف");
        }
    } catch {
        out.className = "bad-text";
        out.textContent = "تعذر الاتصال بالخادم.";
    } finally {
        button.disabled = false;
        refresh();
    }
});

async function refresh() {
    try {
        const response = await fetch("/api/admin/stats", { credentials: "same-origin", cache: "no-store" });
        if (response.status === 401) {
            window.location.replace("/admin");   // الجلسة انتهت: نرجع لصفحة الدخول
            return;
        }
        if (!response.ok) throw new Error("bad status");
        const data = await response.json();
        document.getElementById("user").textContent = data.user;
        document.getElementById("avatar").textContent = String(data.user || "?").trim().charAt(0).toUpperCase() || "؟";
        renderKpis(data);
        renderVisitorsChart(data);
        renderOutcome(data);
        renderKinds(data);
        renderServices(data);
        renderCards(data);
        renderHealth(data);
        renderVisitors(data);
        renderScans(data);
        renderInfo(data);
        renderEvents(data);
        document.getElementById("updated").textContent = "محدَّث " + new Date().toLocaleTimeString("ar-IQ", { hour: "2-digit", minute: "2-digit" });
        document.querySelector(".live").classList.remove("offline");
    } catch {
        document.getElementById("updated").textContent = "غير متصل، إعادة المحاولة...";
        document.querySelector(".live").classList.add("offline");
    }
}

document.getElementById("logout").addEventListener("click", async () => {
    try {
        await fetch("/api/admin/logout", { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", body: "{}" });
    } finally {
        window.location.replace("/admin");
    }
});

// الجداول على الموبايل تُعرض كبطاقات: كل خلية تحمل اسم عمودها (data-label) ليظهر بجانب القيمة
function labelTable(table) {
    const heads = Array.from(table.querySelectorAll("thead th")).map(th => th.textContent.trim());
    if (!heads.length) return;
    table.classList.add("stackable");
    table.querySelectorAll("tbody tr, tr").forEach(tr => {
        Array.from(tr.children).forEach((cell, i) => {
            if (cell.tagName === "TD" && heads[i] && cell.dataset.label !== heads[i]) cell.dataset.label = heads[i];
        });
    });
}
const tableObserver = new MutationObserver(records => {
    const tables = new Set(records.map(r => r.target.closest && r.target.closest("table")).filter(Boolean));
    tables.forEach(labelTable);
});
document.querySelectorAll("table").forEach(table => {
    tableObserver.observe(table, { childList: true, subtree: true });
    labelTable(table);
});

refresh();
setInterval(refresh, REFRESH_MS);
