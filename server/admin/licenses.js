"use strict";

/* قسم الاشتراكات والإيرادات بلوحة الأدمن. كل نص يُعرض بـ textContent (لا innerHTML). */

const STATUS_LABELS = { active: ["نشط", "ok"], expiring: ["ينتهي قريباً", "warn"], expired: ["منتهٍ", "bad"], revoked: ["ملغى", "bad"] };
const TIER_LABELS = { pro: "Pro", enterprise: "Enterprise" };
const MONEY = new Intl.NumberFormat("en-US", { maximumFractionDigits: 2 });

function node(tag, className, text) {
    const n = document.createElement(tag);
    if (className) n.className = className;
    if (text !== undefined) n.textContent = String(text);
    return n;
}

function formatDate(iso) {
    return new Date(iso).toLocaleDateString("ar-IQ", { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" });
}

function showMessage(target, text, tone) {
    target.replaceChildren(node("div", tone === "bad" ? "error" : "notice " + (tone || ""), text));
}

async function api(path, options) {
    const response = await fetch(path, { credentials: "same-origin", cache: "no-store", ...options });
    if (response.status === 401) {
        window.location.replace("/admin");
        throw new Error("unauthorized");
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || "فشل الطلب.");
    return data;
}

function renderNotice(data) {
    const box = document.getElementById("billingNotice");
    const notes = [];
    const storage = data.storage;
    const BACKENDS = { upstash: "قاعدة بيانات خارجية (Upstash): السجل محفوظ خارج الخادم.", file: "ملف على قرص الخادم.", memory: "الذاكرة فقط." };
    if (!data.enabled) notes.push(["الاشتراكات غير مفعّلة. أنشئ سراً بالأمر npm run make-secret وضعه بمتغير البيئة LICENSE_SECRET، ثم أعد تشغيل الخدمة.", "bad"]);
    else {
        notes.push(["مكان حفظ السجل: " + (BACKENDS[storage.backend] || storage.backend), storage.persistent ? "ok" : "bad"]);
        if (!storage.persistent) notes.push([(storage.error || "التخزين غير متاح.") + " لن يُحفظ أي بيع حتى يُحلّ هذا.", "bad"]);
        else if (storage.error) notes.push([storage.error, "warn"]);
        if (storage.notice) notes.push([storage.notice, "warn"]);
        if (storage.ephemeralRisk) notes.push(["تحذير: السجل ملف على قرص Render المؤقت ويُمسح عند كل نشر أو إعادة تشغيل. اربط قاعدة Upstash (UPSTASH_REDIS_REST_URL و UPSTASH_REDIS_REST_TOKEN) أو قرصاً دائماً، وخذ نسخة احتياطية بعد كل بيع.", "bad"]);
    }
    box.replaceChildren(...notes.map(([text, tone]) => node("div", tone === "bad" ? "error" : "notice " + tone, text)));
    document.getElementById("licenseSubmit").disabled = !data.enabled || !storage.persistent;
}

function renderRevenue(summary) {
    const cards = [];
    for (const currency of summary.currencies) {
        const r = summary.revenue[currency];
        cards.push([`إيراد هذا الشهر (${currency})`, MONEY.format(r.thisMonth), "ok"]);
        cards.push([`آخر 30 يوماً (${currency})`, MONEY.format(r.last30), ""]);
        cards.push([`الإجمالي (${currency})`, MONEY.format(r.allTime), ""]);
    }
    cards.push(["اشتراكات Pro فعّالة", summary.activeByTier.pro || 0, "ok"]);
    cards.push(["اشتراكات Enterprise فعّالة", summary.activeByTier.enterprise || 0, "ok"]);
    cards.push(["تنتهي خلال 7 أيام", summary.counts.expiring, summary.counts.expiring ? "warn" : ""]);
    cards.push(["منتهية", summary.counts.expired, ""]);
    cards.push(["ملغاة", summary.counts.revoked, ""]);
    document.getElementById("revenue").replaceChildren(...cards.map(([label, value, tone]) => {
        const card = node("div", "stat " + tone);
        card.append(node("div", "value", value), node("div", "label", label));
        return card;
    }));

    const table = document.getElementById("monthly");
    const head = node("tr");
    for (const title of ["الشهر (UTC)", ...summary.currencies]) head.append(node("th", "", title));
    const body = summary.monthly.slice().reverse().map(row => {
        const tr = node("tr");
        tr.append(node("td", "ltr", row.month), ...summary.currencies.map(c => node("td", "num", MONEY.format(row[c]))));
        return tr;
    });
    table.replaceChildren(node("thead"), node("tbody"));
    table.firstChild.append(head);
    table.lastChild.append(...body);
}

function showKey(license, key, heading) {
    const box = document.getElementById("newKey");
    const wrap = node("div", "notice ok");
    wrap.append(node("strong", "", heading));
    const code = node("code", "key ltr", key);
    const copy = node("button", "secondary", "نسخ المفتاح");
    copy.type = "button";
    copy.addEventListener("click", async () => {
        try {
            await navigator.clipboard.writeText(key);
            copy.textContent = "تم النسخ";
        } catch {
            copy.textContent = "انسخه يدوياً";
        }
    });
    wrap.append(node("div", "", `الزبون: ${license.customer} | الباقة: ${TIER_LABELS[license.tier]} | ينتهي: ${formatDate(license.expiresAt)}`), code, copy);
    box.replaceChildren(wrap);
    box.scrollIntoView({ block: "nearest" });
}

function renderTable(data) {
    const table = document.getElementById("licenses");
    if (!data.licenses.length) {
        table.replaceChildren(node("tbody"));
        const tr = node("tr");
        const td = node("td", "empty", "لا توجد اشتراكات بعد. أصدر أول مفتاح بعد استلامك الدفع.");
        td.colSpan = 8;
        tr.append(td);
        table.firstChild.append(tr);
        return;
    }
    const head = node("tr");
    for (const title of ["الرقم", "الزبون", "الباقة", "الحالة", "ينتهي", "المبلغ", "الدفع", "إجراءات"]) head.append(node("th", "", title));
    const rows = data.licenses.map(license => {
        const tr = node("tr");
        const [statusLabel, tone] = STATUS_LABELS[license.status] || [license.status, ""];
        const status = node("td");
        status.append(node("span", "badge " + tone, statusLabel));
        const actions = node("td");
        const keyButton = node("button", "secondary small", "المفتاح");
        keyButton.type = "button";
        keyButton.addEventListener("click", () => showKey(license, license.key, "مفتاح الترخيص " + license.id));
        const renewButton = node("button", "secondary small", "تجديد");
        renewButton.type = "button";
        renewButton.addEventListener("click", () => prepareRenewal(license));
        actions.append(keyButton, renewButton);
        if (license.status !== "revoked") {
            const revokeButton = node("button", "danger small", "إلغاء");
            revokeButton.type = "button";
            revokeButton.addEventListener("click", () => revoke(license));
            actions.append(revokeButton);
        }
        tr.append(
            node("td", "ltr", license.id), node("td", "detail", license.customer), node("td", "", TIER_LABELS[license.tier]), status,
            node("td", "", formatDate(license.expiresAt)), node("td", "num", `${MONEY.format(license.amount)} ${license.currency}`),
            node("td", "", license.method), actions
        );
        return tr;
    });
    table.replaceChildren(node("thead"), node("tbody"));
    table.firstChild.append(head);
    table.lastChild.append(...rows);
}

function prepareRenewal(license) {
    const form = document.getElementById("licenseForm");
    form.elements.customer.value = license.customer;
    form.elements.tier.value = license.tier;
    form.elements.days.value = 30;
    form.elements.amount.value = "";
    form.elements.renewalOf.value = license.id;
    form.elements.note.value = "";
    document.getElementById("renewalHint").textContent = `تجديد للترخيص ${license.id}: سيُصدر مفتاح جديد بتاريخ جديد، والقديم يبقى صالحاً حتى انتهائه إلا إذا ألغيته.`;
    form.scrollIntoView({ block: "center" });
    form.elements.amount.focus();
}

async function revoke(license) {
    if (!window.confirm(`إلغاء الترخيص ${license.id} للزبون "${license.customer}"؟ لن يعمل مفتاحه بعد الآن. (الإيراد المسجّل لا يتغيّر.)`)) return;
    try {
        await api("/api/admin/licenses/revoke", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id: license.id }) });
        await load();
    } catch (error) {
        showMessage(document.getElementById("newKey"), error.message, "bad");
    }
}

async function load() {
    try {
        const data = await api("/api/admin/licenses");
        renderNotice(data);
        renderRevenue(data.summary);
        renderTable(data);
    } catch (error) {
        if (error.message !== "unauthorized") showMessage(document.getElementById("billingNotice"), "تعذر تحميل الاشتراكات: " + error.message, "bad");
    }
}

document.getElementById("licenseForm").addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.target;
    const button = document.getElementById("licenseSubmit");
    button.disabled = true;
    try {
        const payload = {
            customer: form.elements.customer.value,
            tier: form.elements.tier.value,
            days: Number(form.elements.days.value),
            amount: Number(form.elements.amount.value),
            currency: form.elements.currency.value,
            method: form.elements.method.value,
            note: form.elements.note.value,
            renewalOf: form.elements.renewalOf.value
        };
        const data = await api("/api/admin/licenses", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
        showKey(data.license, data.key, "تم إصدار المفتاح. انسخه وأرسله للزبون الآن:");
        form.reset();
        form.elements.renewalOf.value = "";
        document.getElementById("renewalHint").textContent = "";
        await load();
    } catch (error) {
        if (error.message !== "unauthorized") showMessage(document.getElementById("newKey"), error.message, "bad");
    } finally {
        button.disabled = false;
    }
});

load();
