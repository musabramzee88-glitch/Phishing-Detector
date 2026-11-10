"use strict";

/* تبويب «إعدادات الموقع» بلوحة الأدمن. النموذج يُبنى من الوصف أدناه، وكل النصوص تُعرض بـ textContent/value فقط. */
(function () {
    const GROUPS = [
        {
            id: "home", title: "الصفحة الرئيسية",
            fields: [
                { key: "title", label: "العنوان الرئيسي", type: "text", max: 120 },
                { key: "subtitle", label: "الوصف تحت العنوان", type: "textarea", max: 400, rows: 3 },
                { key: "announcement", label: "شريط إعلان لكل الزوار (اتركه فارغاً لإخفائه)", type: "textarea", max: 300, rows: 2 },
                { key: "announcementTone", label: "لون الإعلان", type: "select", options: [["info", "معلومة (أزرق)"], ["success", "خبر سار (أخضر)"], ["warn", "تنبيه (برتقالي)"]] }
            ]
        },
        {
            id: "features", title: "الخدمات",
            fields: [
                { key: "urlScan", label: "فحص الروابط", type: "toggle" },
                { key: "textScan", label: "فحص النصوص والرسائل", type: "toggle" },
                { key: "fileScan", label: "فحص الملفات وتنظيف الصور", type: "toggle" },
                { key: "mediaScan", label: "فحص الصوت والفيديو", type: "toggle" },
                { key: "cyberbot", label: "CyberBot", type: "toggle" },
                { key: "bulk", label: "الفحص الجماعي (Pro)", type: "toggle" },
                { key: "awareness", label: "المسار التوعوي ومحاكي التصيد", type: "toggle" },
                { key: "registration", label: "إنشاء حسابات جديدة", type: "toggle" },
                { key: "maintenance", label: "وضع الصيانة (يوقف الموقع للزوار؛ لوحة الإدارة تبقى تعمل)", type: "toggle", danger: true },
                { key: "maintenanceMessage", label: "رسالة الصيانة", type: "textarea", max: 300, rows: 2 }
            ]
        },
        {
            id: "plans", title: "الأسعار والحدود اليومية",
            fields: [
                { key: "priceUsd", label: "سعر Pro الشهري (دولار)", type: "number", min: 0, max: 1000, step: 0.5 },
                { key: "priceIqd", label: "السعر المقابل بالدينار", type: "number", min: 0, max: 10000000, step: 250 },
                { key: "trialDays", label: "أيام التجربة المجانية للحساب الجديد", type: "number", min: 0, max: 365, step: 1 },
                { key: "freeScansPerDay", label: "فحوصات الخطة المجانية باليوم", type: "number", min: 0, max: 10000, step: 1 },
                { key: "freeChatPerDay", label: "رسائل CyberBot المجانية باليوم", type: "number", min: 0, max: 10000, step: 1 },
                { key: "proScansPerDay", label: "فحوصات Pro باليوم", type: "number", min: 1, max: 100000, step: 1 },
                { key: "proChatPerDay", label: "رسائل CyberBot لـ Pro باليوم", type: "number", min: 1, max: 100000, step: 1 },
                { key: "proBulkMaxUrls", label: "أقصى روابط بالفحص الجماعي", type: "number", min: 1, max: 500, step: 1 }
            ]
        },
        {
            id: "cyberbot", title: "CyberBot",
            fields: [
                { key: "greeting", label: "رسالة الترحيب (اتركها فارغة للرسالة الافتراضية). تقدر تستخدم **غامق** و - للنقاط", type: "textarea", max: 600, rows: 4 },
                { key: "suggestions", label: "الأسئلة الجاهزة (سؤال بكل سطر، حتى 6)", type: "lines", max: 6, rows: 6 },
                { key: "extraInstructions", label: "تعليمات إضافية للذكاء الاصطناعي (مثلاً: اذكر رقم الدعم، ركّز على طلاب الجامعة). لا تُعرض للزوار", type: "textarea", max: 1500, rows: 4 }
            ]
        },
        {
            id: "security", title: "الأمان",
            fields: [
                { key: "mfaEmail", label: "التحقق الثنائي: إرسال رمز دخول للبريد عند كل تسجيل دخول (بكلمة السر أو Google/Microsoft/Apple)", type: "toggle" }
            ]
        }
    ];

    const $ = id => document.getElementById(id);
    const form = $("settingsForm");
    let loaded = null;
    let dirty = false;

    function node(tag, className, text) {
        const el = document.createElement(tag);
        if (className) el.className = className;
        if (text !== undefined) el.textContent = String(text);
        return el;
    }

    function status(text, tone) {
        const box = $("settingsStatus");
        box.textContent = text;
        box.className = tone === "ok" ? "ok-text" : tone === "bad" ? "bad-text" : "muted";
    }

    function inputFor(group, field, value) {
        const id = `set_${group}_${field.key}`;
        let input;
        if (field.type === "toggle") {
            const wrap = node("label", "switch-row" + (field.danger ? " danger" : ""));
            input = document.createElement("input");
            input.type = "checkbox";
            input.id = id;
            input.checked = Boolean(value);
            const slider = node("span", "switch");
            wrap.append(input, slider, node("span", "switch-label", field.label));
            input.dataset.group = group;
            input.dataset.key = field.key;
            input.dataset.type = field.type;
            return wrap;
        }
        const label = node("label", "field");
        label.htmlFor = id;
        label.append(node("span", "field-label", field.label));
        if (field.type === "select") {
            input = document.createElement("select");
            for (const [v, text] of field.options) {
                const opt = node("option", "", text);
                opt.value = v;
                input.append(opt);
            }
            input.value = value;
        } else if (field.type === "textarea" || field.type === "lines") {
            input = document.createElement("textarea");
            input.rows = field.rows || 3;
            input.value = field.type === "lines" ? (value || []).join("\n") : (value || "");
            if (field.type !== "lines") input.maxLength = field.max;
        } else {
            input = document.createElement("input");
            input.type = field.type === "number" ? "number" : "text";
            if (field.type === "number") {
                input.min = field.min; input.max = field.max; input.step = field.step; input.inputMode = "decimal";
                input.dir = "ltr";
            } else input.maxLength = field.max;
            input.value = value === undefined || value === null ? "" : value;
        }
        input.id = id;
        input.dataset.group = group;
        input.dataset.key = field.key;
        input.dataset.type = field.type;
        label.append(input);
        if (field.type === "text" || field.type === "textarea") {
            const counter = node("small", "counter muted");
            const update = () => { counter.textContent = `${input.value.length} / ${field.max}`; };
            input.addEventListener("input", update);
            update();
            label.append(counter);
        }
        return label;
    }

    function render(data) {
        loaded = data;
        dirty = false;
        const values = data.values;
        form.replaceChildren(...GROUPS.map(group => {
            const box = node("fieldset", "settings-group");
            box.append(node("legend", "", group.title));
            const grid = node("div", "settings-grid");
            for (const field of group.fields) grid.append(inputFor(group.id, field, values[group.id][field.key]));
            box.append(grid);
            return box;
        }));
        $("settingsMeta").textContent = data.updatedAt
            ? `آخر تعديل: ${new Date(data.updatedAt).toLocaleString("ar-IQ")}${data.updatedBy ? " بواسطة " + data.updatedBy : ""}`
            : "الإعدادات الافتراضية (لم تُعدَّل بعد)";
        status("");
    }

    function collect() {
        const values = {};
        form.querySelectorAll("[data-group]").forEach(input => {
            const { group, key, type } = input.dataset;
            values[group] = values[group] || {};
            if (type === "toggle") values[group][key] = input.checked;
            else if (type === "number") values[group][key] = input.value === "" ? null : Number(input.value);
            else if (type === "lines") values[group][key] = input.value.split("\n").map(x => x.trim()).filter(Boolean);
            else values[group][key] = input.value;
        });
        return values;
    }

    async function load() {
        status("جارٍ التحميل...");
        try {
            const response = await fetch("/api/admin/settings", { credentials: "same-origin", cache: "no-store" });
            if (response.status === 401) return window.location.replace("/admin");
            if (!response.ok) throw new Error();
            render(await response.json());
        } catch {
            status("تعذر تحميل الإعدادات.", "bad");
        }
    }

    async function post(url, body) {
        const response = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, credentials: "same-origin", body: JSON.stringify(body) });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) throw new Error(data.error || "تعذر الحفظ.");
        return data;
    }

    async function save() {
        const values = collect();
        if (values.features && values.features.maintenance && !(loaded && loaded.values.features.maintenance)) {
            if (!window.confirm("وضع الصيانة راح يوقف الموقع لكل الزوار. متأكد؟")) return;
        }
        const button = $("settingsSave");
        button.disabled = true;
        status("جارٍ الحفظ...");
        try {
            const data = await post("/api/admin/settings", { values });
            render(data.settings);
            status(data.changed.length ? `تم الحفظ ✓ (${data.changed.length} تعديل)` : "ما في تغييرات.", "ok");
        } catch (error) {
            status(error.message, "bad");
        } finally {
            button.disabled = false;
        }
    }

    async function reset() {
        if (!window.confirm("راح ترجع كل إعدادات الموقع (النصوص والأسعار والحدود والخدمات) للقيم الافتراضية. متأكد؟")) return;
        try {
            const data = await post("/api/admin/settings/reset", {});
            render(data.settings);
            status("رجعت الإعدادات للافتراضي ✓", "ok");
        } catch (error) {
            status(error.message, "bad");
        }
    }

    form.addEventListener("input", () => { if (!dirty) { dirty = true; status("فيه تعديلات غير محفوظة."); } });
    form.addEventListener("change", () => { if (!dirty) { dirty = true; status("فيه تعديلات غير محفوظة."); } });
    form.addEventListener("submit", event => event.preventDefault());
    $("settingsSave").addEventListener("click", save);
    $("settingsReload").addEventListener("click", () => { if (loaded) render(loaded); });
    $("settingsReset").addEventListener("click", reset);
    window.addEventListener("beforeunload", event => { if (dirty) { event.preventDefault(); event.returnValue = ""; } });
    load();
})();
