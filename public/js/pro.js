"use strict";

/*
  صفحات الباقات والفحص الجماعي (Pro). يُحمَّل بعد app.js ويضيف أوامره إلى ACTIONS.
  الفرض الفعلي للحدود يتم على الخادم؛ هذه الصفحة واجهة فقط. كل نص يُعرض بـ textContent.
*/

(function () {
    const KEY_STORAGE = "pd_license_key";
    const LEVEL_LABELS = { safe: "لا مؤشرات", warning: "تنبيه", danger: "خطر" };
    const LEVEL_BADGES = { safe: "score-safe", warning: "score-warning", danger: "score-danger" };
    const TIER_NAMES = { pro: "Pro", enterprise: "Enterprise" };
    let lastBulk = [];

    function node(tag, className, text) {
        const n = document.createElement(tag);
        if (className) n.className = className;
        if (text !== undefined) n.textContent = String(text);
        return n;
    }

    function storedKey() {
        try { return localStorage.getItem(KEY_STORAGE) || ""; } catch { return ""; }
    }

    function saveKey(key) {
        try {
            if (key) localStorage.setItem(KEY_STORAGE, key);
            else localStorage.removeItem(KEY_STORAGE);
        } catch { /* المتصفح قد يمنع التخزين: نكمل بدونه */ }
    }

    function formatDate(iso) {
        return new Date(iso).toLocaleDateString("ar-IQ", { year: "numeric", month: "long", day: "numeric", timeZone: "UTC" });
    }

    // ---------------------------------------------------------------- الباقات

    function priceText(tier) {
        if (!tier.price.IQD && !tier.price.USD) return "مجاني";
        const iqd = new Intl.NumberFormat("en-US").format(tier.price.IQD);
        return `${iqd} د.ع (أو ${tier.price.USD}$) ${tier.period}`;
    }

    function renderTiers(data) {
        const grid = document.getElementById("pricingTiers");
        grid.replaceChildren(...data.tiers.map(tier => {
            const card = node("div", "tier-card" + (tier.id === "pro" ? " featured" : ""));
            card.append(node("h3", "", tier.name), node("div", "tier-price", priceText(tier)));
            const list = node("ul", "tier-features");
            for (const feature of tier.features) list.append(node("li", "", feature));
            card.append(list);
            return card;
        }));
    }

    function renderContact(data) {
        const box = document.getElementById("pricingContact");
        const rows = [node("h3", "", "كيف تشترك؟"), node("p", "muted", data.licensingEnabled
            ? "الدفع محلي ويدوي: تواصل معنا، حوّل المبلغ، فنرسل لك مفتاح الترخيص خلال وقت قصير. الصق المفتاح بالأسفل لتفعيله."
            : "الاشتراكات غير مفعّلة حالياً.")];
        const links = node("div", "contact-row");
        const { whatsapp, telegram, note } = data.contact;
        if (whatsapp) {
            const a = node("a", "contact-link", "واتساب");
            a.href = "https://wa.me/" + whatsapp;
            a.target = "_blank";
            a.rel = "noopener noreferrer";
            links.append(a);
        }
        if (telegram) {
            const a = node("a", "contact-link", "تيليجرام");
            a.href = "https://t.me/" + telegram;
            a.target = "_blank";
            a.rel = "noopener noreferrer";
            links.append(a);
        }
        if (!whatsapp && !telegram) links.append(node("span", "muted", "بيانات التواصل لم تُضبط بعد."));
        rows.push(links);
        if (note) rows.push(node("p", "payment-note", note));
        box.replaceChildren(...rows);
    }

    async function loadPricing() {
        try {
            const response = await fetch("/api/pricing", { cache: "no-store" });
            if (!response.ok) throw new Error("bad status");
            const data = await response.json();
            renderTiers(data);
            renderContact(data);
        } catch {
            document.getElementById("pricingTiers").replaceChildren(node("p", "muted", "تعذر تحميل الباقات الآن. حاول لاحقاً."));
        }
    }

    // ---------------------------------------------------------------- تفعيل المفتاح

    function setLicenseStatus(text, tone) {
        const box = document.getElementById("licenseStatus");
        box.replaceChildren(node("div", "license-msg " + (tone || ""), text));
    }

    function refreshBulkNotice(info) {
        const box = document.getElementById("bulkLicenseNotice");
        if (info) {
            box.replaceChildren(node("div", "license-msg ok", `الباقة: ${TIER_NAMES[info.tier]} | الحد: ${info.limits.maxUrls} رابطاً بالطلب | ينتهي: ${formatDate(info.expiresAt)}`));
            return;
        }
        const msg = node("div", "license-msg warn", "الفحص الجماعي للمشتركين. فعّل مفتاحك من صفحة الباقات أولاً. ");
        const go = node("button", "btn-quick", "فتح صفحة الباقات");
        go.type = "button";
        go.dataset.page = "pricingPage";
        go.dataset.title = "الباقات والاشتراكات";
        go.dataset.icon = "fa-solid fa-crown";
        msg.append(go);
        box.replaceChildren(msg);
    }

    async function checkKey(key) {
        const response = await fetch("/api/license/check", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ key })
        });
        const data = await response.json().catch(() => ({}));
        return { ok: response.ok, data };
    }

    async function activateLicense() {
        const input = document.getElementById("licenseInput");
        const key = input.value.trim();
        if (!key) return setLicenseStatus("اكتب مفتاح الترخيص أولاً.", "warn");
        setLicenseStatus("جاري التحقق...", "");
        const { ok, data } = await checkKey(key);
        if (!ok) {
            refreshBulkNotice(null);
            return setLicenseStatus(data.error || "تعذر التحقق من المفتاح.", "bad");
        }
        saveKey(key.toUpperCase().replace(/\s+/g, ""));
        input.value = "";
        setLicenseStatus(`تم التفعيل: باقة ${TIER_NAMES[data.tier]} حتى ${formatDate(data.expiresAt)}.`, "ok");
        refreshBulkNotice(data);
    }

    function deactivateLicense() {
        saveKey("");
        setLicenseStatus("تم حذف المفتاح من هذا المتصفح.", "");
        refreshBulkNotice(null);
    }

    async function restoreLicense() {
        const key = storedKey();
        if (!key) return refreshBulkNotice(null);
        try {
            const { ok, data } = await checkKey(key);
            if (ok) {
                setLicenseStatus(`مفتاحك مفعّل: باقة ${TIER_NAMES[data.tier]} حتى ${formatDate(data.expiresAt)}.`, "ok");
                refreshBulkNotice(data);
            } else {
                setLicenseStatus((data.error || "المفتاح المحفوظ لم يعد صالحاً.") + " يمكنك تفعيل مفتاح جديد.", "warn");
                refreshBulkNotice(null);
            }
        } catch {
            refreshBulkNotice(null);
        }
    }

    // ---------------------------------------------------------------- الفحص الجماعي

    function renderBulk(data) {
        const box = document.getElementById("bulkReport");
        box.style.display = "block";
        lastBulk = data.results;
        const counts = { safe: 0, warning: 0, danger: 0, error: 0 };
        for (const r of data.results) counts[r.error ? "error" : r.level] += 1;
        const summary = node("p", "muted", `فُحص ${data.count} رابطاً: خطر ${counts.danger} | تنبيه ${counts.warning} | لا مؤشرات ${counts.safe}${counts.error ? " | غير صالح " + counts.error : ""}`);

        const table = node("table", "bulk-table");
        const head = node("tr");
        for (const title of ["الرابط", "النتيجة", "أهم الأسباب"]) head.append(node("th", "", title));
        table.append(node("thead"), node("tbody"));
        table.firstChild.append(head);
        for (const r of data.results) {
            const tr = node("tr");
            const result = node("td");
            if (r.error) result.append(node("span", "risk-score-badge score-warning", "غير صالح"));
            else result.append(node("span", "risk-score-badge " + LEVEL_BADGES[r.level], `${LEVEL_LABELS[r.level]} ${r.score}%`));
            const reasons = r.error ? "تعذر تحليل هذا الرابط" : r.reasons.slice(0, 2).map(x => x.text).join(" ؛ ");
            tr.append(node("td", "ltr-cell", r.url), result, node("td", "", reasons));
            table.lastChild.append(tr);
        }
        const wrap = node("div", "bulk-wrap");
        wrap.append(table);
        box.replaceChildren(summary, wrap);
    }

    async function runBulkScan() {
        const key = storedKey();
        const box = document.getElementById("bulkReport");
        if (!key) {
            refreshBulkNotice(null);
            box.style.display = "none";
            return;
        }
        const urls = document.getElementById("bulkInput").value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
        if (!urls.length) {
            box.style.display = "block";
            box.replaceChildren(node("p", "license-msg warn", "ألصق رابطاً واحداً على الأقل (رابط بكل سطر)."));
            return;
        }
        box.style.display = "block";
        box.replaceChildren(node("p", "muted", "جاري الفحص..."));
        const response = await fetch("/api/pro/scan-urls", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-License-Key": key },
            body: JSON.stringify({ urls })
        });
        const data = await response.json().catch(() => ({}));
        if (!response.ok) {
            box.replaceChildren(node("p", "license-msg bad", data.error || "تعذر إكمال الفحص."));
            if (response.status === 401) refreshBulkNotice(null);
            return;
        }
        renderBulk(data);
    }

    // حماية جداول البيانات: الخلية التي تبدأ بـ = + - @ تُسبق بعلامة اقتباس
    function csvCell(value) {
        let text = String(value == null ? "" : value);
        if (/^[=+\-@\t\r]/.test(text)) text = "'" + text;
        return /[",\n\r]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
    }

    function exportBulkCsv() {
        if (!lastBulk.length) return;
        const rows = [["url", "level", "score", "host", "top_reasons"].join(",")];
        for (const r of lastBulk) {
            rows.push([r.url, r.error ? "invalid" : r.level, r.error ? "" : r.score, r.host || "", r.error ? "" : r.reasons.slice(0, 3).map(x => x.text).join(" | ")].map(csvCell).join(","));
        }
        const blob = new Blob(["﻿" + rows.join("\r\n") + "\r\n"], { type: "text/csv;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");
        link.href = url;
        link.download = "bulk-scan.csv";
        document.body.append(link);
        link.click();
        link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    // ---------------------------------------------------------------- التسجيل بموزّع الأحداث (app.js)
    ACTIONS.activateLicense = activateLicense;
    ACTIONS.deactivateLicense = deactivateLicense;
    ACTIONS.runBulkScan = runBulkScan;
    ACTIONS.exportBulkCsv = exportBulkCsv;

    loadPricing();
    restoreLicense();
})();
