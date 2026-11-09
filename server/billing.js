"use strict";

/* منطق الاشتراكات والإيرادات: إنشاء ترخيص بعد استلامك الدفع يدوياً، الإلغاء، الإحصاءات، والتصدير. */

const { PAYMENT_METHODS, CURRENCIES } = require("./pricing");

const DAY_MS = 86_400_000;
const TIERS = ["pro", "enterprise"];
const ID_PATTERN = /^[0-9A-F]{8}$/;

function clean(value, max) {
    return String(value == null ? "" : value).replace(/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/g, " ").replace(/\s+/g, " ").trim().slice(0, max);
}

function round2(n) {
    return Math.round(n * 100) / 100;
}

function statusOf(sale, revoked, now) {
    if (revoked) return "revoked";
    const expires = Date.parse(sale.expiresAt);
    if (expires < now) return "expired";
    if (expires - now < 7 * DAY_MS) return "expiring";
    return "active";
}

function monthKey(ms) {
    return new Date(ms).toISOString().slice(0, 7);
}

// إحصاءات الإيرادات والاشتراكات. دالة صرفة (بدون تخزين) حتى يسهل اختبارها.
// لا نجمع عملات مختلفة معاً أبداً: لكل عملة أرقامها.
function summarize(sales, isRevoked, now = Date.now()) {
    const revenue = {};
    for (const currency of CURRENCIES) revenue[currency] = { allTime: 0, thisMonth: 0, last30: 0 };
    const counts = { total: sales.length, active: 0, expiring: 0, expired: 0, revoked: 0 };
    const activeByTier = { pro: 0, enterprise: 0 };
    const expiringSoon = [];

    const months = [];
    const cursor = new Date(now);
    cursor.setUTCDate(1);
    for (let i = 5; i >= 0; i--) {
        const d = new Date(Date.UTC(cursor.getUTCFullYear(), cursor.getUTCMonth() - i, 1));
        const row = { month: monthKey(d.getTime()) };
        for (const currency of CURRENCIES) row[currency] = 0;
        months.push(row);
    }

    for (const sale of sales) {
        const created = Date.parse(sale.createdAt);
        const bucket = revenue[sale.currency];
        if (bucket) {
            bucket.allTime += sale.amount;
            if (monthKey(created) === monthKey(now)) bucket.thisMonth += sale.amount;
            if (now - created <= 30 * DAY_MS) bucket.last30 += sale.amount;
            const row = months.find(m => m.month === monthKey(created));
            if (row) row[sale.currency] += sale.amount;
        }
        const status = statusOf(sale, isRevoked(sale.id), now);
        counts[status] += 1;
        if (status === "active" || status === "expiring") activeByTier[sale.tier] = (activeByTier[sale.tier] || 0) + 1;
        if (status === "expiring") expiringSoon.push({ id: sale.id, customer: sale.customer, tier: sale.tier, expiresAt: sale.expiresAt });
    }

    for (const currency of CURRENCIES) for (const key of Object.keys(revenue[currency])) revenue[currency][key] = round2(revenue[currency][key]);
    for (const row of months) for (const currency of CURRENCIES) row[currency] = round2(row[currency]);
    expiringSoon.sort((a, b) => Date.parse(a.expiresAt) - Date.parse(b.expiresAt));
    return { currencies: CURRENCIES, revenue, monthly: months, counts, activeByTier, expiringSoon: expiringSoon.slice(0, 10) };
}

// حماية جداول البيانات (CSV Injection): خلية تبدأ بـ = + - @ قد تُنفَّذ كمعادلة بـ Excel
function csvCell(value) {
    let text = String(value == null ? "" : value);
    if (/^[=+\-@\t\r]/.test(text)) text = "'" + text;
    return /[",\n\r]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
}

function createBilling({ store, license, stats, now = Date.now }) {
    function view(sale, time) {
        const revoked = store.isRevoked(sale.id);
        return {
            ...sale,
            status: statusOf(sale, revoked, time),
            key: license.enabled ? license.keyFor({ tier: sale.tier, id: sale.id, expiresAt: Date.parse(sale.expiresAt) }) : ""
        };
    }

    function validate(input) {
        const body = input && typeof input === "object" ? input : {};
        const customer = clean(body.customer, 80);
        if (!customer) return { error: "اسم الزبون مطلوب." };
        if (!TIERS.includes(body.tier)) return { error: "الباقة غير صحيحة." };
        const days = Number(body.days);
        if (!Number.isInteger(days) || days < 1 || days > 3660) return { error: "المدة بالأيام يجب أن تكون بين 1 و3660." };
        const amount = Number(body.amount);
        if (!Number.isFinite(amount) || amount < 0 || amount > 1e9) return { error: "المبلغ غير صحيح." };
        if (!CURRENCIES.includes(body.currency)) return { error: "العملة غير صحيحة." };
        if (!PAYMENT_METHODS.includes(body.method)) return { error: "طريقة الدفع غير صحيحة." };
        const renewalOf = body.renewalOf ? String(body.renewalOf) : "";
        if (renewalOf && !ID_PATTERN.test(renewalOf)) return { error: "رقم الترخيص السابق غير صحيح." };
        return { value: { customer, tier: body.tier, days, amount: round2(amount), currency: body.currency, method: body.method, note: clean(body.note, 200), renewalOf } };
    }

    return {
        enabled: license.enabled,

        // يُصدر مفتاحاً بعد أن تستلم الدفع. المفتاح يُعرض هنا ويمكن عرضه لاحقاً من القائمة.
        create(input, ip) {
            if (!license.enabled) return { status: 503, error: "الاشتراكات غير مفعّلة: ضع LICENSE_SECRET بمتغيرات البيئة (npm run make-secret)." };
            const checked = validate(input);
            if (checked.error) return { status: 400, error: checked.error };
            const { customer, tier, days, amount, currency, method, note, renewalOf } = checked.value;
            const time = now();
            let issued;
            try {
                issued = license.issue({ tier, expiresAt: time + days * DAY_MS });
            } catch (error) {
                return { status: 400, error: error.message };
            }
            const sale = {
                id: issued.id, createdAt: new Date(time).toISOString(), customer, tier,
                expiresAt: new Date(issued.expiresAt).toISOString(), amount, currency, method, note
            };
            if (renewalOf) sale.renewalOf = renewalOf;
            try {
                store.addSale(sale);
            } catch {
                return { status: 507, error: "وصل السجل لأقصى عدد مسموح من السجلات." };
            }
            // اسم الزبون لا يُكتب بسجل التدقيق (سجلات الاستضافة): نكتفي برقم الترخيص
            stats.event("license_created", `ترخيص ${issued.id} (${tier}) لمدة ${days} يوماً`, ip);
            return { status: 201, license: view(sale, time), key: issued.key };
        },

        revoke(id, ip) {
            const target = String(id || "");
            if (!ID_PATTERN.test(target)) return { status: 400, error: "رقم الترخيص غير صحيح." };
            if (!store.sales().some(s => s.id === target)) return { status: 404, error: "الترخيص غير موجود." };
            store.revoke(target);
            stats.event("license_revoked", `إلغاء الترخيص ${target}`, ip);
            return { status: 200, ok: true };
        },

        overview() {
            const time = now();
            const sales = store.sales();
            return {
                enabled: license.enabled,
                storage: { persistent: store.state.persistent, error: store.state.error },
                summary: summarize(sales, id => store.isRevoked(id), time),
                licenses: sales.slice(-500).reverse().map(sale => view(sale, time))
            };
        },

        csv() {
            const time = now();
            const header = ["license_id", "created_at", "customer", "tier", "expires_at", "status", "amount", "currency", "method", "note", "renewal_of"];
            const rows = store.sales().map(sale => {
                const v = view(sale, time);
                return [v.id, v.createdAt, v.customer, v.tier, v.expiresAt, v.status, v.amount, v.currency, v.method, v.note, v.renewalOf || ""].map(csvCell).join(",");
            });
            return "﻿" + [header.join(","), ...rows].join("\r\n") + "\r\n";
        },

        backup() {
            return { version: 1, exportedAt: new Date(now()).toISOString(), sales: store.sales(), revoked: store.revokedIds() };
        }
    };
}

module.exports = { createBilling, summarize, statusOf, csvCell, clean };
