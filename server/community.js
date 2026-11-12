"use strict";

/*
  مجتمع الموقع: تنبيهات الاحتيال، وبلاغات المستخدمين، وقائمة النطاقات المؤكدة.

  - تنبيهات (alerts): يكتبها الأدمن، تظهر للجميع بصفحة /alerts العامة (تفيد الناس ومحركات البحث) وبرئيسية التطبيق.
  - بلاغات (reports): مستخدم مسجّل يبلّغ عن رابط أو رسالة احتيال. حد 10 بلاغات يومياً لكل حساب.
    الأدمن يراجعها: «تأكيد» يضيف نطاق الرابط لقائمة الاحتيال المؤكدة، أو «رفض».
  - القائمة المؤكدة (blocklist): أي فحص لاحق لهذا النطاق (أو نطاق فرعي منه) يُحكم عليه بالخطر.
    تُقرأ من القاعدة وتُحفظ بالذاكرة (تتحدث كل دقيقة) حتى يبقى الفحص سريعاً.

  مفاتيح القاعدة: alerts (JSON)، rep:<id> (JSON)، reps (ZSET)، reps:open (SET)، repn:<uid>:<يوم>، blocklist (SET)
*/

const crypto = require("node:crypto");
const engine = require("../public/js/detection-engine.js");

const MAX_ALERTS = 50;
const MAX_REPORTS_PER_DAY = 10;
const SEVERITIES = new Set(["info", "warn", "danger"]);

const clean = (value, max) => String(value == null ? "" : value)
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g, "")
    .replace(/[<>]/g, "")
    .trim().slice(0, max);

class CommunityError extends Error {
    constructor(message, status = 400) {
        super(message);
        this.status = status;
    }
}

function hostOf(rawUrl) {
    const r = engine.analyzeUrl(String(rawUrl || "").slice(0, 2048));
    if (r.error || !r.host) return null;
    return { host: r.host.replace(/^www\./, ""), registrable: r.registrable || r.host, official: r.official, input: r.input };
}

function createCommunity({ db, now = () => Date.now() }) {
    const k = (...p) => db.key(...p);
    let blocked = new Set();
    let alertsCache = [];
    let loadedAt = 0;
    let timer = null;

    async function refresh() {
        try {
            const [members, raw] = await db.pipe([["SMEMBERS", k("blocklist")], ["GET", k("alerts")]]);
            blocked = new Set(Array.isArray(members) ? members : []);
            alertsCache = raw ? JSON.parse(raw) : [];
            loadedAt = now();
        } catch { /* نبقي آخر نسخة */ }
    }

    function start() {
        refresh();
        if (!timer) {
            timer = setInterval(refresh, 60_000);
            timer.unref();
        }
    }

    function stop() {
        if (timer) clearInterval(timer);
        timer = null;
    }

    // ---------- القائمة المؤكدة ----------
    // يرجع النطاق المؤكد الذي يطابق المضيف (نفسه أو أحد آبائه)، أو ""
    function blockedMatch(host) {
        const h = String(host || "").toLowerCase().replace(/^www\./, "");
        if (!h || !blocked.size) return "";
        const parts = h.split(".");
        for (let i = 0; i < parts.length - 1; i++) {
            const candidate = parts.slice(i).join(".");
            if (blocked.has(candidate)) return candidate;
        }
        return "";
    }

    async function listBlocked() {
        const members = await db.cmd(["SMEMBERS", k("blocklist")]);
        return (Array.isArray(members) ? members : []).sort();
    }

    async function unblock(domain) {
        await db.cmd(["SREM", k("blocklist"), String(domain).toLowerCase().slice(0, 253)]);
        await refresh();
    }

    // ---------- التنبيهات ----------
    function alerts(limit = MAX_ALERTS) {
        return alertsCache.slice(0, limit);
    }

    async function addAlert({ title, body, severity }, by) {
        const alert = {
            id: crypto.randomBytes(5).toString("hex"),
            title: clean(title, 120),
            body: clean(body, 1500),
            severity: SEVERITIES.has(severity) ? severity : "warn",
            at: now(),
            by: clean(by, 40)
        };
        if (alert.title.length < 4) throw new CommunityError("اكتب عنواناً واضحاً للتنبيه.");
        if (alert.body.length < 10) throw new CommunityError("اكتب تفاصيل التنبيه (شنو الرسالة أو الرابط، وشلون يتجنبه الناس).");
        await refresh();
        const next = [alert, ...alertsCache].slice(0, MAX_ALERTS);
        await db.cmd(["SET", k("alerts"), JSON.stringify(next)]);
        alertsCache = next;
        return alert;
    }

    async function deleteAlert(id) {
        await refresh();
        const next = alertsCache.filter(a => a.id !== id);
        if (next.length === alertsCache.length) throw new CommunityError("التنبيه غير موجود.", 404);
        await db.cmd(["SET", k("alerts"), JSON.stringify(next)]);
        alertsCache = next;
    }

    // ---------- البلاغات ----------
    async function createReport(user, { kind, content, note }) {
        if (!["url", "text"].includes(kind)) throw new CommunityError("نوع البلاغ غير صالح.");
        const text = clean(content, kind === "url" ? 2048 : 3000);
        if (text.length < 4) throw new CommunityError("اكتب الرابط أو الرسالة اللي تريد تبلّغ عنها.");
        let target = null;
        if (kind === "url") {
            target = hostOf(text);
            if (!target) throw new CommunityError("الرابط غير صالح.");
            if (target.official) throw new CommunityError(`هذا النطاق رسمي لـ ${target.official}. إذا وصلتك رسالة احتيال تحمله، بلّغ عن الرسالة نفسها.`);
        }
        const day = new Date(now()).toISOString().slice(0, 10);
        const [count] = await db.pipe([["INCR", k("repn", user.id, day)], ["EXPIRE", k("repn", user.id, day), "172800"]]);
        if (Number(count) > MAX_REPORTS_PER_DAY) throw new CommunityError("وصلت لحد البلاغات اليومي. شكراً لمساعدتك، حاول باجر.", 429);
        const report = {
            id: crypto.randomBytes(6).toString("hex"),
            uid: user.id, email: user.email,
            kind, content: kind === "url" ? target.input.slice(0, 2048) : text,
            domain: target ? target.registrable : "",
            note: clean(note, 300),
            status: "open", at: now(), decidedAt: 0, decidedBy: ""
        };
        await db.pipe([
            ["SET", k("rep", report.id), JSON.stringify(report)],
            ["ZADD", k("reps"), String(report.at), report.id],
            ["SADD", k("reps", "open"), report.id],
            ["ZREMRANGEBYRANK", k("reps"), "0", "-1001"]
        ]);
        return report;
    }

    async function listReports({ status = "open", limit = 200 } = {}) {
        const ids = status === "open"
            ? await db.cmd(["SMEMBERS", k("reps", "open")])
            : await db.cmd(["ZREVRANGE", k("reps"), "0", String(limit - 1)]);
        const list = Array.isArray(ids) && ids.length ? await db.pipe(ids.map(id => ["GET", k("rep", id)])) : [];
        return list.map(r => { try { return JSON.parse(r); } catch { return null; } }).filter(Boolean).sort((a, b) => b.at - a.at);
    }

    async function openCount() {
        const ids = await db.cmd(["SMEMBERS", k("reps", "open")]);
        return Array.isArray(ids) ? ids.length : 0;
    }

    // confirm=true: البلاغ صحيح. لرابط: نضيف نطاقه للقائمة المؤكدة
    async function decideReport(id, { confirm, admin }) {
        const raw = await db.cmd(["GET", k("rep", String(id).slice(0, 40))]);
        if (!raw) throw new CommunityError("البلاغ غير موجود.", 404);
        const report = JSON.parse(raw);
        const claimed = await db.cmd(["SREM", k("reps", "open"), report.id]);
        if (Number(claimed) !== 1) throw new CommunityError("تمت مراجعة هذا البلاغ مسبقاً.", 409);
        report.status = confirm ? "confirmed" : "rejected";
        report.decidedAt = now();
        report.decidedBy = clean(admin, 40);
        const commands = [["SET", k("rep", report.id), JSON.stringify(report)]];
        if (confirm && report.domain) commands.push(["SADD", k("blocklist"), report.domain]);
        await db.pipe(commands);
        await refresh();
        return report;
    }

    return { start, stop, refresh, blockedMatch, listBlocked, unblock, alerts, addAlert, deleteAlert, createReport, listReports, openCount, decideReport, loadedAt: () => loadedAt };
}

module.exports = { createCommunity, CommunityError };
