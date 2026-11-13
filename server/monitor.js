"use strict";

/*
  مراقبة انتحال الدومين (Brand Monitoring) لمشتركي Pro.

  - المشترك يضيف حتى 3 نطاقات يملكها أو يمثلها (مثل tu.edu.iq).
  - مصدر البيانات: سجلات شفافية الشهادات (Certificate Transparency) عبر crt.sh. المهاجم عادة يطلع شهادة HTTPS
    لنطاقه المزيف قبل ما يبدي يرسل الرسائل، فنكشفه مبكراً.
  - نبحث عن النطاقات اللي تحتوي اسم النطاق، وعن صيغ استبدال الحروف بأرقام (g00gle)، ونصنّفها بمحرك الكشف:
    دمج الاسم بكلمات (Combosquatting)، أخطاء إملائية، أحرف متشابهة (Homograph)، أو نطاقك كجزء فرعي من نطاق ثاني.
  - فحص يومي داخل الخادم + زر «افحص هسه». النتائج الجديدة تنرسل بالبريد إذا البريد مفعّل.
  - المشترك يعلّم أي نتيجة «مو تهديد» فما تطلع مرة ثانية.
  ملاحظة: على خطة Render المجانية الخادم ينام بدون زوار، فالفحص اليومي يشتغل لما يكون الخادم صاحي (أو استعمل Cron Job مدفوع).
*/

const engine = require("../public/js/detection-engine.js");

const MAX_DOMAINS = 3;
const MAX_FINDINGS = 200;
const CHECK_COOLDOWN_MS = 10 * 60_000;
const RETRY_COOLDOWN_MS = 60_000;          // بعد فشل الاتصال بـ crt.sh يكدر يعيد بعد دقيقة، مو 10 دقائق
const DAY_MS = 24 * 60 * 60_000;

class MonitorError extends Error {
    constructor(message, status = 400) {
        super(message);
        this.status = status;
    }
}

const LEET = { o: "0", l: "1", i: "1", e: "3", a: "4", s: "5" };

// صيغ بحث إضافية: استبدال حرف واحد برقم مشابه (google ← g0ogle)
function searchVariants(label) {
    const out = new Set([label]);
    for (let i = 0; i < label.length && out.size < 4; i++) {
        const sub = LEET[label[i]];
        if (sub) out.add(label.slice(0, i) + sub + label.slice(i + 1));
    }
    return [...out];
}

// يصنّف نطاقاً مرشحاً مقابل نطاق المشترك. يرجع { reason, score } أو null
function classify(candidate, domain) {
    const host = String(candidate).toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
    if (!/^[a-z0-9.-]+\.[a-z0-9-]{2,}$/.test(host)) return null;
    if (host === domain || host.endsWith("." + domain)) return null;
    const own = engine.splitDomain(domain);
    const parts = engine.splitDomain(host);
    const label = own.label;
    let reason = "";
    if (host.includes(domain + ".") || host.includes(domain.replace(/\./g, "-"))) reason = `يستخدم نطاقك (${domain}) كجزء من اسمه حتى يخدع الناس`;
    else if (parts.label === label && parts.registrable !== own.registrable) reason = `نفس الاسم بامتداد ثاني (${parts.suffix})`;
    else if (engine.asciiSkeleton && engine.asciiSkeleton(parts.label) === engine.asciiSkeleton(label) && parts.label !== label) reason = "أحرف متشابهة الشكل (Homograph)";
    else if (label.length >= 4 && parts.label.includes(label)) reason = "يدمج اسمك بكلمات إضافية (Combosquatting)";
    else if (label.length >= 4 && engine.similarity(parts.label.replace(/[01345]/g, c => ({ 0: "o", 1: "l", 3: "e", 4: "a", 5: "s" }[c] || c)), label) >= 0.8) reason = "اسم قريب جداً من اسمك (خطأ إملائي أو أرقام بدل حروف)";
    if (!reason) return null;
    const r = engine.analyzeUrl("https://" + host);
    const score = Math.max(40, r.error ? 40 : r.score);
    return { reason, score, registrable: parts.registrable };
}

function createMonitor({ db, users, mailer, appUrl, fetchImpl = fetch, now = () => Date.now(), log = () => {}, retryDelayMs = 3000 }) {
    const k = (...p) => db.key(...p);
    let timer = null;

    async function load(uid) {
        const raw = await db.cmd(["GET", k("mon", uid)]);
        try { return raw ? JSON.parse(raw) : { domains: [] }; } catch { return { domains: [] }; }
    }
    const save = (uid, data) => db.cmd(["SET", k("mon", uid), JSON.stringify(data)]);

    function normalizeDomain(raw) {
        let v = String(raw || "").trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/?#]/)[0].replace(/^www\./, "").replace(/\.$/, "");
        if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(v) || v.length > 100) return "";
        return engine.splitDomain(v).registrable;
    }

    async function add(user, raw) {
        const domain = normalizeDomain(raw);
        if (!domain) throw new MonitorError("اكتب نطاقاً صحيحاً، مثل example.com أو tu.edu.iq.");
        const data = await load(user.id);
        if (data.domains.some(d => d.domain === domain)) throw new MonitorError("هذا النطاق مضاف مسبقاً.");
        if (data.domains.length >= MAX_DOMAINS) throw new MonitorError(`الحد ${MAX_DOMAINS} نطاقات لكل حساب.`);
        data.domains.push({ domain, addedAt: now(), lastCheck: 0, lastError: "", findings: [] });
        await save(user.id, data);
        await db.cmd(["SADD", k("monusers"), user.id]);
        return data;
    }

    async function remove(user, raw) {
        const domain = normalizeDomain(raw);
        const data = await load(user.id);
        data.domains = data.domains.filter(d => d.domain !== domain);
        await save(user.id, data);
        if (!data.domains.length) await db.cmd(["SREM", k("monusers"), user.id]);
        return data;
    }

    async function dismiss(user, rawDomain, finding) {
        const domain = normalizeDomain(rawDomain);
        const data = await load(user.id);
        const entry = data.domains.find(d => d.domain === domain);
        const f = entry && entry.findings.find(x => x.domain === String(finding || "").toLowerCase());
        if (!f) throw new MonitorError("النتيجة غير موجودة.", 404);
        f.dismissed = true;
        await save(user.id, data);
        return data;
    }

    // crt.sh خدمة مجانية وكثيراً ما ترجع 502/503 أو تتأخر، فنعيد المحاولة قبل ما نعتبره فشل
    async function crtsh(term, attempts = 1) {
        for (let i = 1; ; i++) {
            try {
                return await crtshOnce(term);
            } catch (error) {
                if (i >= attempts) throw error;
                await new Promise(r => setTimeout(r, retryDelayMs));
            }
        }
    }

    // crt.sh: الشهادات اللي اسمها يحتوي الكلمة
    async function crtshOnce(term) {
        const controller = new AbortController();
        const t = setTimeout(() => controller.abort(), 30_000);
        try {
            const res = await fetchImpl(`https://crt.sh/?q=${encodeURIComponent("%" + term + "%")}&output=json&exclude=expired`, { signal: controller.signal, headers: { Accept: "application/json", "User-Agent": "PhishingDetector-BrandMonitor/1" } });
            if (!res.ok) throw new Error("crt.sh HTTP " + res.status);
            const text = await res.text();
            if (text.length > 20 * 1024 * 1024) throw new Error("crt.sh response too large");
            if (/^\s*</.test(text)) throw new Error("crt.sh returned HTML (busy)");
            const rows = JSON.parse(text || "[]");
            return Array.isArray(rows) ? rows.slice(0, 5000) : [];
        } finally {
            clearTimeout(t);
        }
    }

    async function checkDomain(entry) {
        const label = engine.splitDomain(entry.domain).label;
        const seen = new Map(entry.findings.map(f => [f.domain, f]));
        const fresh = [];
        const terms = searchVariants(label);
        for (const term of terms) {
            // الاسم الأصلي ضروري (محاولتين)، أما صيغ الأرقام فإضافية: إذا فشلت نكمل بدونها
            let rows;
            try {
                rows = await crtsh(term, term === label ? 2 : 1);
            } catch (error) {
                if (term === label) throw error;
                continue;
            }
            for (const row of rows) {
                for (const name of String(row.name_value || "").split(/\s+/)) {
                    const host = name.toLowerCase().replace(/^\*\./, "");
                    const c = classify(host, entry.domain);
                    if (!c || seen.has(c.registrable)) continue;
                    const finding = { domain: c.registrable, example: host.slice(0, 120), reason: c.reason, score: c.score, firstSeen: Date.parse(row.not_before) || now(), foundAt: now(), dismissed: false };
                    seen.set(c.registrable, finding);
                    fresh.push(finding);
                }
            }
        }
        entry.findings = [...fresh, ...entry.findings].sort((a, b) => b.foundAt - a.foundAt).slice(0, MAX_FINDINGS);
        entry.lastCheck = now();
        entry.lastError = "";
        return fresh;
    }

    async function check(user, rawDomain, { manual = true } = {}) {
        const domain = normalizeDomain(rawDomain);
        const data = await load(user.id);
        const entry = data.domains.find(d => d.domain === domain);
        if (!entry) throw new MonitorError("أضف النطاق أولاً.", 404);
        if (manual) {
            if (entry.lastError && now() - (entry.lastAttempt || 0) < RETRY_COOLDOWN_MS) throw new MonitorError("جرّب بعد دقيقة.", 429);
            if (!entry.lastError && now() - entry.lastCheck < CHECK_COOLDOWN_MS) throw new MonitorError("فحصته قبل شوية. جرّب بعد 10 دقائق.", 429);
        }
        let fresh = [];
        let failed = false;
        entry.lastAttempt = now();
        try {
            fresh = await checkDomain(entry);
        } catch (error) {
            // ما نحدّث lastCheck (آخر فحص ناجح) حتى الفحص التلقائي يعيد المحاولة، والمستخدم يكدر يعيد بعد دقيقة
            failed = true;
            entry.lastError = "سجلات الشهادات (crt.sh) مشغولة أو ما ترد حالياً. هاي خدمة عامة خارجية وتتعطل أحياناً؛ جرّب بعد دقيقة، والفحص التلقائي يعيد المحاولة وحده.";
            log("brand monitor: " + (error && error.message));
        }
        await save(user.id, data);
        if (fresh.length) await notify(user, entry.domain, fresh);
        return { data, fresh, failed };
    }

    async function notify(user, domain, findings) {
        if (!mailer || !mailer.enabled || !user.email) return;
        const lines = findings.slice(0, 15).map(f => `- ${f.domain}: ${f.reason}`).join("\n");
        try {
            await mailer.send({
                to: user.email,
                subject: `تنبيه: ${findings.length} نطاق جديد يشبه ${domain}`,
                text: `لكينا نطاقات جديدة تشبه نطاقك ${domain} (من سجلات شهادات HTTPS):\n\n${lines}\n\nراجعها من حسابك: ${appUrl}/\nإذا أحدها تابع إلك علّمه «مو تهديد».`
            });
        } catch { /* البريد اختياري */ }
    }

    // الفحص اليومي: كل حساب مرة يومياً، بالتسلسل حتى ما نثقل على crt.sh
    async function runDaily() {
        const ids = await db.cmd(["SMEMBERS", k("monusers")]).catch(() => []);
        for (const uid of Array.isArray(ids) ? ids : []) {
            try {
                const user = await users.get(uid);
                if (!user || user.disabled) continue;
                const data = await load(uid);
                for (const entry of data.domains) {
                    if (now() - entry.lastCheck < DAY_MS - 60_000) continue;
                    await check(user, entry.domain, { manual: false });
                }
            } catch (error) {
                log("brand monitor daily: " + (error && error.message));
            }
        }
    }

    function start() {
        if (timer) return;
        setTimeout(() => runDaily().catch(() => {}), 60_000).unref();
        timer = setInterval(() => runDaily().catch(() => {}), 6 * 60 * 60_000);   // كل 6 ساعات نشوف منو صار عليه الدور
        timer.unref();
    }
    function stop() { if (timer) clearInterval(timer); timer = null; }

    return { load, add, remove, dismiss, check, runDaily, start, stop };
}

module.exports = { createMonitor, classify, searchVariants, MonitorError };
