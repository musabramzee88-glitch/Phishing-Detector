"use strict";

/*
  فحص رقم الهاتف أو الحساب أو المحفظة (سمعة المعرّفات من بلاغات المستخدمين).

  الضوابط (حساسة قانونياً):
  - المعرّف ما ينخزن كنص: نخزن بصمة HMAC-SHA256 بسرّ خاص بالخادم، فحتى لو تسربت القاعدة ما تنقرأ الأرقام منها.
    نخزن معها صيغة مموّهة فقط (0770•••4567) حتى الأدمن يعرف عن شنو الكلام.
  - كل مستخدم يُحسب مرة وحدة لكل معرّف (ما يكدر واحد يضخّم العدد).
  - النتيجة «انبلغ عنه X مرات من X مستخدمين»، ما نقول «محتال» أبداً، وبلاغ واحد ما يصير حكم.
  - ما نعرض اسم صاحب المعرّف ولا هويات المبلّغين.
  - أي شخص يكدر يقدّم اعتراض، والأدمن يراجعه ويكدر يحذف كل البلاغات عن المعرّف (ويبقى محذوفاً).
  - البحث يحتاج حساب وبحد بالدقيقة (يمنع جمع البيانات آلياً).

  مفاتيح القاعدة: idsecret، idrep:<h> (HASH)، idrepu:<h> (SET مستخدمين)، idreps (ZSET)، idsup:<h> (محذوف)،
  idn:<uid>:<يوم>، iddisp:<id> (JSON)، iddisps (ZSET)، iddisps:open (SET)
*/

const crypto = require("node:crypto");

const KINDS = {
    phone: "رقم هاتف",
    telegram: "حساب تيليجرام",
    instagram: "حساب انستغرام",
    facebook: "حساب فيسبوك",
    whatsapp: "رقم واتساب",
    wallet: "محفظة إلكترونية أو حساب مصرفي"
};
const CATEGORIES = {
    fake_seller: "بائع أو متجر وهمي",
    transfer: "طلب تحويل رصيد أو فلوس",
    impersonation: "انتحال جهة أو شخص",
    otp: "طلب رمز تحقق أو بيانات",
    blackmail: "ابتزاز أو تهديد",
    investment: "استثمار أو ربح وهمي",
    other: "أخرى"
};
const MAX_REPORTS_PER_DAY = 10;

class IdentifierError extends Error {
    constructor(message, status = 400) {
        super(message);
        this.status = status;
    }
}

const clean = (v, max) => String(v == null ? "" : v).replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩<>]/g, "").trim().slice(0, max);

// يوحّد المعرّف: الأرقام العراقية كلها بصيغة 9647XXXXXXXXX، والحسابات بحروف صغيرة بدون @ أو رابط
function normalize(kind, raw) {
    let v = String(raw || "").trim().slice(0, 200);
    if (kind === "phone" || kind === "whatsapp") {
        v = v.replace(/[\s\-().]/g, "").replace(/^\+/, "").replace(/^00/, "");
        if (!/^\d{7,15}$/.test(v)) return "";
        if (/^07\d{9}$/.test(v)) v = "964" + v.slice(1);
        else if (/^7\d{9}$/.test(v)) v = "964" + v;
        return v;
    }
    if (kind === "telegram" || kind === "instagram" || kind === "facebook") {
        v = v.toLowerCase().replace(/^https?:\/\/(www\.)?(t\.me|telegram\.me|instagram\.com|facebook\.com|fb\.com)\//, "").replace(/^@/, "").split(/[/?#]/)[0];
        return /^[a-z0-9._]{3,64}$/.test(v) ? v : "";
    }
    if (kind === "wallet") {
        v = v.replace(/\s+/g, "").toLowerCase();
        return /^[a-z0-9:-]{6,80}$/.test(v) ? v : "";
    }
    return "";
}

// صيغة مموّهة للعرض للأدمن فقط
function mask(kind, value) {
    if (value.length <= 6) return value[0] + "•".repeat(Math.max(1, value.length - 2)) + value.slice(-1);
    if (kind === "phone" || kind === "whatsapp") return value.slice(0, 6) + "•".repeat(Math.max(2, value.length - 10)) + value.slice(-4);
    return value.slice(0, 3) + "•".repeat(Math.min(8, value.length - 5)) + value.slice(-2);
}

function createIdentifiers({ db, now = () => Date.now() }) {
    const k = (...p) => db.key(...p);
    let secretPromise = null;

    // سرّ البصمة: من متغير البيئة، وإلا يُولَّد مرة وحدة ويُحفظ بالقاعدة
    function secret() {
        if (process.env.IDENTIFIER_SECRET && process.env.IDENTIFIER_SECRET.length >= 32) return Promise.resolve(process.env.IDENTIFIER_SECRET);
        if (!secretPromise) {
            secretPromise = (async () => {
                const fresh = crypto.randomBytes(32).toString("hex");
                await db.cmd(["SET", k("idsecret"), fresh, "NX"]);
                return String(await db.cmd(["GET", k("idsecret")]));
            })().catch(error => { secretPromise = null; throw error; });
        }
        return secretPromise;
    }

    async function fingerprint(kind, raw) {
        if (!KINDS[kind]) throw new IdentifierError("اختر نوع المعرّف.");
        const value = normalize(kind, raw);
        if (!value) throw new IdentifierError(kind === "phone" || kind === "whatsapp" ? "اكتب رقم هاتف صحيح." : "اكتب اسم الحساب أو رقم المحفظة بشكل صحيح.");
        // الهاتف والواتساب نفس الرقم: بصمة وحدة
        const family = kind === "whatsapp" ? "phone" : kind;
        const h = crypto.createHmac("sha256", await secret()).update(family + ":" + value).digest("hex");
        return { h, value, family };
    }

    async function lookup(kind, raw) {
        const { h } = await fingerprint(kind, raw);
        const [suppressed, data] = await db.pipe([["GET", k("idsup", h)], ["HGETALL", k("idrep", h)]]);
        if (suppressed) return { reports: 0, reporters: 0, categories: {}, lastAt: null };
        const row = {};
        const list = Array.isArray(data) ? data : Object.entries(data || {}).flat();
        for (let i = 0; i + 1 < list.length; i += 2) row[list[i]] = list[i + 1];
        const categories = {};
        for (const key of Object.keys(CATEGORIES)) if (Number(row["c_" + key])) categories[key] = Number(row["c_" + key]);
        return { reports: Number(row.reporters) || 0, reporters: Number(row.reporters) || 0, categories, lastAt: row.lastAt ? new Date(Number(row.lastAt)).toISOString() : null };
    }

    async function report(user, { kind, value, category, note }) {
        const { h, value: normalized, family } = await fingerprint(kind, value);
        const cat = CATEGORIES[category] ? category : "other";
        const day = new Date(now()).toISOString().slice(0, 10);
        const [count] = await db.pipe([["INCR", k("idn", user.id, day)], ["EXPIRE", k("idn", user.id, day), "172800"]]);
        if (Number(count) > MAX_REPORTS_PER_DAY) throw new IdentifierError("وصلت لحد البلاغات اليومي. حاول باجر.", 429);
        if (await db.cmd(["GET", k("idsup", h)])) throw new IdentifierError("هذا المعرّف حُذفت بلاغاته بعد مراجعة اعتراض. إذا عندك دليل جديد تواصل ويّا الإدارة.", 409);
        const added = await db.cmd(["SADD", k("idrepu", h), user.id]);
        if (Number(added) !== 1) throw new IdentifierError("بلّغت عن هذا المعرّف قبل. كل مستخدم ينحسب مرة وحدة.", 409);
        const at = now();
        await db.pipe([
            ["HINCRBY", k("idrep", h), "reporters", "1"],
            ["HINCRBY", k("idrep", h), "c_" + cat, "1"],
            ["HSET", k("idrep", h), "lastAt", String(at), "kind", family, "masked", mask(family, normalized)],
            ["ZADD", k("idreps"), String(at), h]
        ]);
        if (note) await db.cmd(["HSET", k("idrep", h), "lastNote", clean(note, 300)]);
        return lookup(kind, value);
    }

    // اعتراض (من أي شخص، بدون حساب): يوصل للأدمن
    async function dispute({ kind, value, contact, reason }) {
        const { h, value: normalized, family } = await fingerprint(kind, value);
        const text = clean(reason, 1000);
        if (text.length < 10) throw new IdentifierError("اشرح سبب الاعتراض (10 أحرف على الأقل).");
        const item = { id: crypto.randomBytes(6).toString("hex"), h, kind: family, masked: mask(family, normalized), contact: clean(contact, 120), reason: text, status: "open", at: now() };
        await db.pipe([
            ["SET", k("iddisp", item.id), JSON.stringify(item)],
            ["ZADD", k("iddisps"), String(item.at), item.id],
            ["SADD", k("iddisps", "open"), item.id],
            ["ZREMRANGEBYRANK", k("iddisps"), "0", "-501"]
        ]);
        return { ok: true };
    }

    async function loadJson(keys) {
        if (!keys.length) return [];
        const raw = await db.pipe(keys.map(key => ["GET", key]));
        return raw.map(r => { try { return JSON.parse(r); } catch { return null; } }).filter(Boolean);
    }

    // للأدمن: أكثر المعرّفات المبلّغ عنها (مموّهة) والاعتراضات المفتوحة
    async function adminView() {
        const hashes = await db.cmd(["ZREVRANGE", k("idreps"), "0", "99"]);
        const rows = Array.isArray(hashes) && hashes.length ? await db.pipe(hashes.map(h => ["HGETALL", k("idrep", h)])) : [];
        const top = (Array.isArray(hashes) ? hashes : []).map((h, i) => {
            const list = Array.isArray(rows[i]) ? rows[i] : Object.entries(rows[i] || {}).flat();
            const r = {};
            for (let j = 0; j + 1 < list.length; j += 2) r[list[j]] = list[j + 1];
            return { h, kind: r.kind || "", masked: r.masked || "", reporters: Number(r.reporters) || 0, lastAt: Number(r.lastAt) || 0, lastNote: r.lastNote || "" };
        }).filter(r => r.reporters > 0);
        const openIds = await db.cmd(["SMEMBERS", k("iddisps", "open")]);
        const disputes = (await loadJson((Array.isArray(openIds) ? openIds : []).map(id => k("iddisp", id)))).sort((a, b) => b.at - a.at);
        return { top, disputes: disputes.map(({ h, ...d }) => ({ ...d, hasReports: top.some(t => t.h === h) })) };
    }

    // remove=true: نحذف كل البلاغات عن المعرّف ونمنع البلاغات الجديدة عنه
    async function decideDispute(id, { remove, admin }) {
        const raw = await db.cmd(["GET", k("iddisp", String(id).slice(0, 40))]);
        if (!raw) throw new IdentifierError("الاعتراض غير موجود.", 404);
        const item = JSON.parse(raw);
        const claimed = await db.cmd(["SREM", k("iddisps", "open"), item.id]);
        if (Number(claimed) !== 1) throw new IdentifierError("تمت مراجعة هذا الاعتراض مسبقاً.", 409);
        item.status = remove ? "removed" : "rejected";
        item.decidedAt = now();
        item.decidedBy = clean(admin, 40);
        const commands = [["SET", k("iddisp", item.id), JSON.stringify(item)]];
        if (remove) commands.push(["DEL", k("idrep", item.h)], ["DEL", k("idrepu", item.h)], ["ZREM", k("idreps"), item.h], ["SET", k("idsup", item.h), "1"]);
        await db.pipe(commands);
        return item;
    }

    async function removeByHash(h) {
        if (!/^[0-9a-f]{64}$/.test(String(h))) throw new IdentifierError("معرّف غير صالح.");
        await db.pipe([["DEL", k("idrep", h)], ["DEL", k("idrepu", h)], ["ZREM", k("idreps"), h], ["SET", k("idsup", h), "1"]]);
    }

    return { lookup, report, dispute, adminView, decideDispute, removeByHash, KINDS, CATEGORIES };
}

module.exports = { createIdentifiers, IdentifierError, normalize, mask, KINDS, CATEGORIES };
