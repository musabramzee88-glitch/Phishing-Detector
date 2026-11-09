"use strict";

/*
  سجل المبيعات والإلغاءات. ثلاثة أنواع تخزين بنفس الواجهة:
    upstash  قاعدة بيانات خارجية (Upstash Redis عبر REST). الموصى به على Render المجانية لأن قرصها مؤقت.
    file     ملف billing.json داخل DATA_DIR (للتجربة المحلية أو عند وجود قرص دائم). الكتابة ذرّية.
    memory   بالذاكرة فقط (عندما تكون الاشتراكات غير مفعّلة، أو تعذرت الكتابة).

  القراءة دائماً من نسخة بالذاكرة (سريعة ومتزامنة)، والكتابة تُحفظ أولاً بمكان التخزين ثم تدخل النسخة.
  بالـ upstash: إذا تعذر الاتصال بالقاعدة يرفض تسجيل أي بيع أو إلغاء (STORE_UNAVAILABLE) بدل أن يخسره بصمت،
  ويعيد محاولة الاتصال تلقائياً. التحقق من المفاتيح واختبار الإلغاء يستمران من النسخة التي بالذاكرة.
*/

const fs = require("node:fs");
const path = require("node:path");
const { createUpstashClient, describeError } = require("./upstash");

const MAX_SALES = 20_000;
const ID_PATTERN = /^[0-9A-F]{8}$/;

class StoreUnavailableError extends Error {
    constructor() {
        super("store unavailable");
        this.code = "STORE_UNAVAILABLE";
    }
}

function validSale(sale) {
    return Boolean(sale) && typeof sale === "object" && ID_PATTERN.test(String(sale.id)) &&
        ["pro", "enterprise"].includes(sale.tier) && typeof sale.customer === "string" && Number.isFinite(sale.amount) &&
        typeof sale.currency === "string" && !Number.isNaN(Date.parse(sale.createdAt)) && !Number.isNaN(Date.parse(sale.expiresAt));
}

// ---------------------------------------------------------------- ملف / ذاكرة

function validShape(data) {
    return Boolean(data) && data.version === 1 && Array.isArray(data.sales) && Array.isArray(data.revoked);
}

function createStore(dir) {
    const file = dir ? path.join(dir, "billing.json") : "";
    let data = { version: 1, sales: [], revoked: [] };
    let revokedSet = new Set();
    const state = { backend: dir ? "file" : "memory", persistent: false, error: "", notice: "", file };

    function writeFile() {
        const temporary = file + ".tmp";
        fs.writeFileSync(temporary, JSON.stringify(data), { mode: 0o600 });
        fs.renameSync(temporary, file);
    }

    function init() {
        if (!dir) return;           // بدون مجلد: ذاكرة فقط (الاشتراكات غير مفعّلة)
        try {
            fs.mkdirSync(dir, { recursive: true });
            if (fs.existsSync(file)) {
                try {
                    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
                    if (!validShape(parsed)) throw new Error("bad shape");
                    data = parsed;
                    revokedSet = new Set(data.revoked);
                } catch {
                    // ملف تالف: لا نكتب فوقه أبداً. نحفظه باسم آخر ونبدأ بسجل فارغ مع تنبيه ظاهر
                    const backup = file.replace(/\.json$/, `.corrupt-${Date.now()}.json`);
                    fs.renameSync(file, backup);
                    state.error = "كان ملف السجل تالفاً وحُفظت نسخة منه باسم " + path.basename(backup);
                }
            }
            writeFile();                 // نتأكد أن الكتابة ممكنة فعلاً (صلاحيات المجلد)
            state.persistent = true;
        } catch {
            state.persistent = false;
            state.error = state.error || "تعذرت الكتابة بمجلد البيانات؛ السجل يعمل بالذاكرة فقط وسيضيع عند إعادة التشغيل.";
        }
    }
    init();

    function save() {
        if (!state.persistent) return;
        try {
            writeFile();
        } catch {
            state.persistent = false;
            state.error = "فشلت كتابة السجل؛ التغييرات الأخيرة بالذاكرة فقط. صدّر نسخة احتياطية الآن.";
        }
    }

    return {
        state,
        ready: Promise.resolve(),
        sales: () => data.sales,
        isRevoked: id => revokedSet.has(id),
        revokedIds: () => [...revokedSet],
        async addSale(sale) {
            if (data.sales.length >= MAX_SALES) throw new Error("sales limit reached");
            data.sales.push(sale);
            save();
        },
        async revoke(id) {
            if (revokedSet.has(id)) return;
            revokedSet.add(id);
            data.revoked.push(id);
            save();
        },
        close() {}
    };
}

// ---------------------------------------------------------------- Upstash

function hashEntries(raw) {
    // الرد عادة مصفوفة مسطحة [حقل، قيمة، حقل، قيمة...]، ونقبل شكل الكائن أيضاً
    if (Array.isArray(raw)) {
        const entries = [];
        for (let i = 0; i + 1 < raw.length; i += 2) entries.push([raw[i], raw[i + 1]]);
        return entries;
    }
    return raw && typeof raw === "object" ? Object.entries(raw) : [];
}

function createRemoteStore({ client, prefix = "pd", retryMs = 30_000 }) {
    const salesKey = `${prefix}:sales`;
    const revokedKey = `${prefix}:revoked`;
    let sales = [];
    let revoked = new Set();
    let timer = null;
    let closed = false;
    const state = { backend: "upstash", persistent: false, error: "", notice: "" };

    async function load() {
        const [rawSales, rawRevoked] = await client.pipeline([["HGETALL", salesKey], ["SMEMBERS", revokedKey]]);
        const loaded = [];
        let skipped = 0;
        for (const [field, value] of hashEntries(rawSales)) {
            let sale = null;
            try { sale = JSON.parse(value); } catch { /* سجل تالف */ }
            if (validSale(sale) && sale.id === field) loaded.push(sale);
            else skipped += 1;
        }
        loaded.sort((a, b) => Date.parse(a.createdAt) - Date.parse(b.createdAt));
        sales = loaded;
        revoked = new Set((Array.isArray(rawRevoked) ? rawRevoked : []).filter(id => ID_PATTERN.test(String(id))));
        state.notice = skipped ? `تم تجاهل ${skipped} سجلاً تالفاً من القاعدة.` : "";
    }

    async function init() {
        try {
            await load();
            state.persistent = true;
            state.error = "";
        } catch (error) {
            state.persistent = false;
            state.error = `تعذر الاتصال بقاعدة البيانات الخارجية (${describeError(error)}). لن يُسجَّل أي بيع أو إلغاء جديد حتى يعود الاتصال.`;
            if (!closed && !timer) {
                timer = setTimeout(() => { timer = null; init(); }, retryMs);
                timer.unref();
            }
        }
    }

    const ready = init();

    return {
        state,
        ready,
        sales: () => sales,
        isRevoked: id => revoked.has(id),
        revokedIds: () => [...revoked],
        async addSale(sale) {
            if (!state.persistent) throw new StoreUnavailableError();
            if (sales.length >= MAX_SALES) throw new Error("sales limit reached");
            let added;
            try {
                added = await client.command(["HSETNX", salesKey, sale.id, JSON.stringify(sale)]);
            } catch (error) {
                state.error = `فشلت آخر عملية كتابة بقاعدة البيانات (${describeError(error)}).`;
                throw new StoreUnavailableError();
            }
            if (Number(added) !== 1) throw new Error("duplicate id");
            state.error = "";
            sales.push(sale);
        },
        async revoke(id) {
            if (!state.persistent) throw new StoreUnavailableError();
            if (revoked.has(id)) return;
            try {
                await client.command(["SADD", revokedKey, id]);
            } catch (error) {
                state.error = `فشلت آخر عملية كتابة بقاعدة البيانات (${describeError(error)}).`;
                throw new StoreUnavailableError();
            }
            state.error = "";
            revoked.add(id);
        },
        close() {
            closed = true;
            if (timer) clearTimeout(timer);
            timer = null;
        }
    };
}

// يختار نوع التخزين حسب الإعدادات: Upstash إن ضُبط، وإلا ملف DATA_DIR
function openStore(billing) {
    if (billing.upstash) {
        const client = createUpstashClient({ url: billing.upstash.url, token: billing.upstash.token });
        return createRemoteStore({ client, prefix: billing.upstash.prefix, retryMs: billing.retryMs });
    }
    return createStore(billing.dataDir);
}

module.exports = { createStore, createRemoteStore, openStore, StoreUnavailableError, MAX_SALES };
