"use strict";

/*
  سجل المبيعات والإلغاءات في ملف JSON واحد (الكتابة ذرّية: ملف مؤقت ثم إعادة تسمية، فلا يتلف الملف لو انقطع التيار).

  تنبيه مهم: على Render المجانية القرص مؤقت ويُمسح عند كل نشر. استخدم Persistent Disk وضع DATA_DIR على مساره،
  واستخدم "تصدير نسخة احتياطية" من لوحة الأدمن بانتظام. مفاتيح الزبائن نفسها تبقى صالحة حتى لو ضاع السجل
  (لأنها موقَّعة ولا تعتمد عليه)، لكن سجل المبيعات والإلغاءات هو الذي يضيع.
*/

const fs = require("node:fs");
const path = require("node:path");

const MAX_SALES = 20_000;

function validShape(data) {
    return Boolean(data) && data.version === 1 && Array.isArray(data.sales) && Array.isArray(data.revoked);
}

function createStore(dir) {
    const file = dir ? path.join(dir, "billing.json") : "";
    let data = { version: 1, sales: [], revoked: [] };
    let revokedSet = new Set();
    const state = { persistent: false, error: "", file };

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
        sales: () => data.sales,
        isRevoked: id => revokedSet.has(id),
        revokedIds: () => [...revokedSet],
        addSale(sale) {
            if (data.sales.length >= MAX_SALES) throw new Error("sales limit reached");
            data.sales.push(sale);
            save();
        },
        revoke(id) {
            if (revokedSet.has(id)) return;
            revokedSet.add(id);
            data.revoked.push(id);
            save();
        }
    };
}

module.exports = { createStore, MAX_SALES };
