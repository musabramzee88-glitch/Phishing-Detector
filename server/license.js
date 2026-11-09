"use strict";

/*
  مفاتيح الترخيص الموقَّعة. شكل المفتاح:   PD1-P-3F9A2C71-20261209-K7QX2M9ABCDEFGH2
                                             |   |    |        |          |
                                          إصدار نوع  رقم     آخر يوم     توقيع HMAC-SHA256
                                                  الباقة الترخيص صلاحية    (80 بت)

  - بدون قاعدة بيانات: المفتاح يحمل نوع الباقة وتاريخ الانتهاء ويُتحقَّق من توقيعه بسر الخادم (LICENSE_SECRET).
    فلو ضاع سجل المبيعات، مفاتيح الزبائن تبقى تعمل حتى انتهائها.
  - لا يمكن تزوير مفتاح أو تغيير باقته/تاريخه بدون السر.
  - الإلغاء (Revocation) يحتاج السجل: تمرره دالة isRevoked.
  - التجديد = إصدار مفتاح جديد بتاريخ جديد (ترسله للزبون بنفس طريقة الدفع اليدوي).
*/

const crypto = require("node:crypto");
const { base32Encode } = require("./totp");

const TIER_CODES = { pro: "P", enterprise: "E" };
const CODE_TIERS = { P: "pro", E: "enterprise" };
const MIN_SECRET_LENGTH = 32;
const KEY_PATTERN = /^PD1-([PE])-([0-9A-F]{8})-(\d{8})-([A-Z2-7]{16})$/;

function pad2(n) {
    return String(n).padStart(2, "0");
}

function dateToStamp(ms) {
    const d = new Date(ms);
    return `${d.getUTCFullYear()}${pad2(d.getUTCMonth() + 1)}${pad2(d.getUTCDate())}`;
}

// نهاية اليوم (UTC) المذكور بالمفتاح، أو null إذا لم يكن تاريخاً حقيقياً
function stampToExpiry(stamp) {
    const year = Number(stamp.slice(0, 4)), month = Number(stamp.slice(4, 6)), day = Number(stamp.slice(6, 8));
    const date = new Date(Date.UTC(year, month - 1, day, 23, 59, 59, 999));
    if (date.getUTCFullYear() !== year || date.getUTCMonth() !== month - 1 || date.getUTCDate() !== day) return null;
    return date.getTime();
}

function createLicenseManager(secret, { now = Date.now } = {}) {
    const enabled = typeof secret === "string" && secret.length >= MIN_SECRET_LENGTH;

    function sign(tierCode, id, stamp) {
        const digest = crypto.createHmac("sha256", secret).update(`PD1|${tierCode}|${id}|${stamp}`).digest();
        return base32Encode(digest.subarray(0, 10));      // 10 بايت = 16 حرفاً بدون حشو
    }

    function keyFor({ tier, id, expiresAt }) {
        if (!enabled) throw new Error("licensing disabled");
        const code = TIER_CODES[tier];
        if (!code) throw new Error("invalid tier");
        const stamp = dateToStamp(expiresAt);
        return `PD1-${code}-${id}-${stamp}-${sign(code, id, stamp)}`;
    }

    // يصدر ترخيصاً جديداً صالحاً حتى نهاية يوم expiresAt
    function issue({ tier, expiresAt }) {
        if (!enabled) throw new Error("licensing disabled");
        if (!TIER_CODES[tier]) throw new Error("invalid tier");
        if (!Number.isFinite(expiresAt) || expiresAt <= now()) throw new Error("expiry must be in the future");
        const id = crypto.randomBytes(4).toString("hex").toUpperCase();
        const stamp = dateToStamp(expiresAt);
        return { id, tier, expiresAt: stampToExpiry(stamp), key: keyFor({ tier, id, expiresAt }) };
    }

    // يتحقق من مفتاح. يرجع { ok:true, id, tier, expiresAt } أو { ok:false, reason }
    function verify(rawKey) {
        if (!enabled) return { ok: false, reason: "disabled" };
        const key = String(rawKey || "").toUpperCase().replace(/\s+/g, "");
        const match = KEY_PATTERN.exec(key);
        if (!match) return { ok: false, reason: "format" };
        const [, code, id, stamp, mac] = match;
        const expiresAt = stampToExpiry(stamp);
        if (expiresAt === null) return { ok: false, reason: "format" };
        const expected = Buffer.from(sign(code, id, stamp));
        const given = Buffer.from(mac);
        if (expected.length !== given.length || !crypto.timingSafeEqual(expected, given)) return { ok: false, reason: "signature" };
        if (expiresAt < now()) return { ok: false, reason: "expired", id, tier: CODE_TIERS[code], expiresAt };
        return { ok: true, id, tier: CODE_TIERS[code], expiresAt };
    }

    return { enabled, issue, verify, keyFor };
}

module.exports = { createLicenseManager, dateToStamp, stampToExpiry, MIN_SECRET_LENGTH };
