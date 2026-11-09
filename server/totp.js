"use strict";

/* رمز التحقق الثنائي (TOTP) حسب RFC 6238. يتوافق مع Google Authenticator و Microsoft Authenticator وغيرها. */

const crypto = require("node:crypto");

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buffer) {
    let bits = 0, value = 0, out = "";
    for (const byte of buffer) {
        value = (value << 8) | byte;
        bits += 8;
        while (bits >= 5) {
            out += BASE32[(value >>> (bits - 5)) & 31];
            bits -= 5;
        }
    }
    if (bits > 0) out += BASE32[(value << (5 - bits)) & 31];
    return out;
}

function base32Decode(text) {
    const clean = String(text || "").toUpperCase().replace(/[\s=-]/g, "");
    let bits = 0, value = 0;
    const bytes = [];
    for (const ch of clean) {
        const index = BASE32.indexOf(ch);
        if (index < 0) throw new Error("invalid base32");
        value = (value << 5) | index;
        bits += 5;
        if (bits >= 8) {
            bytes.push((value >>> (bits - 8)) & 255);
            bits -= 8;
        }
    }
    return Buffer.from(bytes);
}

function generateSecret() {
    return base32Encode(crypto.randomBytes(20));
}

function hotp(secretBuffer, counter, digits = 6) {
    const message = Buffer.alloc(8);
    message.writeBigUInt64BE(BigInt(counter));
    const hmac = crypto.createHmac("sha1", secretBuffer).update(message).digest();
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary = ((hmac[offset] & 0x7f) << 24) | (hmac[offset + 1] << 16) | (hmac[offset + 2] << 8) | hmac[offset + 3];
    return String(binary % 10 ** digits).padStart(digits, "0");
}

function totp(secret, time = Date.now(), { step = 30, digits = 6 } = {}) {
    return hotp(base32Decode(secret), Math.floor(time / 1000 / step), digits);
}

// يتحقق من الرمز مع سماح بفارق نافذة واحدة (±30 ثانية) لاختلاف ساعات الأجهزة.
// يرجع رقم العدّاد المطابق (لمنع إعادة استخدام نفس الرمز)، أو -1 إذا كان الرمز خاطئاً.
function verify(secret, code, { time = Date.now(), window = 1, step = 30, digits = 6, lastCounter = -1 } = {}) {
    const submitted = String(code || "").replace(/\s/g, "");
    if (!new RegExp(`^\\d{${digits}}$`).test(submitted)) return -1;
    let key;
    try {
        key = base32Decode(secret);
    } catch {
        return -1;
    }
    const current = Math.floor(time / 1000 / step);
    for (let offset = -window; offset <= window; offset++) {
        const counter = current + offset;
        if (counter <= lastCounter) continue;
        const expected = hotp(key, counter, digits);
        if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(submitted))) return counter;
    }
    return -1;
}

function otpauthUri(secret, account, issuer = "Phishing Detector") {
    const label = encodeURIComponent(issuer) + ":" + encodeURIComponent(account);
    return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

module.exports = { generateSecret, base32Encode, base32Decode, hotp, totp, verify, otpauthUri };
