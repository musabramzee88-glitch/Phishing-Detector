"use strict";

/*
  تسجيل الدخول عبر Google و Microsoft و Apple (OpenID Connect، Authorization Code + PKCE).

  كل مزوّد يُفعَّل فقط إذا ضُبطت متغيراته (انظر server/config.js). بدونها لا يظهر زره.

  الحماية:
  - state عشوائي يُخزَّن بالقاعدة 10 دقائق ولمرة واحدة، ومربوط بالمتصفح عبر كوكي (يمنع Login CSRF).
  - PKCE (S256) و nonce داخل id_token.
  - id_token يصلنا مباشرة من نقطة token الخاصة بالمزوّد عبر TLS ومع سرّنا، فنتحقق من مطالباته
    (iss, aud, exp, nonce) حسب OpenID Connect Core 3.1.3.7.
  - Apple ترجع للموقع بطلب POST من نطاقها (form_post)، لذلك كوكي الربط SameSite=None; Secure.
*/

const crypto = require("node:crypto");

const sha256b64 = value => crypto.createHash("sha256").update(value).digest("base64url");
const sha256hex = value => crypto.createHash("sha256").update(value).digest("hex");
const rand = (n = 32) => crypto.randomBytes(n).toString("base64url");

function decodeJwtPayload(jwt) {
    const parts = String(jwt || "").split(".");
    if (parts.length !== 3) throw new Error("bad id_token");
    return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

// سر Apple: JWT موقَّع بمفتاح .p8 (ES256)، صالح لمدة قصيرة
function appleClientSecret({ teamId, keyId, clientId, privateKey }, now = Date.now()) {
    const header = Buffer.from(JSON.stringify({ alg: "ES256", kid: keyId })).toString("base64url");
    const iat = Math.floor(now / 1000);
    const payload = Buffer.from(JSON.stringify({ iss: teamId, iat, exp: iat + 300, aud: "https://appleid.apple.com", sub: clientId })).toString("base64url");
    const signature = crypto.sign("sha256", Buffer.from(header + "." + payload), { key: privateKey, dsaEncoding: "ieee-p1363" });
    return `${header}.${payload}.${signature.toString("base64url")}`;
}

const PROVIDERS = {
    google: {
        label: "Google",
        authorize: "https://accounts.google.com/o/oauth2/v2/auth",
        token: "https://oauth2.googleapis.com/token",
        scope: "openid email profile",
        issuers: ["https://accounts.google.com", "accounts.google.com"],
        extraAuth: { prompt: "select_account" },
        claims(c) {
            return { sub: c.sub, email: c.email, emailVerified: c.email_verified === true || c.email_verified === "true", name: c.name };
        }
    },
    microsoft: {
        label: "Microsoft",
        authorize: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        token: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        scope: "openid email profile",
        // المُصدر يحتوي معرّف المنظمة (tid)، فنتحقق من شكله
        issuerOk: (iss, c) => typeof iss === "string" && typeof c.tid === "string" && iss === `https://login.microsoftonline.com/${c.tid}/v2.0`,
        extraAuth: { prompt: "select_account" },
        claims(c) {
            // Microsoft لا تضمن توثيق البريد لكل الحسابات، لذلك لا نربطه بحساب موجود (emailVerified=false)
            return { sub: `${c.tid}:${c.oid || c.sub}`, email: c.email || c.preferred_username, emailVerified: false, name: c.name };
        }
    },
    apple: {
        label: "Apple",
        authorize: "https://appleid.apple.com/auth/authorize",
        token: "https://appleid.apple.com/auth/token",
        scope: "name email",
        issuers: ["https://appleid.apple.com"],
        extraAuth: { response_mode: "form_post" },
        pkce: false,      // Apple لا توثّق دعم PKCE، فنكتفي بـ state و nonce وسرّ العميل
        claims(c, extra) {
            let name = "";
            try {
                const u = extra && extra.user ? JSON.parse(extra.user) : null;
                if (u && u.name) name = [u.name.firstName, u.name.lastName].filter(Boolean).join(" ");
            } catch { /* اسم اختياري */ }
            return { sub: c.sub, email: c.email, emailVerified: c.email_verified === true || c.email_verified === "true", name };
        }
    }
};

function createOAuth({ config, db, fetchImpl = fetch }) {
    const settings = config.oauth;
    const enabled = Object.keys(PROVIDERS).filter(id => settings[id]);
    const redirectUri = id => `${config.appUrl}/auth/${id}/callback`;

    // يبدأ الدخول: يرجع { url, bindCookieValue }
    async function start(id) {
        const provider = PROVIDERS[id];
        const s = settings[id];
        if (!provider || !s) return null;
        const state = rand(24);
        const verifier = rand(48);
        const nonce = rand(16);
        const bind = rand(24);
        await db.cmd(["SET", db.key("oauth_state", sha256hex(state)), JSON.stringify({ id, verifier, nonce, bind: sha256hex(bind) }), "EX", "600"]);
        const params = new URLSearchParams({
            client_id: s.clientId,
            redirect_uri: redirectUri(id),
            response_type: "code",
            scope: provider.scope,
            state,
            nonce,
            ...(provider.pkce === false ? {} : { code_challenge: sha256b64(verifier), code_challenge_method: "S256" }),
            ...provider.extraAuth
        });
        return { url: `${provider.authorize}?${params}`, bind };
    }

    // يكمل الدخول بعد رجوع المستخدم. يرجع بيانات الهوية أو يرمي خطأ
    async function finish(id, { code, state, bind, extra }) {
        const provider = PROVIDERS[id];
        const s = settings[id];
        if (!provider || !s) throw new Error("provider disabled");
        if (typeof code !== "string" || typeof state !== "string" || code.length > 2048 || state.length > 200) throw new Error("missing code");

        // state لمرة واحدة: نقرأه ونحذفه فوراً
        const key = db.key("oauth_state", sha256hex(state));
        const [stored] = await db.pipe([["GET", key], ["DEL", key]]);
        if (!stored) throw new Error("unknown state");
        const saved = JSON.parse(stored);
        if (saved.id !== id) throw new Error("provider mismatch");
        if (!bind || sha256hex(bind) !== saved.bind) throw new Error("browser mismatch");

        const form = {
            grant_type: "authorization_code",
            code,
            redirect_uri: redirectUri(id),
            client_id: s.clientId,
            ...(provider.pkce === false ? {} : { code_verifier: saved.verifier }),
            client_secret: id === "apple" ? appleClientSecret({ ...s }) : s.clientSecret
        };
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), 10_000);
        let data;
        try {
            const response = await fetchImpl(provider.token, {
                method: "POST",
                headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
                body: new URLSearchParams(form).toString(),
                signal: controller.signal
            });
            data = await response.json().catch(() => ({}));
            if (!response.ok || !data.id_token) throw new Error("token exchange failed (" + response.status + ")");
        } finally {
            clearTimeout(timer);
        }

        const c = decodeJwtPayload(data.id_token);
        const now = Math.floor(Date.now() / 1000);
        const issuerOk = provider.issuerOk ? provider.issuerOk(c.iss, c) : provider.issuers.includes(c.iss);
        const audOk = Array.isArray(c.aud) ? c.aud.includes(s.clientId) : c.aud === s.clientId;
        if (!issuerOk) throw new Error("bad issuer");
        if (!audOk) throw new Error("bad audience");
        if (typeof c.exp !== "number" || c.exp < now - 60) throw new Error("expired id_token");
        if (c.nonce !== saved.nonce) throw new Error("bad nonce");
        const identity = provider.claims(c, extra);
        if (!identity.sub) throw new Error("no subject");
        return { provider: id, ...identity };
    }

    return {
        enabled,
        providers: enabled.map(id => ({ id, label: PROVIDERS[id].label })),
        start,
        finish
    };
}

module.exports = { createOAuth, appleClientSecret, decodeJwtPayload, PROVIDERS };
