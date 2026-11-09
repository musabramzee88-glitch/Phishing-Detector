"use strict";

/*
  عميل بسيط لـ Upstash Redis عبر واجهة REST (بدون أي مكتبة). الوثائق: https://upstash.com/docs/redis/features/restapi
    - أمر واحد:  POST إلى عنوان القاعدة بجسم JSON مصفوفة، مثل ["HSET","key","field","value"]
    - عدة أوامر: POST إلى /pipeline بمصفوفة مصفوفات (غير ذرّية)
    - الرد: {"result": ...} أو {"error": "..."}  والتوثيق بترويسة Authorization: Bearer <token>
  رسائل الأخطاء هنا لا تحتوي أبداً على العنوان ولا الرمز (Token).
*/

const DEFAULT_TIMEOUT_MS = 8000;

class UpstashError extends Error {
    constructor(kind, status = 0, detail = "") {
        super(kind);
        this.name = "UpstashError";
        this.kind = kind;          // network | timeout | unauthorized | http | command | bad_response
        this.status = status;
        this.detail = String(detail || "").slice(0, 200);
    }
}

function createUpstashClient({ url, token, timeoutMs = DEFAULT_TIMEOUT_MS, fetchImpl = fetch }) {
    const base = String(url).replace(/\/+$/, "");

    async function post(path, body) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), timeoutMs);
        let response;
        try {
            response = await fetchImpl(base + path, {
                method: "POST",
                headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" },
                body: JSON.stringify(body),
                signal: controller.signal
            });
        } catch (error) {
            throw new UpstashError(error && error.name === "AbortError" ? "timeout" : "network");
        } finally {
            clearTimeout(timer);
        }
        let data;
        try {
            data = await response.json();
        } catch {
            throw new UpstashError("bad_response", response.status);
        }
        if (response.status === 401) throw new UpstashError("unauthorized", 401);
        // 400 مع حقل error = القاعدة رفضت الأمر نفسه (خطأ صياغة أو أمر غير مدعوم) حسب وثائق Upstash
        if (!response.ok) throw new UpstashError(response.status === 400 && data && data.error ? "command" : "http", response.status, data && data.error);
        return data;
    }

    // أمر واحد. يرجع قيمة result أو يرمي UpstashError
    async function command(args) {
        const data = await post("", args.map(String));
        if (!data || typeof data !== "object") throw new UpstashError("bad_response");
        if (data.error) throw new UpstashError("command", 400, data.error);
        return data.result;
    }

    // عدة أوامر بطلب واحد. يرجع مصفوفة نتائج بنفس الترتيب، ويرمي إذا فشل أي أمر
    async function pipeline(commands) {
        const data = await post("/pipeline", commands.map(c => c.map(String)));
        if (!Array.isArray(data) || data.length !== commands.length) throw new UpstashError("bad_response");
        return data.map(item => {
            if (!item || typeof item !== "object") throw new UpstashError("bad_response");
            if (item.error) throw new UpstashError("command", 400, item.error);
            return item.result;
        });
    }

    return { command, pipeline };
}

// وصف قصير وآمن للخطأ (للعرض بلوحة الأدمن)
function describeError(error) {
    if (!(error instanceof UpstashError)) return "خطأ غير معروف";
    const labels = {
        network: "تعذر الوصول للخادم", timeout: "انتهت مهلة الاتصال", unauthorized: "الرمز (Token) غير صحيح",
        http: "رد غير متوقع (" + error.status + ")", command: "رفضت القاعدة الأمر", bad_response: "رد غير مفهوم"
    };
    return labels[error.kind] || "خطأ";
}

module.exports = { createUpstashClient, UpstashError, describeError };
