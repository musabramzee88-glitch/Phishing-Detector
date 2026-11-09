"use strict";

/*
  طبقة التخزين العامة (حسابات المستخدمين، الجلسات، طلبات الدفع، الاستهلاك اليومي).

  نوعان بنفس الواجهة  db.cmd([...])  و  db.pipe([[...], [...]]):
    upstash  قاعدة Upstash Redis عبر REST (الموصى به على Render لأن قرصها يُمسح عند كل نشر)
    memory   تقليد بسيط لأوامر Redis بالذاكرة (للتشغيل المحلي والاختبارات فقط: يضيع عند إعادة التشغيل)

  نستخدم مجموعة صغيرة من الأوامر فقط، ومنفّذة كلها بنسخة الذاكرة:
    GET SET(EX/NX) DEL EXISTS INCR EXPIRE TTL HSET HGET HGETALL HINCRBY HDEL
    SADD SREM SMEMBERS ZADD ZREM ZCARD ZRANGE ZREVRANGE ZREMRANGEBYRANK
*/

const { createUpstashClient, describeError } = require("./upstash");

function createMemoryDb() {
    const data = new Map();      // key -> { type, value, expiresAt }

    function entry(key) {
        const item = data.get(key);
        if (!item) return null;
        if (item.expiresAt && item.expiresAt <= Date.now()) {
            data.delete(key);
            return null;
        }
        return item;
    }
    function ensure(key, type, make) {
        let item = entry(key);
        if (!item) {
            item = { type, value: make(), expiresAt: 0 };
            data.set(key, item);
        }
        if (item.type !== type) throw new Error("WRONGTYPE");
        return item;
    }
    const str = v => (v === undefined || v === null ? null : String(v));

    function run(args) {
        const [rawName, ...rest] = args.map(String);
        const name = rawName.toUpperCase();
        const [key] = rest;
        switch (name) {
            case "PING": return "PONG";
            case "GET": {
                const item = entry(key);
                if (item && item.type !== "string") throw new Error("WRONGTYPE");
                return item ? item.value : null;
            }
            case "SET": {
                const value = rest[1];
                let ex = 0, nx = false;
                for (let i = 2; i < rest.length; i++) {
                    const opt = rest[i].toUpperCase();
                    if (opt === "EX") ex = Number(rest[++i]);
                    else if (opt === "PX") ex = Number(rest[++i]) / 1000;
                    else if (opt === "NX") nx = true;
                }
                if (nx && entry(key)) return null;
                data.set(key, { type: "string", value: String(value), expiresAt: ex > 0 ? Date.now() + ex * 1000 : 0 });
                return "OK";
            }
            case "DEL": {
                let n = 0;
                for (const k of rest) if (entry(k)) { data.delete(k); n++; }
                return n;
            }
            case "EXISTS": return rest.filter(k => entry(k)).length;
            case "INCR": case "INCRBY": {
                const item = entry(key);
                const by = name === "INCRBY" ? Number(rest[1]) : 1;
                const next = (item ? Number(item.value) : 0) + by;
                data.set(key, { type: "string", value: String(next), expiresAt: item ? item.expiresAt : 0 });
                return next;
            }
            case "EXPIRE": {
                const item = entry(key);
                if (!item) return 0;
                item.expiresAt = Date.now() + Number(rest[1]) * 1000;
                return 1;
            }
            case "TTL": {
                const item = entry(key);
                if (!item) return -2;
                return item.expiresAt ? Math.ceil((item.expiresAt - Date.now()) / 1000) : -1;
            }
            case "HSET": {
                const item = ensure(key, "hash", () => new Map());
                let added = 0;
                for (let i = 1; i + 1 < rest.length; i += 2) {
                    if (!item.value.has(rest[i])) added++;
                    item.value.set(rest[i], rest[i + 1]);
                }
                return added;
            }
            case "HGET": {
                const item = entry(key);
                return item ? str(item.value.get(rest[1])) : null;
            }
            case "HGETALL": {
                const item = entry(key);
                if (!item) return [];
                const out = [];
                for (const [f, v] of item.value) out.push(f, v);
                return out;
            }
            case "HINCRBY": {
                const item = ensure(key, "hash", () => new Map());
                const next = Number(item.value.get(rest[1]) || 0) + Number(rest[2]);
                item.value.set(rest[1], String(next));
                return next;
            }
            case "HDEL": {
                const item = entry(key);
                if (!item) return 0;
                let n = 0;
                for (const f of rest.slice(1)) if (item.value.delete(f)) n++;
                return n;
            }
            case "SADD": {
                const item = ensure(key, "set", () => new Set());
                let n = 0;
                for (const m of rest.slice(1)) if (!item.value.has(m)) { item.value.add(m); n++; }
                return n;
            }
            case "SREM": {
                const item = entry(key);
                if (!item) return 0;
                let n = 0;
                for (const m of rest.slice(1)) if (item.value.delete(m)) n++;
                return n;
            }
            case "SMEMBERS": {
                const item = entry(key);
                return item ? [...item.value] : [];
            }
            case "ZADD": {
                const item = ensure(key, "zset", () => new Map());
                let n = 0;
                for (let i = 1; i + 1 < rest.length; i += 2) {
                    if (!item.value.has(rest[i + 1])) n++;
                    item.value.set(rest[i + 1], Number(rest[i]));
                }
                return n;
            }
            case "ZREM": {
                const item = entry(key);
                if (!item) return 0;
                let n = 0;
                for (const m of rest.slice(1)) if (item.value.delete(m)) n++;
                return n;
            }
            case "ZREMRANGEBYRANK": {
                const item = entry(key);
                if (!item) return 0;
                const sorted = [...item.value].sort((a, b) => (a[1] - b[1]) || (a[0] < b[0] ? -1 : 1));
                let start = Number(rest[1]);
                let stop = Number(rest[2]);
                if (start < 0) start = Math.max(0, sorted.length + start);
                if (stop < 0) stop = sorted.length + stop;
                const victims = sorted.slice(start, stop + 1);
                for (const [m] of victims) item.value.delete(m);
                return victims.length;
            }
            case "ZCARD": {
                const item = entry(key);
                return item ? item.value.size : 0;
            }
            case "ZRANGE": case "ZREVRANGE": {
                const item = entry(key);
                if (!item) return [];
                const rev = name === "ZREVRANGE" || rest.slice(3).some(o => o.toUpperCase() === "REV");
                const sorted = [...item.value].sort((a, b) => (a[1] - b[1]) || (a[0] < b[0] ? -1 : 1));
                if (rev) sorted.reverse();
                let start = Number(rest[1]);
                let stop = Number(rest[2]);
                if (start < 0) start = Math.max(0, sorted.length + start);
                if (stop < 0) stop = sorted.length + stop;
                return sorted.slice(start, stop + 1).map(([m]) => m);
            }
            default:
                throw new Error("unsupported command " + name);
        }
    }

    return {
        backend: "memory",
        persistent: false,
        async cmd(args) { return run(args); },
        async pipe(commands) { return commands.map(run); },
        runSync: run,
        _data: data
    };
}

function createUpstashDb({ url, token, prefix, fetchImpl }) {
    const client = createUpstashClient({ url, token, fetchImpl });
    return {
        backend: "upstash",
        persistent: true,
        cmd: args => client.command(args),
        pipe: commands => client.pipeline(commands),
        prefix
    };
}

// يختار القاعدة من الإعدادات. prefix يفصل مفاتيحنا لو شاركت القاعدة مع مشروع آخر.
function openDb(config) {
    const up = config.billing && config.billing.upstash;
    const db = up ? createUpstashDb(up) : createMemoryDb();
    db.prefix = (up && up.prefix) || "pd";
    db.key = (...parts) => [db.prefix, ...parts].join(":");
    db.describeError = describeError;
    return db;
}

// HGETALL قد ترجع مصفوفة مسطحة أو كائناً
function hashToObject(raw) {
    const out = {};
    if (Array.isArray(raw)) {
        for (let i = 0; i + 1 < raw.length; i += 2) out[raw[i]] = raw[i + 1];
    } else if (raw && typeof raw === "object") {
        Object.assign(out, raw);
    }
    return out;
}

module.exports = { openDb, createMemoryDb, createUpstashDb, hashToObject };
