'use strict';

/*
  خادم يقلّد واجهة REST الخاصة بـ Upstash Redis (الأوامر التي نستخدمها فقط) لاختبار التخزين بدون حساب حقيقي.
  يدعم: POST / بأمر واحد، POST /pipeline بعدة أوامر، توثيق Bearer، ومحاكاة الانقطاع (stop/start بنفس المنفذ والبيانات).
  الوثائق: https://upstash.com/docs/redis/features/restapi
*/

const http = require('node:http');

function createFakeUpstash({ token }) {
    const hashes = new Map();
    const sets = new Map();
    const authHeaders = [];
    const commands = [];
    let objectHashes = false;     // HGETALL يرجع كائناً بدل مصفوفة مسطحة
    let server = null;
    let port = 0;

    function exec(args) {
        const [name, key, ...rest] = args;
        commands.push([String(name).toUpperCase(), key, ...rest]);
        switch (String(name).toUpperCase()) {
            case 'PING': return 'PONG';
            case 'HSETNX': {
                const hash = hashes.get(key) || new Map();
                hashes.set(key, hash);
                if (hash.has(rest[0])) return 0;
                hash.set(rest[0], rest[1]);
                return 1;
            }
            case 'HGETALL': {
                const hash = hashes.get(key) || new Map();
                return objectHashes ? Object.fromEntries(hash) : [...hash].flat();
            }
            case 'SADD': {
                const set = sets.get(key) || new Set();
                sets.set(key, set);
                let added = 0;
                for (const member of rest) if (!set.has(member)) { set.add(member); added += 1; }
                return added;
            }
            case 'SMEMBERS': return [...(sets.get(key) || [])];
            default: throw new Error('ERR unknown command ' + name);
        }
    }

    function handler(req, res) {
        const chunks = [];
        req.on('data', c => chunks.push(c));
        req.on('end', () => {
            const send = (status, body) => {
                const text = JSON.stringify(body);
                res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(text) });
                res.end(text);
            };
            authHeaders.push(req.headers.authorization || '');
            if (req.method !== 'POST') return send(405, { error: 'method not allowed' });
            if (req.headers.authorization !== 'Bearer ' + token) return send(401, { error: 'WRONGPASS invalid or missing token' });
            let body;
            try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { return send(400, { error: 'ERR invalid JSON' }); }
            if (req.url === '/pipeline') {
                if (!Array.isArray(body) || !body.every(Array.isArray)) return send(400, { error: 'ERR invalid pipeline' });
                return send(200, body.map(cmd => { try { return { result: exec(cmd) }; } catch (e) { return { error: e.message }; } }));
            }
            if (req.url === '/' && Array.isArray(body)) {
                try { return send(200, { result: exec(body) }); } catch (e) { return send(400, { error: e.message }); }
            }
            return send(400, { error: 'ERR bad request' });
        });
    }

    return {
        url: () => `http://127.0.0.1:${port}`,
        async start() {
            server = http.createServer(handler);
            await new Promise(resolve => server.listen(port, '127.0.0.1', resolve));
            port = server.address().port;
        },
        async stop() {
            if (!server) return;
            const closing = server;
            server = null;
            await new Promise(resolve => { closing.closeAllConnections(); closing.close(resolve); });
        },
        hashes, sets, authHeaders, commands,
        setObjectHashes(value) { objectHashes = value; }
    };
}

module.exports = { createFakeUpstash };
