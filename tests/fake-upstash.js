'use strict';

/*
  خادم يقلّد واجهة REST الخاصة بـ Upstash Redis لاختبار القاعدة بدون حساب حقيقي.
  الأوامر نفسها تُنفَّذ بنسخة الذاكرة (server/db.js)، والخادم يضيف: POST / لأمر واحد، POST /pipeline لعدة أوامر،
  توثيق Bearer، ومحاكاة الانقطاع (stop/start بنفس المنفذ والبيانات).
  الوثائق: https://upstash.com/docs/redis/features/restapi
*/

const http = require('node:http');
const { createMemoryDb } = require('../server/db');

function createFakeUpstash({ token }) {
    const memory = createMemoryDb();
    const authHeaders = [];
    const commands = [];
    let objectHashes = false;     // HGETALL يرجع كائناً بدل مصفوفة مسطحة (كلا الشكلين ممكن)
    let server = null;
    let port = 0;

    function exec(args) {
        commands.push(args.map(String));
        const result = memory.runSync(args);
        if (objectHashes && String(args[0]).toUpperCase() === 'HGETALL') {
            const out = {};
            for (let i = 0; i + 1 < result.length; i += 2) out[result[i]] = result[i + 1];
            return out;
        }
        return result;
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
                return send(200, body.map(cmd => { try { return { result: exec(cmd) }; } catch (e) { return { error: 'ERR ' + e.message }; } }));
            }
            if (req.url === '/' && Array.isArray(body)) {
                try { return send(200, { result: exec(body) }); } catch (e) { return send(400, { error: 'ERR ' + e.message }); }
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
        memory, authHeaders, commands,
        setObjectHashes(value) { objectHashes = value; }
    };
}

module.exports = { createFakeUpstash };
