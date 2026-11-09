'use strict';

/* أدوات مشتركة لاختبارات الخادم: تشغيل نسخة حقيقية من الموقع على منفذ عشوائي وإرسال طلبات HTTP خام. */

const http = require('node:http');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { loadConfig } = require('../server/config');
const { createApp } = require('../server');
const totp = require('../server/totp');

const scrypt = promisify(crypto.scrypt);

// بيانات اختبار فقط: تُولَّد عشوائياً داخل الاختبار ولا تُكتب في أي ملف
const TEST_PASSWORD = 'T-' + crypto.randomBytes(12).toString('base64url');
const TEST_TOTP = totp.generateSecret();
const FAKE_OPENAI_KEY = 'sk-test-' + crypto.randomBytes(8).toString('hex');

async function adminEntry(user, password, secret) {
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = (await scrypt(password, salt, 32)).toString('hex');
    return `${user}:${salt}:${hash}${secret ? ':' + secret : ''}`;
}

async function startServer(env = {}, tweak) {
    const config = loadConfig({ HOST: '127.0.0.1', ...env });
    if (tweak) tweak(config);
    const app = createApp(config);
    await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
    app.base = { port: app.server.address().port };
    app.close = () => new Promise(resolve => { app.server.closeAllConnections(); app.server.close(resolve); });
    return app;
}

// طلب HTTP خام: نحتاجه لإرسال ترويسات مثل Origin و Host كما نريد
function request(app, method, pathName, { headers = {}, body } = {}) {
    return new Promise((resolve, reject) => {
        const payload = body === undefined ? undefined : (typeof body === 'string' ? body : JSON.stringify(body));
        const req = http.request({
            host: '127.0.0.1', port: app.base.port, method, path: pathName,
            headers: { ...(payload !== undefined ? { 'Content-Length': Buffer.byteLength(payload) } : {}), ...headers }
        }, res => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => {
                const text = Buffer.concat(chunks).toString('utf8');
                let json = null;
                try { json = JSON.parse(text); } catch { /* ليس JSON */ }
                resolve({ status: res.statusCode, headers: res.headers, text, json });
            });
        });
        req.on('error', reject);
        if (payload !== undefined) req.write(payload);
        req.end();
    });
}

const JSON_HEADERS = { 'Content-Type': 'application/json' };
const sameOrigin = app => ({ ...JSON_HEADERS, Origin: `http://127.0.0.1:${app.base.port}` });

function cookieFrom(response) {
    const setCookie = [].concat(response.headers['set-cookie'] || [])[0] || '';
    return setCookie.split(';')[0];
}

async function login(app, { username = 'musab', password = TEST_PASSWORD, code, headers } = {}) {
    return request(app, 'POST', '/api/admin/login', {
        headers: { ...sameOrigin(app), ...headers },
        body: { username, password, code }
    });
}

async function withServer(env, fn, tweak) {
    const app = await startServer(env, tweak);
    try { await fn(app); } finally { await app.close(); }
}

module.exports = {
    TEST_PASSWORD, TEST_TOTP, FAKE_OPENAI_KEY, adminEntry, startServer, request,
    JSON_HEADERS, sameOrigin, cookieFrom, login, withServer, totp
};
