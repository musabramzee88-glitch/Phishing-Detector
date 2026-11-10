'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createChatHandler, pickGeminiModel, extractGeminiText } = require('../server/chat');
const { loadConfig } = require('../server/config');

function handler(fetchImpl, env = { GEMINI_API_KEY: 'AQ.test-key' }) {
    const config = loadConfig(env);
    return createChatHandler({ config, users: {}, auth: {}, scan: {}, stats: { count() {}, event() {} }, fetchImpl });
}

test('Gemini: الواجهة الأصلية مع x-goog-api-key (بدون Bearer) وتعليمات النظام', async () => {
    const calls = [];
    const chat = handler(async (url, opts) => {
        calls.push({ url: String(url), opts });
        return { ok: true, status: 200, json: async () => ({ candidates: [{ content: { parts: [{ text: 'تفكير', thought: true }, { text: 'CyberBot جاهز.' }] } }] }) };
    });
    const r = await chat.test();
    assert.equal(r.ok, true);
    assert.equal(r.reply, 'CyberBot جاهز.');
    assert.match(calls[0].url, /\/v1beta\/models\/gemini-2\.5-flash:generateContent$/);
    assert.equal(calls[0].opts.headers['x-goog-api-key'], 'AQ.test-key');
    assert.equal(calls[0].opts.headers.Authorization, undefined);
    const body = JSON.parse(calls[0].opts.body);
    assert.ok(body.systemInstruction.parts[0].text);
    assert.equal(body.contents[0].role, 'user');
    assert.equal(chat.status().lastError, '');
});

test('Gemini: نموذج متقاعد (404) ينتقل تلقائياً لأفضل نموذج متاح', async () => {
    const seen = [];
    const chat = handler(async url => {
        url = String(url); seen.push(url);
        if (url.includes('/models?')) return { ok: true, status: 200, json: async () => ({ models: [
            { name: 'models/gemini-embedding-001', supportedGenerationMethods: ['embedContent'] },
            { name: 'models/gemini-3.6-flash', supportedGenerationMethods: ['generateContent'] },
            { name: 'models/gemini-3.1-pro', supportedGenerationMethods: ['generateContent'] }
        ] }) };
        if (url.includes('gemini-2.5-flash:')) return { ok: false, status: 404, json: async () => ({ error: { message: 'models/gemini-2.5-flash is not found' } }) };
        return { ok: true, status: 200, json: async () => ({ candidates: [{ content: { parts: [{ text: 'تمام' }] } }] }) };
    });
    const r = await chat.test();
    assert.equal(r.ok, true);
    assert.equal(r.model, 'gemini-3.6-flash');
    assert.equal(chat.status().model, 'gemini-3.6-flash');
});

test('Gemini: مفتاح مرفوض يظهر سبباً واضحاً', async () => {
    const chat = handler(async () => ({ ok: false, status: 403, json: async () => ({ error: { message: 'API key not valid' } }) }));
    const r = await chat.test();
    assert.equal(r.ok, false);
    assert.match(r.error, /المفتاح مرفوض/);
    assert.match(chat.status().lastError, /403/);
});

test('اختيار نموذج Gemini واستخراج النص', () => {
    assert.equal(pickGeminiModel(['gemini-9-flash', 'gemini-2.5-flash'], ''), 'gemini-2.5-flash');
    assert.equal(pickGeminiModel(['gemini-4.2-flash', 'gemini-4.0-flash-lite'], 'x'), 'gemini-4.2-flash');
    assert.equal(pickGeminiModel(['gemini-2.5-flash'], 'gemini-2.5-flash'), '');
    assert.equal(extractGeminiText({}), '');
    assert.equal(loadConfig({ AI_API_KEY: 'k', AI_MODEL: 'm', AI_BASE_URL: 'https://generativelanguage.googleapis.com/v1beta/openai' }).openai.style, 'gemini');
    assert.equal(loadConfig({ GEMINI_API_KEY: 'g', GEMINI_MODEL: 'gemini-3.6-flash' }).openai.model, 'gemini-3.6-flash');
});
