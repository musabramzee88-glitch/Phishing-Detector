/*
  Service Worker بسيط وآمن:
  - الملفات برقم نسخة (?v=بصمة) تُخدم من الذاكرة (لا تتغير أبداً، فالبصمة تتغير مع أي تعديل).
  - الصفحات: من الشبكة دائماً، وإذا ماكو إنترنت نعرض صفحة «بدون اتصال».
  - لا نخزّن أبداً: /api/ و /admin و /auth/ وأي صفحة شخصية (تبقى من الشبكة فقط).
*/
const CACHE = 'pd-static-v1';
const OFFLINE_URL = '/offline.html';

self.addEventListener('install', event => {
    event.waitUntil(caches.open(CACHE).then(c => c.addAll([OFFLINE_URL, '/img/icon-192.png'])).then(() => self.skipWaiting()));
});

self.addEventListener('activate', event => {
    event.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener('fetch', event => {
    const req = event.request;
    if (req.method !== 'GET') return;
    const url = new URL(req.url);
    if (url.origin !== self.location.origin) return;
    if (/^\/(api|admin|auth)\b/.test(url.pathname)) return;

    if (req.mode === 'navigate') {
        event.respondWith(fetch(req).catch(() => caches.match(OFFLINE_URL)));
        return;
    }
    // ملفات ثابتة ببصمة: ذاكرة أولاً
    if (/[?&]v=[\w.-]+/.test(url.search) && /^\/(css|js|img|vendor)\//.test(url.pathname)) {
        event.respondWith(caches.open(CACHE).then(async cache => {
            const hit = await cache.match(req);
            if (hit) return hit;
            const res = await fetch(req);
            if (res.ok && res.type === 'basic') cache.put(req, res.clone());
            return res;
        }));
    }
});
