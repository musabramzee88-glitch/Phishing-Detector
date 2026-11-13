"use strict";

/*
  بصمات الصور (Perceptual hashing) تنحسب داخل المتصفح نفسه بـ canvas، فما نحتاج أي مكتبة صور.

  - pHash: نصغّر الصورة لـ 32×32 رمادي، نطبق DCT ونأخذ أقل 8×8 ترددات، وكل بت = هل القيمة أكبر من الوسيط.
    يتحمل تغيير الحجم والضغط والألوان البسيطة، فصفحتين متطابقتين شكلاً تطلع بصمتهم قريبة جداً.
  - dHash: نصغّر لـ 9×8 ونقارن كل بكسل بجاره. بصمة ثانية مستقلة تقلل التطابق الكاذب.
  - color: متوسط اللون (للتمييز بين صفحات بيضاء متشابهة الشكل وألوانها مختلفة).
  النتيجة: hex من 16 خانة (64 بت) لكل بصمة.

  الدالة تنرسل كما هي لـ page.evaluate، فلازم تكون مستقلة تماماً (بدون أي متغير من خارجها).
*/
async function computeHashes(dataUrl) {
    const img = new Image();
    img.src = dataUrl;
    await img.decode();
    const pixels = (w, h) => {
        const c = document.createElement("canvas");
        c.width = w; c.height = h;
        const x = c.getContext("2d");
        x.fillStyle = "#fff";
        x.fillRect(0, 0, w, h);
        x.drawImage(img, 0, 0, w, h);
        return x.getImageData(0, 0, w, h).data;
    };
    const grayOf = (d, n) => {
        const g = new Float64Array(n);
        for (let i = 0; i < n; i++) g[i] = 0.299 * d[i * 4] + 0.587 * d[i * 4 + 1] + 0.114 * d[i * 4 + 2];
        return g;
    };
    const toHex = bits => {
        let out = "";
        for (let i = 0; i < 64; i += 4) out += ((bits[i] << 3) | (bits[i + 1] << 2) | (bits[i + 2] << 1) | bits[i + 3]).toString(16);
        return out;
    };

    // dHash
    const dg = grayOf(pixels(9, 8), 72);
    const dbits = [];
    for (let y = 0; y < 8; y++) for (let x = 0; x < 8; x++) dbits.push(dg[y * 9 + x] < dg[y * 9 + x + 1] ? 1 : 0);

    // pHash (DCT)
    const N = 32;
    const raw = pixels(N, N);
    const g = grayOf(raw, N * N);
    const cos = [];
    for (let u = 0; u < 8; u++) {
        cos.push(new Float64Array(N));
        for (let x = 0; x < N; x++) cos[u][x] = Math.cos(((2 * x + 1) * u * Math.PI) / (2 * N));
    }
    const coeffs = [];
    for (let v = 0; v < 8; v++) {
        for (let u = 0; u < 8; u++) {
            let sum = 0;
            for (let y = 0; y < N; y++) {
                const cy = cos[v][y];
                for (let x = 0; x < N; x++) sum += g[y * N + x] * cos[u][x] * cy;
            }
            coeffs.push(sum);
        }
    }
    const ac = coeffs.slice(1);
    const median = [...ac].sort((a, b) => a - b)[Math.floor(ac.length / 2)];
    const pbits = coeffs.map((c, i) => (i === 0 ? 0 : c > median ? 1 : 0));

    let r = 0, gr = 0, b = 0;
    for (let i = 0; i < N * N; i++) { r += raw[i * 4]; gr += raw[i * 4 + 1]; b += raw[i * 4 + 2]; }
    const n = N * N;
    return { phash: toHex(pbits), dhash: toHex(dbits), color: [Math.round(r / n), Math.round(gr / n), Math.round(b / n)] };
}

module.exports = { computeHashes };
