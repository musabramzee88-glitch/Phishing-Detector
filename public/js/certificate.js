/* رمز QR بالشهادة يوجّه لصفحة التحقق، وزر الطباعة (حفظ PDF من المتصفح) */
(function () {
    'use strict';
    const cert = document.getElementById('cert');
    const box = document.getElementById('certQr');
    if (cert && box && typeof window.qrcode === 'function') {
        const qr = window.qrcode(0, 'M');
        qr.addData(cert.dataset.verify);
        qr.make();
        const img = document.createElement('img');
        img.src = qr.createDataURL(4, 2);
        img.alt = 'رمز QR للتحقق من الشهادة';
        img.width = img.height = 132;
        box.append(img);
    }
    const btn = document.getElementById('printCert');
    if (btn) btn.addEventListener('click', () => window.print());
})();
