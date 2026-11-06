// عرض اسم الملف عند اختياره
function updateFileName(input) {
    const label = document.getElementById('fileLabelText');
    if (input.files && input.files[0]) {
        label.innerHTML = `الملف المختار: <span style="color: var(--accent-blue);">${input.files[0].name}</span>`;
    }
}

// خوارزمية فحص الملفات المتقدمة وبصمة الثنائيات (Magic Bytes)
function analyzeFile() {
    const fileInput = document.getElementById('fileInput');
    const reportBox = document.getElementById('fileReportBox');
    
    if (fileInput.files.length === 0) {
        alert('يرجى اختيار ملف أولاً لغرض الفحص الأمني.');
        return;
    }

    const file = fileInput.files[0];
    reportBox.style.display = 'block';
    reportBox.innerHTML = '<div style="text-align:center; padding:1rem;"><i class="fa-solid fa-gear fa-spin" style="font-size:2rem; color:var(--accent-blue);"></i><br><br>جاري قراءة التوقيع الرقمي وفحص البصمة الثنائية للملف (Magic Bytes)...</div>';

    const reader = new FileReader();
    
    reader.onload = function(e) {
        const arr = new Uint8Array(e.target.result);
        let header = '';
        for (let i = 0; i < Math.min(arr.length, 4); i++) {
            header += arr[i].toString(16).toUpperCase().padStart(2, '0');
        }

        setTimeout(() => {
            let riskScore = 0;
            let reasons = [];
            let detectedRealType = "مجهول / غير معروف";
            
            if (header.startsWith('4D5A')) {
                detectedRealType = "ملف تنفيذي (PE Executable .exe/.dll)";
                riskScore += 95;
                reasons.push({ text: 'تحذير أمني خطير: الملف المدخل عبارة عن برنامج تنفيذي (EXE) قد يحتوي على حمولة خبيثة (Payload)!', type: 'danger' });
            } else if (header.startsWith('504B')) {
                detectedRealType = "ملف أرشيف مضغوط أو حزمة برمجية (ZIP / JAR / Office XML)";
                riskScore += 15;
                reasons.push({ text: 'الملف مضغوط، يرجى الحذر إذا كان يحتوي على سكربات أو ماكرو مخفي.', type: 'warning' });
            } else if (header.startsWith('25504446')) {
                detectedRealType = "مستند وثيقة رسمية (PDF)";
                riskScore += 0;
                reasons.push({ text: 'تنسيق وثيقة PDF سليم، والبصمة الثنائية متطابقة تماماً.', type: 'safe' });
            } else if (header.startsWith('FFD8FF') || header.startsWith('89504E47')) {
                detectedRealType = "ملف صورة رقمية (JPG / PNG)";
                riskScore += 0;
                reasons.push({ text: 'صورة رقمية سليمة وتوقيعها البرمجي متطابق.', type: 'safe' });
            } else {
                riskScore += 35;
                reasons.push({ text: 'بصمة الملف الثنائية غير شائعة أو غير مطابقة للأنماط القياسية المعتمدة.', type: 'warning' });
            }

            const fileName = file.name.toLowerCase();
            const dangerousExtensions = ['.exe', '.bat', '.cmd', '.vbs', '.scr', '.pif', '.js', '.jar', '.msi'];
            const isDangerousExt = dangerousExtensions.some(ext => fileName.endsWith(ext));
            
            if (isDangerousExt && !header.startsWith('4D5A') && !header.startsWith('504B')) {
                riskScore = 100;
                reasons.unshift({ text: 'تم كشف تلاعب خبيث في الامتداد (Extension Spoofing): الامتداد الظاهري لا يتطابق نهائياً مع البصمة الثنائية الداخلية!', type: 'danger' });
            }

            riskScore = Math.min(riskScore, 100);

            let badgeClass = riskScore >= 50 ? 'score-danger' : (riskScore > 0 ? 'score-warning' : 'score-safe');
            let statusTitle = riskScore >= 50 ? 'تحذير شديد: الملف مشبوه أو مفخخ (High Risk)' : 'الملف سليم وخالٍ من المخاطر الظاهرة (Low Risk)';
            let statusIcon = riskScore >= 50 ? 'fa-triangle-exclamation' : 'fa-circle-check';

            let listHtml = reasons.map(r => `<li class="li-${r.type}">${r.text}</li>`).join('');

            reportBox.innerHTML = `
                <div class="report-header">
                    <div>
                        <strong style="font-size:1.1rem;"><i class="fa-solid ${statusIcon}"></i> ${statusTitle}</strong>
                    </div>
                    <div class="risk-score-badge ${badgeClass}">
                        مؤشر الخطورة: ${riskScore}%
                    </div>
                </div>
                <div style="font-size:0.85rem; color:var(--text-muted); margin-bottom:8px;">
                    <strong>اسم الملف:</strong> ${file.name} | <strong>النوع الحقيقي:</strong> ${detectedRealType} | <strong>الحجم:</strong> ${(file.size / 1024).toFixed(2)} KB
                </div>
                <ul class="report-details-list">
                    ${listHtml}
                </ul>
            `;

            addToHistory(file.name, 'فحص ملف', riskScore, riskScore >= 50 ? 'خطر' : (riskScore > 0 ? 'تنبيه' : 'آمن'));

        }, 700);
    };

    reader.readAsArrayBuffer(file.slice(0, 64));
}
