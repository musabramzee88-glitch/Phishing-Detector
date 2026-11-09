// عرض اسم الملف عند اختياره
function updateFileName(input) {
    const label = document.getElementById('fileLabelText');
    if (input.files && input.files[0]) {
        label.innerHTML = `الملف المختار: <span style="color: var(--accent-blue);">${input.files[0].name}</span>`;
    }
}

// خوارزمية فحص الملفات المعدلة (تفرز الملفات التنفيذية المشروعة عن الخبيثة)
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
                    
                    const fileName = file.name.toLowerCase();
                    const dangerousExtensions = ['.bat', '.cmd', '.vbs', '.scr', '.pif', '.js', '.msi'];
                    const isDangerousExt = dangerousExtensions.some(ext => fileName.endsWith(ext));

                    if (header.startsWith('4D5A')) {
                        detectedRealType = "ملف تنفيذي نظامي (PE Executable .exe)";
                        
                        // التحقق مما إذا كان الملف يمتلك امتداداً مزدوجاً خبيثاً أو تلاعباً واضحاً
                        if (fileName.includes('.pdf.exe') || fileName.includes('.jpg.exe') || fileName.includes('.png.exe') || isDangerousExt) {
                            riskScore = 100;
                            reasons.push({ text: 'تحذير خطير: تم كشف تلاعب خبيث في الامتداد (Extension Spoofing)! الملف عبارة عن تنفيذى مخفي بصيغة وهمية.', type: 'danger' });
                        } else {
                            // الملف التنفيذي العادي (مثل برامج التشغيل أو المتصفحات) يعتبر برنامجاً تنفيذياً ولكن ليس بالضرورة خبيثاً
                            riskScore = 20;
                            reasons.push({ text: 'الملف عبارة عن برنامج تنفيذي (PE Executable). وهو ملف تشغيلي نظامي، يرجى التأكد من مصدره إذا لم تقم بتحميله من جهة موثوقة.', type: 'warning' });
                        }
                    } else if (header.startsWith('504B')) {
                        detectedRealType = "ملف أرشيف مضغوط أو حزمة برمجية (ZIP / JAR / Office XML)";
                        riskScore += 10;
                        reasons.push({ text: 'الملف مضغوط، وتوقيعه الثنائي سليم.', type: 'safe' });
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

                    riskScore = Math.min(riskScore, 100);

                    let badgeClass = riskScore >= 50 ? 'score-danger' : (riskScore > 20 ? 'score-warning' : 'score-safe');
                    let statusTitle = riskScore >= 50 ? 'تحذير شديد: الملف مشبوه أو مفخخ (High Risk)' : (riskScore > 20 ? 'تنبيه: ملف تنفيذي يتطلب الحذر (Medium Risk)' : 'الملف سليم وموثوق (Low Risk)');
                    let statusIcon = riskScore >= 50 ? 'fa-triangle-exclamation' : (riskScore > 20 ? 'fa-circle-exclamation' : 'fa-circle-check');

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

                    addToHistory(file.name, 'فحص ملف', riskScore, riskScore >= 50 ? 'خطر' : (riskScore > 20 ? 'تنبيه' : 'آمن'));

                }, 700);
            };

            reader.readAsArrayBuffer(file.slice(0, 64));
        }