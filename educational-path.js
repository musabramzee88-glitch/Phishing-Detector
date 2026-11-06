/**
 * Phishing Education & Awareness Guided Path
 * وحدة التوعية والتدريب التفاعلي لمكافحة التصيد الإلكتروني
 * إعداد: مشروع تخرج الأمن السيبراني - جامعة تكريت
 */

// 1. محتوى المراحل والدروس التوعوية
const EDUCATION_STEPS = [
    {
        title: "1. اكتشاف التلاعب بالنطاقات (Typosquatting)",
        icon: "fa-font",
        description: "يلجأ المخترقون إلى تسجيل نطاقات تشبه المواقع الشهيرة بدقة عبر استبدال بعض الحروف (مثل استخدام `g00gle.com` بدلاً من `google.com` أو `fasebook.com`).",
        tip: "💡 <strong>نصيحة أمنية:</strong> تحقق دائماً من شريط العنوان (URL) حرفاً بحرف قبل إدخال بياناتك.",
        demoUrl: "https://g00gle-security-verify.com"
    },
    {
        title: "2. فحص البروتوكول وتشفير الاتصال (HTTP vs HTTPS)",
        icon: "fa-lock",
        description: "المواقع التي تستخدم `http://` غير مشفرة، ويمكن لأي شخص على نفس الشبكة التقاط كلمات السر والمعلومات الحساسة التي تدخلها.",
        tip: "💡 <strong>نصيحة أمنية:</strong> لا تدخل أي كلمة سر أو بطاقة ائتمانية في موقع لا يبدأ بـ `https://` مع وجود رمز القفل المغلق.",
        demoUrl: "http://mybank-login-update.com"
    },
    {
        title: "3. خطورة العناوين الرقمية المباشرة (IP Addresses)",
        icon: "fa-network-wired",
        description: "تستخدم معظم المنصات الموثوقة أسماء نطاقات رسمية (Domain Names). إذا رأيت رابطاً يحتوي على أرقام مباشرة مثل `http://192.168.1.50/login` فهذا مؤشر خطر عالي.",
        tip: "💡 <strong>نصيحة أمنية:</strong> البنوك والشركات الكبرى لا تطلب منك إطلاقاً الدخول عبر عنوان IP مباشر.",
        demoUrl: "http://185.220.101.5/verify-account"
    },
    {
        title: "4. خدعة رمز التضليل (@ Symbol)",
        icon: "fa-at",
        description: "عند وجود رمز `@` في الرابط، فإن المتصفح يتجاهل كلياً كل ما يسبق الرمز ويوجهك إلى العنوان الواقع بعد الرمز مباشرة! (مثال: `https://facebook.com@evil-site.com`).",
        tip: "💡 <strong>نصيحة أمنية:</strong> وجود رمز `@` داخل رابط ويب هو محاولة احتيال وشيكة.",
        demoUrl: "https://paypal.com-security-check@hacker-server.net"
    },
    {
        title: "5. هندسة الاستعجال والتهديد في النصوص",
        icon: "fa-triangle-exclamation",
        description: "تعتمد رسائل التصيد على خلق حالة من الخوف أو الطمع (مثل: 'تم تجميد حسابك! اضغط هنا خلال 24 ساعة' أو 'لقد ربحت جائزة كبرى').",
        tip: "💡 <strong>نصيحة أمنية:</strong> المؤسسات الرسمية لا تهدد بإغلاق الحسابات فوراً عبر رسائل نصية قصيرة أو بريد غير رسمي.",
        demoUrl: "عزيزي العميل، تم إيقاف بطاقتك المصرفية لعدم التحديث، اضغط هنا للتفعيل..."
    }
];

let currentEduStep = 0;

// 2. بناء واجهة المسار التوعوي وتضمين التنسيقات (CSS & Dynamic HTML)
function initEducationalPath() {
    // إضافة زر المسار التوعوي في شريط الملاحة تائياً (Navbar)
    const navLinks = document.querySelector('.nav-links');
    if (navLinks && !document.getElementById('eduNavBtn')) {
        const eduBtn = document.createElement('button');
        eduBtn.id = 'eduNavBtn';
        eduBtn.className = 'nav-btn';
        eduBtn.innerHTML = '<i class="fa-solid fa-graduation-cap"></i> المسار التوعوي';
        eduBtn.onclick = function() { openEduModal(); };
        navLinks.appendChild(eduBtn);
    }

    // إنشاء النافذة المنبثقة للمسار التوعوي (Modal)
    if (!document.getElementById('eduModal')) {
        const modalHtml = `
        <div id="eduModal" style="display:none; position:fixed; top:0; left:0; width:100%; height:100%; background:rgba(0,0,0,0.85); backdrop-filter:blur(8px); z-index:9999; justify-content:center; align-items:center; padding:20px;">
            <div style="background:var(--bg-card, #131b2e); border:1px solid var(--accent-blue, #00f2fe); border-radius:20px; max-width:650px; width:100%; padding:30px; position:relative; box-shadow:0 0 30px rgba(0,242,254,0.2); text-align:right;">
                
                <button onclick="closeEduModal()" style="position:absolute; top:15px; left:20px; background:none; border:none; color:var(--text-muted, #8e9aaf); font-size:1.5rem; cursor:pointer;">&times;</button>
                
                <div style="display:flex; align-items:center; gap:10px; margin-bottom:15px;">
                    <span style="background:rgba(0,242,254,0.15); color:var(--accent-blue, #00f2fe); padding:8px 14px; border-radius:12px; font-weight:bold; font-size:0.9rem;" id="stepIndicator">المرحلة 1 من 5</span>
                    <h3 style="margin:0; font-size:1.2rem; color:var(--text-main, #fff);" id="eduStepTitle">عنوان الدرس</h3>
                </div>

                <div style="background:rgba(0,0,0,0.2); border-right:4px solid var(--accent-blue, #00f2fe); padding:15px; border-radius:10px; margin-bottom:20px; line-height:1.7; font-size:0.95rem; color:var(--text-main, #fff);" id="eduStepDesc">
                    وصف المرحلة...
                </div>

                <div style="background:rgba(255,171,0,0.1); border:1px solid rgba(255,171,0,0.3); color:#ffab00; padding:12px 15px; border-radius:10px; font-size:0.88rem; margin-bottom:20px;" id="eduStepTip">
                    نصيحة أمنية...
                </div>

                <div style="margin-bottom:25px;">
                    <label style="font-size:0.85rem; color:var(--text-muted, #8e9aaf); display:block; margin-bottom:6px;">مثال توضيحي للاختبار الفوري في النظام:</label>
                    <div style="display:flex; gap:10px;">
                        <input type="text" id="eduDemoInput" readonly style="flex:1; background:rgba(0,0,0,0.3); border:1px solid rgba(255,255,255,0.1); padding:10px; border-radius:8px; color:var(--accent-blue, #00f2fe); font-family:monospace; direction:ltr; text-align:left;">
                        <button onclick="testEduSample()" style="background:linear-gradient(135deg, #00c6ff, #0072ff); border:none; color:#fff; padding:10px 18px; border-radius:8px; cursor:pointer; font-weight:bold; white-space:nowrap;">
                            <i class="fa-solid fa-flask"></i> فحص في المنظومة
                        </button>
                    </div>
                </div>

                <div style="display:flex; justify-content:space-between; align-items:center; border-top:1px solid rgba(255,255,255,0.1); padding-top:20px;">
                    <button id="prevStepBtn" onclick="changeEduStep(-1)" style="background:rgba(255,255,255,0.05); border:1px solid rgba(255,255,255,0.1); color:#fff; padding:10px 20px; border-radius:10px; cursor:pointer;" disabled>السابق</button>
                    <button id="nextStepBtn" onclick="changeEduStep(1)" style="background:var(--accent-blue, #00f2fe); border:none; color:#0a0f1d; padding:10px 24px; border-radius:10px; font-weight:bold; cursor:pointer;">التالي <i class="fa-solid fa-arrow-left"></i></button>
                </div>

            </div>
        </div>
        `;
        document.body.insertAdjacentHTML('beforeend', modalHtml);
    }
}

// 3. التحكم بالنافذة والخطوات
function openEduModal() {
    document.getElementById('eduModal').style.display = 'flex';
    renderEduStep(0);
}

function closeEduModal() {
    document.getElementById('eduModal').style.display = 'none';
}

function renderEduStep(index) {
    currentEduStep = index;
    const data = EDUCATION_STEPS[index];

    document.getElementById('stepIndicator').innerText = `المرحلة ${index + 1} من ${EDUCATION_STEPS.length}`;
    document.getElementById('eduStepTitle').innerHTML = `<i class="fa-solid ${data.icon}"></i> ${data.title}`;
    document.getElementById('eduStepDesc').innerHTML = data.description;
    document.getElementById('eduStepTip').innerHTML = data.tip;
    document.getElementById('eduDemoInput').value = data.demoUrl;

    document.getElementById('prevStepBtn').disabled = (index === 0);
    
    const nextBtn = document.getElementById('nextStepBtn');
    if (index === EDUCATION_STEPS.length - 1) {
        nextBtn.innerHTML = 'إنهاء المسار <i class="fa-solid fa-check"></i>';
    } else {
        nextBtn.innerHTML = 'التالي <i class="fa-solid fa-arrow-left"></i>';
    }
}

function changeEduStep(direction) {
    const newStep = currentEduStep + direction;
    if (newStep >= 0 && newStep < EDUCATION_STEPS.length) {
        renderEduStep(newStep);
    } else if (newStep >= EDUCATION_STEPS.length) {
        closeEduModal();
        alert('🎉 تهانينا! لقد أكملت المسار التوعوي بنجاح وأصبحت جاهزاً لكشف حيل التصيد الاحتيالي.');
    }
}

// 4. الربط التفاعلي المباشر مع فاحص الروابط والنصوص الموجود في موقعكم
function testEduSample() {
    const sample = EDUCATION_STEPS[currentEduStep].demoUrl;
    closeEduModal();

    if (currentEduStep === 4) {
        // إذا كانت خطوة فحص النص
        const textBtn = document.querySelectorAll('.nav-btn')[2];
        if (typeof switchPage === 'function') switchPage('textScannerPage', textBtn);
        const textInput = document.getElementById('textInput');
        if (textInput) {
            textInput.value = sample;
            if (typeof analyzeText === 'function') analyzeText();
        }
    } else {
        // إذا كانت خطوة فحص الرابط
        const scannerBtn = document.querySelectorAll('.nav-btn')[1];
        if (typeof switchPage === 'function') switchPage('scannerPage', scannerBtn);
        const urlInput = document.getElementById('urlInput');
        if (urlInput) {
            urlInput.value = sample;
            if (typeof analyzeUrl === 'function') analyzeUrl();
        }
    }
}

// تشغيل الوحدة فور اكتمال تحميل الصفحة
document.addEventListener('DOMContentLoaded', initEducationalPath);
