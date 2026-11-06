import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;

import java.awt.Desktop;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.regex.Pattern;

public class PhishingDetectorServer {

    public static void main(String[] args) throws IOException {
        // قراءة البورت من Render تلقائياً أو استخدام 9000 محلياً
        int port = 9000;
        String portEnv = System.getenv("PORT");
        if (portEnv != null) {
            try {
                port = Integer.parseInt(portEnv);
            } catch (NumberFormatException e) {
                port = 9000;
            }
        }

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);
        
        // 1. المسار الرئيسي "/" -> يعرض صفحة الترحيب (Landing Page) التي تحتوي على الزرين
        // 2. مسار التطبيق "/app" -> يشغل واجهة الفحص الأصلية للمشروع (HomeHandler)
        server.createContext("/app", new HomeHandler());

        // 3. مسار الشعار "/logo.png" -> لخدمة وتوصيل صورة الشعار للمهندس والمتصفح بدقة
        // مسار مخصص لخدمة صورة الشعار وإرسالها للمتصفح عبر السيرفر المحلي
        server.createContext("/logo.png", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                File file = new File("logo.png");
                if (!file.exists()) {
                    String err = "Logo not found";
                    exchange.sendResponseHeaders(404, err.length());
                    OutputStream os = exchange.getResponseBody();
                    os.write(err.getBytes());
                    os.close();
                    return;
                }
                byte[] bytes = Files.readAllBytes(file.toPath());
                exchange.getResponseHeaders().set("Content-Type", "image/png");
                exchange.sendResponseHeaders(200, bytes.length);
                OutputStream os = exchange.getResponseBody();
                os.write(bytes);
                os.close();
            }
        });

        server.setExecutor(Executors.newFixedThreadPool(20)); 
        server.start();
    }
    static class RiskDetail {
        String title;
        int weight;
        String explanation;

        public RiskDetail(String title, int weight, String explanation) {
            this.title = title;
            this.weight = weight;
            this.explanation = explanation;
        }
    }

    static class HomeHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            String query = exchange.getRequestURI().getQuery();
            String targetUrl = "";
            int totalScore = 0;
            List<RiskDetail> detectedRisks = new ArrayList<>();
            boolean scanned = false;
            boolean isOfficialTrusted = false;
            boolean typosquattingDetected = false;

            if (query != null && query.contains("url=")) {
                scanned = true;
                String[] parts = query.split("=", 2);
                if (parts.length > 1) {
                    targetUrl = URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
                }
                
                String lowerUrl = targetUrl.toLowerCase();

                String[] officialDomains = {
                    "tu.edu.iq", "mohe.gov.iq", "gov.iq", "uobaghdad.edu.iq", "uomustansiriyah.edu.iq",
                    "google.com", "facebook.com", "youtube.com", "instagram.com",
                    "twitter.com", "x.com", "microsoft.com", "apple.com",
                    "whatsapp.com", "telegram.org", "github.com", "linkedin.com"
                };

                for (String official : officialDomains) {
                    if (lowerUrl.contains(official)) {
                        if (!lowerUrl.contains("facebooki") && !lowerUrl.contains("youtabe") && !lowerUrl.contains("g00gle")) {
                            isOfficialTrusted = true;
                            break;
                        }
                    }
                }

                String[] fakeBrands = {
                    "g00gle", "gogle", "gcsgle", "googe", "gooogle", "g-oogle",
                    "faecbook", "facebk", "facbook", "face-book", "fcebook", "faebook", 
                    "facebooki", "faceboook", "fb-login", "secure-facebook",
                    "youtabe", "yutube", "youtubbe", "ytube", "you-tube",
                    "paypol", "paypa1", "pay-pal", "pyapal",
                    "instgram", "intagram", "inst-gram",
                    "m1crosoft", "microsft"
                };
                
                for (String brand : fakeBrands) {
                    if (lowerUrl.contains(brand)) {
                        typosquattingDetected = true;
                        break;
                    }
                }

                if (lowerUrl.contains("googl3") || lowerUrl.contains("faceb00k") || lowerUrl.contains("app1e") || lowerUrl.contains("youtub3")) {
                    typosquattingDetected = true;
                }

                if (typosquattingDetected) {
                    int w = 5;
                    totalScore += w;
                    detectedRisks.add(new RiskDetail(
                        "انتحال النطاقات وتغيير الحروف (Typosquatting)", 
                        w, 
                        "الخطر: تم اكتشاف تغيير مقصود في حروف نطاق شهير أو حكومي (مثل تغيير حروف YouTube أو Facebook). هذا أسلوب خداع وتصيد احتيالي."
                    ));
                }

                if (lowerUrl.contains(".xyz") || lowerUrl.contains(".top") || lowerUrl.contains(".tk") || lowerUrl.contains(".cc") || lowerUrl.contains(".gq")) {
                    int w = 2;
                    totalScore += w;
                    detectedRisks.add(new RiskDetail(
                        "استخدام نطاق مشبوه (Risky TLD)", 
                        w, 
                        "الخطر: النطاق ينتهي بامتداد يُستخدم بكثافة في إطلاق حملات التصيد الاحتيالي المجانية أو الرخيصة."
                    ));
                }

                if (Pattern.compile("https?://(?:\\d{1,3}\\.){3}\\d{1,3}").matcher(targetUrl).find()) {
                    int w = 3;
                    totalScore += w;
                    detectedRisks.add(new RiskDetail(
                        "استخدام عنوان IP مباشر", 
                        w, 
                        "الخطر: الرابط يعتمد على أرقام IP مباشرة بدلاً من اسم نطاق موثوق لتجاوز أنظمة الحماية."
                    ));
                }

                if (targetUrl.contains("@")) {
                    int w = 3;
                    totalScore += w;
                    detectedRisks.add(new RiskDetail(
                        "وجود رمز التضليل (@)", 
                        w, 
                        "الخطر: وجود رمز '@' يستدعي الحذر الشديد؛ حيث تتجاهل المتصفحات ما يسبق الرمز وتوجه المستخدم لعنوان آخر مخفي."
                    ));
                }

                if (lowerUrl.startsWith("http://") && !isOfficialTrusted) {
                    int w = 2;
                    totalScore += w;
                    detectedRisks.add(new RiskDetail(
                        "بروتوكول غير مشفر (HTTP)", 
                        w, 
                        "الخطر: الرابط لا يدعم التشفير (HTTPS)، مما يعني أن البيانات معرضة للاعتراض والسرقة بسهولة."
                    ));
                }

                if (!isOfficialTrusted) {
                    String[] keywords = {"login", "verify", "update", "banking", "secure", "account", "signin", "free", "win", "prize"};
                    int keywordMatches = 0;
                    for (String word : keywords) {
                        if (lowerUrl.contains(word)) {
                            keywordMatches++;
                        }
                    }
                    if (keywordMatches > 0) {
                        int w = Math.min(keywordMatches, 2);
                        totalScore += w;
                        detectedRisks.add(new RiskDetail(
                            "كلمات مفتاحية مرتبطة بالتصيد الاحتيالي (Phishing)", 
                            w, 
                            "الخطر: يحتوي الرابط على كلمات حساسة تُستخدم عادة لخداع الضحايا وإيهامهم بأن الصفحة رسمية."
                        ));
                    }
                }

                if (targetUrl.length() > 75) {
                    int w = 1;
                    totalScore += w;
                    detectedRisks.add(new RiskDetail(
                        "طول الرابط غير الطبيعي", 
                        w, 
                        "الخطر: طول الرابط يتجاوز الحد الطبيعي لإخفاء اسم النطاق الحقيقي والمسارات الخبيثة."
                    ));
                }

                if (isOfficialTrusted && !typosquattingDetected) {
                    totalScore = 0;
                }

                if (totalScore > 10) {
                    totalScore = 10;
                }
            }

            StringBuilder html = new StringBuilder();
            html.append("<!DOCTYPE html>\n")
                .append("<html lang=\"ar\" dir=\"rtl\">\n")
                .append("<head>\n")
                .append("<meta charset=\"UTF-8\">\n")
                .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n")
                .append("<title>نظام كشف وتقييم الروابط الخبيثة | جامعة تكريت</title>\n")
                .append("<link href=\"https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;900&display=swap\" rel=\"stylesheet\">\n")
                .append("<style>\n")
                .append(":root { --bg-main: #0b0f19; --card-bg: #111827; --border-color: #1f2937; --accent-blue: #3b82f6; --accent-glow: rgba(59, 130, 246, 0.2); --text-muted: #9ca3af; --danger: #ef4444; --warning: #f59e0b; --safe: #10b981; }\n")
                .append("* { box-sizing: border-box; }\n")
                .append("body { font-family: 'Cairo', sans-serif; background-color: var(--bg-main); color: #f3f4f6; margin: 0; padding: 40px 20px; min-height: 100vh; display: flex; justify-content: center; align-items: flex-start; }\n")
                .append(".container { width: 100%; max-width: 900px; }\n")
                .append(".main-card { background-color: var(--card-bg); border: 1px solid var(--border-color); border-radius: 20px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5), 0 10px 10px -5px rgba(0, 0, 0, 0.4); padding: 40px; position: relative; overflow: hidden; }\n")
                .append(".main-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px; background: linear-gradient(90deg, #3b82f6, #8b5cf6, #ec4899); }\n")
                .append(".header { text-align: center; margin-bottom: 30px; }\n")
                .append(".header .uni-logo { font-size: 13px; font-weight: 700; color: #60a5fa; letter-spacing: 1px; margin-bottom: 5px; text-transform: uppercase; }\n")
                .append(".header h1 { margin: 0 0 10px 0; font-size: 24px; font-weight: 900; color: #ffffff; }\n")
                .append(".header h2 { margin: 0; font-size: 16px; font-weight: 600; color: var(--text-muted); }\n")
                .append(".team-banner { background: rgba(30, 58, 138, 0.3); border: 1px solid rgba(59, 130, 246, 0.3); padding: 15px 20px; border-radius: 12px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px; margin-bottom: 35px; font-size: 14px; }\n")
                .append(".team-banner span { color: #93c5fd; font-weight: 600; }\n")
                .append(".search-form { display: flex; gap: 12px; margin-bottom: 10px; }\n")
                .append(".input-wrapper { flex: 1; position: relative; }\n")
                .append("input[type='text'] { width: 100%; padding: 16px 20px; background-color: #1f2937; border: 2px solid #374151; border-radius: 12px; color: #ffffff; font-size: 15px; font-family: 'Cairo', sans-serif; outline: none; transition: all 0.3s ease; }\n")
                .append("input[type='text']:focus { border-color: var(--accent-blue); box-shadow: 0 0 0 4px var(--accent-glow); background-color: #111827; }\n")
                .append("button[type='submit'] { background: linear-gradient(135deg, #2563eb, #1d4ed8); color: white; border: none; padding: 0 30px; border-radius: 12px; font-size: 16px; font-weight: 700; font-family: 'Cairo', sans-serif; cursor: pointer; transition: all 0.3s ease; box-shadow: 0 4px 12px rgba(37, 99, 235, 0.4); }\n")
                .append("button[type='submit']:hover { background: linear-gradient(135deg, #1d4ed8, #1e40af); transform: translateY(-1px); box-shadow: 0 6px 16px rgba(37, 99, 235, 0.6); }\n")
                .append(".result-section { margin-top: 35px; background-color: #1a2234; border: 1px solid #2d3748; border-radius: 16px; padding: 30px; animation: fadeIn 0.4s ease-in-out; }\n")
                .append("@keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }\n")
                .append(".url-display { word-break: break-all; font-family: monospace; background: #0f172a; padding: 12px 16px; border-radius: 8px; border: 1px solid #334155; font-size: 13px; color: #38bdf8; margin-bottom: 25px; }\n")
                .append(".risk-card { background: #111827; border: 1px solid rgba(239, 68, 68, 0.3); border-right: 4px solid var(--danger); padding: 15px 18px; border-radius: 10px; margin-bottom: 15px; }\n")
                .append(".risk-title { font-weight: 700; color: #f87171; font-size: 15px; margin-bottom: 6px; display: flex; align-items: center; gap: 8px; }\n")
                .append(".risk-desc { font-size: 13px; color: #9ca3af; line-height: 1.6; }\n")
                .append(".score-box { display: flex; align-items: center; justify-content: space-between; background: #111827; padding: 20px 25px; border-radius: 12px; border: 1px solid #374151; margin-top: 25px; flex-wrap: wrap; gap: 15px; }\n")
                .append(".score-label { font-size: 16px; font-weight: 700; color: #e5e7eb; }\n")
                .append(".score-value { font-family: monospace; font-size: 24px; font-weight: 900; }\n")
                .append(".status-badge { display: inline-block; padding: 10px 20px; border-radius: 30px; font-weight: 700; font-size: 14px; margin-top: 20px; text-align: center; width: 100%; }\n")
                .append(".badge-danger { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }\n")
                .append(".badge-warning { background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }\n")
                .append(".badge-safe { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }\n")
                .append(".trusted-box { background: rgba(16, 185, 129, 0.1); border: 1px solid rgba(16, 185, 129, 0.3); padding: 15px 20px; border-radius: 10px; color: #34d399; font-weight: 600; margin-bottom: 20px; display: flex; align-items: center; gap: 10px; }\n")
                .append(".back-home { display: inline-block; margin-bottom: 20px; color: #60a5fa; text-decoration: none; font-size: 14px; font-weight: 600; }\n")
                .append(".back-home:hover { text-decoration: underline; }\n")
                .append("</style>\n")
                .append("</head>\n")
                .append("<body>\n")
                .append("<div class=\"container\">\n")
                .append("<div class=\"main-card\">\n")
                
                .append("<a href=\"/\" class=\"back-home\">← العودة لصفحة الترحيب الرئيسية</a>\n")

                .append("<div class=\"header\">\n")
                .append("<div class=\"uni-logo\">جمهورية العراق | وزارة التعليم العالي والبحث العلمي</div>\n")
                .append("<h1>جامعة تكريت - كلية علوم الحاسوب والرياضيات</h1>\n")
                .append("<h2>قسم الأمن السيبراني (المرحلة الثالثة)</h2>\n")
                .append("</div>\n")
                
                .append("<div class=\"team-banner\">\n")
                .append("<div>👨‍💻 <strong>إعداد الطلبة:</strong> <span>مصعب رمزي أحمد</span> &nbsp;|&nbsp; <span>محمود حكمت ذياب</span></div>\n")
                .append("<div>🎯 <strong>الإشراف:</strong> رئاسة القسم</div>\n")
                .append("</div>\n")

                .append("<h3 style=\"text-align: center; color: #ffffff; font-size: 18px; margin-bottom: 25px; font-weight: 700;\">🛡️ نظام الذكاء الاصطناعي لفحص وتقييم خطورة الروابط والتصيد</h3>\n")
                
                // تم تعديل الـ action هنا ليكون إلى "/app" لكي يبقى المستخدم داخل التطبيق عند الضغط على فحص
                .append("<form method=\"GET\" action=\"/app\">\n")
                .append("<div class=\"search-form\">\n")
                .append("<div class=\"input-wrapper\">\n")
                .append("<input type=\"text\" name=\"url\" value=\"").append(escapeHtml(targetUrl)).append("\" placeholder=\"أدخل أو الصق الرابط هنا للتحقق الفوري (مثال: https://example.com)...\" required>\n")
                .append("</div>\n")
                .append("<button type=\"submit\">فحص الرابط</button>\n")
                .append("</div>\n")
                .append("</form>\n");

            if (scanned) {
                html.append("<div class=\"result-section\">\n");
                html.append("<h4 style=\"margin-top:0; color:#93c5fd; font-size:16px; border-bottom:1px solid #2d3748; padding-bottom:12px; margin-bottom:15px;\">📊 تقرير التحليل الأمني المتقدم:</h4>\n")
                .append("<div class=\"url-display\">").append(escapeHtml(targetUrl)).append("</div>\n");
                
                if (isOfficialTrusted && !typosquattingDetected) {
                    html.append("<div class=\"trusted-box\">\n")
                        .append("✅ النطاق موثوق ومعتمد رسمياً ضمن القائمة البيضاء (White-listed Official Domain).\n")
                        .append("</div>\n");
                }

                if (!detectedRisks.isEmpty()) {
                    html.append("<div style=\"display: flex; flex-direction: column; gap: 12px;\">\n");
                    for (RiskDetail r : detectedRisks) {
                        html.append("<div class=\"risk-card\">\n")
                            .append("<div class=\"risk-title\">⚠️ ").append(escapeHtml(r.title)).append(" <span style=\"margin-right: auto; background: rgba(239, 68, 68, 0.2); padding: 2px 8px; border-radius: 6px; font-size: 12px;\">+").append(r.weight).append(" درجات خطورة</span></div>\n")
                            .append("<div class=\"risk-desc\">").append(escapeHtml(r.explanation)).append("</div>\n")
                            .append("</div>\n");
                    }
                    html.append("</div>\n");
                } else if (!isOfficialTrusted) {
                    html.append("<p style=\"color: #34d399; font-weight: 600; text-align: center; padding: 15px; background: rgba(16, 185, 129, 0.05); border-radius: 8px;\">✨ لم يتم رصد أي أنماط تصيد أو ثغرات هيكلية في الرابط المدخل.</p>\n");
                }

                String scoreColor = totalScore >= 5 ? "#f87171" : (totalScore > 0 ? "#fbbf24" : "#34d399");
                html.append("<div class=\"score-box\">\n")
                    .append("<div class=\"score-label\">مؤشر تقييم الخطورة الكلي:</div>\n")
                    .append("<div class=\"score-value\" style=\"color: ").append(scoreColor).append(";\">").append(totalScore).append(" <span style=\"font-size: 14px; color: #9ca3af;\">/ 10</span></div>\n")
                    .append("</div>\n");
                
                if (totalScore >= 5) {
                    html.append("<div><div class=\"status-badge badge-danger\">🚨 تحذير أمني خطير: الرابط يمثل تهديداً محتملاً وعالي الخطورة (يحتمل بشدة أن يكون صفحة تصيد احتيالي)!</div></div>\n");
                } else if (totalScore > 0) {
                    html.append("<div><div class=\"status-badge badge-warning\">⚡ تنبيه: الرابط يحتوي على خصائص مشبوهة، يرجى توخي الحذر الشديد وعدم مشاركة أي بيانات حساسة.</div></div>\n");
                } else {
                    html.append("<div><div class=\"status-badge badge-safe\">🛡️ النتيجة النهائية: الرابط آمن للاستخدام وموثوق.</div></div>\n");
                }
                html.append("</div>\n");
            }

            html.append("</div>\n")
                .append("</div>\n")
                .append("</body>\n")
                .append("</html>\n");

            byte[] response = html.toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/html; charset=UTF-8");
            exchange.sendResponseHeaders(200, response.length);
            OutputStream os = exchange.getResponseBody();
            os.write(response);
            os.close();
        }

        private String escapeHtml(String str) {
            if (str == null) return "";
            return str.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace("\"", "&quot;")
                    .replace("'", "&#x27;");
        }
    }
}
