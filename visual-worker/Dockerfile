# خدمة الكشف البصري (منفصلة عن الموقع). تُبنى من جذر المستودع:
#   docker build -f visual-worker/Dockerfile -t pd-visual .
# صورة Playwright الرسمية فيها Chromium ومكتباته، ورقم نسختها لازم يطابق playwright بـ package.json.
FROM mcr.microsoft.com/playwright:v1.63.0-noble
WORKDIR /app

COPY visual-worker/package.json visual-worker/
RUN cd visual-worker && npm install --omit=dev --no-audit --no-fund

# الخدمة تستخدم فحص العناوين (isPublicIp) من الموقع نفسه حتى تبقى قواعد الحماية وحدة
COPY visual-worker/*.js visual-worker/
COPY server/inspect.js server/
COPY public/js/detection-engine.js public/js/

ENV NODE_ENV=production PORT=8090
EXPOSE 8090
USER pwuser

# VISUAL_WORKER_TOKEN يُضاف من لوحة الاستضافة (مفتاح سري، 24 حرفاً أو أكثر، نفسه بالموقع الرئيسي)
CMD ["node", "visual-worker/worker.js"]
