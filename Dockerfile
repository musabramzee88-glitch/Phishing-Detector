FROM node:22-alpine
WORKDIR /app

# الموقع يستخدم مكتبات Node المدمجة فقط، فما نحتاج npm install.
# ننسخ ملفات الموقع فقط (بدون الاختبارات وملفات الجافا القديمة وcloudflared.exe).
COPY package.json server.js ./
COPY server ./server
COPY public ./public
COPY tools ./tools

# المنفذ يحدده Render عبر متغير PORT، والقيمة الافتراضية 8080 عند التشغيل محلياً
ENV NODE_ENV=production \
    HOST=0.0.0.0

EXPOSE 8080
USER node

# الأسرار (OPENAI_API_KEY و ADMINS ...) ما تنحط هنا: تُضاف كمتغيرات بيئة من لوحة الاستضافة.
CMD ["node", "server.js"]
