FROM node:22-alpine
WORKDIR /app

# الموقع يشتغل على server.js، وهو يستخدم مكتبات Node المدمجة فقط، فما نحتاج npm install.
# ننسخ ملفات الموقع فقط، حتى ما يقدّم الخادم ملفات المشروع الثانية (app.py، ملفات الجافا، cloudflared.exe).
COPY server.js index.html detection-engine.js logo.png ./

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8080

EXPOSE 8080
USER node

# مفتاح CyberBot ما ينحط هنا: مرّر OPENAI_API_KEY و OPENAI_MODEL كمتغيرات بيئة عند التشغيل.
CMD ["node", "server.js"]
