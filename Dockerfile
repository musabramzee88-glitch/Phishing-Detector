FROM eclipse-temurin:latest
WORKDIR /app

# نسخ جميع ملفات المشروع (بما فيها ملف الـ html وملف الـ jar)
COPY . /app

EXPOSE 8080

# ضع هنا اسم ملف الـ jar الخاص بك بدلاً من PhishingDetector.jar
CMD ["java", "-jar", "PhishingDetector.jar"]
