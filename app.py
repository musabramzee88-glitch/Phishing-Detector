"""
خادم تجريبي لتحليل الصوت والفيديو (غير مربوط بالموقع حالياً).

تنبيه: العتبات المستخدمة هنا (تباين MFCC أقل من 50، أو غياب الوجه في أكثر من 30% من الإطارات)
قواعد تقريبية للعرض التعليمي، وليست نموذجاً مدرَّباً لكشف التزييف العميق. لا تعرض نتائجها
للمستخدمين على أنها حكم نهائي.

التشغيل: python app.py  (يستمع على 127.0.0.1:5000، ولتفعيل وضع التطوير: FLASK_DEBUG=1)
فحص الفيديو يحتاج cv2.CascadeClassifier، وهو غير موجود في OpenCV 5:  pip install "opencv-python<5"
"""
import os
import tempfile

import cv2
import librosa
import numpy as np
from flask import Flask, jsonify, request
from flask_cors import CORS
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # أقصى حجم للملف المرفوع: 50 ميغابايت
CORS(app)  # السماح للواجهة الأمامية بالاتصال بالخادم

AUDIO_EXTENSIONS = {".mp3", ".wav", ".ogg", ".flac", ".m4a", ".aac"}
VIDEO_EXTENSIONS = {".mp4", ".mov", ".avi", ".mkv", ".webm"}
MAX_VIDEO_FRAMES = 300  # حد أعلى لعدد الإطارات المفحوصة حتى لا يعلق الخادم بفيديو طويل


# 1. دالة فحص الصوت
def analyze_audio_deepfake(audio_file_path):
    y, sr = librosa.load(audio_file_path, sr=None, duration=120)
    mfccs = librosa.feature.mfcc(y=y, sr=sr, n_mfcc=13)
    mfcc_var = np.var(mfccs)

    if mfcc_var < 50.0:
        risk_score = 85
        status = "🚨 تنبيه: يوجد احتمال كبير جداً أن الصوت مولد بالذكاء الاصطناعي (Audio Deepfake)!"
    else:
        risk_score = 10
        status = "🛡 الصوت يبدو بشرياً وتأثيرات الترددات الطبيعية سليمة."

    return {
        "score": risk_score,
        "status": status,
        "mfcc_variance": float(mfcc_var)
    }


# 2. دالة فحص الفيديو
def analyze_video_deepfake(video_file_path):
    cap = cv2.VideoCapture(video_file_path)
    frame_count = 0
    inconsistencies = 0

    face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

    while cap.isOpened() and frame_count < MAX_VIDEO_FRAMES:
        ret, frame = cap.read()
        if not ret:
            break

        frame_count += 1
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, 1.3, 5)

        if len(faces) == 0:
            inconsistencies += 1

    cap.release()

    if frame_count == 0:
        return {"error": "تعذر قراءة إطارات الفيديو. قد يكون الملف تالفاً أو بصيغة غير مدعومة."}

    anomaly_ratio = (inconsistencies / frame_count) * 100

    if anomaly_ratio > 30:
        return {"score": 90, "status": "🚨 تحذير: تم رصد انقطاعات وتشوهات بصرية في الفيديو تعود لتقنية التزييف العميق!"}
    else:
        return {"score": 15, "status": "🛡 الفيديو طبيعي ولا توجد مؤشرات تلاعب بإطارات الوجه."}


def scan_uploaded_file(allowed_extensions, analyzer):
    """يحفظ الملف المرفوع في ملف مؤقت باسم آمن، يحلله، ثم يحذفه دائماً."""
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']

    # لا نستخدم اسم الملف كما أرسله المستخدم: اسم مثل ../../server.js كان يكتب فوق ملفات أخرى
    extension = os.path.splitext(secure_filename(file.filename or ""))[1].lower()
    if extension not in allowed_extensions:
        return jsonify({"error": "صيغة الملف غير مدعومة."}), 400

    fd, temp_path = tempfile.mkstemp(suffix=extension)
    os.close(fd)
    try:
        file.save(temp_path)
        result = analyzer(temp_path)
    except Exception:
        app.logger.exception("Media analysis failed")
        return jsonify({"error": "تعذر تحليل الملف."}), 422
    finally:
        os.remove(temp_path)  # تنظيف الملف بعد الفحص حتى لو فشل التحليل

    if "error" in result:
        return jsonify(result), 422
    return jsonify(result)


# مسار استقبال فحص الصوت
@app.route('/api/scan-audio', methods=['POST'])
def scan_audio():
    return scan_uploaded_file(AUDIO_EXTENSIONS, analyze_audio_deepfake)


# مسار استقبال فحص الفيديو
@app.route('/api/scan-video', methods=['POST'])
def scan_video():
    return scan_uploaded_file(VIDEO_EXTENSIONS, analyze_video_deepfake)


if __name__ == '__main__':
    # وضع debug يسمح بتنفيذ أوامر على الجهاز من صفحة الخطأ، فلا يُفعَّل إلا محلياً وعند الطلب
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
