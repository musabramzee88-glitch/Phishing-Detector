from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import librosa
import numpy as np
import cv2

app = Flask(__name__)
CORS(app)  # السماح للواجهة الأمامية بالاتصال بالخادم

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 1. دالة فحص الصوت
def analyze_audio_deepfake(audio_file_path):
    y, sr = librosa.load(audio_file_path, sr=None)
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
    
    while cap.isOpened():
        ret, frame = cap.read()
        if not ret:
            break
            
        frame_count += 1
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, 1.3, 5)
        
        if len(faces) == 0:
            inconsistencies += 1
            
    cap.release()
    
    anomaly_ratio = (inconsistencies / frame_count) * 100 if frame_count > 0 else 0
    
    if anomaly_ratio > 30:
        return {"score": 90, "status": "🚨 تحذير: تم رصد انقطاعات وتشوهات بصرية في الفيديو تعود لتقنية التزييف العميق!"}
    else:
        return {"score": 15, "status": "🛡 الفيديو طبيعي ولا توجد مؤشرات تلاعب بإطارات الوجه."}

# مسار استقبال فحص الصوت
@app.route('/api/scan-audio', methods=['POST'])
def scan_audio():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    
    result = analyze_audio_deepfake(filepath)
    os.remove(filepath) # تنظيف الملف بعد الفحص
    return jsonify(result)

# مسار استقبال فحص الفيديو
@app.route('/api/scan-video', methods=['POST'])
def scan_video():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    filepath = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(filepath)
    
    result = analyze_video_deepfake(filepath)
    os.remove(filepath)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
    