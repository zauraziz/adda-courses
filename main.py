import os
from fastapi import FastAPI, Form, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import psycopg2
from dotenv import load_dotenv
import json
import shutil
from pathlib import Path

load_dotenv()
app = FastAPI()

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Fayl yükləmə qovluğu
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

@app.get("/health")
async def health():
    try:
        conn = psycopg2.connect(os.getenv("DATABASE_URL"), sslmode='require')
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        conn.close()
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        return {"status": "error", "database": str(e)}

@app.post("/init-db")
async def init_db():
    try:
        print("[INIT-DB] Başlangıç...")
        conn = psycopg2.connect(os.getenv("DATABASE_URL"), sslmode='require')
        cur = conn.cursor()
        # Cədvəli yarat və files sütunu əlavə et
        cur.execute("""
            CREATE TABLE IF NOT EXISTS enrollments (
                id SERIAL PRIMARY KEY,
                student_name TEXT NOT NULL,
                phone TEXT NOT NULL,
                course_name TEXT NOT NULL,
                files JSONB DEFAULT '{}'
            )
        """)
        # Əgər files sütunu yoxdursa, əlavə et
        cur.execute("""
            ALTER TABLE enrollments
            ADD COLUMN IF NOT EXISTS files JSONB DEFAULT '{}'
        """)
        conn.commit()
        cur.close()
        conn.close()
        print("[INIT-DB] Uğurlu!")
        return {"status": "success", "message": "Baza sxemi yeniləndi!"}
    except Exception as e:
        print(f"[INIT-DB] Xəta: {str(e)}")
        return {"status": "error", "message": str(e)}

@app.post("/enroll")
async def enroll(
    name: str = Form(...),
    phone: str = Form(...),
    course_name: str = Form(...),
    id_file: UploadFile = File(None),
    diploma_file: UploadFile = File(None),
    work_file: UploadFile = File(None),
    medical_file: UploadFile = File(None),
    application_file: UploadFile = File(None),
    receipt_file: UploadFile = File(None)
):
    try:
        print(f"[ENROLL] Başlangıç - Name: {name}, Phone: {phone}, Course: {course_name}")
        
        conn = psycopg2.connect(os.getenv("DATABASE_URL"), sslmode='require')
        cur = conn.cursor()

        # Faylları saxla və yolları topla
        files = {}
        file_fields = {
            'id_file': id_file,
            'diploma_file': diploma_file,
            'work_file': work_file,
            'medical_file': medical_file,
            'application_file': application_file,
            'receipt_file': receipt_file
        }

        for field_name, file in file_fields.items():
            if file and file.filename:
                try:
                    file_path = UPLOAD_DIR / f"{name.replace(' ', '_')}_{field_name}_{file.filename}"
                    with open(file_path, "wb") as buffer:
                        shutil.copyfileobj(file.file, buffer)
                    files[field_name] = str(file_path.relative_to(UPLOAD_DIR))
                    print(f"[ENROLL] Fayl saxlandı: {field_name} -> {file_path}")
                except Exception as e:
                    print(f"[ENROLL] Fayl saxlama xətası ({field_name}): {str(e)}")
                    files[field_name] = f"error: {str(e)}"

        files_json = json.dumps(files)
        print(f"[ENROLL] Files JSON: {files_json}")
        
        cur.execute(
            "INSERT INTO enrollments (student_name, phone, course_name, files) VALUES (%s, %s, %s, %s::jsonb)",
            (name, phone, course_name, files_json)
        )
        conn.commit()
        cur.close()
        conn.close()
        print(f"[ENROLL] Uğurlu - {name} qeydiyyat edildi")
        return {"status": "success", "message": "Məlumat və fayllar bazaya yazıldı!"}
    except Exception as e:
        print(f"[ENROLL] Xəta: {str(e)}")
        return {"status": "error", "message": str(e)}

@app.get("/students")
async def students():
    try:
        conn = psycopg2.connect(os.getenv("DATABASE_URL"), sslmode='require')
        cur = conn.cursor()
        cur.execute("SELECT id, student_name, phone, course_name, files FROM enrollments ORDER BY id DESC")
        rows = cur.fetchall()
        cur.close()
        conn.close()
        result = []
        for row in rows:
            files_data = row[4] if row[4] else {}
            # Eğer string ise parse et
            if isinstance(files_data, str):
                try:
                    files_data = json.loads(files_data)
                except:
                    files_data = {}
            result.append({
                "id": row[0],
                "name": row[1],
                "phone": row[2],
                "course_name": row[3],
                "files": files_data
            })
        return result
    except Exception as e:
        return {"status": "error", "message": str(e)}