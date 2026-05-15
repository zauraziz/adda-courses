import os
import logging
import json
from fastapi import FastAPI, Form, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import psycopg2
import psycopg2.pool
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("adda")

app = FastAPI(title="ADDA Enrollment API", root_path="/api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Connection pool (Neon pooled connection)
from typing import Optional
_pool: Optional[psycopg2.pool.SimpleConnectionPool] = None

def get_pool() -> psycopg2.pool.SimpleConnectionPool:
    global _pool
    if _pool is None:
        db_url = os.getenv("DATABASE_URL")
        if not db_url:
            raise RuntimeError("DATABASE_URL environment variable is not set")
        _pool = psycopg2.pool.SimpleConnectionPool(1, 5, db_url, sslmode="require")
    return _pool

def get_conn():
    return get_pool().getconn()

def put_conn(conn):
    get_pool().putconn(conn)


async def upload_to_blob(file: UploadFile, prefix: str) -> str:
    """Upload a file to Vercel Blob and return the public URL."""
    token = os.getenv("BLOB_READ_WRITE_TOKEN")
    if not token:
        raise RuntimeError("BLOB_READ_WRITE_TOKEN is not set")

    try:
        from vercel_blob import put as blob_put
        content = await file.read()
        safe_name = file.filename.replace(" ", "_") if file.filename else "file.pdf"
        pathname = f"enrollments/{prefix}_{safe_name}"
        result = blob_put(pathname, content, {"access": "public", "addRandomSuffix": True})
        return result["url"]
    except Exception as e:
        log.error("Blob upload failed for %s: %s", file.filename, e)
        raise


@app.get("/health")
async def health():
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        put_conn(conn)
        return {"status": "ok", "database": "connected"}
    except Exception as e:
        log.error("Health check failed: %s", e)
        return {"status": "error", "database": str(e)}


@app.post("/enroll")
async def enroll(
    name: str = Form(...),
    phone: str = Form(...),
    fin: str = Form(...),
    email: str = Form(...),
    course_name: str = Form(...),
    course_code: str = Form(...),
    id_file: UploadFile = File(None),
    diploma_file: UploadFile = File(None),
    work_file: UploadFile = File(None),
    medical_file: UploadFile = File(None),
    application_file: UploadFile = File(None),
    receipt_file: UploadFile = File(None),
):
    log.info("Enroll: name=%s fin=%s course=%s", name, fin, course_code)

    file_fields = {
        "id_file": id_file,
        "diploma_file": diploma_file,
        "work_file": work_file,
        "medical_file": medical_file,
        "application_file": application_file,
        "receipt_file": receipt_file,
    }

    files: dict[str, str] = {}
    prefix = f"{fin}_{course_code}"

    for field_name, file in file_fields.items():
        if file and file.filename:
            try:
                url = await upload_to_blob(file, f"{prefix}_{field_name}")
                files[field_name] = url
                log.info("Uploaded %s → %s", field_name, url)
            except Exception as e:
                log.error("Failed to upload %s: %s", field_name, e)
                return {"status": "error", "message": f"Fayl yükləmə xətası ({field_name}): {str(e)}"}

    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO enrollments
              (student_name, phone, fin, email, course_name, course_code, files, status)
            VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, 'pending')
            """,
            (name, phone, fin, email, course_name, course_code, json.dumps(files)),
        )
        conn.commit()
        cur.close()
        log.info("Enrollment saved: %s %s", name, course_code)
        return {"status": "success", "message": "Qeydiyyat uğurla tamamlandı!"}
    except Exception as e:
        if conn:
            conn.rollback()
        log.error("DB insert failed: %s", e)
        return {"status": "error", "message": str(e)}
    finally:
        if conn:
            put_conn(conn)


@app.get("/students")
async def students():
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
SELECT id, code, name, level, stcw, subtitle,
                   duration_weeks, hours, price, currency, price_note, active, sort_order
            FROM courses
            WHERE active = true
            ORDER BY sort_order ASC
            """
        )
        rows = cur.fetchall()
        cur.close()
        result = []
        for row in rows:
            files_data = row[9] if row[9] else {}
            if isinstance(files_data, str):
                try:
                    files_data = json.loads(files_data)
                except Exception:
                    files_data = {}
            result.append({
"id": row[0],
"code": row[1],
"name": row[2],
"level": row[3],
"stcw": row[4],
"subtitle": row[5],
"duration_weeks": row[6],
"hours": row[7],
"price": float(row[8]) if row[8] is not None else None,
"currency": row[9],
"price_note": row[10],
"active": row[11],
"sort_order": row[12],
            })
        return result
    except Exception as e:
        log.error("Students fetch failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            put_conn(conn)


@app.get("/courses")
async def courses():
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, code, name, level, stcw, subtitle,
                   duration_weeks, hours, price, currency, price_note, active
            FROM courses
            WHERE active = true
            ORDER BY sort_order ASC
            """
        )
        rows = cur.fetchall()
        cur.close()
        return [
            {
                "id": row[0],
                "code": row[1],
                "name": row[2],
                "level": row[3],
                "stcw": row[4],
                "subtitle": row[5],
                "duration_weeks": row[6],
                "hours": row[7],
                "price": float(row[8]) if row[8] is not None else None,
                "currency": row[9],
                "price_note": row[10],
                "active": row[11],
            }
            for row in rows
        ]
    except Exception as e:
        log.error("Courses fetch failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            put_conn(conn)


class StatusUpdate(BaseModel):
    status: str


@app.patch("/enrollments/{enrollment_id}/status")
async def update_status(enrollment_id: int, body: StatusUpdate):
    allowed = {"pending", "approved", "rejected", "contacted"}
    if body.status not in allowed:
        raise HTTPException(status_code=400, detail=f"Status must be one of: {', '.join(allowed)}")

    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "UPDATE enrollments SET status = %s WHERE id = %s RETURNING id",
            (body.status, enrollment_id),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Enrollment not found")
        conn.commit()
        cur.close()
        log.info("Status updated: enrollment %s → %s", enrollment_id, body.status)
        return {"status": "success", "id": enrollment_id, "new_status": body.status}
    except HTTPException:
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        log.error("Status update failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            put_conn(conn)
