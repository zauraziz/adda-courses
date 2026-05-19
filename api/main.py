import os
import logging
import json
import secrets
from datetime import datetime, timedelta
from typing import Optional
from fastapi import FastAPI, Form, UploadFile, File, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse, JSONResponse
from pydantic import BaseModel
import psycopg2
import psycopg2.pool
import httpx
import jwt
from jwt import PyJWKClient
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
log = logging.getLogger("adda")

app = FastAPI(title="ADDA Enrollment API", root_path="/api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://adda-courses.vercel.app",
        "https://portal.adda.edu.az",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============= CONFIG =============
TENANT_ID         = os.getenv("AZURE_TENANT_ID", "")
CLIENT_ID         = os.getenv("AZURE_CLIENT_ID", "")
CLIENT_SECRET     = os.getenv("AZURE_CLIENT_SECRET", "")
ADMIN_GROUP_ID    = os.getenv("AZURE_ADMIN_GROUP_ID", "")
SESSION_SECRET    = os.getenv("SESSION_SECRET", "")

# Computed
AUTHORITY         = f"https://login.microsoftonline.com/{TENANT_ID}"
AUTHORIZE_URL     = f"{AUTHORITY}/oauth2/v2.0/authorize"
TOKEN_URL         = f"{AUTHORITY}/oauth2/v2.0/token"
JWKS_URL          = f"{AUTHORITY}/discovery/v2.0/keys"
ISSUER            = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"

SCOPES = ["openid", "profile", "email", "User.Read", "GroupMember.Read.All"]

# ============= DB POOL =============
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

# ============= AUTH HELPERS =============
def get_origin(request: Request) -> str:
    """Sorğunun gəldiyi domain-i tapır (vercel.app vs portal.adda.edu.az)."""
    host = request.headers.get("x-forwarded-host") or request.headers.get("host", "")
    proto = request.headers.get("x-forwarded-proto", "https")
    return f"{proto}://{host}"

def create_session_token(user_data: dict) -> str:
    """7 günlük session token yaradır."""
    payload = {
        "sub": user_data["sub"],
        "email": user_data.get("email", ""),
        "name": user_data.get("name", ""),
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=7),
    }
    return jwt.encode(payload, SESSION_SECRET, algorithm="HS256")

def verify_session_token(token: str) -> Optional[dict]:
    """Session token-i yoxlayır, yararsızdırsa None qaytarır."""
    try:
        return jwt.decode(token, SESSION_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError as e:
        log.warning("Session token invalid: %s", e)
        return None

def require_admin(request: Request) -> dict:
    """Sorğunun admin token-ə sahib olduğunu yoxlayır."""
    # Token Authorization header və ya cookie-dən gəlir
    auth_header = request.headers.get("authorization", "")
    token = None
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
    else:
        token = request.cookies.get("adda_session")
    
    if not token:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    payload = verify_session_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid or expired session")
    
    return payload

async def verify_user_in_admin_group(access_token: str, user_id: str) -> bool:
    """Microsoft Graph API ilə istifadəçinin admin qrupunda olub-olmadığını yoxlayır."""
    if not ADMIN_GROUP_ID:
        log.error("ADMIN_GROUP_ID is not configured")
        return False
    
    url = f"https://graph.microsoft.com/v1.0/me/memberOf"
    headers = {"Authorization": f"Bearer {access_token}"}
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            res = await client.get(url, headers=headers)
            res.raise_for_status()
            data = res.json()
            for grp in data.get("value", []):
                if grp.get("id") == ADMIN_GROUP_ID:
                    return True
            return False
    except Exception as e:
        log.error("Failed to verify admin group: %s", e)
        return False

# ============= AUTH ENDPOINTS =============
@app.get("/auth/login")
async def auth_login(request: Request):
    """Microsoft login səhifəsinə yönləndirir."""
    if not (TENANT_ID and CLIENT_ID):
        raise HTTPException(status_code=500, detail="OAuth not configured")
    
    origin = get_origin(request)
    redirect_uri = f"{origin}/api/auth/callback"
    state = secrets.token_urlsafe(32)
    
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "response_mode": "query",
        "scope": " ".join(SCOPES),
        "state": state,
        "prompt": "select_account",
    }
    qs = "&".join(f"{k}={httpx.URL('').copy_with(params={k: v})}".split("?")[-1] for k, v in params.items())
    # Sadə qurma:
    from urllib.parse import urlencode
    auth_url = f"{AUTHORIZE_URL}?{urlencode(params)}"
    
    response = RedirectResponse(url=auth_url, status_code=302)
    response.set_cookie(
        "adda_oauth_state",
        state,
        max_age=600,
        httponly=True,
        secure=True,
        samesite="lax",
    )
    return response

@app.get("/auth/callback")
async def auth_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    """Microsoft login-dən qayıdışı işləyir."""
    origin = get_origin(request)
    
    if error:
        log.error("OAuth error from Microsoft: %s", error)
        return RedirectResponse(url=f"{origin}/login.html?error={error}", status_code=302)
    
    if not code:
        return RedirectResponse(url=f"{origin}/login.html?error=no_code", status_code=302)
    
    # State CSRF qoruması
    saved_state = request.cookies.get("adda_oauth_state", "")
    if not saved_state or saved_state != state:
        log.warning("State mismatch: cookie=%s, query=%s", saved_state, state)
        return RedirectResponse(url=f"{origin}/login.html?error=state_mismatch", status_code=302)
    
    # Code ilə token al
    redirect_uri = f"{origin}/api/auth/callback"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            token_res = await client.post(
                TOKEN_URL,
                data={
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "grant_type": "authorization_code",
                    "scope": " ".join(SCOPES),
                },
            )
            token_res.raise_for_status()
            tokens = token_res.json()
    except httpx.HTTPStatusError as e:
        log.error("Token exchange failed: %s — %s", e.response.status_code, e.response.text)
        return RedirectResponse(url=f"{origin}/login.html?error=token_exchange_failed", status_code=302)
    except Exception as e:
        log.error("Token exchange exception: %s", e)
        return RedirectResponse(url=f"{origin}/login.html?error=token_exchange_failed", status_code=302)
    
    id_token = tokens.get("id_token")
    access_token = tokens.get("access_token")
    if not id_token or not access_token:
        return RedirectResponse(url=f"{origin}/login.html?error=no_token", status_code=302)
    
    # id_token-i decode et (signature yoxlanması olmadan — Microsoft-dan gəldiyinə əminik)
    try:
        # JWKS ilə signature yoxlanması
        jwks_client = PyJWKClient(JWKS_URL)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256"],
            audience=CLIENT_ID,
            issuer=ISSUER,
        )
    except Exception as e:
        log.error("ID token verification failed: %s", e)
        return RedirectResponse(url=f"{origin}/login.html?error=invalid_token", status_code=302)
    
    user_id = claims.get("oid") or claims.get("sub")
    user_email = claims.get("preferred_username") or claims.get("email", "")
    user_name = claims.get("name", "")
    
    # Token-də gələn qrup siyahısını yoxla
    groups = claims.get("groups", [])
    is_admin = ADMIN_GROUP_ID in groups
    
    # Token-də qrup yoxdursa (overage), Graph API ilə yoxla
    if not is_admin and "_claim_names" in claims:
        is_admin = await verify_user_in_admin_group(access_token, user_id)
    
    if not is_admin:
        log.info("Access denied for user %s (%s) — not in admin group", user_email, user_id)
        return RedirectResponse(url=f"{origin}/login.html?error=not_authorized", status_code=302)
    
    log.info("Admin login: %s (%s)", user_name, user_email)
    
    # Session token yarat
    session_token = create_session_token({
        "sub": user_id,
        "email": user_email,
        "name": user_name,
    })
    
    # Cookie-də saxla, admin.html-ə yönləndir
    response = RedirectResponse(url=f"{origin}/admin.html", status_code=302)
    response.set_cookie(
        "adda_session",
        session_token,
        max_age=7 * 24 * 60 * 60,
        httponly=True,
        secure=True,
        samesite="lax",
    )
    response.delete_cookie("adda_oauth_state")
    return response

@app.get("/auth/me")
async def auth_me(user=Depends(require_admin)):
    """Cari session sahibinin məlumatları."""
    return {
        "email": user["email"],
        "name": user["name"],
        "sub": user["sub"],
    }

@app.post("/auth/logout")
async def auth_logout():
    """Session cookie-sini silir."""
    response = JSONResponse({"status": "ok"})
    response.delete_cookie("adda_session")
    return response

# ============= BLOB UPLOAD =============
async def upload_to_blob(file: UploadFile, prefix: str) -> str:
    """Vercel Blob-a faylı yükləyir, public URL qaytarır."""
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

# ============= PUBLIC ENDPOINTS =============
@app.get("/health")
async def health():
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        put_conn(conn)
        oauth_ok = bool(TENANT_ID and CLIENT_ID and CLIENT_SECRET and ADMIN_GROUP_ID and SESSION_SECRET)
        return {
            "status": "ok",
            "database": "connected",
            "oauth": "configured" if oauth_ok else "missing_env",
        }
    except Exception as e:
        log.error("Health check failed: %s", e)
        return {"status": "error", "database": str(e)}

@app.get("/courses")
async def courses():
    """Public — index.html bunu çağırır."""
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
                "sort_order": row[12],
            }
            for row in rows
        ]
    except Exception as e:
        log.error("Courses fetch failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            put_conn(conn)

@app.post("/enroll")
async def enroll(
    name: str = Form(...),
    phone: str = Form(...),
    fin: str = Form(...),
    email: str = Form(...),
    course_name: str = Form(...),
    course_code: str = Form(...),
    workplace_id: str = Form(""),
    workplace_other: str = Form(""),
    position: str = Form(""),
    experience_years: str = Form(""),
    id_file: UploadFile = File(None),
    diploma_file: UploadFile = File(None),
    work_file: UploadFile = File(None),
    medical_file: UploadFile = File(None),
    application_file: UploadFile = File(None),
    receipt_file: UploadFile = File(None),
):
    """Public — form qeydiyyatı."""
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
                log.info("Uploaded %s -> %s", field_name, url)
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
              (student_name, phone, fin, email, course_name, course_code, files, status,
               workplace_id, workplace_other, position, experience_years)
            VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, 'pending',
                    %s, %s, %s, %s)
            """,
            (name, phone, fin, email, course_name, course_code, json.dumps(files),
             workplace_id or None, workplace_other or None, position or None,
             int(experience_years) if experience_years.strip().isdigit() else None),
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

# ============= ADMIN ENDPOINTS (qorunan) =============
@app.get("/students")
async def students(user=Depends(require_admin)):
    """Admin — bütün qeydiyyatlar."""
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, created_at, student_name, fin, phone, email,
                   course_name, course_code, status, files,
                   workplace_id, workplace_other, position, experience_years
            FROM enrollments
            ORDER BY id DESC
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
                "created_at": row[1].isoformat() if row[1] else None,
                "student_name": row[2],
                "fin": row[3],
                "phone": row[4],
                "email": row[5],
                "course_name": row[6],
                "course_code": row[7],
                "status": row[8],
                "files": files_data,
                "workplace_id": row[9],
                "workplace_other": row[10],
                "position": row[11],
                "experience_years": row[12],
            })
        return result
    except Exception as e:
        log.error("Students fetch failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            put_conn(conn)

class StatusUpdate(BaseModel):
    status: str

@app.patch("/enrollments/{enrollment_id}/status")
async def update_status(enrollment_id: int, body: StatusUpdate, user=Depends(require_admin)):
    """Admin — qeydiyyat statusu dəyişdir."""
    allowed = {"pending", "approved", "rejected", "contacted"}
    if body.status not in allowed:
        raise HTTPException(status_code=400, detail=f"Status must be one of: {', '.join(allowed)}")

    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            "SELECT status FROM enrollments WHERE id = %s",
            (enrollment_id,)
        )
        old_row = cur.fetchone()
        if old_row is None:
            raise HTTPException(status_code=404, detail="Enrollment not found")
        old_status = old_row[0]

        cur.execute(
            "UPDATE enrollments SET status = %s WHERE id = %s",
            (body.status, enrollment_id),
        )

        cur.execute(
            """INSERT INTO enrollment_audit_log
               (enrollment_id, admin_email, admin_name, action, details)
               VALUES (%s, %s, %s, %s, %s::jsonb)""",
            (enrollment_id, user["email"], user.get("name", ""), "status_changed",
             json.dumps({"from": old_status, "to": body.status}))
        )
        conn.commit()
        cur.close()
        log.info("Status updated by %s: enrollment %s -> %s", user["email"], enrollment_id, body.status)
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


class NoteCreate(BaseModel):
    content: str


@app.get("/enrollments/{enrollment_id}/notes")
async def get_notes(enrollment_id: int, user=Depends(require_admin)):
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT id, author_email, author_name, content, created_at
               FROM enrollment_notes
               WHERE enrollment_id = %s
               ORDER BY created_at DESC""",
            (enrollment_id,)
        )
        rows = cur.fetchall()
        cur.close()
        return [
            {
                "id": r[0],
                "author_email": r[1],
                "author_name": r[2],
                "content": r[3],
                "created_at": r[4].isoformat() if r[4] else None,
            }
            for r in rows
        ]
    except Exception as e:
        log.error("Notes fetch failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            put_conn(conn)


@app.post("/enrollments/{enrollment_id}/notes")
async def create_note(enrollment_id: int, body: NoteCreate, user=Depends(require_admin)):
    if not body.content.strip():
        raise HTTPException(status_code=400, detail="Note content cannot be empty")

    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute("SELECT id FROM enrollments WHERE id = %s", (enrollment_id,))
        if cur.fetchone() is None:
            raise HTTPException(status_code=404, detail="Enrollment not found")

        cur.execute(
            """INSERT INTO enrollment_notes
               (enrollment_id, author_email, author_name, content)
               VALUES (%s, %s, %s, %s)
               RETURNING id, created_at""",
            (enrollment_id, user["email"], user.get("name", ""), body.content.strip())
        )
        note_row = cur.fetchone()

        cur.execute(
            """INSERT INTO enrollment_audit_log
               (enrollment_id, admin_email, admin_name, action, details)
               VALUES (%s, %s, %s, %s, %s::jsonb)""",
            (enrollment_id, user["email"], user.get("name", ""), "note_added",
             json.dumps({"note_id": note_row[0], "preview": body.content.strip()[:100]}))
        )
        conn.commit()
        cur.close()
        return {
            "id": note_row[0],
            "author_email": user["email"],
            "author_name": user.get("name", ""),
            "content": body.content.strip(),
            "created_at": note_row[1].isoformat()
        }
    except HTTPException:
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        log.error("Note create failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            put_conn(conn)


@app.get("/enrollments/{enrollment_id}/audit")
async def get_audit(enrollment_id: int, user=Depends(require_admin)):
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT id, admin_email, admin_name, action, details, created_at
               FROM enrollment_audit_log
               WHERE enrollment_id = %s
               ORDER BY created_at DESC
               LIMIT 200""",
            (enrollment_id,)
        )
        rows = cur.fetchall()
        cur.close()
        return [
            {
                "id": r[0],
                "admin_email": r[1],
                "admin_name": r[2],
                "action": r[3],
                "details": r[4] if isinstance(r[4], dict) else (json.loads(r[4]) if r[4] else {}),
                "created_at": r[5].isoformat() if r[5] else None,
            }
            for r in rows
        ]
    except Exception as e:
        log.error("Audit fetch failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            put_conn(conn)


class FileView(BaseModel):
    file_key: str


@app.post("/enrollments/{enrollment_id}/file-view")
async def log_file_view(enrollment_id: int, body: FileView, user=Depends(require_admin)):
    """Log when admin views a file. Fire-and-forget."""
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO enrollment_audit_log
               (enrollment_id, admin_email, admin_name, action, details)
               VALUES (%s, %s, %s, %s, %s::jsonb)""",
            (enrollment_id, user["email"], user.get("name", ""), "file_viewed",
             json.dumps({"file": body.file_key}))
        )
        conn.commit()
        cur.close()
        return {"status": "ok"}
    except Exception as e:
        log.error("File view log failed: %s", e)
        return {"status": "ok"}
    finally:
        if conn:
            put_conn(conn)
