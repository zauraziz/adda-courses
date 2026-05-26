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

# Email sender configuration
EMAIL_FROM = os.getenv("EMAIL_FROM", "zaur.aziz@adda.edu.az")
EMAIL_FROM_NAME = os.getenv("EMAIL_FROM_NAME", "ADDA Tədris Şöbəsi")
GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"

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


# ============= EMAIL (Microsoft Graph) =============
async def get_graph_token() -> Optional[str]:
    """Get Microsoft Graph access token using client credentials flow."""
    if not (TENANT_ID and CLIENT_ID and CLIENT_SECRET):
        log.error("Microsoft Graph credentials not configured")
        return None

    token_url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            res = await client.post(
                token_url,
                data={
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                }
            )
            res.raise_for_status()
            return res.json().get("access_token")
    except Exception as e:
        log.error("Graph token fetch failed: %s", e)
        return None


def render_template(body: str, variables: dict) -> str:
    """Replace {{key}} placeholders in template body."""
    result = body
    for k, v in variables.items():
        result = result.replace("{{" + k + "}}", str(v) if v is not None else "")
    return result


async def send_email_via_graph(to_email: str, to_name: str, subject: str, body_html: str):
    """Send email via Microsoft Graph API. Returns (success, error_message)."""
    token = await get_graph_token()
    if not token:
        return False, "Failed to obtain Graph token"

    url = f"{GRAPH_BASE_URL}/users/{EMAIL_FROM}/sendMail"
    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": body_html},
            "toRecipients": [
                {"emailAddress": {"address": to_email, "name": to_name or to_email}}
            ],
            "from": {
                "emailAddress": {"address": EMAIL_FROM, "name": EMAIL_FROM_NAME}
            }
        },
        "saveToSentItems": True
    }
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            res = await client.post(url, json=payload, headers=headers)
            if res.status_code in (200, 202):
                return True, ""
            error_text = res.text[:500] if res.text else f"HTTP {res.status_code}"
            log.error("Graph sendMail failed: %s - %s", res.status_code, error_text)
            return False, f"HTTP {res.status_code}: {error_text}"
    except Exception as e:
        log.error("Graph sendMail exception: %s", e)
        return False, str(e)


async def send_enrollment_email(enrollment_id: int, template_key: str, sent_by: str = "system") -> dict:
    """Load template, render with enrollment data, send via Graph, log to DB."""
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()

        cur.execute(
            """SELECT id, student_name, email, course_name, course_code,
                      price_at_enrollment, created_at
               FROM enrollments WHERE id = %s""",
            (enrollment_id,)
        )
        e = cur.fetchone()
        if not e:
            cur.close()
            return {"success": False, "error": "Enrollment not found"}

        e_id, e_name, e_email, e_course_name, e_course_code, e_price, e_created = e

        if not e_email:
            cur.close()
            return {"success": False, "error": "Enrollment has no email"}

        cur.execute(
            "SELECT subject, body_html, auto_send FROM email_templates WHERE template_key = %s",
            (template_key,)
        )
        t = cur.fetchone()
        if not t:
            cur.close()
            return {"success": False, "error": f"Template '{template_key}' not found"}

        subject_tpl, body_tpl, auto_send = t

        if sent_by == "system" and not auto_send:
            cur.close()
            return {"success": False, "error": "Auto-send disabled for this template", "skipped": True}

        date_str = ""
        if e_created:
            date_str = f"{e_created.day:02d}.{e_created.month:02d}.{e_created.year}"

        variables = {
            "name": e_name or "",
            "course_name": e_course_name or "",
            "course_code": e_course_code or "",
            "registration_number": str(e_id),
            "price": f"{e_price:.2f}" if e_price else "—",
            "date": date_str,
            "email": e_email,
        }

        subject = render_template(subject_tpl, variables)
        body = render_template(body_tpl, variables)

        success, error_msg = await send_email_via_graph(e_email, e_name, subject, body)

        cur.execute(
            """INSERT INTO email_log (enrollment_id, template_key, to_email, to_name, subject, body_preview, status, error_message, sent_by)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
               RETURNING id""",
            (enrollment_id, template_key, e_email, e_name, subject, body[:200],
             "sent" if success else "failed", error_msg if not success else None, sent_by)
        )
        log_id = cur.fetchone()[0]
        conn.commit()
        cur.close()

        return {
            "success": success,
            "log_id": log_id,
            "error": error_msg if not success else None
        }
    except Exception as e:
        if conn:
            conn.rollback()
        log.error("send_enrollment_email failed: %s", e)
        return {"success": False, "error": str(e)}
    finally:
        if conn:
            put_conn(conn)


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
async def courses(include_inactive: bool = False, user_data: dict = None):
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        where_clause = "" if include_inactive else "WHERE active = true"
        cur.execute(
            f"""
            SELECT id, code, name, level, stcw, subtitle,
                   duration_weeks, hours, price, currency, price_note, active, sort_order,
                   topics, icon
            FROM courses
            {where_clause}
            ORDER BY sort_order ASC, name ASC
            """
        )
        rows = cur.fetchall()
        cur.close()
        return [
            {
                "id": row[0], "code": row[1], "name": row[2], "level": row[3],
                "stcw": row[4], "subtitle": row[5], "duration_weeks": row[6],
                "hours": row[7], "price": float(row[8]) if row[8] is not None else None,
                "currency": row[9], "price_note": row[10], "active": row[11],
                "sort_order": row[12],
                "topics": row[13] if isinstance(row[13], list) else (json.loads(row[13]) if row[13] else []),
                "icon": row[14] or "compass",
            }
            for row in rows
        ]
    except Exception as e:
        log.error("Courses fetch failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            put_conn(conn)

class EnrollRequest(BaseModel):
    name: str
    phone: str
    fin: str
    email: str
    course_name: str
    course_code: str
    workplace_id: str = ""
    workplace_other: str = ""
    position: str = ""
    experience_years: str = ""
    files: dict = {}  # {field_name: url}


@app.post("/upload-file")
async def upload_single_file(
    file: UploadFile = File(...),
    prefix: str = Form(...),
    field: str = Form(...)
):
    """Upload a single file to Vercel Blob. Public — used by registration form before /enroll."""
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    allowed_fields = {"id_file", "diploma_file", "work_file", "medical_file", "application_file", "receipt_file"}
    if field not in allowed_fields:
        raise HTTPException(status_code=400, detail=f"Invalid field: {field}")

    content_type = (file.content_type or "").lower()
    if not (content_type == "application/pdf" or file.filename.lower().endswith(".pdf")):
        raise HTTPException(status_code=400, detail="Yalnız PDF faylları qəbul edilir")

    safe_prefix = "".join(c for c in prefix if c.isalnum() or c in "-_")[:50]

    try:
        url = await upload_to_blob(file, f"{safe_prefix}_{field}")
        return {"status": "success", "url": url, "field": field}
    except Exception as e:
        log.error("Single file upload failed (%s): %s", field, e)
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/enroll")
async def enroll(body: EnrollRequest):
    """Public — form qeydiyyatı. JSON body with pre-uploaded Blob URLs."""
    log.info("Enroll: name=%s fin=%s course=%s files=%s",
             body.name, body.fin, body.course_code, list(body.files.keys()))

    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()

        # Snapshot the current course price
        cur.execute("SELECT price FROM courses WHERE code = %s", (body.course_code,))
        price_row = cur.fetchone()
        snapshot_price = price_row[0] if price_row else None

        exp_years = None
        if body.experience_years and body.experience_years.strip().isdigit():
            exp_years = int(body.experience_years.strip())

        cur.execute(
            """
            INSERT INTO enrollments
              (student_name, phone, fin, email, course_name, course_code, files, status,
               workplace_id, workplace_other, position, experience_years, price_at_enrollment)
            VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, 'pending',
                    %s, %s, %s, %s, %s)
            RETURNING id
            """,
            (body.name, body.phone, body.fin, body.email, body.course_name, body.course_code,
             json.dumps(body.files),
             body.workplace_id or None, body.workplace_other or None, body.position or None,
             exp_years, snapshot_price),
        )
        new_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
        log.info("Enrollment saved: id=%s %s %s", new_id, body.name, body.course_code)

        # Trigger auto-email (do not fail enrollment if email fails)
        try:
            email_result = await send_enrollment_email(new_id, "received", sent_by="system")
            if not email_result.get("success") and not email_result.get("skipped"):
                log.warning("Auto-email failed for new enrollment %s: %s", new_id, email_result.get("error"))
        except Exception as ee:
            log.warning("Auto-email exception for new enrollment %s: %s", new_id, ee)

        return {"status": "success", "message": "Qeydiyyat uğurla tamamlandı!", "id": new_id}
    except Exception as e:
        if conn:
            conn.rollback()
        log.error("DB insert failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
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
                   workplace_id, workplace_other, position, experience_years,
                   price_at_enrollment
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
                "workplace_id": row[10],
                "workplace_other": row[11],
                "position": row[12],
                "experience_years": row[13],
                "price_at_enrollment": float(row[14]) if row[14] is not None else None,
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

        # Trigger auto-email based on new status
        template_map = {
            "contacted": "contacted",
            "approved": "approved",
            "rejected": "rejected",
        }
        template_key = template_map.get(body.status)
        if template_key:
            try:
                email_result = await send_enrollment_email(enrollment_id, template_key, sent_by="system")
                if not email_result.get("success") and not email_result.get("skipped"):
                    log.warning("Auto-email failed for enrollment %s: %s", enrollment_id, email_result.get("error"))
            except Exception as ee:
                log.warning("Auto-email exception for enrollment %s: %s", enrollment_id, ee)

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


@app.get("/audit/recent")
async def get_recent_audit(user=Depends(require_admin)):
    """Get last 200 audit log entries across all enrollments — used by analytics dashboard."""
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT id, enrollment_id, admin_email, admin_name, action, details, created_at
               FROM enrollment_audit_log
               ORDER BY created_at DESC
               LIMIT 200"""
        )
        rows = cur.fetchall()
        cur.close()
        return [
            {
                "id": r[0],
                "enrollment_id": r[1],
                "admin_email": r[2],
                "admin_name": r[3],
                "action": r[4],
                "details": r[5] if isinstance(r[5], dict) else (json.loads(r[5]) if r[5] else {}),
                "created_at": r[6].isoformat() if r[6] else None,
            }
            for r in rows
        ]
    except Exception as e:
        log.error("Recent audit fetch failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            put_conn(conn)


class CourseInput(BaseModel):
    code: str
    name: str
    level: str = ""
    stcw: str = ""
    subtitle: str = ""
    duration_weeks: int
    hours: int
    price: float
    currency: str = "AZN"
    price_note: str = ""
    sort_order: int = 0
    active: bool = True
    topics: list[str] = []
    icon: str = "compass"


@app.post("/courses")
async def create_course(body: CourseInput, user=Depends(require_admin)):
    """Admin - create a new course."""
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()

        # Check code uniqueness
        cur.execute("SELECT id FROM courses WHERE code = %s", (body.code,))
        if cur.fetchone() is not None:
            raise HTTPException(status_code=409, detail=f"Course code '{body.code}' already exists")

        cur.execute(
            """INSERT INTO courses
               (code, name, level, stcw, subtitle, duration_weeks, hours, price, currency, price_note, sort_order, active, topics, icon)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s)
               RETURNING id""",
            (body.code, body.name, body.level, body.stcw, body.subtitle,
             body.duration_weeks, body.hours, body.price, body.currency,
             body.price_note, body.sort_order, body.active,
             json.dumps(body.topics), body.icon)
        )
        new_id = cur.fetchone()[0]

        # Audit log
        cur.execute(
            """INSERT INTO course_audit_log (course_code, admin_email, admin_name, action, details)
               VALUES (%s, %s, %s, %s, %s::jsonb)""",
            (body.code, user["email"], user.get("name", ""), "course_created",
             json.dumps({"name": body.name, "price": body.price}))
        )
        conn.commit()
        cur.close()
        return {"status": "success", "id": new_id, "code": body.code}
    except HTTPException:
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        log.error("Course create failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            put_conn(conn)


@app.patch("/courses/{code}")
async def update_course(code: str, body: CourseInput, user=Depends(require_admin)):
    """Admin - edit existing course."""
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()

        # Get current values for audit
        cur.execute(
            "SELECT name, price, active FROM courses WHERE code = %s",
            (code,)
        )
        old_row = cur.fetchone()
        if old_row is None:
            raise HTTPException(status_code=404, detail="Course not found")
        old_name, old_price, old_active = old_row

        cur.execute(
            """UPDATE courses
               SET name = %s, level = %s, stcw = %s, subtitle = %s,
                   duration_weeks = %s, hours = %s, price = %s, currency = %s,
                   price_note = %s, sort_order = %s, active = %s,
                   topics = %s::jsonb, icon = %s
               WHERE code = %s""",
            (body.name, body.level, body.stcw, body.subtitle,
             body.duration_weeks, body.hours, body.price, body.currency,
             body.price_note, body.sort_order, body.active,
             json.dumps(body.topics), body.icon, code)
        )

        # Build change log
        changes = {}
        if old_name != body.name: changes["name"] = {"from": old_name, "to": body.name}
        if float(old_price or 0) != float(body.price): changes["price"] = {"from": float(old_price or 0), "to": body.price}
        if old_active != body.active: changes["active"] = {"from": old_active, "to": body.active}

        if changes:
            cur.execute(
                """INSERT INTO course_audit_log (course_code, admin_email, admin_name, action, details)
                   VALUES (%s, %s, %s, %s, %s::jsonb)""",
                (code, user["email"], user.get("name", ""), "course_updated",
                 json.dumps(changes))
            )

        conn.commit()
        cur.close()
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        log.error("Course update failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            put_conn(conn)


@app.delete("/courses/{code}")
async def delete_course(code: str, user=Depends(require_admin)):
    """Admin - delete course (only if no enrollments exist)."""
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()

        # Check enrollments
        cur.execute("SELECT COUNT(*) FROM enrollments WHERE course_code = %s", (code,))
        count = cur.fetchone()[0]
        if count > 0:
            raise HTTPException(
                status_code=409,
                detail=f"Bu kursun {count} müraciəti var. Silmək əvəzinə deaktiv edin."
            )

        cur.execute("DELETE FROM courses WHERE code = %s RETURNING id", (code,))
        if cur.fetchone() is None:
            raise HTTPException(status_code=404, detail="Course not found")

        cur.execute(
            """INSERT INTO course_audit_log (course_code, admin_email, admin_name, action, details)
               VALUES (%s, %s, %s, %s, %s::jsonb)""",
            (code, user["email"], user.get("name", ""), "course_deleted", json.dumps({}))
        )
        conn.commit()
        cur.close()
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        log.error("Course delete failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            put_conn(conn)


class SendEmailRequest(BaseModel):
    template_key: str


@app.post("/enrollments/{enrollment_id}/send-email")
async def send_email_manual(enrollment_id: int, body: SendEmailRequest, user=Depends(require_admin)):
    """Admin manually sends an email to enrollment."""
    result = await send_enrollment_email(enrollment_id, body.template_key, sent_by=user["email"])
    if not result["success"]:
        raise HTTPException(status_code=500, detail=result.get("error", "Email send failed"))
    return result


@app.get("/enrollments/{enrollment_id}/emails")
async def get_enrollment_emails(enrollment_id: int, user=Depends(require_admin)):
    """Get email history for an enrollment."""
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT id, template_key, to_email, subject, body_preview, status,
                      error_message, sent_by, sent_at
               FROM email_log
               WHERE enrollment_id = %s
               ORDER BY sent_at DESC""",
            (enrollment_id,)
        )
        rows = cur.fetchall()
        cur.close()
        return [
            {
                "id": r[0], "template_key": r[1], "to_email": r[2], "subject": r[3],
                "body_preview": r[4], "status": r[5], "error_message": r[6],
                "sent_by": r[7], "sent_at": r[8].isoformat() if r[8] else None,
            }
            for r in rows
        ]
    except Exception as e:
        log.error("Email log fetch failed: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            put_conn(conn)


@app.get("/email-templates")
async def list_templates(user=Depends(require_admin)):
    """List all email templates."""
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """SELECT template_key, subject, body_html, auto_send, updated_at, updated_by
               FROM email_templates ORDER BY id"""
        )
        rows = cur.fetchall()
        cur.close()
        return [
            {
                "template_key": r[0], "subject": r[1], "body_html": r[2],
                "auto_send": r[3],
                "updated_at": r[4].isoformat() if r[4] else None,
                "updated_by": r[5],
            }
            for r in rows
        ]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            put_conn(conn)


class TemplateUpdate(BaseModel):
    subject: str
    body_html: str
    auto_send: bool = True


@app.patch("/email-templates/{template_key}")
async def update_template(template_key: str, body: TemplateUpdate, user=Depends(require_admin)):
    """Update an email template."""
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute(
            """UPDATE email_templates
               SET subject = %s, body_html = %s, auto_send = %s,
                   updated_at = NOW(), updated_by = %s
               WHERE template_key = %s""",
            (body.subject, body.body_html, body.auto_send, user["email"], template_key)
        )
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Template not found")
        conn.commit()
        cur.close()
        return {"status": "success"}
    except HTTPException:
        raise
    except Exception as e:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if conn:
            put_conn(conn)
