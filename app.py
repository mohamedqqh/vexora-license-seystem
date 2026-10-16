import os
import secrets
import sqlite3
import string
from datetime import datetime, timedelta, timezone
from functools import wraps

from fastapi import FastAPI, Request, Form, Header, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware
from passlib.context import CryptContext

APP_NAME = "VEXORA License System"
DATABASE_PATH = os.getenv("DATABASE_PATH", "licenses.db")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
API_SHARED_SECRET = os.getenv("API_SHARED_SECRET", "")
DEFAULT_HOURS = 48
DEFAULT_DEVICE_LIMIT = 2

if not ADMIN_PASSWORD or not SESSION_SECRET or not API_SHARED_SECRET:
    # Keep the app runnable locally but make deployment misconfiguration visible.
    print("WARNING: Set ADMIN_PASSWORD, SESSION_SECRET, and API_SHARED_SECRET environment variables.")

app = FastAPI(title=APP_NAME)
app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET or secrets.token_urlsafe(32), https_only=True, same_site="lax")
templates = Jinja2Templates(directory="templates")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def now_utc():
    return datetime.now(timezone.utc)


def dt_to_str(value):
    return value.astimezone(timezone.utc).isoformat()


def parse_dt(value):
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def db():
    conn = sqlite3.connect(DATABASE_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    with db() as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT NOT NULL UNIQUE,
            duration_hours INTEGER NOT NULL,
            device_limit INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            activated_at TEXT,
            expires_at TEXT,
            status TEXT NOT NULL DEFAULT 'active'
        )""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            first_seen_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            UNIQUE(license_id, device_id),
            FOREIGN KEY(license_id) REFERENCES licenses(id) ON DELETE CASCADE
        )""")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_license ON devices(license_id)")


init_db()


def is_logged_in(request: Request):
    return bool(request.session.get("admin_logged_in"))


def require_admin(request: Request):
    if not is_logged_in(request):
        raise HTTPException(status_code=401, detail="تسجيل الدخول مطلوب")


def make_key():
    alphabet = string.ascii_uppercase + string.digits
    return "VEX-" + "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3))


def device_count(conn, license_id):
    return conn.execute("SELECT COUNT(*) FROM devices WHERE license_id = ?", (license_id,)).fetchone()[0]


def license_status(row, current):
    if row["status"] != "active":
        return row["status"]
    if row["expires_at"] and current >= parse_dt(row["expires_at"]):
        return "expired"
    return "active"


@app.get("/health")
def health():
    return {"ok": True, "service": APP_NAME}


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    if not is_logged_in(request):
        return RedirectResponse("/login", status_code=303)
    with db() as conn:
        rows = conn.execute("""
          SELECT l.*, (SELECT COUNT(*) FROM devices d WHERE d.license_id=l.id) AS registered_devices
          FROM licenses l ORDER BY l.id DESC
        """).fetchall()
    current = now_utc()
    items = []
    for row in rows:
        item = dict(row)
        item["effective_status"] = license_status(row, current)
        items.append(item)
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "items": items, "default_hours": DEFAULT_HOURS,
        "default_devices": DEFAULT_DEVICE_LIMIT, "app_name": APP_NAME
    })


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    if is_logged_in(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse("login.html", {"request": request, "error": ""})


@app.post("/login", response_class=HTMLResponse)
def login(request: Request, password: str = Form(...)):
    if not ADMIN_PASSWORD or not secrets.compare_digest(password, ADMIN_PASSWORD):
        return templates.TemplateResponse("login.html", {"request": request, "error": "كلمة المرور غير صحيحة أو لم يتم ضبطها في متغيرات البيئة"}, status_code=401)
    request.session.clear()
    request.session["admin_logged_in"] = True
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


@app.post("/admin/licenses")
def create_license(request: Request, duration_hours: int = Form(...), device_limit: int = Form(...)):
    require_admin(request)
    if duration_hours < 1 or duration_hours > 24 * 3650:
        raise HTTPException(status_code=400, detail="المدة يجب أن تكون بين ساعة و10 سنوات")
    if device_limit < 1 or device_limit > 10000:
        raise HTTPException(status_code=400, detail="حد الأجهزة يجب أن يكون بين 1 و10000")
    with db() as conn:
        for _ in range(10):
            key = make_key()
            try:
                conn.execute("""
                  INSERT INTO licenses(key, duration_hours, device_limit, created_at, status)
                  VALUES(?,?,?,?, 'active')
                """, (key, duration_hours, device_limit, dt_to_str(now_utc())))
                break
            except sqlite3.IntegrityError:
                continue
        else:
            raise HTTPException(status_code=500, detail="تعذر إنشاء كود فريد")
    return RedirectResponse("/", status_code=303)


@app.post("/admin/licenses/{license_id}/status")
def update_status(request: Request, license_id: int, status: str = Form(...)):
    require_admin(request)
    if status not in ("active", "banned"):
        raise HTTPException(status_code=400, detail="حالة غير صالحة")
    with db() as conn:
        result = conn.execute("UPDATE licenses SET status=? WHERE id=?", (status, license_id))
        if result.rowcount == 0:
            raise HTTPException(status_code=404, detail="الكود غير موجود")
    return RedirectResponse("/", status_code=303)


@app.post("/admin/licenses/{license_id}/delete")
def delete_license(request: Request, license_id: int):
    require_admin(request)
    with db() as conn:
        conn.execute("DELETE FROM licenses WHERE id=?", (license_id,))
    return RedirectResponse("/", status_code=303)


@app.post("/admin/licenses/{license_id}/renew")
def renew_license(request: Request, license_id: int, duration_hours: int = Form(...)):
    require_admin(request)
    if duration_hours < 1 or duration_hours > 24 * 3650:
        raise HTTPException(status_code=400, detail="المدة يجب أن تكون بين ساعة و10 سنوات")
    with db() as conn:
        row = conn.execute("SELECT * FROM licenses WHERE id=?", (license_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="الكود غير موجود")
        current = now_utc()
        if row["expires_at"] and parse_dt(row["expires_at"]) > current:
            new_expiry = parse_dt(row["expires_at"]) + timedelta(hours=duration_hours)
        else:
            new_expiry = current + timedelta(hours=duration_hours)
        conn.execute("UPDATE licenses SET expires_at=?, status='active' WHERE id=?",
                     (dt_to_str(new_expiry), license_id))
    return RedirectResponse("/", status_code=303)


def require_api_secret(x_api_secret: str | None):
    if not API_SHARED_SECRET or not x_api_secret or not secrets.compare_digest(x_api_secret, API_SHARED_SECRET):
        raise HTTPException(status_code=401, detail="غير مصرح")


@app.post("/api/v1/activate")
async def activate(request: Request, x_api_secret: str | None = Header(default=None)):
    require_api_secret(x_api_secret)
    payload = await request.json()
    key = str(payload.get("key", "")).strip().upper()
    device_id = str(payload.get("device_id", "")).strip()
    if not key or not device_id or len(device_id) > 200 or len(key) > 100:
        raise HTTPException(status_code=400, detail="أدخل الكود ومعرّف الجهاز")
    current = now_utc()
    with db() as conn:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()
        if not row:
            return JSONResponse({"ok": False, "status": "invalid", "message": "كود التفعيل غير صحيح"}, status_code=403)
        status = license_status(row, current)
        if status != "active":
            return JSONResponse({"ok": False, "status": status, "message": "الترخيص منتهي أو محظور"}, status_code=403)
        known = conn.execute("SELECT id FROM devices WHERE license_id=? AND device_id=?", (row["id"], device_id)).fetchone()
        if not known:
            count = device_count(conn, row["id"])
            if count >= row["device_limit"]:
                return JSONResponse({"ok": False, "status": "device_limit", "message": "تم الوصول إلى الحد الأقصى للأجهزة"}, status_code=403)
            stamp = dt_to_str(current)
            conn.execute("INSERT INTO devices(license_id,device_id,first_seen_at,last_seen_at) VALUES(?,?,?,?)",
                         (row["id"], device_id, stamp, stamp))
        else:
            conn.execute("UPDATE devices SET last_seen_at=? WHERE id=?", (dt_to_str(current), known["id"]))
        if not row["expires_at"]:
            expiry = current + timedelta(hours=row["duration_hours"])
            conn.execute("UPDATE licenses SET activated_at=?, expires_at=? WHERE id=?",
                         (dt_to_str(current), dt_to_str(expiry), row["id"]))
            expires_at = expiry
        else:
            expires_at = parse_dt(row["expires_at"])
        return {"ok": True, "status": "active", "expires_at": dt_to_str(expires_at),
                "remaining_seconds": max(0, int((expires_at-current).total_seconds())),
                "registered_devices": device_count(conn, row["id"]), "device_limit": row["device_limit"]}


@app.post("/api/v1/verify")
async def verify(request: Request, x_api_secret: str | None = Header(default=None)):
    require_api_secret(x_api_secret)
    payload = await request.json()
    key = str(payload.get("key", "")).strip().upper()
    device_id = str(payload.get("device_id", "")).strip()
    current = now_utc()
    with db() as conn:
        row = conn.execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()
        if not row:
            return JSONResponse({"ok": False, "status": "invalid", "message": "كود التفعيل غير صحيح"}, status_code=403)
        status = license_status(row, current)
        if status != "active":
            return JSONResponse({"ok": False, "status": status, "message": "الترخيص منتهي أو محظور"}, status_code=403)
        device = conn.execute("SELECT id FROM devices WHERE license_id=? AND device_id=?", (row["id"], device_id)).fetchone()
        if not device:
            return JSONResponse({"ok": False, "status": "device_not_registered", "message": "هذا الجهاز غير مسجل"}, status_code=403)
        expiry = parse_dt(row["expires_at"]) if row["expires_at"] else None
        if not expiry:
            return JSONResponse({"ok": False, "status": "not_activated", "message": "يجب تفعيل الترخيص أولاً"}, status_code=403)
        return {"ok": True, "status": "active", "expires_at": dt_to_str(expiry),
                "remaining_seconds": max(0, int((expiry-current).total_seconds()))}
