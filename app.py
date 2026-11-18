"""Service Health Monitor - Flask + SQLite.

Security notes (see README for the full justification):
  * SQL injection : every query is parameterised.
  * XSS           : Jinja2 autoescaping, no |safe, strict CSP (no inline scripts/styles).
  * CSRF          : Flask-WTF CSRFProtect on every state-changing request.
  * Passwords     : PBKDF2-HMAC-SHA256 (600k iterations, per-password salt).
  * Secrets       : read from environment; never hardcoded.
"""
import functools
import os
import re
import secrets
import sqlite3
import time
from collections import defaultdict, deque

import psutil
from flask import (Flask, abort, flash, g, jsonify, redirect, render_template,
                   request, session, url_for)
from cryptography.fernet import Fernet, InvalidToken
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

DATA_DIR = os.environ.get("DATA_DIR", "/data")
DB_PATH = os.path.join(DATA_DIR, "monitor.db")
MAX_LOGS = int(os.environ.get("MAX_LOGS_PER_USER", "5"))
if MAX_LOGS < 1 or MAX_LOGS > 100:
    raise ValueError("MAX_LOGS_PER_USER must be between 1 and 100")
STATUSES = ("Operational", "Degraded", "Down", "Maintenance")
PW_METHOD = "pbkdf2:sha256:600000"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
LOGIN_WINDOW, LOGIN_MAX_ATTEMPTS = 300, 8  # 8 failures / 5 min per (ip, username)


# --------------------------------------------------------------------- setup
def load_data_key() -> bytes:
    """Load a Fernet key from the environment or the persistent data volume.

    A backed-up database MUST be backed up with this key to retain access to logs.
    """
    env = os.environ.get("DATA_ENCRYPTION_KEY")
    if env:
        key = env.encode("ascii")
        Fernet(key)  # validate before app starts
        return key
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, ".data_key")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        with open(path, "rb") as fh:
            key = fh.read().strip()
        Fernet(key)
        return key
    with os.fdopen(fd, "wb") as fh:
        key = Fernet.generate_key()
        fh.write(key)
    return key


def encrypt_field(value: str) -> str:
    """Prefix makes encrypted values distinguishable from older database rows."""
    return "enc:v1:" + _fernet.encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_field(value: str) -> str:
    if value.startswith("enc:v1:"):
        return _fernet.decrypt(value[len("enc:v1:"):].encode("ascii")).decode("utf-8")
    return value  # legacy row only, migrated by init_db


def visible_logs(rows):
    """Decrypt only when authorized routes prepare records for templates."""
    result = []
    for row in rows:
        log = dict(row)
        log["service"] = decrypt_field(log["service"])
        log["description"] = decrypt_field(log["description"])
        result.append(log)
    return result


def load_secret_key() -> str:
    """SECRET_KEY env var wins. Otherwise generate a random key once and persist
    it in the data volume (mode 600) so sessions survive restarts."""
    key = os.environ.get("SECRET_KEY")
    if key:
        return key
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, ".secret_key")
    if os.path.exists(path):
        with open(path) as fh:
            return fh.read().strip()
    key = secrets.token_hex(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(key)
    return key


_fernet = Fernet(load_data_key())
app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=7200,
    MAX_CONTENT_LENGTH=16 * 1024,
)
csrf = CSRFProtect(app)


def connect():
    db = sqlite3.connect(DB_PATH, isolation_level=None, timeout=10)  # autocommit; we BEGIN explicitly
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def get_db():
    if "db" not in g:
        g.db = connect()
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    db = connect()
    db.execute("PRAGMA journal_mode = WAL")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            locked INTEGER NOT NULL DEFAULT 0,
            submission_count INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            service TEXT NOT NULL,
            status TEXT NOT NULL,
            description TEXT NOT NULL,
            flagged INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    """)
    # Upgrade older databases. Older versions stored both fields as plaintext.
    # Perform migration in one write transaction and back up /data first.
    db.execute("BEGIN IMMEDIATE")
    try:
        legacy = db.execute("SELECT id, service, description FROM logs").fetchall()
        for entry in legacy:
            new_service = (entry["service"] if entry["service"].startswith("enc:v1:")
                           else encrypt_field(entry["service"]))
            new_description = (entry["description"] if entry["description"].startswith("enc:v1:")
                               else encrypt_field(entry["description"]))
            if new_service != entry["service"] or new_description != entry["description"]:
                db.execute("UPDATE logs SET service = ?, description = ? WHERE id = ?",
                           (new_service, new_description, entry["id"]))
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        db.close()
        raise
    # Bootstrap the first admin from env vars; if no password is supplied,
    # generate one and print it ONCE to the container logs.
    if db.execute("SELECT 1 FROM users WHERE is_admin = 1").fetchone() is None:
        name = os.environ.get("ADMIN_USERNAME", "admin")
        pw = os.environ.get("ADMIN_PASSWORD")
        generated = pw is None
        if generated:
            pw = secrets.token_urlsafe(16)
        if not USERNAME_RE.fullmatch(name):
            raise RuntimeError("Invalid ADMIN_USERNAME: must match the registration username rules")
        existing = db.execute("SELECT id FROM users WHERE username = ?", (name,)).fetchone()
        if existing:
            raise RuntimeError("ADMIN_USERNAME already belongs to a standard user. "
                               "Choose a different ADMIN_USERNAME; privileges were NOT granted.")
        db.execute("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, 1)",
                   (name, generate_password_hash(pw, method=PW_METHOD)))
        if generated:
            print(f"[bootstrap] Generated first-run admin credentials -> username: {name} password: {pw}", flush=True)
            print("[bootstrap] Change/record this now; it is not shown again.", flush=True)
    db.close()


init_db()
_DUMMY_HASH = generate_password_hash("dummy-password-for-timing", method=PW_METHOD)
_attempts = defaultdict(deque)


# ------------------------------------------------------------ auth helpers
@app.before_request
def load_user():
    g.user = None
    uid = session.get("uid")
    if uid is not None:
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if g.user is None:
            session.clear()


def login_required(view):
    @functools.wraps(view)
    def wrapper(*a, **kw):
        if g.user is None:
            return redirect(url_for("login"))
        return view(*a, **kw)
    return wrapper


def admin_required(view):
    @functools.wraps(view)
    def wrapper(*a, **kw):
        if g.user is None:
            return redirect(url_for("login"))
        if not g.user["is_admin"]:
            abort(403)
        return view(*a, **kw)
    return wrapper


def throttled(key) -> bool:
    now, q = time.time(), _attempts[key]
    while q and now - q[0] > LOGIN_WINDOW:
        q.popleft()
    return len(q) >= LOGIN_MAX_ATTEMPTS


@app.after_request
def security_headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Cache-Control"] = "no-store"
    return resp


# ------------------------------------------------------------------ routes
@app.route("/")
def index():
    return redirect(url_for("dashboard" if g.user else "login"))


@app.route("/healthz")
def healthz():
    return jsonify(status="ok")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        pw, pw2 = request.form.get("password", ""), request.form.get("confirm", "")
        error = None
        if not USERNAME_RE.match(username):
            error = "Username must be 3-32 characters: letters, digits, . _ -"
        elif not 10 <= len(pw) <= 128:
            error = "Password must be 10-128 characters."
        elif pw != pw2:
            error = "Passwords do not match."
        if error:
            flash(error, "error")
        else:
            try:
                get_db().execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                                 (username, generate_password_hash(pw, method=PW_METHOD)))
                flash("Account created. Please log in.", "ok")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already taken.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        key = (request.remote_addr, username.lower())
        if throttled(key):
            flash("Too many failed attempts. Try again in a few minutes.", "error")
            return render_template("login.html"), 429
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        # Always run a hash check so response time doesn't reveal valid usernames.
        ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH,
                                 request.form.get("password", ""))
        if user and ok:
            _attempts.pop(key, None)
            session.clear()  # new session on login (prevents fixation)
            session["uid"] = user["id"]
            session.permanent = True
            return redirect(url_for("dashboard"))
        _attempts[key].append(time.time())
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


def collect_metrics():
    disk = psutil.disk_usage("/")
    mem = psutil.virtual_memory()
    load = psutil.getloadavg()
    # psutil metrics can reflect host visibility depending on the container runtime.
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.2),
        "cpu_count": psutil.cpu_count(),
        "load": [round(x, 2) for x in load],
        "mem_percent": mem.percent,
        "mem_used_mb": round(mem.used / 1048576),
        "mem_total_mb": round(mem.total / 1048576),
        "disk_percent": disk.percent,
        "disk_used_gb": round(disk.used / 1073741824, 2),
        "disk_total_gb": round(disk.total / 1073741824, 2),
        "uptime_min": int((time.time() - psutil.boot_time()) / 60),
    }


@app.route("/api/metrics")
@login_required
def api_metrics():
    return jsonify(collect_metrics())


@app.route("/dashboard")
@login_required
def dashboard():
    logs = get_db().execute(
        "SELECT * FROM logs WHERE user_id = ? ORDER BY id DESC", (g.user["id"],)).fetchall()
    return render_template("dashboard.html", metrics=collect_metrics(), logs=visible_logs(logs),
                           statuses=STATUSES, max_logs=MAX_LOGS)


@app.route("/logs", methods=["POST"])
@login_required
def submit_log():
    service = request.form.get("service", "").strip()
    status = request.form.get("status", "")
    desc = request.form.get("description", "").strip()
    if not (1 <= len(service) <= 64) or status not in STATUSES or not (1 <= len(desc) <= 1000):
        flash("Invalid entry: service (1-64 chars), a valid status and description (1-1000 chars) are required.", "error")
        return redirect(url_for("dashboard"))
    db = get_db()
    db.execute("BEGIN IMMEDIATE")  # atomic quota check + insert (no race between requests)
    try:
        cur = db.execute(
            "UPDATE users SET submission_count = submission_count + 1 "
            "WHERE id = ? AND locked = 0 AND submission_count < ?", (g.user["id"], MAX_LOGS))
        if cur.rowcount == 0:
            db.execute("ROLLBACK")
            flash("Submission refused: your account is locked or you reached the "
                  f"limit of {MAX_LOGS} entries.", "error")
            return redirect(url_for("dashboard"))
        db.execute("INSERT INTO logs (user_id, service, status, description) VALUES (?, ?, ?, ?)",
                   (g.user["id"], encrypt_field(service), status, encrypt_field(desc)))
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    flash("Log entry submitted.", "ok")
    return redirect(url_for("dashboard"))


# ------------------------------------------------------------------- admin
@app.route("/admin")
@admin_required
def admin():
    db = get_db()
    status = request.args.get("status", "")
    q = ("SELECT logs.*, users.username FROM logs JOIN users ON users.id = logs.user_id")
    args = ()
    if status in STATUSES:
        q += " WHERE logs.status = ?"
        args = (status,)
    logs = db.execute(q + " ORDER BY logs.id DESC", args).fetchall()
    users = db.execute("SELECT * FROM users ORDER BY id").fetchall()
    return render_template("admin.html", logs=visible_logs(logs), users=users, statuses=STATUSES,
                           current=status, max_logs=MAX_LOGS)


@app.route("/admin/logs/<int:log_id>/flag", methods=["POST"])
@admin_required
def flag_log(log_id):
    get_db().execute("UPDATE logs SET flagged = 1 - flagged WHERE id = ?", (log_id,))
    return redirect(url_for("admin"))


@app.route("/admin/logs/<int:log_id>/delete", methods=["POST"])
@admin_required
def delete_log(log_id):
    get_db().execute("DELETE FROM logs WHERE id = ?", (log_id,))
    flash("Log deleted.", "ok")
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:user_id>/lock", methods=["POST"])
@admin_required
def toggle_lock(user_id):
    db = get_db()
    target = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        abort(404)
    if target["is_admin"]:
        flash("Administrator accounts cannot be locked.", "error")
    else:
        db.execute("UPDATE users SET locked = 1 - locked WHERE id = ?", (user_id,))
        flash(f"User '{target['username']}' {'unlocked' if target['locked'] else 'locked'}.", "ok")
    return redirect(url_for("admin"))


@app.errorhandler(403)
def forbidden(_e):
    return render_template("error.html", code=403, msg="You don't have permission to view this page."), 403


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, msg="Page not found."), 404


@app.errorhandler(400)
def bad_request(_e):
    return render_template("error.html", code=400, msg="Bad request (your form may have expired - reload and retry)."), 400
