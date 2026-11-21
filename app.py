"""Service Health Monitor - Flask + SQLite.

Security notes (see README for the full justification):
  * SQL injection : every query is parameterised.
  * XSS           : Jinja2 autoescaping, no |safe, strict CSP (no inline scripts/styles).
  * CSRF          : Flask-WTF CSRFProtect on every state-changing request.
  * Passwords     : PBKDF2-HMAC-SHA256 (600k iterations, per-password salt).
  * Secrets       : are read from environment; never hardcoded.
"""
import csv
import functools
import io
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone

import psutil
from flask import (Flask, abort, flash, g, jsonify, make_response, redirect, render_template,
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
TICKET_STATUSES = ("Open", "In Progress", "Resolved", "Closed")
PRIORITIES = ("Low", "Medium", "High", "Critical")
PW_METHOD = "pbkdf2:sha256:600000"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
LOGIN_WINDOW, LOGIN_MAX_ATTEMPTS = 300, 8  # 8 failures / 5 min per IP and account
SESSION_IDLE_TIMEOUT_SECONDS = 15 * 60
METRIC_SAMPLE_INTERVAL_SECONDS = 60
METRIC_HISTORY_SECONDS = 24 * 60 * 60
TICKET_SELECT = """
    SELECT logs.*, users.username, assignee.username AS assigned_name,
           CASE WHEN COALESCE(logs.resolved_at, logs.closed_at) IS NOT NULL
                THEN MAX(0, CAST((julianday(COALESCE(logs.resolved_at, logs.closed_at))
                                  - julianday(logs.created_at)) * 86400 AS INTEGER))
                ELSE NULL END AS resolution_seconds
    FROM logs
    JOIN users ON users.id = logs.user_id
    LEFT JOIN users AS assignee ON assignee.id = logs.assigned_to
"""


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
    SESSION_IDLE_TIMEOUT_SECONDS=SESSION_IDLE_TIMEOUT_SECONDS,
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
            is_support INTEGER NOT NULL DEFAULT 0,
            session_version INTEGER NOT NULL DEFAULT 0,
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
            ticket_ref TEXT,
            ticket_status TEXT NOT NULL DEFAULT 'Open',
            priority TEXT NOT NULL DEFAULT 'Medium',
            assigned_to INTEGER REFERENCES users(id) ON DELETE SET NULL,
            resolved_at TEXT,
            closed_at TEXT,
            flagged INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS metric_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sampled_at INTEGER NOT NULL UNIQUE,
            cpu_percent REAL NOT NULL,
            mem_percent REAL NOT NULL,
            disk_percent REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS ticket_responses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER NOT NULL REFERENCES logs(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS ticket_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_id INTEGER NOT NULL REFERENCES logs(id) ON DELETE CASCADE,
            actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            log_id INTEGER REFERENCES logs(id) ON DELETE CASCADE,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            read_at TEXT
        );
        CREATE TABLE IF NOT EXISTS login_attempts (
            ip_address TEXT NOT NULL,
            username TEXT NOT NULL,
            failed_count INTEGER NOT NULL,
            window_started INTEGER NOT NULL,
            blocked_until INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (ip_address, username)
        );
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            attempted_username TEXT NOT NULL DEFAULT '',
            ip_address TEXT NOT NULL DEFAULT '',
            details TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS admin_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            target_type TEXT NOT NULL,
            target_id TEXT NOT NULL,
            details TEXT NOT NULL,
            ip_address TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
    """)
    user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
    if "is_support" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN is_support INTEGER NOT NULL DEFAULT 0")
    if "session_version" not in user_columns:
        db.execute("ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0")
    log_columns = {row["name"] for row in db.execute("PRAGMA table_info(logs)")}
    for column, definition in (
        ("ticket_ref", "TEXT"),
        ("ticket_status", "TEXT NOT NULL DEFAULT 'Open'"),
        ("priority", "TEXT NOT NULL DEFAULT 'Medium'"),
        ("assigned_to", "INTEGER REFERENCES users(id) ON DELETE SET NULL"),
        ("resolved_at", "TEXT"),
        ("closed_at", "TEXT"),
    ):
        if column not in log_columns:
            db.execute(f"ALTER TABLE logs ADD COLUMN {column} {definition}")
    # Upgrade older databases. Older versions stored both fields as plaintext.
    # Perform migration in one write transaction and back up /data first.
    db.execute("BEGIN IMMEDIATE")
    try:
        legacy = db.execute(
            "SELECT id, user_id, service, description, ticket_ref, created_at FROM logs"
        ).fetchall()
        for entry in legacy:
            new_service = (entry["service"] if entry["service"].startswith("enc:v1:")
                           else encrypt_field(entry["service"]))
            new_description = (entry["description"] if entry["description"].startswith("enc:v1:")
                               else encrypt_field(entry["description"]))
            if new_service != entry["service"] or new_description != entry["description"]:
                db.execute("UPDATE logs SET service = ?, description = ? WHERE id = ?",
                           (new_service, new_description, entry["id"]))
            if entry["ticket_ref"] is None:
                ticket_ref = f"INC-{entry['id']:04d}"
                db.execute("UPDATE logs SET ticket_ref = ? WHERE id = ?",
                           (ticket_ref, entry["id"]))
                db.execute(
                    "INSERT INTO ticket_events "
                    "(log_id, actor_id, event_type, details, created_at) "
                    "VALUES (?, ?, 'created', 'Imported from an existing service log.', ?)",
                    (entry["id"], entry["user_id"], entry["created_at"]))
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        db.close()
        raise
    db.executescript("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_logs_ticket_ref ON logs(ticket_ref);
        CREATE INDEX IF NOT EXISTS idx_ticket_responses_log_id
            ON ticket_responses(log_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_ticket_events_log_id
            ON ticket_events(log_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_notifications_user_unread
            ON notifications(user_id, read_at);
        CREATE INDEX IF NOT EXISTS idx_security_events_recent
            ON security_events(event_type, created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_admin_audit_recent
            ON admin_audit(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_login_attempts_blocked
            ON login_attempts(blocked_until);
    """)
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


#  auth helpers
@app.before_request
def load_user():
    g.user = None
    g.unread_notifications = 0
    uid = session.get("uid")
    if uid is not None and request.endpoint != "static":
        last_activity = session.get("last_activity")
        if (isinstance(last_activity, (int, float))
                and time.time() - last_activity > app.config["SESSION_IDLE_TIMEOUT_SECONDS"]):
            session.clear()
            uid = None
            flash("Your session expired due to inactivity. Please log in again.", "error")
            if request.endpoint != "login":
                return redirect(url_for("login"))
    if uid is not None:
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
        if g.user is None:
            session.clear()
        elif g.user["locked"]:
            session.clear()
            g.user = None
            flash("Your account is locked. Please contact an administrator.", "error")
            if request.endpoint != "login":
                return redirect(url_for("login"))
        elif session.get("session_version", 0) != g.user["session_version"]:
            session.clear()
            g.user = None
            flash("Your password or security settings changed. Please log in again.", "error")
            if request.endpoint != "login":
                return redirect(url_for("login"))
        else:
            if request.endpoint != "static":
                session["last_activity"] = time.time()
            g.unread_notifications = get_db().execute(
                "SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_at IS NULL",
                (g.user["id"],)).fetchone()[0]


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


def can_access_ticket(ticket, user):
    return bool(
        user["is_admin"]
        or ticket["user_id"] == user["id"]
        or (user["is_support"] and not user["locked"]
            and ticket["assigned_to"] == user["id"])
    )


def can_work_ticket(ticket, user):
    return bool(not user["locked"] and
                (user["is_admin"] or
                 (user["is_support"] and ticket["assigned_to"] == user["id"])))


def get_ticket_or_404(ticket_id):
    ticket = get_db().execute(TICKET_SELECT + " WHERE logs.id = ?", (ticket_id,)).fetchone()
    if ticket is None:
        abort(404)
    return ticket


def ticket_event(ticket_id, actor_id, event_type, details):
    get_db().execute(
        "INSERT INTO ticket_events (log_id, actor_id, event_type, details) VALUES (?, ?, ?, ?)",
        (ticket_id, actor_id, event_type, details))


def notify_ticket_owner(ticket, message, actor_id):
    if ticket["user_id"] != actor_id:
        get_db().execute(
            "INSERT INTO notifications (user_id, log_id, message) VALUES (?, ?, ?)",
            (ticket["user_id"], ticket["id"], message))


def normalize_service(value):
    return " ".join(value.casefold().split())


def record_security_event(event_type, details, attempted_username="", actor_id=None):
    db = get_db()
    db.execute(
        "DELETE FROM security_events WHERE event_type IN "
        "('login_failed', 'login_rate_limited', 'password_change_failed') "
        "AND created_at < datetime('now', '-90 days')")
    db.execute(
        "INSERT INTO security_events "
        "(event_type, actor_id, attempted_username, ip_address, details) "
        "VALUES (?, ?, ?, ?, ?)",
        (event_type, actor_id, attempted_username[:128],
         request.remote_addr or "", details))


def audit_admin_action(action, target_type, target_id, details):
    get_db().execute(
        "INSERT INTO admin_audit "
        "(actor_id, action, target_type, target_id, details, ip_address) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (g.user["id"], action, target_type, str(target_id), details,
         request.remote_addr or ""))


def login_throttled(ip_address, username, now=None):
    now = int(time.time()) if now is None else int(now)
    db = get_db()
    db.execute(
        "DELETE FROM login_attempts WHERE blocked_until <= ? AND window_started <= ?",
        (now, now - LOGIN_WINDOW))
    normalized_username = username.casefold()[:32]
    row = db.execute(
        "SELECT MAX(blocked_until) FROM login_attempts "
        "WHERE (ip_address = ? AND username = '') "
        "OR (ip_address = '' AND username = ?) "
        "OR (ip_address = ? AND username = ?)",
        (ip_address, normalized_username, ip_address, normalized_username)).fetchone()
    blocked_until = row[0] or 0
    return blocked_until > now


def record_failed_login(ip_address, username, now=None, details="Invalid username or password."):
    now = int(time.time()) if now is None else int(now)
    db = get_db()
    normalized_username = username.casefold()[:32]
    db.execute("BEGIN IMMEDIATE")
    try:
        record_security_event("login_failed", details, attempted_username=username)
        activated = False
        scopes = [(ip_address, "")]
        if normalized_username:
            scopes.append(("", normalized_username))
            if ip_address:
                scopes.append((ip_address, normalized_username))
        for scoped_ip, scoped_username in scopes:
            row = db.execute(
                "SELECT failed_count, window_started, blocked_until FROM login_attempts "
                "WHERE ip_address = ? AND username = ?",
                (scoped_ip, scoped_username)).fetchone()
            if row is None or now - row["window_started"] >= LOGIN_WINDOW:
                failed_count, window_started, blocked_until = 1, now, 0
                db.execute(
                    "INSERT INTO login_attempts "
                    "(ip_address, username, failed_count, window_started, blocked_until) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (scoped_ip, scoped_username, failed_count, window_started, blocked_until))
            else:
                failed_count = row["failed_count"] + 1
                window_started = row["window_started"]
                blocked_until = row["blocked_until"]
                if failed_count >= LOGIN_MAX_ATTEMPTS and blocked_until <= now:
                    blocked_until = now + LOGIN_WINDOW
                    activated = True
                db.execute(
                    "UPDATE login_attempts SET failed_count = ?, blocked_until = ? "
                    "WHERE ip_address = ? AND username = ?",
                    (failed_count, blocked_until, scoped_ip, scoped_username))
        if activated:
            record_security_event(
                "login_rate_limited", "Repeated failed logins triggered a temporary block.",
                attempted_username=username)
        db.execute("COMMIT")
    except Exception:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise


def clear_login_attempts(ip_address, username):
    normalized_username = username.casefold()[:32]
    get_db().execute(
        "DELETE FROM login_attempts WHERE ip_address = ? AND username = ''",
        (ip_address,))
    if normalized_username:
        get_db().execute(
            "DELETE FROM login_attempts WHERE username = ? "
            "AND ip_address IN (?, '')",
            (normalized_username, ip_address))


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


#  routes
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
        ip_address = request.remote_addr or ""
        if login_throttled(ip_address, username):
            flash("Too many failed attempts. Try again in a few minutes.", "error")
            return render_template("login.html"), 429
        user = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        # Always run a hash check so response time doesn't reveal valid usernames.
        ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH,
                                 request.form.get("password", ""))
        if user and ok and not user["locked"]:
            clear_login_attempts(ip_address, username)
            session.clear()  # new session on login (prevents fixation)
            session["uid"] = user["id"]
            session["session_version"] = user["session_version"]
            session["last_activity"] = time.time()
            session.permanent = True
            return redirect(url_for("dashboard"))
        details = ("Login rejected because the account is locked."
                   if user and user["locked"] and ok
                   else "Invalid username or password.")
        record_failed_login(ip_address, username, details=details)
        flash("Invalid username or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirmation = request.form.get("confirm_password", "")
        if not check_password_hash(g.user["password_hash"], current_password):
            record_security_event(
                "password_change_failed", "Current password verification failed.",
                actor_id=g.user["id"])
            flash("Current password is incorrect.", "error")
        elif not 10 <= len(new_password) <= 128:
            flash("New password must be 10-128 characters.", "error")
        elif new_password != confirmation:
            flash("New passwords do not match.", "error")
        elif check_password_hash(g.user["password_hash"], new_password):
            flash("Choose a password different from your current password.", "error")
        else:
            password_hash = generate_password_hash(new_password, method=PW_METHOD)
            db = get_db()
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(
                    "UPDATE users SET password_hash = ?, session_version = session_version + 1 "
                    "WHERE id = ?",
                    (password_hash, g.user["id"]))
                version = db.execute(
                    "SELECT session_version FROM users WHERE id = ?",
                    (g.user["id"],)).fetchone()["session_version"]
                record_security_event(
                    "password_changed", "Account password changed.", actor_id=g.user["id"])
                db.execute("COMMIT")
            except Exception:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
            session.clear()
            session["uid"] = g.user["id"]
            session["session_version"] = version
            session["last_activity"] = time.time()
            session.permanent = True
            flash("Password changed. Other active sessions have been signed out.", "ok")
            return redirect(url_for("dashboard"))
    return render_template("change_password.html")


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


def record_metric_sample(sampled_at, metrics):
    db = get_db()
    cursor = db.execute(
        "INSERT INTO metric_samples (sampled_at, cpu_percent, mem_percent, disk_percent) "
        "SELECT ?, ?, ?, ? WHERE NOT EXISTS ("
        "SELECT 1 FROM metric_samples WHERE sampled_at > ?)",
        (sampled_at, metrics["cpu_percent"], metrics["mem_percent"],
         metrics["disk_percent"], sampled_at - METRIC_SAMPLE_INTERVAL_SECONDS))
    if cursor.rowcount:
        db.execute("DELETE FROM metric_samples WHERE sampled_at < ?",
                   (sampled_at - METRIC_HISTORY_SECONDS,))


@app.route("/api/metrics")
@login_required
def api_metrics():
    metrics = collect_metrics()
    record_metric_sample(int(time.time()), metrics)
    return jsonify(metrics)


@app.route("/api/metrics/history")
@login_required
def api_metric_history():
    now = int(time.time())
    samples = get_db().execute(
        "SELECT sampled_at, cpu_percent, mem_percent, disk_percent "
        "FROM metric_samples WHERE sampled_at >= ? AND sampled_at <= ? "
        "ORDER BY sampled_at",
        (now - METRIC_HISTORY_SECONDS, now)).fetchall()
    return jsonify(samples=[
        {"time": row["sampled_at"], "cpu_percent": row["cpu_percent"],
         "mem_percent": row["mem_percent"], "disk_percent": row["disk_percent"]}
        for row in samples
    ])


@app.route("/api/tickets/suggestions")
@login_required
def ticket_suggestions():
    service = request.args.get("service", "").strip()
    if not service:
        return jsonify(suggestions=[])
    if len(service) > 64:
        abort(400)
    expected = normalize_service(service)
    rows = get_db().execute(
        "SELECT ticket_ref, ticket_status, service, created_at FROM logs "
        "WHERE ticket_status IN (?, ?) ORDER BY id DESC",
        ("Open", "In Progress")).fetchall()
    matches = []
    for row in rows:
        if normalize_service(decrypt_field(row["service"])) == expected:
            matches.append({
                "reference": row["ticket_ref"],
                "status": row["ticket_status"],
                "created_at": row["created_at"],
            })
            if len(matches) == 5:
                break
    return jsonify(suggestions=matches)


@app.route("/tickets")
@login_required
def ticket_queue():
    if g.user["is_admin"]:
        condition, args = "", ()
    elif g.user["is_support"] and not g.user["locked"]:
        condition, args = "WHERE logs.user_id = ? OR logs.assigned_to = ?", (
            g.user["id"], g.user["id"])
    else:
        condition, args = "WHERE logs.user_id = ?", (g.user["id"],)
    rows = get_db().execute(
        TICKET_SELECT + f" {condition} ORDER BY logs.id DESC", args).fetchall()
    return render_template("tickets.html", tickets=visible_logs(rows))


@app.route("/tickets/<int:ticket_id>")
@login_required
def ticket_detail(ticket_id):
    ticket = get_ticket_or_404(ticket_id)
    if not can_access_ticket(ticket, g.user):
        abort(403)
    ticket = visible_logs([ticket])[0]
    responses = get_db().execute(
        "SELECT ticket_responses.*, users.username FROM ticket_responses "
        "LEFT JOIN users ON users.id = ticket_responses.user_id "
        "WHERE ticket_responses.log_id = ? ORDER BY ticket_responses.id",
        (ticket_id,)).fetchall()
    responses = [dict(response, body=decrypt_field(response["body"]))
                 for response in responses]
    events = get_db().execute(
        "SELECT ticket_events.*, users.username FROM ticket_events "
        "LEFT JOIN users ON users.id = ticket_events.actor_id "
        "WHERE ticket_events.log_id = ? ORDER BY ticket_events.id",
        (ticket_id,)).fetchall()
    assignees = []
    if g.user["is_admin"]:
        assignees = get_db().execute(
            "SELECT id, username FROM users WHERE locked = 0 "
            "AND (is_admin = 1 OR is_support = 1) ORDER BY username").fetchall()
    return render_template(
        "ticket_detail.html", ticket=ticket, responses=responses, events=events,
        can_work=can_work_ticket(ticket, g.user), assignees=assignees,
        ticket_statuses=TICKET_STATUSES, priorities=PRIORITIES)


@app.route("/notifications")
@login_required
def notifications():
    items = get_db().execute(
        "SELECT notifications.*, logs.ticket_ref FROM notifications "
        "LEFT JOIN logs ON logs.id = notifications.log_id "
        "WHERE notifications.user_id = ? ORDER BY notifications.id DESC",
        (g.user["id"],)).fetchall()
    return render_template("notifications.html", notifications=items)


@app.route("/notifications/<int:notification_id>/read", methods=["POST"])
@login_required
def mark_notification_read(notification_id):
    cursor = get_db().execute(
        "UPDATE notifications SET read_at = CURRENT_TIMESTAMP "
        "WHERE id = ? AND user_id = ? AND read_at IS NULL",
        (notification_id, g.user["id"]))
    if cursor.rowcount == 0:
        exists = get_db().execute(
            "SELECT 1 FROM notifications WHERE id = ? AND user_id = ?",
            (notification_id, g.user["id"])).fetchone()
        if exists is None:
            abort(404)
    return redirect(url_for("notifications"))


@app.route("/dashboard")
@login_required
def dashboard():
    rows = get_db().execute(
        TICKET_SELECT + " WHERE logs.user_id = ? ORDER BY logs.id DESC",
        (g.user["id"],)).fetchall()
    return render_template("dashboard.html", metrics=collect_metrics(),
                           tickets=visible_logs(rows), statuses=STATUSES,
                           priorities=PRIORITIES, max_logs=MAX_LOGS)


@app.route("/logs", methods=["POST"])
@app.route("/tickets", methods=["POST"], endpoint="create_ticket")
@login_required
def submit_log():
    service = request.form.get("service", "").strip()
    status = request.form.get("service_status", request.form.get("status", ""))
    priority = request.form.get("priority", "Medium")
    desc = request.form.get("description", "").strip()
    if (not (1 <= len(service) <= 64) or status not in STATUSES
            or priority not in PRIORITIES or not (1 <= len(desc) <= 1000)):
        flash("Invalid ticket: provide a service, valid service status and priority, "
              "and a description of 1-1000 characters.", "error")
        return redirect(url_for("dashboard"))
    db = get_db()
    db.execute("BEGIN IMMEDIATE")  # atomic quota check + insert (no race between requests)
    try:
        cur = db.execute(
            "UPDATE users SET submission_count = submission_count + 1 "
            "WHERE id = ? AND locked = 0 AND submission_count < ?", (g.user["id"], MAX_LOGS))
        if cur.rowcount == 0:
            db.execute("ROLLBACK")
            flash("Ticket submission refused: your account is locked or you reached "
                  f"the limit of {MAX_LOGS} tickets.", "error")
            return redirect(url_for("dashboard"))
        cur = db.execute(
            "INSERT INTO logs (user_id, service, status, description, ticket_status, priority) "
            "VALUES (?, ?, ?, ?, 'Open', ?)",
            (g.user["id"], encrypt_field(service), status, encrypt_field(desc), priority))
        ticket_id = cur.lastrowid
        ticket_ref = f"INC-{ticket_id:04d}"
        db.execute("UPDATE logs SET ticket_ref = ? WHERE id = ?", (ticket_ref, ticket_id))
        ticket_event(ticket_id, g.user["id"], "created",
                     f"Ticket created with {priority} priority and {status} service status.")
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    flash(f"Ticket {ticket_ref} submitted.", "ok")
    return redirect(url_for("ticket_detail", ticket_id=ticket_id))


def read_admin_ticket_filters():
    filters = {
        "user": request.args.get("user", "").strip()[:32],
        "service": request.args.get("service", "").strip()[:64],
        "from_date": request.args.get("from_date", "").strip(),
        "to_date": request.args.get("to_date", "").strip(),
        "priority": request.args.get("priority", ""),
        "service_status": request.args.get(
            "service_status", request.args.get("status", "")),
        "ticket_status": request.args.get("ticket_status", ""),
    }
    valid = True
    for key in ("from_date", "to_date"):
        if filters[key]:
            try:
                datetime.strptime(filters[key], "%Y-%m-%d")
            except ValueError:
                filters[key] = ""
                valid = False
    if filters["priority"] not in PRIORITIES:
        filters["priority"] = ""
    if filters["service_status"] not in STATUSES:
        filters["service_status"] = ""
    if filters["ticket_status"] not in TICKET_STATUSES:
        filters["ticket_status"] = ""
    return filters, valid


def filtered_admin_tickets(filters):
    conditions, args = [], []
    if filters["user"]:
        conditions.append("users.username LIKE ?")
        args.append(f"%{filters['user']}%")
    if filters["from_date"]:
        conditions.append("date(logs.created_at) >= ?")
        args.append(filters["from_date"])
    if filters["to_date"]:
        conditions.append("date(logs.created_at) <= ?")
        args.append(filters["to_date"])
    if filters["priority"]:
        conditions.append("logs.priority = ?")
        args.append(filters["priority"])
    if filters["service_status"]:
        conditions.append("logs.status = ?")
        args.append(filters["service_status"])
    if filters["ticket_status"]:
        conditions.append("logs.ticket_status = ?")
        args.append(filters["ticket_status"])
    where = f" WHERE {' AND '.join(conditions)}" if conditions else ""
    rows = get_db().execute(TICKET_SELECT + where + " ORDER BY logs.id DESC", args).fetchall()
    tickets = visible_logs(rows)
    if filters["service"]:
        needle = normalize_service(filters["service"])
        tickets = [ticket for ticket in tickets
                   if needle in normalize_service(ticket["service"])]
    return tickets


def csv_safe(value):
    text = "" if value is None else str(value)
    if text.lstrip()[:1] in ("=", "+", "-", "@"):
        return "'" + text
    return text


@app.route("/admin")
@admin_required
def admin():
    filters, valid = read_admin_ticket_filters()
    if not valid:
        flash("Date filters must use a valid YYYY-MM-DD date.", "error")
    tickets = filtered_admin_tickets(filters)
    users = get_db().execute("SELECT * FROM users ORDER BY id").fetchall()
    assignees = get_db().execute(
        "SELECT id, username FROM users WHERE locked = 0 "
        "AND (is_admin = 1 OR is_support = 1) ORDER BY username").fetchall()
    return render_template(
        "admin.html", tickets=tickets, users=users, assignees=assignees,
        service_statuses=STATUSES, ticket_statuses=TICKET_STATUSES,
        priorities=PRIORITIES, current=filters, max_logs=MAX_LOGS)


@app.route("/admin/security")
@admin_required
def security_console():
    db = get_db()
    db.execute(
        "DELETE FROM security_events WHERE event_type IN "
        "('login_failed', 'login_rate_limited', 'password_change_failed') "
        "AND created_at < datetime('now', '-90 days')")
    failed_logins = db.execute(
        "SELECT event_type, attempted_username, ip_address, details, created_at "
        "FROM security_events WHERE event_type IN "
        "('login_failed', 'login_rate_limited', 'password_change_failed') "
        "ORDER BY id DESC LIMIT 100").fetchall()
    active_limits = db.execute(
        "SELECT ip_address, username, failed_count, window_started, blocked_until "
        "FROM login_attempts WHERE blocked_until > ? ORDER BY blocked_until DESC",
        (int(time.time()),)).fetchall()
    active_limits = [
        dict(row, blocked_until_utc=datetime.fromtimestamp(
            row["blocked_until"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
        for row in active_limits
    ]
    locked_accounts = db.execute(
        "SELECT id, username, is_support, created_at FROM users "
        "WHERE locked = 1 ORDER BY username").fetchall()
    audit_events = db.execute(
        "SELECT admin_audit.*, users.username FROM admin_audit "
        "LEFT JOIN users ON users.id = admin_audit.actor_id "
        "ORDER BY admin_audit.id DESC LIMIT 100").fetchall()
    return render_template(
        "security.html", failed_logins=failed_logins,
        active_limits=active_limits, locked_accounts=locked_accounts,
        audit_events=audit_events)


@app.route("/admin/tickets.csv")
@admin_required
def export_tickets():
    filters, valid = read_admin_ticket_filters()
    if not valid:
        abort(400)
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow([
        "Reference", "Submitted by", "Service", "Service status", "Ticket status",
        "Priority", "Assigned to", "Description", "Created at (UTC)",
        "Resolved at (UTC)", "Resolution time (seconds)", "Flagged",
    ])
    for ticket in filtered_admin_tickets(filters):
        writer.writerow([csv_safe(value) for value in (
            ticket["ticket_ref"], ticket["username"], ticket["service"], ticket["status"],
            ticket["ticket_status"], ticket["priority"], ticket["assigned_name"],
            ticket["description"], ticket["created_at"], ticket["resolved_at"],
            ticket["resolution_seconds"], "Yes" if ticket["flagged"] else "No",
        )])
    response = make_response(output.getvalue())
    response.mimetype = "text/csv"
    response.headers["Content-Disposition"] = 'attachment; filename="incidents.csv"'
    return response


@app.route("/tickets/<int:ticket_id>/status", methods=["POST"])
@login_required
def update_ticket_status(ticket_id):
    ticket = get_ticket_or_404(ticket_id)
    if not can_work_ticket(ticket, g.user):
        abort(403)
    status = request.form.get("ticket_status", "")
    if status not in TICKET_STATUSES:
        flash("Choose a valid ticket status.", "error")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        ticket = get_ticket_or_404(ticket_id)
        if not can_work_ticket(ticket, g.user):
            abort(403)
        if status == ticket["ticket_status"]:
            db.execute("COMMIT")
            return redirect(url_for("ticket_detail", ticket_id=ticket_id))
        db.execute(
            "UPDATE logs SET ticket_status = ?, "
            "resolved_at = CASE WHEN ? IN ('Resolved', 'Closed') "
            "THEN COALESCE(resolved_at, CURRENT_TIMESTAMP) ELSE resolved_at END, "
            "closed_at = CASE WHEN ? = 'Closed' THEN CURRENT_TIMESTAMP ELSE NULL END "
            "WHERE id = ?",
            (status, status, status, ticket_id))
        ticket_event(ticket_id, g.user["id"], "status",
                     f"Ticket status changed from {ticket['ticket_status']} to {status}.")
        if g.user["is_admin"]:
            audit_admin_action(
                "ticket.status", "ticket", ticket["ticket_ref"],
                f"Status changed from {ticket['ticket_status']} to {status}.")
        notify_ticket_owner(
            ticket, f"{ticket['ticket_ref']} status updated to {status}.", g.user["id"])
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    flash(f"{ticket['ticket_ref']} updated to {status}.", "ok")
    return redirect(url_for("ticket_detail", ticket_id=ticket_id))


@app.route("/tickets/<int:ticket_id>/priority", methods=["POST"])
@login_required
def update_ticket_priority(ticket_id):
    ticket = get_ticket_or_404(ticket_id)
    if not can_work_ticket(ticket, g.user):
        abort(403)
    priority = request.form.get("priority", "")
    if priority not in PRIORITIES:
        flash("Choose a valid priority.", "error")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        ticket = get_ticket_or_404(ticket_id)
        if not can_work_ticket(ticket, g.user):
            abort(403)
        if priority == ticket["priority"]:
            db.execute("COMMIT")
            return redirect(url_for("ticket_detail", ticket_id=ticket_id))
        db.execute("UPDATE logs SET priority = ? WHERE id = ?", (priority, ticket_id))
        ticket_event(ticket_id, g.user["id"], "priority",
                     f"Priority changed from {ticket['priority']} to {priority}.")
        if g.user["is_admin"]:
            audit_admin_action(
                "ticket.priority", "ticket", ticket["ticket_ref"],
                f"Priority changed from {ticket['priority']} to {priority}.")
        notify_ticket_owner(
            ticket, f"{ticket['ticket_ref']} priority updated to {priority}.", g.user["id"])
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    flash(f"{ticket['ticket_ref']} priority updated.", "ok")
    return redirect(url_for("ticket_detail", ticket_id=ticket_id))


@app.route("/tickets/<int:ticket_id>/assign", methods=["POST"])
@admin_required
def assign_ticket(ticket_id):
    raw_assignee = request.form.get("assigned_to", "")
    assignee_id = None
    if raw_assignee:
        try:
            assignee_id = int(raw_assignee)
        except ValueError:
            flash("Choose a valid support team member.", "error")
            return redirect(url_for("ticket_detail", ticket_id=ticket_id))
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        ticket = get_ticket_or_404(ticket_id)
        assignee_name = "Unassigned"
        if assignee_id is not None:
            assignee = db.execute(
                "SELECT id, username FROM users WHERE id = ? AND locked = 0 "
                "AND (is_admin = 1 OR is_support = 1)", (assignee_id,)).fetchone()
            if assignee is None:
                db.execute("ROLLBACK")
                flash("Tickets can only be assigned to active administrators or support staff.", "error")
                return redirect(url_for("ticket_detail", ticket_id=ticket_id))
            assignee_name = assignee["username"]
        if assignee_id == ticket["assigned_to"]:
            db.execute("COMMIT")
            return redirect(url_for("ticket_detail", ticket_id=ticket_id))
        db.execute("UPDATE logs SET assigned_to = ? WHERE id = ?", (assignee_id, ticket_id))
        ticket_event(ticket_id, g.user["id"], "assignment",
                     f"Ticket assigned to {assignee_name}.")
        audit_admin_action(
            "ticket.assignment", "ticket", ticket["ticket_ref"],
            f"Assignment changed to {assignee_name}.")
        notify_ticket_owner(
            ticket, f"{ticket['ticket_ref']} assignment updated to {assignee_name}.",
            g.user["id"])
        if (assignee_id is not None and assignee_id != g.user["id"]
                and assignee_id != ticket["user_id"]):
            db.execute(
                "INSERT INTO notifications (user_id, log_id, message) VALUES (?, ?, ?)",
                (assignee_id, ticket_id, f"{ticket['ticket_ref']} was assigned to you."))
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    flash(f"{ticket['ticket_ref']} assigned to {assignee_name}.", "ok")
    return redirect(url_for("ticket_detail", ticket_id=ticket_id))


@app.route("/tickets/<int:ticket_id>/responses", methods=["POST"])
@login_required
def respond_to_ticket(ticket_id):
    ticket = get_ticket_or_404(ticket_id)
    if not can_work_ticket(ticket, g.user):
        abort(403)
    body = request.form.get("body", "").strip()
    if not 1 <= len(body) <= 2000:
        flash("A response must contain 1-2000 characters.", "error")
        return redirect(url_for("ticket_detail", ticket_id=ticket_id))
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        ticket = get_ticket_or_404(ticket_id)
        if not can_work_ticket(ticket, g.user):
            abort(403)
        role = "administrator" if g.user["is_admin"] else "support team"
        db.execute(
            "INSERT INTO ticket_responses (log_id, user_id, body) VALUES (?, ?, ?)",
            (ticket_id, g.user["id"], encrypt_field(body)))
        ticket_event(ticket_id, g.user["id"], "response",
                     f"A response was added by the {role}.")
        if g.user["is_admin"]:
            audit_admin_action(
                "ticket.response", "ticket", ticket["ticket_ref"],
                "An administrator response was added.")
        notify_ticket_owner(
            ticket, f"New {role} response on {ticket['ticket_ref']}.", g.user["id"])
        db.execute("COMMIT")
    except Exception:
        db.execute("ROLLBACK")
        raise
    flash("Response added.", "ok")
    return redirect(url_for("ticket_detail", ticket_id=ticket_id))


@app.route("/admin/logs/<int:log_id>/flag", methods=["POST"])
@admin_required
def flag_log(log_id):
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        ticket = get_ticket_or_404(log_id)
        flagged = 1 - ticket["flagged"]
        db.execute("UPDATE logs SET flagged = ? WHERE id = ?", (flagged, log_id))
        ticket_event(
            log_id, g.user["id"], "flag",
            "Ticket flagged." if flagged else "Ticket unflagged.")
        audit_admin_action(
            "ticket.flag" if flagged else "ticket.unflag",
            "ticket", ticket["ticket_ref"],
            "Ticket flagged." if flagged else "Ticket unflagged.")
        db.execute("COMMIT")
    except Exception:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return redirect(url_for("admin"))


@app.route("/admin/logs/<int:log_id>/delete", methods=["POST"])
@admin_required
def delete_log(log_id):
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        ticket = get_ticket_or_404(log_id)
        audit_admin_action(
            "ticket.delete", "ticket", ticket["ticket_ref"], "Ticket deleted.")
        db.execute("DELETE FROM logs WHERE id = ?", (log_id,))
        db.execute("COMMIT")
    except Exception:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    flash("Ticket deleted.", "ok")
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:user_id>/support", methods=["POST"])
@admin_required
def toggle_support(user_id):
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        target = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if target is None:
            abort(404)
        if target["is_admin"]:
            flash("Administrator accounts already have support access.", "error")
        elif target["locked"] and not target["is_support"]:
            flash("Unlock this account before granting support access.", "error")
        elif target["is_support"]:
            active = db.execute(
                "SELECT COUNT(*) FROM logs WHERE assigned_to = ? "
                "AND ticket_status IN ('Open', 'In Progress')", (user_id,)).fetchone()[0]
            if active:
                flash("Reassign this user's active tickets before removing support access.", "error")
            else:
                db.execute("UPDATE users SET is_support = 0 WHERE id = ?", (user_id,))
                audit_admin_action(
                    "user.support_removed", "user", user_id,
                    "Support access removed.")
                flash(f"Support access removed for '{target['username']}'.", "ok")
        else:
            db.execute("UPDATE users SET is_support = 1 WHERE id = ?", (user_id,))
            audit_admin_action(
                "user.support_granted", "user", user_id,
                "Support access granted.")
            flash(f"'{target['username']}' added to the support team.", "ok")
        db.execute("COMMIT")
    except Exception:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
    return redirect(url_for("admin"))


@app.route("/admin/users/<int:user_id>/lock", methods=["POST"])
@admin_required
def toggle_lock(user_id):
    db = get_db()
    db.execute("BEGIN IMMEDIATE")
    try:
        target = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if target is None:
            abort(404)
        if target["is_admin"]:
            flash("Administrator accounts cannot be locked.", "error")
        elif target["is_support"] and not target["locked"]:
            active = db.execute(
                "SELECT COUNT(*) FROM logs WHERE assigned_to = ? "
                "AND ticket_status IN ('Open', 'In Progress')", (user_id,)).fetchone()[0]
            if active:
                flash("Reassign this support user's active tickets before locking the account.", "error")
            else:
                db.execute("UPDATE users SET locked = 1 WHERE id = ?", (user_id,))
                audit_admin_action(
                    "user.lock", "user", user_id, "User account locked.")
                flash(f"User '{target['username']}' locked.", "ok")
        else:
            db.execute("UPDATE users SET locked = 1 - locked WHERE id = ?", (user_id,))
            audit_admin_action(
                "user.unlock" if target["locked"] else "user.lock",
                "user", user_id,
                "User account unlocked." if target["locked"] else "User account locked.")
            flash(f"User '{target['username']}' {'unlocked' if target['locked'] else 'locked'}.", "ok")
        db.execute("COMMIT")
    except Exception:
        if db.in_transaction:
            db.execute("ROLLBACK")
        raise
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
