# Service Health Monitor — TechTeam Technical Assessment 2026

A secure Flask + SQLite application in **one custom Alpine Linux Docker container**. This is an improved version of the original candidate's application, preserving the existing routes, page templates, database design, and presentation.

> **Assessment deadline:** 27 November 2026, 16:00 (South Africa time). **Repository must be private** and shared with GitHub user `AvinashSingh786`. Add your own `CV.pdf` in the project root before submitting the repository URL through the official form.

## 1. What the application does

- Standard users **register** and **log in** using salted PBKDF2 password hashes, then see a dashboard.
- Dashboard shows periodically refreshed CPU, memory, disk, load, and uptime values sourced through `psutil`.
- Authenticated users submit a **Service Name**, **Status** (`Operational`, `Degraded`, `Down`, `Maintenance`), and **Description**.
- Each account can submit **at most five entries in total** by default; even if an administrator deletes an entry, the quota is **not restored**. This is a deliberate anti-spam decision. The counter is persistent and concurrency-safe.
- Administrators see all users and all logs, filter by status, flag/unflag entries, delete entries, and lock/unlock standard user accounts. A locked user may still sign in/read their own data but cannot submit new entries.
- Operational service names and descriptions are **encrypted at rest**. User passwords are **hashed**, not encrypted.

## 2. Directory structure

```text
service-health-monitor/
├── app.py                 Flask routes, auth, metrics, database and encryption
├── Dockerfile             Alpine image; apk installs Python/SQLite/dependencies
├── templates/             Seven Jinja HTML templates
├── static/                CSS and auto-refresh JavaScript
├── tests/test_app.py      Functional and security regression tests
├── .dockerignore
├── .gitignore
├── README.md
└── CV.pdf                 YOU MUST ADD YOUR OWN CV BEFORE SUBMISSION
```

## 3. Before you start

Install Docker Desktop (Windows/macOS) or Docker Engine (Linux). For Windows, use PowerShell or a WSL terminal; the commands below use a POSIX shell (Linux/macOS/WSL).

From the directory containing `Dockerfile`, build:

```bash
docker build -t techteam-health-monitor .
```

**Recommended first launch (persistent volume):**

```bash
docker run -d --name techteam-health-monitor \
  -p 5000:5000 \
  -v techteam-monitor-data:/data \
  -e ADMIN_USERNAME=admin \
  -e ADMIN_PASSWORD='REPLACE-WITH-A-UNIQUE-LONG-PASSWORD' \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  techteam-health-monitor
```

Open **http://localhost:5000**. Use the configured administrator credentials to log in, or select **Register** to create a normal user. Do not reuse the sample password text. For repeatable deployment, store generated keys securely and supply the *same keys* at each restart.

**Minimum launch (also supported):**

```bash
docker run --rm --name health-demo -p 5000:5000 techteam-health-monitor
```

On a brand-new data directory, the app generates an administrator password, prints it **once** in container logs, and generates persistent signing/encryption keys. Retrieve the generated password with `docker logs health-demo`. **This convenience path is intended only for a local demo:** container logs can expose that initial password to anyone who can read them; prefer supplying `ADMIN_PASSWORD` for normal use. No password is stored in the database as plaintext.

> **Safety:** Do not commit passwords, `.env`, the SQLite DB, encryption keys or actual operational secrets. A local demonstration over HTTP is appropriate for the assessment; internet deployment requires HTTPS with `COOKIE_SECURE=1` and preferably a reverse proxy.

## 4. Docker commands and troubleshooting

```bash
# Show runtime logs
docker logs techteam-health-monitor

# Check container health and process status
docker ps

# Stop/remove without deleting its named volume
docker stop techteam-health-monitor
docker rm techteam-health-monitor

# Rebuild after changing code
docker build -t techteam-health-monitor .
```

The default image uses **port 5000** and a non-root `app` user. SQLite files and encryption keys are stored under `/data`, with volume persistence. You can map a different host port, for example `-p 8000:5000`, then visit http://localhost:8000.

If you get `port is already allocated`, stop the other service or use `-p 8000:5000`. If the administrator account seems to ignore updated environment variables, that is expected: the account is bootstrapped only when the database contains no administrators. New passwords supplied on later starts do **not** overwrite stored password hashes. A username collision with an existing standard user now fails explicitly instead of silently leaving you with no administrator. To reset a demonstration, use a **new empty named volume**, not the production volume.

### Supported environment variables

| Variable | Description |
| --- | --- |
| `DATA_DIR` | SQLite and key storage directory; default `/data` |
| `SECRET_KEY` | Flask signing key. If missing, generated and written to `/data/.secret_key` (mode 0600). |
| `DATA_ENCRYPTION_KEY` | Optional Fernet encryption key. If absent, generated and written to `/data/.data_key` (mode 0600). |
| `ADMIN_USERNAME` | Initial admin name; default `admin`. |
| `ADMIN_PASSWORD` | Initial admin password. If missing, generated and printed **once** to Docker logs. |
| `MAX_LOGS_PER_USER` | Total submission allowance, default `5` (allowed: 1–100). |
| `COOKIE_SECURE` | `1` for HTTPS deployments, `0` for local HTTP. |

**Encryption-key note:** `DATA_ENCRYPTION_KEY` must be a valid Fernet key, e.g. generated with:

```bash
python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'
```

**Back up the SQLite database and `/data/.data_key` together.** Losing the key means encrypted log details cannot be recovered. Changing an externally supplied `DATA_ENCRYPTION_KEY` for an existing database makes existing encrypted data unreadable. A host-side data-volume backup can also contain pre-encryption legacy data, so protect backups and snapshots.

## 5. Architecture and request flow

```text
Browser ──HTTP:5000──> Gunicorn (1 worker, 4 threads)
                          │
                          ▼
                     Flask routes
               ┌──────────┴──────────┐
               │                     │
     Session + role checks      Metrics from psutil
               │
        Flask-WTF CSRF
               │
    Parameterized SQL queries
               │
           SQLite /data
       users          logs
    salted hashes  Fernet-encrypted fields
```

- **Alpine Linux**: the `Dockerfile` starts from `alpine:3.22`, **not** `python:alpine` or `node:alpine`. Packages installed through Alpine's `apk`: `python3`, `py3-flask`, `py3-flask-wtf`, `py3-psutil`, `py3-gunicorn`, `py3-cryptography` and `sqlite`.
- **Flask**: handles authentication, pages, input validation, access-control decorators and API routes; Jinja renders escaped templates.
- **SQLite**: stores account data and log metadata with foreign keys and WAL mode; a named Docker volume persists state.
- **Gunicorn**: one worker with four threads is adequate for a small SQLite-backed app and avoids separate worker-local login-throttle dictionaries.
- **Fernet**: encrypts operational log `service` and `description` before writing to SQLite. `status`, IDs, timestamps, username and flag state remain unencrypted metadata to support filtering, querying and moderation; don't put passwords or other secrets into those fields.

**Routes:** `/register`, `/login`, `POST /logout`, `/dashboard`, `GET /api/metrics`, `POST /logs`, `/admin`, `POST /admin/logs/<id>/flag`, `POST /admin/logs/<id>/delete`, `POST /admin/users/<id>/lock`, `/healthz`.

## 6. Security decisions and their limits

| Risk | Protection | Important limit |
| --- | --- | --- |
| Password compromise | Salted PBKDF2-HMAC-SHA256, 600,000 iterations | Password policy is basic: 10–128 characters, no breach-password check |
| SQL injection | SQLite `?` parameters for user data | SQL query structure is authored in code; status filter validated against allowlist |
| Stored/reflected XSS | Jinja escaping, restricted CSP, input length checks | Do not add `|safe` or inject untrusted HTML later |
| Cross-site request forgery | Flask-WTF token on every mutating POST | CSRF checks depend on a stable Flask `SECRET_KEY` |
| Unauthorized admin access | Backend `@admin_required`; never trust a hidden link | Standard users receive HTTP 403 on admin routes |
| Submission spam | Atomic `BEGIN IMMEDIATE` / count update / insertion | Quota counts **lifetime entries**, not entries remaining after deletion |
| Account lock | Database flag checked at insertion | Locked accounts can still view their own dashboards |
| Session theft | `HttpOnly`, `SameSite=Lax`, 2h lifetime; `Secure` opt-in | Deploy with TLS for real users |
| Operational log confidentiality | Encrypted service + description with Fernet | Other metadata remain plaintext; access to encryption keys defeats encryption |
| HTTP response hardening | CSP, no-sniff, anti-framing, no-store | This does not replace HTTPS |
| Container privilege | Runs as dedicated non-root Linux user | Docker daemon/host security remains operator responsibility |
| Login guessing | In-memory per-IP-and-username limiter | Not persistent across restart; not a production distributed limiter |

**Metrics accuracy:** `psutil` uses the system interfaces visible from inside Docker. Values such as CPU count, memory totals and uptime **may reflect the Docker host rather than strict container-cgroup consumption**. Treat them as indicative system metrics; for exact cgroup usage, implement `/sys/fs/cgroup` support as an enhancement.

**Legacy database migration:** On startup, unencrypted `service` and `description` values created by the original version are encrypted in a SQLite transaction. **Make an offline backup first**, and preserve the encryption key. Older backups and database journal artifacts may still contain historical plaintext and need separate protection.

**First-run keys:** The fallback file keys are stored with restrictive permissions inside the `/data` volume, which is fine for a self-contained assessment demo but is weaker than a managed secret store. Keep this limitation explicit in an interview.

## 7. Automated tests

Tests use `unittest` and Flask's test client. To run them in the image (with a *temporary* disposable container and database):

```bash
docker run --rm --entrypoint python3 techteam-health-monitor \
  -m unittest discover -s tests -v
```

These test routes, access restrictions, the submission quota, encrypted DB values, XSS escaping, CSRF protection, user locks and admin moderation. Tests use a temporary database instead of changing `/data/monitor.db`.

**Important:** The tests intentionally disable CSRF only for ordinary route tests that do not provide HTML CSRF tokens; one separate test turns CSRF **back on** and verifies an invalid request returns 400. This is test-only configuration and does not disable protection in the running app.

### Manual acceptance checks

1. `docker build -t techteam-health-monitor .` succeeds from the repository root.
2. `docker run` brings up the app on port 5000; `docker ps` reports the container up and eventually healthy.
3. Register `student1`; confirm the password is not visible in plaintext in SQLite.
4. Log in as `student1`; verify CPU/memory/disk figures appear and update after 5 seconds.
5. Submit five valid logs; confirm the sixth fails, even after a page refresh.
6. Submit description `<script>alert(1)</script>`; confirm it displays as text, not executed code.
7. Visit `/admin` as `student1`; confirm a 403 response.
8. Log in as the administrator; view all user entries, filter, flag one, then delete one.
9. Lock `student1` as administrator; verify `student1` can log in but cannot add a log.
10. Stop and recreate the container using the same named volume; confirm users, quotas, entries and encrypted content persist.
11. Check with SQLite that `logs.service` and `logs.description` begin `enc:v1:` and do not expose submitted text.
12. Run the automated tests and keep screenshots of the successful application and terminal output.

## 8. How this submission satisfies the assessment

| Requirement in assessment | Implementation / evidence |
| --- | --- |
| One container using base Alpine | `Dockerfile` (`FROM alpine:3.22`) |
| Install Flask, SQLite inside | Docker `apk add` instructions |
| Registration, login, password hashing | `register`, `login`, Werkzeug PBKDF2 |
| Standard / administrator access | `is_admin` database field and `@admin_required` |
| Live health data | `collect_metrics()`, `/api/metrics`, `static/dashboard.js` |
| Service, status, description | Dashboard form and `submit_log()` |
| Five logs per user | Atomic `submission_count` check in transaction |
| All logs unified for administrators | `/admin` join of users and logs |
| Flag/delete and lock user | Three POST `/admin/...` routes |
| SQL injection, XSS and CSRF defense | Parameters, Jinja+CSP, Flask-WTF |
| No plaintext passwords/sensitive descriptions | PBKDF2 and Fernet encryption |
| Environment-based secrets | `SECRET_KEY`, `DATA_ENCRYPTION_KEY`, admin credentials |
| Private repository, CV, reviewer invitation | **User must complete manually**; see section 9 |
| Clear instructions, security justification | This README |
| App working on 5000 or 8000 | Docker `EXPOSE 5000` and mapped host port |

## 9. Final submission checklist

- [ ] Open every changed file, understand it, and complete a live demonstration.
- [ ] Run Docker build and launch commands on your own computer.
- [ ] Run the tests and fix any failures.
- [ ] Capture dashboard, administrator console, limit enforcement and successful test output.
- [ ] **Add your own `CV.pdf` (or `.png`/`.jpg`) in the root of the repository.**
- [ ] Confirm the project root contains `Dockerfile`, `app.py`, `README.md`, `templates/`, `static/`, `tests/` and CV.
- [ ] Create a **private** GitHub repository; push your project without `.env`, keys or DB files.
- [ ] Invite GitHub username **`AvinashSingh786`** as collaborator and verify the invite is sent.
- [ ] Submit your private GitHub repository link using the **official form**: https://forms.gle/zUQaZiu2nrpWrgJ98
- [ ] Submit before **27 November 2026, 16:00 SAST**.

## 10. Potential optional improvements

1. **Admin action audit trail** storing action, admin user ID, target, and timestamp.
2. **More accurate container-cgroup metrics** instead of host-level memory/CPU where supported.
3. **Persistent login throttling** in SQLite instead of in process memory.
4. **Charts for metric history**, retaining only a bounded time window.

Do not implement optional features at the expense of the core functionality, tests, and a well-explained demo.
