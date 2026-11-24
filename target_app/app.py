"""
target_app/app.py — Vulnerable Mock Financial Web Service
===========================================================
Intentionally vulnerable Flask application for SOC automation demo purposes.
DO NOT deploy this in any real or production environment.

Vulnerabilities present (by design):
  • Simulated SQL Injection on the /login endpoint
  • No real authentication — JWT is a signed mock token

Telemetry:
  Every request writes a structured ONE-LINE JSON entry to logs/app.log,
  matching the PostgreSQL telemetry_logs schema exactly.

Run:
    python3 target_app/app.py
"""

import json
import logging
import os
import uuid
import hmac
import hashlib
import base64
from datetime import datetime, timezone, timedelta
from pathlib import Path

from flask import Flask, request, jsonify

# ─────────────────────────────────────────────────────────────────
# DIRECTORY SETUP
# Ensure logs/ exists before the logging handler tries to open the file.
# This runs at import time so it's guaranteed before any request arrives.
# ─────────────────────────────────────────────────────────────────
LOGS_DIR = Path(__file__).parent.parent / "logs"   # soc/logs/
LOGS_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = LOGS_DIR / "app.log"

# ─────────────────────────────────────────────────────────────────
# TELEMETRY LOGGER
# A dedicated logger that writes ONLY to app.log, one JSON line per record.
# The root logger (Flask's own output) is kept separate so it doesn't
# pollute the structured log file.
# ─────────────────────────────────────────────────────────────────
BLOCKED_IPS_FILE = LOGS_DIR / "blocked_ips.json"
BLOCKED_IPS: set[str] = set()

def load_blocked_ips():
    global BLOCKED_IPS
    if BLOCKED_IPS_FILE.exists():
        try:
            with open(BLOCKED_IPS_FILE, "r", encoding="utf-8") as f:
                BLOCKED_IPS = set(json.load(f))
        except Exception:
            BLOCKED_IPS = set()

def save_blocked_ips():
    try:
        with open(BLOCKED_IPS_FILE, "w", encoding="utf-8") as f:
            json.dump(list(BLOCKED_IPS), f)
    except Exception as e:
        print(f"Error saving blocked IPs: {e}")

load_blocked_ips()


def get_client_ip() -> str:
    """
    Extracts the client IP address.
    Checks X-Forwarded-For header first so demo scripts can simulate
    realistic external attack IPs (Tor exit nodes, botnets, foreign hosts).
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"


telemetry_logger = logging.getLogger("telemetry")
telemetry_logger.setLevel(logging.INFO)
telemetry_logger.propagate = False      # don't bubble up to root logger

_file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
# Formatter outputs only the log message — the message IS the JSON string
_file_handler.setFormatter(logging.Formatter("%(message)s"))
telemetry_logger.addHandler(_file_handler)

# Also echo telemetry to stdout so you can watch it in the terminal
_stdout_handler = logging.StreamHandler()
_stdout_handler.setFormatter(logging.Formatter("%(message)s"))
telemetry_logger.addHandler(_stdout_handler)


def write_telemetry(
    *,
    event_type: str,
    status_code: int,
    user_id: str | None = None,
    extra_payload: dict | None = None,
):
    """
    Builds and writes a single structured JSON log line to app.log.

    All fields map directly to columns in the PostgreSQL telemetry_logs table:
        timestamp       — ISO 8601, UTC, timezone-aware
        source_ip       — client IP from the request context
        endpoint        — URL path (e.g. /api/v1/auth/login)
        http_method     — GET / POST / etc.
        status_code     — HTTP response code we are about to send
        event_type      — semantic label (AUTH_SUCCESS, SQLI_DETECTED, …)
        user_id         — username / account identifier if known
        headers         — dict of request headers
        payload         — dict of the JSON request body (sanitised)

    Parameters
    ----------
    event_type    : semantic event label string
    status_code   : HTTP status code being returned
    user_id       : optional user identifier extracted from request body
    extra_payload : optional extra keys merged into the payload field
    """

    # Safely read the JSON body; fall back to empty dict on parse errors
    try:
        body = request.get_json(silent=True) or {}
    except Exception:
        body = {}

    # Merge any additional context the caller wants to record
    if extra_payload:
        body = {**body, **extra_payload}

    # Scrub sensitive fields before logging (never log raw passwords)
    sanitised_body = {
        k: ("***REDACTED***" if k.lower() in {"password", "pin", "secret"} else v)
        for k, v in body.items()
    }

    record = {
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "source_ip":   get_client_ip(),
        "endpoint":    request.path,
        "http_method": request.method,
        "status_code": status_code,
        "event_type":  event_type,
        "user_id":     user_id,
        "headers":     dict(request.headers),   # all HTTP headers as a dict
        "payload":     sanitised_body,
        "raw_message": f"{request.method} {request.path} → {status_code} [{event_type}]",
    }

    # json.dumps with ensure_ascii=False keeps unicode intact;
    # the result is a single line (no newlines inside the JSON)
    telemetry_logger.info(json.dumps(record, ensure_ascii=False, default=str))


# ─────────────────────────────────────────────────────────────────
# MOCK JWT HELPERS
# A real app would use PyJWT + a secret stored in env vars.
# Here we roll a minimal HS256-style token purely for demo purposes.
# ─────────────────────────────────────────────────────────────────
_JWT_SECRET = "DEMO_SECRET_NOT_FOR_PRODUCTION"


def _b64url(data: bytes) -> str:
    """URL-safe base64 encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def generate_mock_jwt(username: str, role: str = "user") -> str:
    """
    Generates a minimal HS256 JWT for demo purposes.
    Header.Payload.Signature — same structure as a real JWT.
    """
    header  = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    now     = datetime.now(timezone.utc)
    payload = _b64url(json.dumps({
        "sub":  username,
        "role": role,
        "iat":  int(now.timestamp()),
        "exp":  int((now + timedelta(hours=1)).timestamp()),
        "jti":  str(uuid.uuid4()),
    }).encode())

    signing_input = f"{header}.{payload}"
    sig = _b64url(
        hmac.new(
            _JWT_SECRET.encode(),
            signing_input.encode(),
            hashlib.sha256,
        ).digest()
    )
    return f"{signing_input}.{sig}"


# ─────────────────────────────────────────────────────────────────
# MOCK USER DATABASE
# In a real app this would be a proper DB table with hashed passwords.
# ─────────────────────────────────────────────────────────────────
MOCK_USERS = {
    "alice":   {"password": "password123", "role": "user"},
    "bob":     {"password": "securepass",  "role": "user"},
    "charlie": {"password": "ch@rlie99",   "role": "analyst"},
    "admin":   {"password": "adminpass",   "role": "admin"},
}

# ─────────────────────────────────────────────────────────────────
# FLASK APPLICATION
# ─────────────────────────────────────────────────────────────────
app = Flask(__name__)


# ── Active WAF / SOAR Containment Enforcement ────────────────────
@app.before_request
def check_containment_and_waf():
    """
    Simulates enterprise WAF / automated firewall blocking.
    If the caller's IP is in BLOCKED_IPS, immediately terminate connection with 403.
    """
    # Allow SOC control plane API and health checks through
    if request.path.startswith("/api/v1/soc/") or request.path in ("/health", "/"):
        return None

    client_ip = get_client_ip()
    if client_ip in BLOCKED_IPS:
        write_telemetry(
            event_type="WAF_BLOCK",
            status_code=403,
            user_id="BLOCKED_ACTOR",
            extra_payload={
                "alert": "Traffic dropped by SOC Automated Containment Playbook (WAF Policy)",
                "blocked_ip": client_ip,
                "action": "DROP_CONNECTION",
            },
        )
        return jsonify({
            "error": "Access Denied: Traffic blocked by SOC Automated Containment Playbook (WAF)",
            "blocked_ip": client_ip,
            "status": "CONTAINED",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }), 403

    return None


# ── Utility: require JSON body ────────────────────────────────────

def _require_json():
    """Returns parsed JSON body or (None, error_response) tuple."""
    data = request.get_json(silent=True)
    if data is None:
        return None, jsonify({"error": "Request body must be valid JSON"}), 400
    return data, None, None


# ─────────────────────────────────────────────────────────────────
# ENDPOINT 1: POST /api/v1/auth/login
# ─────────────────────────────────────────────────────────────────

@app.route("/api/v1/auth/login", methods=["POST"])
def login():
    """
    Simulated login endpoint with an intentional SQL Injection vulnerability.

    Normal flow:
        POST {"username": "alice", "password": "password123"}
        → 200 OK + JWT token

    SQL Injection bypass (the vulnerability):
        POST {"username": "' OR 1=1 --", "password": "anything"}
        → The username string contains a classic SQLi pattern.
          A real vulnerable app would interpolate this directly into a
          SQL query string, bypassing the WHERE clause check.
          Here we simulate that behaviour: if the username contains
          recognised SQLi patterns we "authenticate" as admin,
          which is exactly what a real SQLi would achieve.

    Telemetry events emitted:
        SQLI_DETECTED   — username contains injection pattern
        AUTH_SUCCESS    — valid credentials
        AUTH_FAILURE    — wrong password or unknown user
    """
    body = request.get_json(silent=True)

    # ── Validate request body ─────────────────────────────────────
    if not body or "username" not in body or "password" not in body:
        write_telemetry(event_type="AUTH_FAILURE", status_code=400)
        return jsonify({"error": "username and password are required"}), 400

    username = str(body.get("username", ""))
    password = str(body.get("password", ""))

    # ── SQLi detection patterns ───────────────────────────────────
    # In a real vulnerable app this check would NOT exist — the app
    # would just blindly execute:
    #   SELECT * FROM users WHERE username='<input>' AND password='<pw>'
    # and the OR 1=1 would make the WHERE clause always true.
    SQLI_PATTERNS = [
        "' or 1=1",
        "' or '1'='1",
        "' or 1=1--",
        "' or 1=1 --",
        "admin'--",
        "' or 'x'='x",
        "1; drop table",
        "union select",
    ]

    is_sqli = any(pattern in username.lower() for pattern in SQLI_PATTERNS)

    if is_sqli:
        # ── VULNERABILITY: SQLi bypass succeeds → grant admin access ──
        token = generate_mock_jwt("admin", role="admin")

        # Log with SQLI_DETECTED so the SOC pipeline picks it up
        write_telemetry(
            event_type="SQLI_DETECTED",
            status_code=200,
            user_id=username,          # log the raw malicious input
            extra_payload={
                "injected_username": username,
                "bypassed_as":       "admin",
                "alert":             "SQL Injection pattern detected in username field",
            },
        )

        return jsonify({
            "message":    "Login successful",          # app "thinks" it's fine
            "token":      token,
            "user":       "admin",
            "role":       "admin",
            "_debug_note": "SQLi bypass succeeded — this is intentional for demo",
        }), 200

    # ── Normal authentication path ─────────────────────────────────
    user_record = MOCK_USERS.get(username)

    if user_record and user_record["password"] == password:
        # Valid credentials
        token = generate_mock_jwt(username, role=user_record["role"])

        write_telemetry(
            event_type="AUTH_SUCCESS",
            status_code=200,
            user_id=username,
        )

        return jsonify({
            "message": "Login successful",
            "token":   token,
            "user":    username,
            "role":    user_record["role"],
        }), 200

    else:
        # Wrong password or unknown user
        write_telemetry(
            event_type="AUTH_FAILURE",
            status_code=401,
            user_id=username,
            extra_payload={"reason": "Invalid credentials"},
        )

        return jsonify({"error": "Invalid username or password"}), 401


# ─────────────────────────────────────────────────────────────────
# ENDPOINT 2: POST /api/v1/accounts/transfer
# ─────────────────────────────────────────────────────────────────

@app.route("/api/v1/accounts/transfer", methods=["POST"])
def transfer():
    """
    Simulated fund transfer endpoint.

    Expected body:
        {
            "sender":    "alice",
            "recipient": "bob",
            "amount":    500.00
        }

    Validation rules:
        • All three fields required
        • amount must be a positive number
        • amount > 10,000 is flagged as a suspicious large transfer

    Telemetry events emitted:
        TRANSFER            — normal successful transfer
        TRANSFER_LARGE      — amount exceeds $10,000 threshold (suspicious)
        TRANSFER_FAILED     — validation error
    """
    body = request.get_json(silent=True)

    # ── Validate presence of required fields ──────────────────────
    if not body or not all(k in body for k in ("sender", "recipient", "amount")):
        write_telemetry(
            event_type="TRANSFER_FAILED",
            status_code=400,
            user_id=body.get("sender") if body else None,
            extra_payload={"reason": "Missing required fields"},
        )
        return jsonify({"error": "sender, recipient, and amount are required"}), 400

    sender    = str(body["sender"])
    recipient = str(body["recipient"])

    # ── Validate amount ───────────────────────────────────────────
    try:
        amount = float(body["amount"])
        if amount <= 0:
            raise ValueError("Amount must be positive")
    except (TypeError, ValueError) as exc:
        write_telemetry(
            event_type="TRANSFER_FAILED",
            status_code=400,
            user_id=sender,
            extra_payload={"reason": str(exc)},
        )
        return jsonify({"error": f"Invalid amount: {exc}"}), 400

    # ── Large transfer threshold check ────────────────────────────
    LARGE_TRANSFER_THRESHOLD = 10_000.00
    is_large = amount > LARGE_TRANSFER_THRESHOLD
    event    = "TRANSFER_LARGE" if is_large else "TRANSFER"

    # Generate a mock transaction reference
    tx_ref = f"TXN-{uuid.uuid4().hex[:10].upper()}"

    write_telemetry(
        event_type=event,
        status_code=200,
        user_id=sender,
        extra_payload={
            "transaction_id": tx_ref,
            "recipient":      recipient,
            "amount":         amount,
            "currency":       "USD",
            "flagged_large":  is_large,
        },
    )

    response_body = {
        "message":        "Transfer successful",
        "transaction_id": tx_ref,
        "sender":         sender,
        "recipient":      recipient,
        "amount":         amount,
        "currency":       "USD",
    }

    if is_large:
        response_body["warning"] = (
            f"Transfer of ${amount:,.2f} exceeds reporting threshold "
            f"and has been flagged for review."
        )

    return jsonify(response_body), 200


# ─────────────────────────────────────────────────────────────────
# ROOT ROUTE — API index page (browser friendly)
# ─────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    """
    Returns an HTML landing page listing all available endpoints.
    Styled to match the dark cybersecurity theme of the SOC dashboard.
    """
    html = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Mock Financial API — SOC Demo</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #0d1117;
      color: #c9d1d9;
      font-family: 'JetBrains Mono', 'Courier New', monospace;
      padding: 40px 24px;
    }
    .container { max-width: 760px; margin: 0 auto; }
    .header { display: flex; align-items: center; gap: 14px; margin-bottom: 32px; }
    .header h1 { font-size: 1.6rem; color: #58a6ff; }
    .header .badge {
      background: #f85149; color: #fff;
      font-size: 0.7rem; font-weight: 700;
      padding: 3px 10px; border-radius: 12px;
      letter-spacing: 0.08em;
    }
    .subtitle { color: #8b949e; font-size: 0.85rem; margin-top: -24px; margin-bottom: 32px; }
    .section-title {
      font-size: 0.75rem; font-weight: 700;
      color: #8b949e; letter-spacing: 0.12em;
      text-transform: uppercase; margin-bottom: 12px;
    }
    .endpoint-card {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 8px;
      padding: 18px 20px;
      margin-bottom: 14px;
    }
    .endpoint-card:hover { border-color: #58a6ff; }
    .ep-header { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
    .method {
      font-size: 0.75rem; font-weight: 700;
      padding: 3px 10px; border-radius: 4px;
      letter-spacing: 0.06em;
    }
    .method.post { background: #1f6feb; color: #fff; }
    .method.get  { background: #238636; color: #fff; }
    .path { color: #e6edf3; font-size: 0.95rem; font-weight: 600; }
    .description { color: #8b949e; font-size: 0.82rem; margin-bottom: 10px; }
    .payload-label { color: #58a6ff; font-size: 0.75rem; margin-bottom: 4px; }
    pre {
      background: #0d1117;
      border: 1px solid #21262d;
      border-radius: 6px;
      padding: 12px 14px;
      font-size: 0.8rem;
      color: #a5d6ff;
      overflow-x: auto;
    }
    .tag {
      display: inline-block;
      background: #21262d;
      color: #8b949e;
      font-size: 0.7rem;
      padding: 2px 8px;
      border-radius: 10px;
      margin-right: 6px;
      margin-top: 8px;
    }
    .tag.vuln { background: #3d1a1a; color: #f85149; }
    .divider { border: none; border-top: 1px solid #21262d; margin: 28px 0; }
    .footer { color: #484f58; font-size: 0.78rem; margin-top: 32px; text-align: center; }
  </style>
</head>
<body>
  <div class="container">

    <div class="header">
      <span style="font-size:2rem;">🛡️</span>
      <h1>Mock Financial API</h1>
      <span class="badge">SOC DEMO</span>
    </div>
    <p class="subtitle">AI-Powered SOC Automation · Target Application · v1.0.0-demo</p>

    <p class="section-title">Available Endpoints</p>

    <!-- Health -->
    <div class="endpoint-card">
      <div class="ep-header">
        <span class="method get">GET</span>
        <span class="path">/health</span>
      </div>
      <p class="description">Liveness probe — confirms the service is running.</p>
      <span class="tag">no auth required</span>
    </div>

    <!-- Login -->
    <div class="endpoint-card">
      <div class="ep-header">
        <span class="method post">POST</span>
        <span class="path">/api/v1/auth/login</span>
      </div>
      <p class="description">
        Authenticates a user and returns a mock JWT token.
        Contains a simulated SQL Injection vulnerability.
      </p>
      <p class="payload-label">Request body</p>
      <pre>{
  "username": "alice",
  "password": "password123"
}</pre>
      <span class="tag">returns JWT</span>
      <span class="tag vuln">⚠ SQLi vulnerable</span>
    </div>

    <!-- SQLi example -->
    <div class="endpoint-card">
      <div class="ep-header">
        <span class="method post">POST</span>
        <span class="path">/api/v1/auth/login</span>
        <span style="color:#f85149;font-size:0.8rem;font-weight:700;">ATTACK EXAMPLE</span>
      </div>
      <p class="description">
        SQL Injection bypass — authenticates as admin without valid credentials.
        Triggers a <code style="color:#f85149;">SQLI_DETECTED</code> telemetry event.
      </p>
      <p class="payload-label">Malicious payload</p>
      <pre>{
  "username": "' OR 1=1 --",
  "password": "anything"
}</pre>
      <span class="tag vuln">⚠ triggers SQLI_DETECTED log</span>
    </div>

    <!-- Transfer -->
    <div class="endpoint-card">
      <div class="ep-header">
        <span class="method post">POST</span>
        <span class="path">/api/v1/accounts/transfer</span>
      </div>
      <p class="description">
        Initiates a fund transfer between accounts.
        Transfers over $10,000 are flagged as suspicious.
      </p>
      <p class="payload-label">Request body</p>
      <pre>{
  "sender":    "alice",
  "recipient": "bob",
  "amount":    500.00
}</pre>
      <span class="tag">TRANSFER event</span>
      <span class="tag vuln">⚠ &gt;$10k → TRANSFER_LARGE</span>
    </div>

    <hr class="divider"/>

    <p class="section-title">Mock Users</p>
    <div class="endpoint-card">
      <pre>alice   / password123   (role: user)
bob     / securepass    (role: user)
charlie / ch@rlie99     (role: analyst)
admin   / adminpass     (role: admin)</pre>
    </div>

    <p class="footer">
      ⚠️ &nbsp;Intentionally vulnerable — for SOC demo purposes only.
      Do not deploy in production.
    </p>

  </div>
</body>
</html>
"""
    return html, 200


# ─────────────────────────────────────────────────────────────────
# ENDPOINT 3: GET /api/v1/system/file (Local File Inclusion / Path Traversal)
# ─────────────────────────────────────────────────────────────────

@app.route("/api/v1/system/file", methods=["GET"])
def system_file():
    """
    Simulated sensitive file download endpoint.
    Vulnerable to Directory Traversal (LFI) probes like name=../../../../etc/passwd.
    """
    filename = request.args.get("name", "")
    client_ip = get_client_ip()

    if not filename:
        return jsonify({"error": "Query parameter 'name' is required"}), 400

    # Detect traversal attempts
    is_traversal = any(p in filename for p in ("..", "/etc/", "/proc/", "\\windows\\", "system.ini"))

    if is_traversal:
        write_telemetry(
            event_type="LFI_DETECTED",
            status_code=400,
            user_id="anonymous",
            extra_payload={
                "alert": "Directory Traversal / LFI attempt detected",
                "attempted_path": filename,
                "client_ip": client_ip,
                "mitre": "T1059 - Command and Scripting Interpreter",
            },
        )
        return jsonify({
            "error": "Directory traversal sequence detected. Access to system files is restricted.",
            "attempted_path": filename,
            "status_code": 400,
        }), 400

    write_telemetry(
        event_type="FILE_ACCESS",
        status_code=200,
        user_id="system",
        extra_payload={"file": filename},
    )
    return jsonify({
        "status":  "ok",
        "file":    filename,
        "content": f"[Simulated Content for file: {filename}]",
    }), 200


# ─────────────────────────────────────────────────────────────────
# SOAR AUTOMATED CONTAINMENT ENDPOINTS (Invoked by SOC Dashboard)
# ─────────────────────────────────────────────────────────────────

@app.route("/api/v1/soc/block-ip", methods=["POST"])
def soc_block_ip():
    """Blocks an IP address at the simulated WAF / perimeter gateway."""
    data = request.get_json(silent=True) or {}
    ip = str(data.get("ip", "")).strip()

    if not ip:
        return jsonify({"error": "Missing 'ip' in request body"}), 400

    BLOCKED_IPS.add(ip)
    save_blocked_ips()

    write_telemetry(
        event_type="SOAR_IP_BLOCKED",
        status_code=200,
        user_id="SOC_AUTOMATION",
        extra_payload={
            "action":     "FIREWALL_DROP_RULE_INSTALLED",
            "blocked_ip": ip,
            "playbook":   "SOAR-PB-001-AUTO-CONTAINMENT",
        },
    )

    return jsonify({
        "status":      "CONTAINED",
        "message":     f"Firewall rule installed: Traffic from {ip} dropped.",
        "blocked_ips": list(BLOCKED_IPS),
    }), 200


@app.route("/api/v1/soc/unblock-ip", methods=["POST"])
def soc_unblock_ip():
    """Removes an IP block rule."""
    data = request.get_json(silent=True) or {}
    ip = str(data.get("ip", "")).strip()

    if not ip:
        return jsonify({"error": "Missing 'ip' in request body"}), 400

    BLOCKED_IPS.discard(ip)
    save_blocked_ips()

    write_telemetry(
        event_type="SOAR_IP_UNBLOCKED",
        status_code=200,
        user_id="SOC_ANALYST",
        extra_payload={"action": "FIREWALL_RULE_REMOVED", "unblocked_ip": ip},
    )

    return jsonify({
        "status":      "UNBLOCKED",
        "message":     f"Firewall rule removed for {ip}.",
        "blocked_ips": list(BLOCKED_IPS),
    }), 200


@app.route("/api/v1/soc/blocked-ips", methods=["GET"])
def soc_get_blocked_ips():
    """Returns all currently quarantined/blocked IPs."""
    return jsonify({
        "count":       len(BLOCKED_IPS),
        "blocked_ips": sorted(list(BLOCKED_IPS)),
    }), 200


# ─────────────────────────────────────────────────────────────────
# HEALTH CHECK (useful for demos — shows the app is alive)
# ─────────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Simple liveness probe. Does not write telemetry."""
    return jsonify({
        "status":  "ok",
        "service": "mock-financial-api",
        "version": "1.0.0-demo",
    }), 200


# ─────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"\n{'='*60}")
    print("  Mock Financial API — SOC Demo Target")
    print(f"  Logging telemetry to: {LOG_FILE.resolve()}")
    print(f"{'='*60}\n")

    # debug=False is intentional — debug mode would expose the interactive
    # debugger which is its own vulnerability and distracts from the demo
    app.run(host="0.0.0.0", port=5001, debug=False)
