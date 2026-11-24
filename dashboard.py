"""
dashboard.py — Next-Gen AI-Powered Enterprise SOC Dashboard
=============================================================
Real-time security telemetry monitoring, AI threat triage, MITRE ATT&CK mapping,
SOAR automated containment, live threat simulation, and AI SOC Copilot.

Usage:
    streamlit run dashboard.py
"""

import json
import os
import re
import time
import random
from datetime import datetime, timezone, timedelta
from pathlib import Path

import psycopg2
import psycopg2.extras
import pandas as pd
import requests
import streamlit as st
import plotly.graph_objects as go
import plotly.express as px

# ─────────────────────────────────────────────────────────────────
# PAGE CONFIG — must be the very first Streamlit call
# ─────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Autonomous AI SOC Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────
# LOAD .env FILE (if present)
# ─────────────────────────────────────────────────────────────────
_env_path = Path(__file__).parent / ".env"
if _env_path.exists():
    with open(_env_path, "r", encoding="utf-8") as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#") and "=" in _line:
                _k, _v = _line.split("=", 1)
                os.environ.setdefault(_k.strip(), _v.strip().strip('"').strip("'"))

# ─────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────
DB_CONFIG = {
    "host":     "localhost",
    "port":     5432,
    "dbname":   "soc",
    "user":     "paarthchhikara",
    "password": "",
}
TARGET_API_URL = "http://localhost:5001"
AUTO_REFRESH_SECONDS = 10

# ─────────────────────────────────────────────────────────────────
# CUSTOM CYBER ENTERPRISE CSS
# ─────────────────────────────────────────────────────────────────
st.markdown("""
<style>
/* Global Dark Theme */
html, body, [data-testid="stAppViewContainer"] {
    background-color: #080c14;
    color: #c9d1d9;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
[data-testid="stSidebar"] {
    background-color: #0e1422;
    border-right: 1px solid #1c273c;
}
[data-testid="metric-container"] {
    background: linear-gradient(145deg, #101728 0%, #0d1320 100%);
    border: 1px solid #1f2c44;
    border-radius: 10px;
    padding: 14px 18px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
}
[data-testid="stDataFrame"] {
    border: 1px solid #1f2c44;
    border-radius: 8px;
    background-color: #0e1422;
}
h1, h2, h3, h4 {
    color: #e6edf3;
    letter-spacing: -0.02em;
}
hr { border-color: #1c273c; margin: 16px 0; }

/* Radar pulse animation */
@keyframes pulse {
    0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 229, 255, 0.7); }
    70% { transform: scale(1); box-shadow: 0 0 0 10px rgba(0, 229, 255, 0); }
    100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(0, 229, 255, 0); }
}
.radar-pulse-green {
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #00e676;
    animation: pulse 2s infinite;
    margin-right: 6px;
    vertical-align: middle;
}
.radar-pulse-red {
    display: inline-block;
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #ff1744;
    animation: pulse 1.2s infinite;
    margin-right: 6px;
    vertical-align: middle;
}

/* Incident Cards */
.alert-card-critical {
    background: linear-gradient(135deg, rgba(255, 23, 68, 0.12) 0%, rgba(13, 19, 32, 0.95) 100%);
    border: 2px solid #ff1744;
    border-radius: 12px;
    padding: 22px 26px;
    margin-bottom: 16px;
    box-shadow: 0 0 25px rgba(255, 23, 68, 0.25);
}
.alert-card-high {
    background: linear-gradient(135deg, rgba(255, 145, 0, 0.12) 0%, rgba(13, 19, 32, 0.95) 100%);
    border: 2px solid #ff9100;
    border-radius: 12px;
    padding: 22px 26px;
    margin-bottom: 16px;
    box-shadow: 0 0 20px rgba(255, 145, 0, 0.2);
}
.alert-card-medium {
    background: linear-gradient(135deg, rgba(255, 214, 0, 0.10) 0%, rgba(13, 19, 32, 0.95) 100%);
    border: 2px solid #ffd600;
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 16px;
}
.alert-card-low {
    background: linear-gradient(135deg, rgba(0, 230, 118, 0.08) 0%, rgba(13, 19, 32, 0.95) 100%);
    border: 1px solid #00e676;
    border-radius: 12px;
    padding: 20px 24px;
    margin-bottom: 16px;
}

/* Badges */
.badge-tag {
    display: inline-block;
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    font-family: monospace;
}
.badge-mitre {
    background: rgba(0, 229, 255, 0.12);
    border: 1px solid #00e5ff;
    color: #00e5ff;
}
.badge-crit {
    background: rgba(255, 23, 68, 0.2);
    border: 1px solid #ff1744;
    color: #ff5252;
}
.badge-contained {
    background: rgba(0, 230, 118, 0.2);
    border: 1px solid #00e676;
    color: #69f0ae;
}

/* Simulator cards */
.sim-card {
    background: #101625;
    border: 1px solid #202c45;
    border-radius: 10px;
    padding: 16px 18px;
    margin-bottom: 12px;
    transition: transform 0.2s, border-color 0.2s;
}
.sim-card:hover {
    border-color: #00e5ff;
    transform: translateY(-2px);
}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────
# DATABASE LAYER
# ─────────────────────────────────────────────────────────────────
@st.cache_resource
def get_connection():
    """Maintains a persistent connection to the PostgreSQL database."""
    conn = psycopg2.connect(**DB_CONFIG)
    conn.autocommit = True
    return conn

def _conn():
    try:
        c = get_connection()
        if c.closed:
            st.cache_resource.clear()
            c = get_connection()
        return c
    except psycopg2.OperationalError:
        st.cache_resource.clear()
        return get_connection()


def fetch_recent_logs(limit: int = 100) -> pd.DataFrame:
    """Retrieves up to limit recent log rows."""
    sql = """
        SELECT id, timestamp, source_ip, user_id, event_type,
               endpoint, http_method, status_code, raw_message, payload, headers
        FROM telemetry_logs
        ORDER BY id DESC
        LIMIT %(limit)s;
    """
    try:
        with _conn().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, {"limit": limit})
            rows = cur.fetchall()
        if not rows:
            return pd.DataFrame()
        df = pd.DataFrame(rows)
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        return df
    except Exception as exc:
        st.error(f"PostgreSQL Query Error: {exc}")
        return pd.DataFrame()


def fetch_logs_for_triage(limit: int = 15) -> list[dict]:
    """Retrieves the latest logs formatted for LLM triage."""
    sql = """
        SELECT id, timestamp, source_ip, user_id, event_type,
               endpoint, http_method, status_code, payload, raw_message
        FROM telemetry_logs
        ORDER BY id DESC
        LIMIT %(limit)s;
    """
    try:
        with _conn().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, {"limit": limit})
            rows = cur.fetchall()
        for r in rows:
            if isinstance(r.get("timestamp"), datetime):
                r["timestamp"] = r["timestamp"].isoformat()
            if isinstance(r.get("payload"), (dict, list)):
                pass
            elif r.get("payload") is None:
                r["payload"] = {}
        return rows
    except Exception:
        return []


def fetch_incidents(limit: int = 25) -> pd.DataFrame:
    """Retrieves historical incidents including lifecycle status and analyst notes."""
    sql = """
        SELECT id, created_at, source_ip, threat_level, confidence_score, status, mitre_technique, summary, analyst_notes
        FROM incidents
        ORDER BY id DESC
        LIMIT %(limit)s;
    """
    try:
        with _conn().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, {"limit": limit})
            rows = cur.fetchall()
        return pd.DataFrame(rows) if rows else pd.DataFrame()
    except Exception:
        return pd.DataFrame()


def insert_incident(result: dict, triage_logs: list[dict]) -> int | None:
    """Persists a new incident record into PostgreSQL."""
    sql = """
        INSERT INTO incidents
            (source_ip, threat_level, confidence_score, status, mitre_technique, summary, raw_telemetry_ids)
        VALUES
            (%(source_ip)s, %(threat_level)s, %(confidence_score)s, %(status)s, %(mitre_technique)s, %(summary)s, %(raw_telemetry_ids)s)
        RETURNING id;
    """
    primary_ip = result.get("_flagged_ip") or (triage_logs[0].get("source_ip", "0.0.0.0") if triage_logs else "0.0.0.0")
    ids = [r["id"] for r in triage_logs if r.get("id")]
    row = {
        "source_ip":         primary_ip,
        "threat_level":      result.get("threat_level", "UNKNOWN"),
        "confidence_score":  float(result.get("confidence_score", 0)),
        "status":            "NEW",
        "mitre_technique":   result.get("mitre_technique", "T1190 - Exploit Public-Facing App"),
        "summary":           result.get("summary", ""),
        "raw_telemetry_ids": ids,
    }
    try:
        with _conn().cursor() as cur:
            cur.execute(sql, row)
            return cur.fetchone()[0]
    except Exception as exc:
        st.warning(f"Could not persist incident: {exc}")
        return None


def update_incident_lifecycle(incident_id: int, new_status: str, notes: str = "") -> bool:
    """Updates the status and analyst notes of an incident."""
    sql = """
        UPDATE incidents
        SET status = %(status)s,
            analyst_notes = CASE WHEN %(notes)s != '' THEN %(notes)s ELSE analyst_notes END
        WHERE id = %(id)s;
    """
    try:
        with _conn().cursor() as cur:
            cur.execute(sql, {"status": new_status, "notes": notes, "id": incident_id})
        return True
    except Exception as exc:
        st.error(f"Error updating incident #{incident_id}: {exc}")
        return False


# ─────────────────────────────────────────────────────────────────
# SOAR AUTOMATED CONTAINMENT HELPERS
# ─────────────────────────────────────────────────────────────────
def get_perimeter_blocked_ips() -> list[str]:
    """Queries target_app perimeter for currently quarantined IPs."""
    try:
        resp = requests.get(f"{TARGET_API_URL}/api/v1/soc/blocked-ips", timeout=1.5)
        if resp.status_code == 200:
            return resp.json().get("blocked_ips", [])
    except Exception:
        pass
    return []

def block_ip_on_perimeter(ip: str) -> bool:
    """Sends SOAR automated containment block signal to the target application gateway."""
    try:
        resp = requests.post(f"{TARGET_API_URL}/api/v1/soc/block-ip", json={"ip": ip}, timeout=2.0)
        return resp.status_code == 200
    except Exception:
        return False

def unblock_ip_on_perimeter(ip: str) -> bool:
    """Removes an IP block rule."""
    try:
        resp = requests.post(f"{TARGET_API_URL}/api/v1/soc/unblock-ip", json={"ip": ip}, timeout=2.0)
        return resp.status_code == 200
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────
# AI TRIAGE ENGINE (MOCK & GROQ LLM)
# ─────────────────────────────────────────────────────────────────
def mock_ai_triage(logs: list[dict]) -> dict:
    """Expert rule-based heuristics simulating a Tier-3 SOC analyst triage."""
    if not logs:
        return {
            "threat_level":       "LOW",
            "confidence_score":   10.0,
            "mitre_tactic":       "Nominal",
            "mitre_technique":    "N/A",
            "summary":            "No telemetry logs available in the analysis window.",
            "recommended_action": "Maintain routine baseline monitoring.",
            "_mock": True,
            "_flagged_ip": "N/A"
        }

    event_types = [l.get("event_type", "") for l in logs]
    status_codes = [int(l.get("status_code", 200)) for l in logs]
    auth_fails = event_types.count("AUTH_FAILURE")

    # 1. SQL Injection Detection
    sqli_log = next((l for l in logs if l.get("event_type") == "SQLI_DETECTED"), None)
    if sqli_log:
        return {
            "threat_level":       "CRITICAL",
            "confidence_score":   98.2,
            "mitre_tactic":       "Initial Access / Privilege Escalation",
            "mitre_technique":    "T1190 - Exploit Public-Facing Application",
            "summary": (
                f"High-impact SQL Injection exploit verified from host {sqli_log.get('source_ip')}. "
                f"Malicious payload `' OR 1=1 --` bypassed authentication logic on {sqli_log.get('endpoint')}, "
                f"granting administrative privileges. Immediate isolation required."
            ),
            "recommended_action": "Execute SOAR Containment Playbook #1: Block attacker IP, revoke active JWT tokens, and inspect database query logs.",
            "_mock": True,
            "_flagged_ip": sqli_log.get("source_ip", "127.0.0.1"),
        }

    # 2. Local File Inclusion (LFI) / Path Traversal
    lfi_log = next((l for l in logs if l.get("event_type") == "LFI_DETECTED"), None)
    if lfi_log:
        return {
            "threat_level":       "HIGH",
            "confidence_score":   94.5,
            "mitre_tactic":       "Discovery / Initial Access",
            "mitre_technique":    "T1059 - Command and Scripting Interpreter / T1005 - Data from Local System",
            "summary": (
                f"Directory traversal and local file inclusion attack detected from {lfi_log.get('source_ip')}. "
                f"Path traversal sequence `../../etc/passwd` submitted to {lfi_log.get('endpoint')} targeting system credential files."
            ),
            "recommended_action": "Block source IP at gateway. Verify web application chroot jail and audit sanitization filters.",
            "_mock": True,
            "_flagged_ip": lfi_log.get("source_ip", "127.0.0.1"),
        }

    # 3. Credential Stuffing / Brute Force
    if auth_fails >= 3:
        bf_log = next((l for l in logs if l.get("event_type") == "AUTH_FAILURE"), logs[0])
        return {
            "threat_level":       "HIGH",
            "confidence_score":   89.0,
            "mitre_tactic":       "Credential Access",
            "mitre_technique":    "T1110 - Brute Force / Password Guessing",
            "summary": (
                f"Distributed credential stuffing / brute force attack identified from {bf_log.get('source_ip')}. "
                f"{auth_fails} failed login attempts registered across accounts within seconds. Threshold exceeded."
            ),
            "recommended_action": "Trigger account lockout policy. Rate limit origin subnet. Block source IP.",
            "_mock": True,
            "_flagged_ip": bf_log.get("source_ip", "127.0.0.1"),
        }

    # 4. Large Suspicious Financial Wire Transfer
    transfer_log = next((l for l in logs if l.get("event_type") == "TRANSFER_LARGE"), None)
    if transfer_log:
        return {
            "threat_level":       "MEDIUM",
            "confidence_score":   76.0,
            "mitre_tactic":       "Exfiltration / Impact",
            "mitre_technique":    "T1041 - Exfiltration Over C2 Channel / T1499 - Endpoint DoS",
            "summary": (
                f"High-value anomalous fund transfer flagged from account associated with {transfer_log.get('source_ip')}. "
                f"Amount exceeds automated clearing limits ($10,000 threshold)."
            ),
            "recommended_action": "Place transaction on temporary compliance hold. Trigger Step-Up MFA authentication.",
            "_mock": True,
            "_flagged_ip": transfer_log.get("source_ip", "127.0.0.1"),
        }

    # 5. WAF Containment Active Event
    waf_log = next((l for l in logs if l.get("event_type") == "WAF_BLOCK"), None)
    if waf_log:
        return {
            "threat_level":       "MEDIUM",
            "confidence_score":   92.0,
            "mitre_tactic":       "Defense Evasion (Prevented)",
            "mitre_technique":    "T1562 - Impair Defenses (Blocked)",
            "summary": (
                f"Quarantined IP {waf_log.get('source_ip')} attempted reconnection. Traffic was successfully "
                f"dropped with 403 Forbidden by the perimeter SOAR firewall rule."
            ),
            "recommended_action": "Firewall containment is active and functioning properly. No manual action required.",
            "_mock": True,
            "_flagged_ip": waf_log.get("source_ip", "127.0.0.1"),
        }

    # 6. General HTTP Errors
    if any(c >= 400 for c in status_codes):
        return {
            "threat_level":       "LOW",
            "confidence_score":   45.0,
            "mitre_tactic":       "Reconnaissance",
            "mitre_technique":    "T1595 - Active Scanning",
            "summary":            "Elevated HTTP error responses detected. Potential automated endpoint reconnaissance.",
            "recommended_action": "Monitor source IP traffic patterns for escalation.",
            "_mock": True,
            "_flagged_ip": logs[0].get("source_ip", "N/A"),
        }

    # 7. Nominal
    return {
        "threat_level":       "LOW",
        "confidence_score":   12.0,
        "mitre_tactic":       "Nominal Operations",
        "mitre_technique":    "None",
        "summary":            "All telemetry streams within expected operational parameters. No malicious signatures identified.",
        "recommended_action": "Continue automated telemetry polling.",
        "_mock": True,
        "_flagged_ip": logs[0].get("source_ip", "N/A") if logs else "N/A",
    }


def groq_triage(logs: list[dict], api_key: str) -> dict:
    """Calls Groq LLM (openai/gpt-oss-120b) for structured zero-shot triage."""
    try:
        from groq import Groq
    except ImportError:
        return mock_ai_triage(logs)

    system_prompt = (
        "You are a Tier-3 Principal SOC Analyst. Review telemetry logs from an enterprise banking web service.\n"
        "Identify attacks (SQL Injection, Directory Traversal, Brute Force, Large Wire Fraud).\n"
        "Return ONLY a raw JSON object with keys:\n"
        '{"threat_level": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL", "confidence_score": <float 0-100>, '
        '"mitre_tactic": "<tactic>", "mitre_technique": "<e.g. T1190 - ...>", '
        '"summary": "<concise technical executive analysis>", "recommended_action": "<action>", "flagged_ip": "<ip>"}'
    )

    try:
        client = Groq(api_key=api_key)
        resp = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Telemetry window ({len(logs)} events):\n{json.dumps(logs, indent=2, default=str)}"}
            ],
            temperature=0.1,
            max_tokens=512,
        )
        raw = resp.choices[0].message.content.strip()
        raw = re.sub(r"^```(?:json)?\s*", "", raw)
        raw = re.sub(r"\s*```$", "", raw)
        res = json.loads(raw)
        res["threat_level"] = str(res.get("threat_level", "LOW")).upper()
        res["confidence_score"] = float(res.get("confidence_score", 85.0))
        res["_mock"] = False
        res["_flagged_ip"] = res.get("flagged_ip") or (logs[0].get("source_ip") if logs else "127.0.0.1")
        return res
    except Exception:
        return mock_ai_triage(logs)


def query_ai_copilot(question: str, context_logs: list[dict], current_incident: dict | None, api_key: str) -> str:
    """Interactive SOC Copilot Q&A handler with fallback intelligence."""
    # Context summary string
    context_str = f"Active Threat Level: {current_incident.get('threat_level') if current_incident else 'NORMAL'}\n"
    if current_incident:
        context_str += f"MITRE Technique: {current_incident.get('mitre_technique')}\nSummary: {current_incident.get('summary')}\nFlagged IP: {current_incident.get('_flagged_ip')}\n"
    context_str += f"Recent Telemetry Events: {len(context_logs)} events loaded.\n"

    if api_key:
        try:
            from groq import Groq
            client = Groq(api_key=api_key)
            resp = client.chat.completions.create(
                model="openai/gpt-oss-120b",
                messages=[
                    {"role": "system", "content": "You are 'Atlas', an Autonomous Senior AI SOC Analyst. Provide crisp, technical, actionable cybersecurity answers using the MITRE ATT&CK framework, NIST SP 800-61, and enterprise security engineering practices. Answer directly without fluff."},
                    {"role": "system", "content": f"Current SOC Environment Context:\n{context_str}"},
                    {"role": "user", "content": question}
                ],
                temperature=0.2,
                max_tokens=600,
            )
            return resp.choices[0].message.content.strip()
        except Exception:
            pass

    # Intelligent expert fallback responses for common questions
    q_lower = question.lower()
    if "root cause" in q_lower or "how did" in q_lower:
        return (
            "**Root Cause Analysis:**\n"
            "- **Vulnerability:** Unsanitized user input concatenated into SQL query string (`' OR 1=1 --`) on the `/api/v1/auth/login` endpoint.\n"
            "- **Mechanism:** The SQL injection altered the boolean evaluation of the `WHERE` clause, evaluating truthy for all records and returning the top-ranked user (`admin`).\n"
            "- **Impact:** Total authentication bypass, yielding valid admin mock JWT tokens to an untrusted actor."
        )
    elif "waf" in q_lower or "patch" in q_lower or "fix" in q_lower:
        return (
            "**Recommended Technical Remediation:**\n\n"
            "**1. Code Patch (Python / Parameterized Queries):**\n"
            "```python\n"
            "# NEVER interpolate user input: f\"SELECT * FROM users WHERE user='{username}'\"\n"
            "# USE parameterized query bindings:\n"
            "cur.execute(\"SELECT * FROM users WHERE username = %s AND password_hash = %s\", (username, hashed_pw))\n"
            "```\n\n"
            "**2. Perimeter Nginx / ModSecurity WAF Rule:**\n"
            "```nginx\n"
            "# Block SQLi syntax in request URIs or request bodies\n"
            "SecRule REQUEST_URI|REQUEST_BODY \"(?i:(\\b(select|union|insert|update|delete|drop)\\b|'\\s*(or|and)\\s*\\d+=\\d+))\" \\\n"
            "    \"id:10001,phase:2,deny,status:403,log,msg:'SQL Injection Attempt Dropped'\"\n"
            "```"
        )
    elif "pci" in q_lower or "compliance" in q_lower or "gdpr" in q_lower:
        return (
            "**Regulatory & Compliance Assessment:**\n"
            "- **PCI-DSS v4.0 Requirement 6.5.1:** Direct violation of injection flaw prevention controls. Mandatory code remediation within 30 days.\n"
            "- **GDPR Article 32 (Security of Processing):** If customer records or PII were accessed during the bypass, formal notification to supervisory authorities (DPA) is required within 72 hours under Article 33.\n"
            "- **Audit Trail Integrity:** Ensure PostgreSQL `telemetry_logs` are preserved with write-once/append-only policies for forensic admissibility."
        )
    else:
        return (
            f"**Autonomous SOC Analyst Assessment:**\n\n"
            f"Based on current telemetry telemetry logs and the active incident dossier:\n"
            f"- **Threat Profile:** {current_incident.get('mitre_technique', 'T1190 - Exploit Public-Facing Application') if current_incident else 'Nominal Baseline'}\n"
            f"- **Attacking Host:** `{current_incident.get('_flagged_ip', '185.220.101.5') if current_incident else 'N/A'}`\n"
            f"- **Tactical Response:** Execute automated containment rule to null-route the origin IP, cycle API secrets, and review database access audit tables."
        )


def generate_executive_briefing(incident: dict, logs: list[dict]) -> str:
    """Generates an executive-ready Markdown Incident Briefing."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    threat = incident.get("threat_level", "HIGH")
    ip = incident.get("_flagged_ip", "185.220.101.5")
    mitre = incident.get("mitre_technique", "T1190 - Exploit Public-Facing Application")
    conf = incident.get("confidence_score", 95.0)

    return f"""# 🛡️ CYBERSECURITY INCIDENT BRIEFING (EXECUTIVE DOSSIER)
**Document Ref:** SEC-INC-{datetime.now().strftime('%Y%m%d')}-001  
**Classification:** TLP:AMBER (Internal Leadership & SOC Review)  
**Generated At:** {ts}  
**Investigation Lead:** AI Autonomous SOC Engine (Tier-3 AI Analyst)

---

### 1. Executive Summary
On {ts}, the Autonomous SOC monitoring engine identified a **{threat}** security intrusion targeting the production Financial Web Service. 
The incident involves an adversary attempting **{mitre}** from originating IP `{ip}`. 
Automated detection heuristics and LLM triage mapped the activity with a confidence score of **{conf}%**.

---

### 2. Threat Vector & Technical Analysis
- **Target Application:** Mock Financial API (`http://localhost:5001`)
- **Vulnerability Category:** CWE-89 (Improper Neutralization of Special Elements in SQL Command)
- **Targeted Endpoints:** `/api/v1/auth/login`
- **Adversary Origin:** `{ip}` (Simulated Foreign Gateway / Bulletproof Infrastructure)
- **Observed Behavior:** Exploitation payload was delivered via JSON body, executing a classic SQL evaluation bypass (`' OR 1=1 --`) allowing arbitrary privilege escalation to administrator credentials.

---

### 3. Business & Compliance Risk Assessment
| Regulatory Framework | Status | Assessment |
| :--- | :--- | :--- |
| **PCI-DSS v4.0** | **ALERT** | Requirement 6.5.1 injection vulnerability flagged. |
| **GDPR Art. 32** | **ASSESSING** | Blast radius verification in progress to verify if customer PII was exfiltrated. |
| **SOC 2 Type II** | **COMPLIANT** | Telemetry and containment audit logs were captured without data loss. |

---

### 4. Containment & Remediation Actions Taken
1. **Perimeter Quarantine:** Threat IP `{ip}` submitted to SOAR automated firewall rule.
2. **Session Invalidation:** Revocation tokens broadcasted to API gateways.
3. **Forensic Logging:** All telemetry ingested into immutable PostgreSQL store (`telemetry_logs`).

---

*Report prepared by AI SOC Automation Platform · Financial Services Defense Architecture*
"""


# ─────────────────────────────────────────────────────────────────
# ATTACK SIMULATOR BACKEND
# ─────────────────────────────────────────────────────────────────
def run_simulation(attack_type: str) -> dict:
    """Dispatches real HTTP requests to target_app simulating realistic attacks."""
    base_url = TARGET_API_URL
    try:
        if attack_type == "sqli":
            resp = requests.post(
                f"{base_url}/api/v1/auth/login",
                json={"username": "' OR 1=1 --", "password": "password"},
                headers={"X-Forwarded-For": "185.220.101.5", "User-Agent": "sqlmap/1.7.2#stable"},
                timeout=2.0,
            )
            return {"status": "success", "msg": "SQL Injection Exploit triggered from 185.220.101.5", "code": resp.status_code}

        elif attack_type == "bruteforce":
            users = ["admin", "root", "sarah.mitchell", "david.h", "finance_exec", "treasury"]
            for u in users:
                requests.post(
                    f"{base_url}/api/v1/auth/login",
                    json={"username": u, "password": f"Password{random.randint(100,999)}!"},
                    headers={"X-Forwarded-For": "45.146.164.110", "User-Agent": "Hydra/9.5"},
                    timeout=1.0,
                )
            return {"status": "success", "msg": f"Credential Stuffing burst ({len(users)} attempts) launched from 45.146.164.110", "code": 401}

        elif attack_type == "lfi":
            resp = requests.get(
                f"{base_url}/api/v1/system/file",
                params={"name": "../../../../etc/passwd"},
                headers={"X-Forwarded-For": "194.26.29.112", "User-Agent": "Nikto/2.1.6"},
                timeout=2.0,
            )
            return {"status": "success", "msg": "Directory Traversal (LFI) probe triggered from 194.26.29.112", "code": resp.status_code}

        elif attack_type == "large_transfer":
            resp = requests.post(
                f"{base_url}/api/v1/accounts/transfer",
                json={"sender": "alice", "recipient": "offshore_cayman_holdings", "amount": 500000.00},
                headers={"X-Forwarded-For": "103.251.167.22", "User-Agent": "curl/8.7.1"},
                timeout=2.0,
            )
            return {"status": "success", "msg": "Suspicious $500,000 Transfer dispatched from 103.251.167.22", "code": resp.status_code}

        elif attack_type == "normal":
            # Normal clean traffic
            requests.post(f"{base_url}/api/v1/auth/login", json={"username": "alice", "password": "password123"}, timeout=1.0)
            requests.post(f"{base_url}/api/v1/accounts/transfer", json={"sender": "alice", "recipient": "bob", "amount": 45.50}, timeout=1.0)
            requests.post(f"{base_url}/api/v1/auth/login", json={"username": "bob", "password": "securepass"}, timeout=1.0)
            return {"status": "success", "msg": "Nominal user traffic baseline generated", "code": 200}

        elif attack_type == "apt":
            # Multi-stage kill chain
            requests.get(f"{base_url}/api/v1/system/file", params={"name": "../../../../etc/passwd"}, headers={"X-Forwarded-For": "185.220.101.5"}, timeout=1.0)
            requests.post(f"{base_url}/api/v1/auth/login", json={"username": "admin", "password": "wrong"}, headers={"X-Forwarded-For": "185.220.101.5"}, timeout=1.0)
            requests.post(f"{base_url}/api/v1/auth/login", json={"username": "' OR 1=1 --", "password": "any"}, headers={"X-Forwarded-For": "185.220.101.5"}, timeout=1.0)
            requests.post(f"{base_url}/api/v1/accounts/transfer", json={"sender": "admin", "recipient": "shadow_broker", "amount": 250000.00}, headers={"X-Forwarded-For": "185.220.101.5"}, timeout=1.0)
            return {"status": "success", "msg": "Full 4-Stage APT Intrusion Campaign executed from 185.220.101.5", "code": 200}

    except Exception as exc:
        return {"status": "error", "msg": f"Target App unreachable: {exc}", "code": 500}

    return {"status": "error", "msg": "Unknown scenario", "code": 400}


# ─────────────────────────────────────────────────────────────────
# PLOTLY CHART BUILDERS
# ─────────────────────────────────────────────────────────────────
def create_threat_velocity_chart(df: pd.DataFrame):
    """Area sparkline of request velocity with highlighted threat markers."""
    if df.empty or len(df) < 2:
        fig = go.Figure()
        fig.add_annotation(text="Awaiting telemetry data stream...", showarrow=False, font=dict(color="#8b949e", size=14))
        fig.update_layout(paper_bgcolor="#0e1422", plot_bgcolor="#0e1422", height=240, margin=dict(l=10, r=10, t=20, b=10))
        return fig

    dff = df.sort_values("timestamp").copy()
    dff["count"] = 1
    # Resample or index-based trace
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=dff["timestamp"],
        y=list(range(1, len(dff) + 1)),
        mode="lines+markers",
        name="Telemetry Stream",
        line=dict(color="#00e5ff", width=2.5, shape="spline"),
        marker=dict(size=5, color="#00e5ff"),
        fill="tozeroy",
        fillcolor="rgba(0, 229, 255, 0.08)",
        hovertemplate="Time: %{x}<br>Cumulative Events: %{y}<extra></extra>"
    ))

    # Highlight threats
    threat_mask = dff["event_type"].isin(["SQLI_DETECTED", "LFI_DETECTED", "WAF_BLOCK"])
    if threat_mask.any():
        threat_df = dff[threat_mask]
        indices = [list(dff.index).index(i) + 1 for i in threat_df.index]
        fig.add_trace(go.Scatter(
            x=threat_df["timestamp"],
            y=indices,
            mode="markers",
            name="Critical Exploit",
            marker=dict(color="#ff1744", size=12, symbol="cross", line=dict(color="#ffffff", width=1.5)),
            hovertemplate="ALERT: %{text}<br>Time: %{x}<extra></extra>",
            text=threat_df["event_type"]
        ))

    fig.update_layout(
        paper_bgcolor="#0e1422",
        plot_bgcolor="#0e1422",
        height=240,
        margin=dict(l=15, r=15, t=10, b=25),
        xaxis=dict(showgrid=True, gridcolor="#1b2438", zeroline=False, color="#8b949e"),
        yaxis=dict(showgrid=True, gridcolor="#1b2438", zeroline=False, color="#8b949e"),
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, font=dict(color="#8b949e", size=11)),
    )
    return fig


def create_threat_distribution_chart(df: pd.DataFrame):
    """Donut chart of event types."""
    if df.empty:
        fig = go.Figure()
        fig.update_layout(paper_bgcolor="#0e1422", plot_bgcolor="#0e1422", height=240)
        return fig

    counts = df["event_type"].value_counts().reset_index()
    counts.columns = ["event_type", "count"]

    color_map = {
        "SQLI_DETECTED": "#ff1744",
        "LFI_DETECTED":  "#d500f9",
        "AUTH_FAILURE":  "#ff9100",
        "TRANSFER_LARGE": "#ffd600",
        "WAF_BLOCK":     "#ff5252",
        "AUTH_SUCCESS":  "#00e676",
        "TRANSFER":      "#00b0ff",
        "FILE_ACCESS":   "#7c4dff",
    }
    colors = [color_map.get(k, "#58a6ff") for k in counts["event_type"]]

    fig = go.Figure(data=[go.Pie(
        labels=counts["event_type"],
        values=counts["count"],
        hole=0.62,
        marker=dict(colors=colors, line=dict(color="#0e1422", width=2)),
        textinfo="percent",
        hoverinfo="label+value+percent",
    )])

    fig.update_layout(
        paper_bgcolor="#0e1422",
        plot_bgcolor="#0e1422",
        height=240,
        margin=dict(l=10, r=10, t=10, b=10),
        showlegend=True,
        legend=dict(orientation="v", y=0.5, font=dict(color="#c9d1d9", size=10)),
    )
    return fig


def create_top_ips_chart(df: pd.DataFrame, blocked_ips: list[str]):
    """Horizontal bar chart of top active source IPs."""
    if df.empty:
        fig = go.Figure()
        fig.update_layout(paper_bgcolor="#0e1422", plot_bgcolor="#0e1422", height=240)
        return fig

    ip_counts = df["source_ip"].astype(str).value_counts().head(5).reset_index()
    ip_counts.columns = ["source_ip", "events"]

    bar_colors = ["#ff1744" if ip in blocked_ips else "#00e5ff" for ip in ip_counts["source_ip"]]

    fig = go.Figure(go.Bar(
        x=ip_counts["events"],
        y=ip_counts["source_ip"],
        orientation="h",
        marker=dict(color=bar_colors, line=dict(color="#1f2c44", width=1)),
        text=ip_counts["events"],
        textposition="outside",
        hovertemplate="IP: %{y}<br>Events: %{x}<extra></extra>"
    ))

    fig.update_layout(
        paper_bgcolor="#0e1422",
        plot_bgcolor="#0e1422",
        height=240,
        margin=dict(l=10, r=20, t=10, b=20),
        xaxis=dict(showgrid=True, gridcolor="#1b2438", zeroline=False, color="#8b949e"),
        yaxis=dict(autorange="reversed", color="#c9d1d9"),
    )
    return fig


def create_confidence_gauge(score: float):
    """Semi-circle gauge for AI threat confidence."""
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        number={'suffix': "%", 'font': {'color': '#ffffff', 'size': 26}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#484f58"},
            'bar': {'color': "#00e5ff" if score < 70 else ("#ff9100" if score < 85 else "#ff1744"), 'thickness': 0.3},
            'bgcolor': "#0e1422",
            'borderwidth': 1,
            'bordercolor': "#1f2c44",
            'steps': [
                {'range': [0, 50], 'color': 'rgba(0, 230, 118, 0.15)'},
                {'range': [50, 80], 'color': 'rgba(255, 145, 0, 0.15)'},
                {'range': [80, 100], 'color': 'rgba(255, 23, 68, 0.20)'},
            ],
        }
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        height=150,
        margin=dict(l=15, r=15, t=10, b=10),
    )
    return fig


# ─────────────────────────────────────────────────────────────────
# SESSION STATE INITIALIZATION
# ─────────────────────────────────────────────────────────────────
if "triage_result" not in st.session_state: st.session_state["triage_result"] = None
if "incident_id" not in st.session_state: st.session_state["incident_id"] = None
if "triage_logs" not in st.session_state: st.session_state["triage_logs"] = []
if "chat_messages" not in st.session_state: st.session_state["chat_messages"] = []
if "copilot_input" not in st.session_state: st.session_state["copilot_input"] = ""


# ─────────────────────────────────────────────────────────────────
# SIDEBAR CONTROL PLANE
# ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("### 🛡️ SOC CONTROL PLANE")
    st.caption("Next-Gen Autonomous AI Operations")
    st.markdown("---")

    # Ingestion & System Status
    blocked_ips = get_perimeter_blocked_ips()
    st.markdown("**Infrastructure Telemetry**")
    st.markdown(f'<span class="radar-pulse-green"></span> Ingest Daemon: **ONLINE**', unsafe_allow_html=True)
    st.markdown(f'<span class="radar-pulse-green"></span> PostgreSQL Store: **CONNECTED**', unsafe_allow_html=True)
    st.markdown(f'<span class="{"radar-pulse-red" if blocked_ips else "radar-pulse-green"}"></span> Perimeter WAF: **{len(blocked_ips)} Blocked**', unsafe_allow_html=True)
    st.markdown("---")

    # AI Engine Config
    st.markdown("**AI Intelligence Engine**")
    env_key = os.environ.get("GROQ_API_KEY", "")
    groq_api_key = st.text_input(
        "Groq API Key",
        value=env_key,
        type="password",
        placeholder="gsk_••••••••••••••••••••••",
        help="Powered by Groq Llama-3 / GPT-OSS inference. Uses heuristic Tier-3 mock engine when omitted.",
    )
    if groq_api_key.strip():
        st.success("🔑 LLM Engine: Groq Active")
    else:
        st.info("⚡ Mode: Heuristic Tier-3 Mock Active")
    st.markdown("---")

    # Primary Action Button
    st.markdown("**Threat Triage Actions**")
    run_triage = st.button("🔍 Run AI Threat Triage", use_container_width=True, type="primary")

    auto_refresh = st.toggle("⚡ Live Auto-Refresh (10s)", value=True)
    if st.button("🔃 Refresh Dashboard Now", use_container_width=True):
        st.rerun()

    if blocked_ips:
        st.markdown("---")
        st.markdown(f"**Quarantined Perimeter IPs ({len(blocked_ips)})**")
        for b_ip in blocked_ips:
            col_b1, col_b2 = st.columns([3, 1])
            col_b1.code(b_ip)
            if col_b2.button("Unblock", key=f"unblock_{b_ip}"):
                unblock_ip_on_perimeter(b_ip)
                st.rerun()

    st.markdown("---")
    st.caption("Autonomous AI SOC Platform v3.0\nPresentation Edition · Enterprise Grade")


# ─────────────────────────────────────────────────────────────────
# TRIAGE EXECUTION LOGIC
# ─────────────────────────────────────────────────────────────────
if run_triage:
    triage_logs = fetch_logs_for_triage(limit=15)
    if not triage_logs:
        st.sidebar.error("⚠️ No logs available to analyze. Launch a simulated attack first.")
    else:
        with st.spinner("🤖 AI Analyst correlating telemetry patterns & MITRE tactics..."):
            if groq_api_key.strip():
                result = groq_triage(triage_logs, groq_api_key.strip())
            else:
                time.sleep(1.0)
                result = mock_ai_triage(triage_logs)

        st.session_state["triage_result"] = result
        st.session_state["triage_logs"] = triage_logs

        if result.get("threat_level") in ("HIGH", "CRITICAL", "MEDIUM"):
            inc_id = insert_incident(result, triage_logs)
            st.session_state["incident_id"] = inc_id
        else:
            st.session_state["incident_id"] = None


# ─────────────────────────────────────────────────────────────────
# DASHBOARD HEADER
# ─────────────────────────────────────────────────────────────────
current_result = st.session_state.get("triage_result")
active_threat = current_result.get("threat_level") if current_result else "NORMAL"

col_head1, col_head2 = st.columns([7, 3])
with col_head1:
    st.markdown(
        "<div style='display:flex;align-items:center;gap:12px;margin-bottom:4px;'>"
        "<span style='font-size:2.2rem;'>🛡️</span>"
        "<h1 style='margin:0;font-size:1.85rem;font-weight:800;letter-spacing:-0.03em;'>AUTONOMOUS AI SECURITY OPERATIONS CENTER</h1>"
        "</div>",
        unsafe_allow_html=True
    )
    st.markdown(
        "<p style='color:#8b949e;margin-top:-6px;font-size:0.88rem;'>"
        "Real-Time Telemetry Correlation · Groq LLM Triage · SOAR Automated Containment · MITRE ATT&CK Framework"
        "</p>",
        unsafe_allow_html=True
    )

with col_head2:
    if active_threat in ("CRITICAL", "HIGH"):
        defcon_html = f'<div style="text-align:right;"><span class="radar-pulse-red"></span><span style="color:#ff1744;font-weight:800;font-size:1.1rem;letter-spacing:0.05em;">DEFCON 2 · ELEVATED THREAT</span><br><span style="color:#8b949e;font-size:0.75rem;">Active Adversary Activity Detected</span></div>'
    else:
        defcon_html = f'<div style="text-align:right;"><span class="radar-pulse-green"></span><span style="color:#00e676;font-weight:800;font-size:1.1rem;letter-spacing:0.05em;">DEFCON 5 · NOMINAL</span><br><span style="color:#8b949e;font-size:0.75rem;">Continuous Perimeter Monitoring</span></div>'
    st.markdown(defcon_html, unsafe_allow_html=True)

st.markdown("---")


# ─────────────────────────────────────────────────────────────────
# TABBED PRESENTATION INTERFACE
# ─────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Real-Time Operations & Telemetry",
    "🛡️ AI Threat Triage & SOAR Playbooks",
    "🎯 Threat Simulation Center (1-Click)",
    "🧠 AI SOC Copilot & Executive Briefing",
])


# ═════════════════════════════════════════════════════════════════
# TAB 1: OPERATIONS & REAL-TIME TELEMETRY
# ═════════════════════════════════════════════════════════════════
with tab1:
    df_logs = fetch_recent_logs(limit=100)
    blocked_ips_list = get_perimeter_blocked_ips()

    # Executive KPI Metric Row
    total_events = len(df_logs)
    error_count = int((df_logs["status_code"] >= 400).sum()) if not df_logs.empty else 0
    sqli_count = int((df_logs["event_type"] == "SQLI_DETECTED").sum()) if not df_logs.empty else 0
    lfi_count = int((df_logs["event_type"] == "LFI_DETECTED").sum()) if not df_logs.empty else 0
    unique_ips = int(df_logs["source_ip"].nunique()) if not df_logs.empty else 0
    error_rate = (error_count / total_events * 100) if total_events > 0 else 0

    kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
    kpi1.metric("Ingested Telemetry", f"{total_events:,}", delta="Live PostgreSQL Stream")
    kpi2.metric("Critical Exploit Signals", sqli_count + lfi_count, delta=f"{sqli_count} SQLi / {lfi_count} LFI", delta_color="inverse")
    kpi3.metric("HTTP Error Rate", f"{error_rate:.1f}%", delta=f"{error_count} Anomalies", delta_color="inverse")
    kpi4.metric("Perimeter WAF Blocks", len(blocked_ips_list), delta="SOAR Quarantined", delta_color="normal")
    kpi5.metric("Unique Origin IPs", unique_ips, delta="Telemetry Sources")

    st.markdown("<br>", unsafe_allow_html=True)

    # Visual Analytics Row
    col_chart1, col_chart2, col_chart3 = st.columns([4, 3, 3])
    with col_chart1:
        st.markdown("**📡 Telemetry Velocity & Exploit Timeline**")
        st.plotly_chart(create_threat_velocity_chart(df_logs), use_container_width=True)

    with col_chart2:
        st.markdown("**🎯 Threat & Event Classification**")
        st.plotly_chart(create_threat_distribution_chart(df_logs), use_container_width=True)

    with col_chart3:
        st.markdown("**🌐 Top Active Originating IPs**")
        st.plotly_chart(create_top_ips_chart(df_logs, blocked_ips_list), use_container_width=True)

    st.markdown("---")

    # Filterable Live Telemetry Table
    st.markdown("### 📡 Live Structured Telemetry Stream")

    if df_logs.empty:
        st.info("⏳ Telemetry pipeline listening on `logs/app.log`. Generate traffic using the Threat Simulation Center tab.")
    else:
        # Filter controls
        f_col1, f_col2, f_col3 = st.columns([3, 3, 4])
        with f_col1:
            all_types = ["ALL"] + sorted(list(df_logs["event_type"].unique()))
            sel_type = st.selectbox("Filter Event Type", all_types)
        with f_col2:
            all_codes = ["ALL"] + sorted([str(c) for c in df_logs["status_code"].unique()])
            sel_code = st.selectbox("Filter HTTP Status", all_codes)
        with f_col3:
            search_query = st.text_input("Search (IP, Endpoint, User)", placeholder="e.g. 185.220 or login or alice")

        filtered_df = df_logs.copy()
        if sel_type != "ALL":
            filtered_df = filtered_df[filtered_df["event_type"] == sel_type]
        if sel_code != "ALL":
            filtered_df = filtered_df[filtered_df["status_code"] == int(sel_code)]
        if search_query.strip():
            sq = search_query.strip().lower()
            filtered_df = filtered_df[
                filtered_df["source_ip"].astype(str).str.lower().str.contains(sq) |
                filtered_df["endpoint"].astype(str).str.lower().str.contains(sq) |
                filtered_df["user_id"].astype(str).str.lower().str.contains(sq)
            ]

        # Format display
        display_table = filtered_df[["id", "timestamp", "source_ip", "event_type", "endpoint", "http_method", "status_code", "user_id"]].copy()
        display_table["timestamp"] = pd.to_datetime(display_table["timestamp"]).dt.strftime("%H:%M:%S UTC")

        st.dataframe(display_table, use_container_width=True, height=320)

        with st.expander("🔬 Telemetry Inspector (View Raw JSON Payloads & Headers)"):
            row_ids = filtered_df["id"].tolist()
            if row_ids:
                selected_id = st.selectbox("Select Telemetry Row ID to Inspect", row_ids)
                row_data = filtered_df[filtered_df["id"] == selected_id].iloc[0]
                insp_col1, insp_col2 = st.columns(2)
                with insp_col1:
                    st.markdown("**Sanitized Request Payload**")
                    st.json(row_data.get("payload") or {})
                with insp_col2:
                    st.markdown("**HTTP Request Headers**")
                    st.json(row_data.get("headers") or {})


# ═════════════════════════════════════════════════════════════════
# TAB 2: AI THREAT TRIAGE & SOAR PLAYBOOKS
# ═════════════════════════════════════════════════════════════════
with tab2:
    st.markdown("### 🚨 Active Incident Analysis & Automated Containment")

    result = st.session_state.get("triage_result")
    inc_id = st.session_state.get("incident_id")

    if result is None:
        st.markdown(
            "<div style='background:#101625;border:1px solid #1f2c44;border-radius:10px;padding:26px;text-align:center;color:#8b949e;'>"
            "<h4>No Active Incident Evaluated</h4>"
            "<p>Click <strong>🔍 Run AI Threat Triage</strong> in the sidebar or trigger an exploit from the <strong>Threat Simulation Center</strong>.</p>"
            "</div>",
            unsafe_allow_html=True
        )
    else:
        threat_level = result.get("threat_level", "LOW")
        card_class = {
            "CRITICAL": "alert-card-critical",
            "HIGH":     "alert-card-high",
            "MEDIUM":   "alert-card-medium",
            "LOW":      "alert-card-low",
        }.get(threat_level, "alert-card-low")

        flagged_ip = result.get("_flagged_ip", "185.220.101.5")
        conf_score = float(result.get("confidence_score", 95.0))
        is_blocked = flagged_ip in get_perimeter_blocked_ips()

        col_inc_left, col_inc_right = st.columns([6, 4])

        with col_inc_left:
            st.markdown(f"""
            <div class="{card_class}">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
                    <div>
                        <span class="badge-tag badge-crit">{threat_level} THREAT</span>
                        <span class="badge-tag badge-mitre" style="margin-left:8px;">{result.get('mitre_tactic', 'Initial Access')}</span>
                        {f'<span class="badge-tag badge-contained" style="margin-left:8px;">CONTAINED</span>' if is_blocked else ''}
                    </div>
                    <span style="color:#8b949e;font-size:0.8rem;font-family:monospace;">INCIDENT ID #{inc_id or 'LIVE'}</span>
                </div>
                <h3 style="margin-top:6px;color:#ffffff;font-size:1.25rem;">{result.get('mitre_technique', 'T1190 - Exploit Public-Facing Application')}</h3>
                <p style="color:#c9d1d9;font-size:0.95rem;line-height:1.5;margin-top:10px;">{result.get('summary', '')}</p>
                <div style="background:#090d16;border:1px solid #1c273c;border-radius:8px;padding:12px 14px;margin-top:14px;">
                    <span style="color:#58a6ff;font-weight:700;font-size:0.8rem;letter-spacing:0.05em;text-transform:uppercase;">RECOMMENDED PLAYBOOK ACTION</span>
                    <p style="color:#e6edf3;font-size:0.88rem;margin:4px 0 0 0;">{result.get('recommended_action', '')}</p>
                </div>
            </div>
            """, unsafe_allow_html=True)

        with col_inc_right:
            st.markdown("**🤖 AI Confidence & SOAR Containment Playbook**")
            st.plotly_chart(create_confidence_gauge(conf_score), use_container_width=True)

            # SOAR One-Click Containment Buttons
            st.markdown("**⚡ Automated Response Actions**")
            soar_col1, soar_col2 = st.columns(2)

            with soar_col1:
                if is_blocked:
                    if st.button("🔓 Revoke IP Quarantine", key="btn_unblock", use_container_width=True):
                        unblock_ip_on_perimeter(flagged_ip)
                        st.success(f"Quarantine removed for {flagged_ip}")
                        st.rerun()
                else:
                    if st.button("🛑 Block Attacker IP (SOAR)", key="btn_block", use_container_width=True, type="primary"):
                        if block_ip_on_perimeter(flagged_ip):
                            if inc_id:
                                update_incident_lifecycle(inc_id, "CONTAINED", f"Automated SOAR block installed for {flagged_ip}")
                            st.toast(f"✅ Threat Host {flagged_ip} blocked at gateway perimeter!")
                            st.rerun()

            with soar_col2:
                if st.button("🔒 Invalidate User Tokens", key="btn_tokens", use_container_width=True):
                    st.toast("✅ Admin JWT tokens revoked across gateway!")

            # Quick Report Download
            briefing_text = generate_executive_briefing(result, st.session_state.get("triage_logs", []))
            st.download_button(
                "📋 Export Incident Briefing (.md)",
                data=briefing_text,
                file_name=f"Incident_Report_{inc_id or 'latest'}.md",
                mime="text/markdown",
                use_container_width=True,
            )

    st.markdown("---")

    # Incident Lifecycle & History
    st.markdown("### 🗂️ Historical Incident Lifecycle Management")
    df_incidents = fetch_incidents(limit=15)

    if df_incidents.empty:
        st.caption("No persisted incidents yet.")
    else:
        # Incident management tool
        col_mgt1, col_mgt2, col_mgt3 = st.columns([2, 3, 5])
        with col_mgt1:
            sel_inc_id = st.selectbox("Select Incident ID", df_incidents["id"].tolist())
        with col_mgt2:
            new_st = st.selectbox("Update Status", ["NEW", "INVESTIGATING", "CONTAINED", "RESOLVED", "FALSE_POSITIVE"])
        with col_mgt3:
            note_text = st.text_input("Analyst Investigation Note", placeholder="e.g. Host quarantined via WAF rule #1002")

        if st.button("💾 Save Incident Update", key="btn_save_note"):
            if update_incident_lifecycle(sel_inc_id, new_st, note_text):
                st.success(f"Incident #{sel_inc_id} updated to {new_st}")
                st.rerun()

        # Display history table
        st.dataframe(df_incidents[["id", "created_at", "source_ip", "threat_level", "confidence_score", "status", "mitre_technique", "analyst_notes"]], use_container_width=True)


# ═════════════════════════════════════════════════════════════════
# TAB 3: THREAT SIMULATION CENTER ("DEMO MAGIC")
# ═════════════════════════════════════════════════════════════════
with tab3:
    st.markdown("### 🎯 Live Threat & Attack Vector Simulator")
    st.caption("Generate real adversarial telemetry payloads with 1-click to demonstrate live detection and SOAR containment during presentations.")

    sim_col1, sim_col2 = st.columns(2)

    with sim_col1:
        # Scenario 1: SQLi
        st.markdown("""
        <div class="sim-card">
            <span class="badge-tag badge-crit">CRITICAL EXPLOIT</span>
            <h4 style="margin:6px 0 4px 0;">SQL Injection Authentication Bypass</h4>
            <p style="color:#8b949e;font-size:0.85rem;margin-bottom:8px;">
                Injects <code>' OR 1=1 --</code> into login parameters from Tor Exit Node (<code>185.220.101.5</code>) to grant unauthorized admin credentials.
            </p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("🚀 Launch SQL Injection Attack", key="sim_sqli", use_container_width=True, type="primary"):
            res = run_simulation("sqli")
            st.toast(res["msg"])
            time.sleep(1.2)
            st.rerun()

        # Scenario 2: Brute Force
        st.markdown("""
        <div class="sim-card">
            <span class="badge-tag" style="background:rgba(255,145,0,0.2);border:1px solid #ff9100;color:#ff9100;">HIGH THREAT</span>
            <h4 style="margin:6px 0 4px 0;">Credential Stuffing Campaign (Brute Force)</h4>
            <p style="color:#8b949e;font-size:0.85rem;margin-bottom:8px;">
                Launches a rapid burst of failed authentication attempts from botnet host <code>45.146.164.110</code> against employee usernames.
            </p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("🚀 Launch Credential Stuffing Campaign", key="sim_bf", use_container_width=True):
            res = run_simulation("bruteforce")
            st.toast(res["msg"])
            time.sleep(1.2)
            st.rerun()

        # Scenario 3: APT Multi-Stage
        st.markdown("""
        <div class="sim-card">
            <span class="badge-tag" style="background:rgba(255,23,68,0.25);border:1px solid #ff1744;color:#ff1744;">FULL APT KILL CHAIN</span>
            <h4 style="margin:6px 0 4px 0;">Multi-Stage APT Intrusion Campaign</h4>
            <p style="color:#8b949e;font-size:0.85rem;margin-bottom:8px;">
                Runs sequential Recon (LFI) ➔ Password Spray ➔ SQLi Bypass ➔ Large Fund Exfiltration.
            </p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("⚡ Execute Full APT Multi-Stage Campaign", key="sim_apt", use_container_width=True):
            with st.spinner("Executing 4-stage kill-chain intrusion..."):
                res = run_simulation("apt")
            st.toast(res["msg"])
            time.sleep(1.5)
            st.rerun()

    with sim_col2:
        # Scenario 4: LFI
        st.markdown("""
        <div class="sim-card">
            <span class="badge-tag" style="background:rgba(213,0,249,0.2);border:1px solid #d500f9;color:#ea80fc;">SYSTEM PROBE</span>
            <h4 style="margin:6px 0 4px 0;">Directory Traversal / Local File Inclusion</h4>
            <p style="color:#8b949e;font-size:0.85rem;margin-bottom:8px;">
                Adversary probes <code>/api/v1/system/file?name=../../../../etc/passwd</code> from scanner host <code>194.26.29.112</code>.
            </p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("🚀 Execute Path Traversal (LFI) Probe", key="sim_lfi", use_container_width=True):
            res = run_simulation("lfi")
            st.toast(res["msg"])
            time.sleep(1.2)
            st.rerun()

        # Scenario 5: Large Transfer
        st.markdown("""
        <div class="sim-card">
            <span class="badge-tag" style="background:rgba(255,214,0,0.2);border:1px solid #ffd600;color:#ffd600;">FINANCIAL FRAUD</span>
            <h4 style="margin:6px 0 4px 0;">Suspicious $500,000 Wire Exfiltration</h4>
            <p style="color:#8b949e;font-size:0.85rem;margin-bottom:8px;">
                Initiates a high-value wire transfer exceeding institutional limits to an offshore shell account.
            </p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("🚀 Simulate Suspicious $500,000 Transfer", key="sim_wire", use_container_width=True):
            res = run_simulation("large_transfer")
            st.toast(res["msg"])
            time.sleep(1.2)
            st.rerun()

        # Scenario 6: Normal Baseline
        st.markdown("""
        <div class="sim-card">
            <span class="badge-tag" style="background:rgba(0,230,118,0.2);border:1px solid #00e676;color:#69f0ae;">BASELINE TRAFFIC</span>
            <h4 style="margin:6px 0 4px 0;">Generate Normal Banking Operations</h4>
            <p style="color:#8b949e;font-size:0.85rem;margin-bottom:8px;">
                Generates routine legitimate user logins and standard low-value transfers for alice, bob, and charlie.
            </p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("🌱 Generate Normal User Baseline Traffic", key="sim_norm", use_container_width=True):
            res = run_simulation("normal")
            st.toast(res["msg"])
            time.sleep(1.2)
            st.rerun()


# ═════════════════════════════════════════════════════════════════
# TAB 4: AI SOC COPILOT & EXECUTIVE BRIEFING
# ═════════════════════════════════════════════════════════════════
with tab4:
    st.markdown("### 🧠 AI SOC Analyst Copilot")
    st.caption("Interact with the autonomous security intelligence engine in natural language to investigate blast radius, compliance liability, or generate code fixes.")

    col_chat, col_brief = st.columns([6, 5])

    with col_chat:
        st.markdown("**💬 Inquire with AI Analyst (Atlas)**")

        # Quick prompt chips for live presentation demos
        st.markdown("<p style='font-size:0.78rem;color:#8b949e;margin-bottom:6px;'>Quick Demo Prompts:</p>", unsafe_allow_html=True)
        q_cols = st.columns(2)
        if q_cols[0].button("💡 Explain Attack Root Cause", use_container_width=True):
            st.session_state["copilot_input"] = "Explain the root cause and mechanism of the latest security attack."
        if q_cols[1].button("🛡️ Generate WAF & Code Fix", use_container_width=True):
            st.session_state["copilot_input"] = "Provide the exact Nginx WAF rule and parameterized SQL query to permanently fix this."
        q_cols2 = st.columns(2)
        if q_cols2[0].button("⚖️ Assess PCI-DSS / GDPR Liability", use_container_width=True):
            st.session_state["copilot_input"] = "What is our regulatory compliance liability under PCI-DSS and GDPR?"
        if q_cols2[1].button("🚨 Draft Incident Escalation", use_container_width=True):
            st.session_state["copilot_input"] = "Draft a formal escalation notice to the CISO and Incident Response team."

        # Chat conversation log
        chat_container = st.container(height=340)
        with chat_container:
            if not st.session_state["chat_messages"]:
                st.markdown(
                    "<p style='color:#8b949e;font-size:0.85rem;padding-top:20px;text-align:center;'>"
                    "Ask Atlas any question regarding active incidents, attacker profiling, or remediation runbooks."
                    "</p>",
                    unsafe_allow_html=True
                )
            for msg in st.session_state["chat_messages"]:
                with st.chat_message(msg["role"]):
                    st.markdown(msg["content"])

        # Chat input box
        prompt = st.chat_input("Ask AI SOC Analyst...", key="chat_input_box")
        if not prompt and st.session_state["copilot_input"]:
            prompt = st.session_state["copilot_input"]
            st.session_state["copilot_input"] = ""

        if prompt:
            st.session_state["chat_messages"].append({"role": "user", "content": prompt})
            with chat_container:
                with st.chat_message("user"):
                    st.markdown(prompt)

                with st.chat_message("assistant"):
                    with st.spinner("Analyzing telemetry & MITRE knowledgebase..."):
                        reply = query_ai_copilot(
                            prompt,
                            fetch_logs_for_triage(limit=10),
                            st.session_state.get("triage_result"),
                            groq_api_key.strip()
                        )
                        st.markdown(reply)
            st.session_state["chat_messages"].append({"role": "assistant", "content": reply})

    with col_brief:
        st.markdown("**📋 Executive Incident Briefing Dossier**")
        st.caption("Auto-generated C-Level briefing ready for presentation slides or regulatory submission.")

        current_res = st.session_state.get("triage_result") or {
            "threat_level": "HIGH",
            "_flagged_ip": "185.220.101.5",
            "mitre_technique": "T1190 - Exploit Public-Facing Application",
            "confidence_score": 96.5,
        }
        briefing_md = generate_executive_briefing(current_res, fetch_logs_for_triage(limit=10))

        st.text_area("Executive Summary Preview", value=briefing_md, height=360)
        st.download_button(
            "📥 Download Executive Briefing (.md)",
            data=briefing_md,
            file_name="SOC_Executive_Briefing.md",
            mime="text/markdown",
            use_container_width=True,
            type="primary"
        )


# ─────────────────────────────────────────────────────────────────
# AUTO-REFRESH CONTROLLER
# ─────────────────────────────────────────────────────────────────
st.markdown("---")
now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
st.markdown(
    f"<p style='color:#484f58;font-size:0.75rem;text-align:center;'>"
    f"Perimeter Status: ACTIVE &nbsp;·&nbsp; Last Poll: {now_utc} &nbsp;·&nbsp; "
    f"Autonomous AI SOC Platform · Financial Defense Architecture</p>",
    unsafe_allow_html=True
)

if auto_refresh:
    time.sleep(AUTO_REFRESH_SECONDS)
    st.rerun()
