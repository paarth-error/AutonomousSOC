# 🛡️ ATLAS — Autonomous AI-Powered Security Operations Center (SOC)

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15%2B-336791.svg)](https://www.postgresql.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.35%2B-FF4B4B.svg)](https://streamlit.io/)
[![Groq LLM](https://img.shields.io/badge/LLM-Groq%20Llama--3%20%2F%20GPT--OSS-f55036.svg)](https://groq.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**ATLAS** (**A**utonomous **T**hreat **L**ogging & **A**daptive **S**ecurity) is a next-generation, AI-driven Security Operations Center (SOC) and SOAR platform built specifically for real-time telemetry monitoring, automated adversary triage, MITRE ATT&CK mapping, and active perimeter containment.

---

## 🏛️ System Architecture

```
┌─────────────────────────────────┐
│ Target App (Flask :5001)        │  Simulated Financial Web Service (Mock Banking API)
│ [logs/app.log]                  │  Structured JSON telemetry logging & Dynamic WAF policy
└────────────────┬────────────────┘
                 │ (1.0s poll)
┌────────────────▼────────────────┐
│ Ingest Daemon (ingest.py)       │  Resilient background streaming worker
└────────────────┬────────────────┘
                 │ (psycopg2)
┌────────────────▼────────────────┐
│ PostgreSQL (soc database)       │  • telemetry_logs: immutable structured telemetry
│                                 │  • incidents: AI-triaged dossiers & lifecycle states
└────────────────┬────────────────┘
                 │ (real-time queries)
┌────────────────▼────────────────┐
│ ATLAS Dashboard (Streamlit :8501)│ • Real-time telemetry feed & Plotly dark cyber analytics
│ [dashboard.py]                  │ • Groq LLM Triage & MITRE ATT&CK Mapping
│                                 │ • 1-Click SOAR Perimeter Quarantine
│                                 │ • Threat Simulation Center ("Demo Magic")
│                                 │ • Interactive AI SOC Copilot ("Atlas") & Executive Briefing
└─────────────────────────────────┘
```

---

## ✨ Key Capabilities

### 1. 📊 Real-Time Operations & Plotly Visual Analytics
* **Cyber Operations Console:** Enterprise dark theme with live animated radar indicators (`DEFCON 2 · ELEVATED THREAT` vs `DEFCON 5 · NOMINAL`).
* **Telemetry Velocity Sparkline:** Area chart tracking event volume per second with red crosshair markers highlighting exploit spikes.
* **Threat Classification Donut:** Interactive distribution breakdown of `SQLI_DETECTED`, `LFI_DETECTED`, `AUTH_FAILURE`, and nominal traffic.
* **Top Attacking Hosts:** Bar chart identifying high-frequency malicious IPs.
* **Deep Telemetry Inspector:** Drill down into any event ID to inspect sanitized JSON payloads and raw HTTP request headers.

### 2. 🛡️ AI Threat Triage & SOAR Playbooks
* **Zero-Shot LLM Triage:** Connects to Groq (`openai/gpt-oss-120b` / `llama-3`) with strict JSON schema parsing and intelligent Tier-3 heuristic fallback.
* **MITRE ATT&CK Mapping:** Automatically maps attacks to tactics and techniques (e.g., *T1190 - Exploit Public-Facing Application*, *T1059 - Command and Scripting Interpreter*, *T1110 - Brute Force*).
* **AI Confidence Gauge:** Semi-circular visual dial indicating threat confidence (0–100%).
* **1-Click Perimeter Containment (SOAR):** Clicking **"🛑 Block Attacker IP"** dynamically updates the target application's WAF policy. Subsequent requests from that host are instantly dropped with `403 Forbidden` and logged as `WAF_BLOCK` events!
* **Incident Lifecycle Management:** Update statuses (`NEW` ➔ `INVESTIGATING` ➔ `CONTAINED` ➔ `RESOLVED`) and persist investigation notes directly to PostgreSQL.

### 3. 🎯 Threat Simulation Center (1-Click Demo)
* **SQL Injection Authentication Bypass:** Injects `' OR 1=1 --` from a simulated Tor Exit Node (`185.220.101.5`).
* **Credential Stuffing Campaign:** Fires a burst of failed logins from botnet host `45.146.164.110`.
* **Path Traversal / Local File Inclusion (LFI):** Probes `../../../../etc/passwd` from scanner host `194.26.29.112`.
* **Suspicious $500,000 Wire Transfer:** Dispatches an anomalous transfer exceeding institutional compliance thresholds.
* **Multi-Stage APT Kill-Chain:** Sequentially simulates *Recon ➔ Brute Force ➔ SQLi Bypass ➔ Exfiltration*.
* **Baseline Operations:** Generates clean legitimate user banking traffic.

### 4. 🧠 Interactive AI SOC Copilot ("Atlas") & Executive Dossier
* **Natural Language Security Analyst:** Ask Atlas questions in real time regarding root cause, blast radius, or remediation steps.
* **1-Click Demo Prompts:** Instantly generate parameterized SQL queries, Nginx WAF rules, PCI-DSS / GDPR compliance liability assessments, and formal incident escalation drafts.
* **C-Suite Executive Briefing Generator:** Formats and exports a comprehensive executive summary dossier (`.md`) ready for presentation slides or executive review.

---

## 🚀 Quickstart Guide

### 1. Prerequisites
* **Python 3.10+**
* **PostgreSQL** (running locally on port 5432)

### 2. Database Setup
Create the `soc` database and tables:
```sql
CREATE DATABASE soc;

\c soc;

CREATE TABLE telemetry_logs (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    source_ip INET NOT NULL,
    user_id VARCHAR(255),
    event_type VARCHAR(64) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    http_method VARCHAR(16) NOT NULL,
    status_code INT NOT NULL,
    payload JSONB,
    headers JSONB,
    raw_message TEXT
);

CREATE TABLE incidents (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    source_ip INET,
    threat_level VARCHAR(32) NOT NULL,
    confidence_score NUMERIC(5,2),
    status VARCHAR(32) DEFAULT 'NEW',
    mitre_technique VARCHAR(64) DEFAULT 'T1190',
    summary TEXT,
    analyst_notes TEXT DEFAULT '',
    raw_telemetry_ids BIGINT[]
);
```

### 3. Installation
```bash
git clone https://github.com/paarth-error/AutonomousSOC.git
cd AutonomousSOC

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment variables (optional for Groq LLM)
cp .env.example .env
```

### 4. Running the Platform
Start the three core components in separate terminals (or as background daemons):

**Terminal 1 — Target Financial Web Service:**
```bash
python3 target_app/app.py
# Runs on http://localhost:5001
```

**Terminal 2 — Telemetry Ingestion Daemon:**
```bash
python3 ingest.py
# Watches logs/app.log and streams to PostgreSQL
```

**Terminal 3 — ATLAS SOC Dashboard:**
```bash
streamlit run dashboard.py
# Launches on http://localhost:8501
```

---

## 🛡️ License
Distributed under the MIT License. See `LICENSE` for more information.
