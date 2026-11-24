"""
ingest.py — SOC Log Ingestion Daemon
=====================================
Polls logs/app.log every second for new JSON lines and inserts
them into the PostgreSQL telemetry_logs table via psycopg2.

Replaced watchdog with simple file polling — more reliable on macOS
where FSEvents can miss rapid successive writes.

Usage:
    python3 ingest.py
"""

import json
import time
import logging
import sys
from pathlib import Path

import psycopg2
import psycopg2.extras

# ─────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────
DB_CONFIG = {
    "host":     "localhost",
    "port":     5432,
    "dbname":   "soc",
    "user":     "paarthchhikara",  # Homebrew default: your Mac username
    "password": "",                # Homebrew installs have no password
}

LOG_FILE_PATH = Path("logs/app.log")

POLL_INTERVAL = 1.0   # seconds between file checks

# ─────────────────────────────────────────────
# LOGGING SETUP
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [INGEST] %(levelname)s — %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# DATABASE HELPERS
# ─────────────────────────────────────────────

def get_db_connection():
    """Opens and returns a psycopg2 connection."""
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = True
        return conn
    except psycopg2.OperationalError as exc:
        log.error("Cannot connect to PostgreSQL: %s", exc)
        raise


def insert_telemetry(conn, record: dict):
    """Inserts one parsed log record into telemetry_logs."""
    sql = """
        INSERT INTO telemetry_logs (
            timestamp, source_ip, user_id, event_type,
            endpoint, http_method, status_code,
            payload, headers, raw_message
        )
        VALUES (
            %(timestamp)s, %(source_ip)s, %(user_id)s, %(event_type)s,
            %(endpoint)s, %(http_method)s, %(status_code)s,
            %(payload)s, %(headers)s, %(raw_message)s
        )
        RETURNING id;
    """
    row = {
        "timestamp":   record.get("timestamp"),
        "source_ip":   record.get("source_ip", "0.0.0.0"),
        "user_id":     record.get("user_id"),
        "event_type":  record.get("event_type", "UNKNOWN"),
        "endpoint":    record.get("endpoint", "/"),
        "http_method": record.get("http_method", "GET"),
        "status_code": int(record.get("status_code", 0)),
        "payload":     psycopg2.extras.Json(record.get("payload")),
        "headers":     psycopg2.extras.Json(record.get("headers")),
        "raw_message": record.get("raw_message") or json.dumps(record),
    }
    try:
        with conn.cursor() as cur:
            cur.execute(sql, row)
            new_id = cur.fetchone()[0]
            log.info(
                "✔  Inserted row id=%s | %s %s → %s [%s]",
                new_id,
                row["http_method"],
                row["endpoint"],
                row["status_code"],
                row["event_type"],
            )
    except psycopg2.Error as exc:
        log.error("DB insert failed: %s", exc)


# ─────────────────────────────────────────────
# MAIN POLLING LOOP
# ─────────────────────────────────────────────

def tail_and_ingest():
    """
    Opens the log file, seeks to the end, then polls every
    POLL_INTERVAL seconds for new lines. Each new complete
    line is parsed as JSON and inserted into the database.
    """
    # Ensure the file exists
    LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOG_FILE_PATH.touch(exist_ok=True)

    log.info("Connecting to PostgreSQL at %s:%s/%s …",
             DB_CONFIG["host"], DB_CONFIG["port"], DB_CONFIG["dbname"])
    conn = get_db_connection()
    log.info("Database connection established ✔")

    with open(LOG_FILE_PATH, "r", encoding="utf-8") as fh:
        # Seek to end — only process lines written from now on
        fh.seek(0, 2)
        log.info("Watching %s (polling every %.1fs). Press Ctrl+C to stop.\n",
                 LOG_FILE_PATH, POLL_INTERVAL)

        while True:
            line = fh.readline()

            if not line:
                # No new data yet — wait and try again
                time.sleep(POLL_INTERVAL)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                log.warning("Skipping non-JSON line: %s", line[:120])
                continue

            # Reconnect if connection dropped
            if conn.closed:
                log.warning("DB connection lost — reconnecting…")
                conn = get_db_connection()

            insert_telemetry(conn, record)


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    try:
        tail_and_ingest()
    except KeyboardInterrupt:
        log.info("Stopped.")
