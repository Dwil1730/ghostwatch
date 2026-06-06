import hashlib
import sqlite3
import os
import secrets
from datetime import datetime, timezone
from typing import Optional, Dict
from fastapi import HTTPException, status
from fastapi.security import APIKeyHeader

DB_PATH = os.getenv("DB_PATH", "ghostwatch.db")
ADMIN_KEY = os.getenv("GHOSTWATCH_ADMIN_KEY", "admin-change-me")

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_auth_db():
    conn = _get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            key_hash TEXT UNIQUE NOT NULL,
            client_name TEXT NOT NULL,
            industry TEXT DEFAULT 'general',
            plan TEXT DEFAULT 'starter',
            scans_per_day INTEGER DEFAULT 10,
            total_scans INTEGER DEFAULT 0,
            created_at TEXT NOT NULL,
            active INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS usage_log (
            id TEXT PRIMARY KEY,
            key_hash TEXT NOT NULL,
            client_name TEXT NOT NULL,
            target_url TEXT,
            scan_date TEXT NOT NULL,
            vulnerabilities_found INTEGER DEFAULT 0,
            scan_duration_seconds REAL DEFAULT 0,
            timestamp TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_usage_key_date
            ON usage_log(key_hash, scan_date);
    """)
    conn.commit()
    conn.close()
    print("Auth database initialized.")


def generate_api_key(client_name: str, industry: str = "general",
                     plan: str = "starter", scans_per_day: int = 10) -> Dict:
    import uuid
    raw_key = f"gw-{secrets.token_hex(24)}"
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    key_id = str(uuid.uuid4())

    conn = _get_db()
    conn.execute(
        """INSERT INTO api_keys
           (id, key_hash, client_name, industry, plan, scans_per_day, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (key_id, key_hash, client_name, industry, plan,
         scans_per_day, datetime.now(timezone.utc).isoformat())
    )
    conn.commit()
    conn.close()

    return {
        "api_key": raw_key,
        "client_name": client_name,
        "plan": plan,
        "scans_per_day": scans_per_day,
        "industry": industry,
        "warning": "Store this key securely. It will not be shown again."
    }


def verify_api_key(api_key: str) -> Dict:
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required. Include X-API-Key header."
        )

    if api_key == ADMIN_KEY:
        return {"client_name": "admin", "plan": "unlimited",
                "scans_remaining": 9999, "industry": "internal"}

    key_hash = hashlib.sha256(api_key.encode()).hexdigest()
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    conn = _get_db()
    row = conn.execute(
        "SELECT * FROM api_keys WHERE key_hash = ? AND active = 1",
        (key_hash,)
    ).fetchone()

    if not row:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or inactive API key."
        )

    usage_today = conn.execute(
        "SELECT COUNT(*) FROM usage_log WHERE key_hash = ? AND scan_date = ?",
        (key_hash, today)
    ).fetchone()[0]
    conn.close()

    if usage_today >= row["scans_per_day"]:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Daily scan limit reached ({row['scans_per_day']}/day)."
        )

    return {
        "client_name": row["client_name"],
        "plan": row["plan"],
        "industry": row["industry"],
        "scans_remaining": row["scans_per_day"] - usage_today,
        "key_hash": key_hash
    }


def log_scan_usage(key_hash: str, client_name: str, target_url: str,
                   vulnerabilities: int, duration: float):
    import uuid
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    now = datetime.now(timezone.utc).isoformat()

    conn = _get_db()
    conn.execute(
        """INSERT INTO usage_log
           (id, key_hash, client_name, target_url, scan_date,
            vulnerabilities_found, scan_duration_seconds, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (str(uuid.uuid4()), key_hash, client_name, target_url,
         today, vulnerabilities, duration, now)
    )
    conn.execute(
        "UPDATE api_keys SET total_scans = total_scans + 1 WHERE key_hash = ?",
        (key_hash,)
    )
    conn.commit()
    conn.close()
