from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Iterable

from config import DATA_DIR, MAX_HISTORY_LIMIT, MAX_INVENTORY_LIMIT

DB_FILE = DATA_DIR / "netwatch.db"


def _connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_FILE, timeout=5)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def init_db() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                summary TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'completed'
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS assets (
                ip_address TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                open_ports TEXT NOT NULL DEFAULT '[]',
                exposure_score INTEGER NOT NULL DEFAULT 0,
                exposure_level TEXT NOT NULL DEFAULT 'Clean'
            )
            """
        )


def add_scan_run(
    scan_type: str, target: str, summary: str, status: str = "completed"
) -> int:
    init_db()
    now = _utc_timestamp()
    with _connect() as conn:
        cursor = conn.execute(
            """
            INSERT INTO scan_runs (created_at, scan_type, target, summary, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (now, scan_type, target, summary, status),
        )
        return int(cursor.lastrowid)


def upsert_hosts(host_rows: Iterable[dict]) -> None:
    init_db()
    now = _utc_timestamp()
    with _connect() as conn:
        for row in host_rows:
            ip = str(row.get("IP Address", "")).strip()
            if not ip:
                continue
            status = str(row.get("Status", "Online"))
            details = str(row.get("Details", ""))
            conn.execute(
                """
                INSERT INTO assets (ip_address, first_seen, last_seen, status, details)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    last_seen=excluded.last_seen,
                    status=excluded.status,
                    details=excluded.details
                """,
                (ip, now, now, status, details),
            )


def update_asset_ports(
    ip_address: str, port_rows: Iterable[dict], exposure_score: int, exposure_level: str
) -> None:
    init_db()
    now = _utc_timestamp()
    open_ports = [row for row in port_rows if row.get("Status") == "Open"]
    encoded = json.dumps(open_ports, ensure_ascii=False)
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO assets (ip_address, first_seen, last_seen, status, details, open_ports, exposure_score, exposure_level)
            VALUES (?, ?, ?, 'Seen', 'Port audit completed', ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                last_seen=excluded.last_seen,
                status=excluded.status,
                details=excluded.details,
                open_ports=excluded.open_ports,
                exposure_score=excluded.exposure_score,
                exposure_level=excluded.exposure_level
            """,
            (ip_address, now, now, encoded, exposure_score, exposure_level),
        )


def recent_scan_runs(limit: int = 30) -> list[dict]:
    bounded_limit = max(1, min(int(limit), MAX_HISTORY_LIMIT))
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT created_at, scan_type, target, summary, status
            FROM scan_runs
            ORDER BY id DESC
            LIMIT ?
            """,
            (bounded_limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def asset_inventory(limit: int = MAX_INVENTORY_LIMIT) -> list[dict]:
    bounded_limit = max(1, min(int(limit), MAX_INVENTORY_LIMIT))
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT ip_address, first_seen, last_seen, status, details, exposure_score, exposure_level, open_ports
            FROM assets
            ORDER BY exposure_score DESC, ip_address ASC
            LIMIT ?
            """,
            (bounded_limit,),
        ).fetchall()

    inventory = []
    for row in rows:
        item = dict(row)
        try:
            ports = json.loads(item.pop("open_ports") or "[]")
        except json.JSONDecodeError:
            ports = []
        item["open_port_count"] = len(ports)
        item["open_ports"] = (
            ", ".join(str(port.get("Port")) for port in ports) if ports else "-"
        )
        inventory.append(item)
    return inventory


def asset_open_ports(limit: int = MAX_INVENTORY_LIMIT) -> list[dict]:
    """Return normalized open-port rows saved in the local asset inventory."""
    bounded_limit = max(1, min(int(limit), MAX_INVENTORY_LIMIT))
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT ip_address, open_ports
            FROM assets
            WHERE open_ports != '[]'
            ORDER BY exposure_score DESC, ip_address ASC
            LIMIT ?
            """,
            (bounded_limit,),
        ).fetchall()

    findings: list[dict] = []
    for row in rows:
        try:
            ports = json.loads(row["open_ports"] or "[]")
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(ports, list):
            continue
        for port in ports:
            if isinstance(port, dict):
                findings.append({**port, "IP Address": row["ip_address"]})
    return findings
