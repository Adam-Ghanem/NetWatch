from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Iterable

DATA_DIR = Path("data")
DB_FILE = DATA_DIR / "netwatch.db"


def _connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


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


def add_scan_run(scan_type: str, target: str, summary: str, status: str = "completed") -> int:
    init_db()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
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


def update_asset_ports(ip_address: str, port_rows: Iterable[dict], exposure_score: int, exposure_level: str) -> None:
    init_db()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    open_ports = [row for row in port_rows if row.get("Status") == "Open"]
    encoded = json.dumps(open_ports, ensure_ascii=False)
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO assets (ip_address, first_seen, last_seen, status, details, open_ports, exposure_score, exposure_level)
            VALUES (?, ?, ?, 'Seen', 'Port audit completed', ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                last_seen=excluded.last_seen,
                open_ports=excluded.open_ports,
                exposure_score=excluded.exposure_score,
                exposure_level=excluded.exposure_level
            """,
            (ip_address, now, now, encoded, exposure_score, exposure_level),
        )


def recent_scan_runs(limit: int = 30) -> list[dict]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT created_at, scan_type, target, summary, status
            FROM scan_runs
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def asset_inventory() -> list[dict]:
    init_db()
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT ip_address, first_seen, last_seen, status, details, exposure_score, exposure_level, open_ports
            FROM assets
            ORDER BY exposure_score DESC, ip_address ASC
            """
        ).fetchall()

    inventory = []
    for row in rows:
        item = dict(row)
        try:
            ports = json.loads(item.pop("open_ports") or "[]")
        except json.JSONDecodeError:
            ports = []
        item["open_port_count"] = len(ports)
        item["open_ports"] = ", ".join(str(port.get("Port")) for port in ports) if ports else "-"
        inventory.append(item)
    return inventory
