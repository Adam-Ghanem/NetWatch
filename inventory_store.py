from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from config import (
    MAX_ASSET_EVENTS,
    MAX_AUDIT_LOG_ENTRIES,
    MAX_INVENTORY_ROWS,
    MAX_NETWORK_OBSERVATIONS,
)
from operations_store import create_operations_schema

DATA_DIR = Path(os.getenv("NETWATCH_DATA_DIR", "data"))
DB_FILE = DATA_DIR / "netwatch.db"
NOT_OBSERVED_STATUS = "Not observed"
ASSET_CRITICALITIES = ("Low", "Medium", "High", "Critical")
EVENT_LABELS = {
    "new_asset": "New asset",
    "asset_returned": "Returned",
    "not_observed": "Not observed",
}


@dataclass(frozen=True)
class NetworkChangeSummary:
    scan_run_id: int
    observed_assets: tuple[str, ...]
    new_assets: tuple[str, ...]
    returned_assets: tuple[str, ...]
    not_observed_assets: tuple[str, ...]

    @property
    def total_changes(self) -> int:
        return len(self.new_assets) + len(self.returned_assets) + len(self.not_observed_assets)

    @property
    def summary(self) -> str:
        return (
            f"{len(self.observed_assets)} online host(s); "
            f"{len(self.new_assets)} new, {len(self.returned_assets)} returned, "
            f"{len(self.not_observed_assets)} not observed"
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "scan_run_id": self.scan_run_id,
            "observed_assets": list(self.observed_assets),
            "new_assets": list(self.new_assets),
            "returned_assets": list(self.returned_assets),
            "not_observed_assets": list(self.not_observed_assets),
            "total_changes": self.total_changes,
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_FILE, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def init_db() -> None:
    with _connect() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                summary TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'completed'
            )
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS assets (
                ip_address TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                open_ports TEXT NOT NULL DEFAULT '[]',
                exposure_score INTEGER NOT NULL DEFAULT 0,
                exposure_level TEXT NOT NULL DEFAULT 'Clean',
                owner TEXT NOT NULL DEFAULT '',
                department TEXT NOT NULL DEFAULT '',
                location TEXT NOT NULL DEFAULT '',
                criticality TEXT NOT NULL DEFAULT 'Medium',
                notes TEXT NOT NULL DEFAULT '',
                context_updated_at TEXT NOT NULL DEFAULT ''
            )
            """)
        _ensure_asset_context_columns(conn)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_created_at ON scan_runs(created_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_type ON scan_runs(scan_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_last_seen ON assets(last_seen)")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS network_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_run_id INTEGER NOT NULL,
                ip_address TEXT NOT NULL,
                observed INTEGER NOT NULL CHECK (observed IN (0, 1)),
                status TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                UNIQUE(scan_run_id, ip_address),
                FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
            )
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS asset_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                event_type TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                scan_run_id INTEGER,
                FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id) ON DELETE SET NULL
            )
            """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                actor_role TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                outcome TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT ''
            )
            """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_observations_scan ON network_observations(scan_run_id)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_observations_asset "
            "ON network_observations(ip_address, id)"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_asset_events_id ON asset_events(id)")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_asset_events_asset ON asset_events(ip_address, id)"
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_id ON audit_log(id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action, id)")
        create_operations_schema(conn)
        conn.execute("PRAGMA user_version = 4")


def _ensure_asset_context_columns(conn: sqlite3.Connection) -> None:
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(assets)").fetchall()}
    columns = {
        "owner": "TEXT NOT NULL DEFAULT ''",
        "department": "TEXT NOT NULL DEFAULT ''",
        "location": "TEXT NOT NULL DEFAULT ''",
        "criticality": "TEXT NOT NULL DEFAULT 'Medium'",
        "notes": "TEXT NOT NULL DEFAULT ''",
        "context_updated_at": "TEXT NOT NULL DEFAULT ''",
    }
    for name, definition in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE assets ADD COLUMN {name} {definition}")


def _insert_scan_run(
    conn: sqlite3.Connection,
    scan_type: str,
    target: str,
    summary: str,
    status: str = "completed",
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO scan_runs (created_at, scan_type, target, summary, status)
        VALUES (?, ?, ?, ?, ?)
        """,
        (_utc_now(), scan_type, target, summary, status),
    )
    if cursor.lastrowid is None:
        raise RuntimeError("SQLite did not return an ID for the saved scan run.")
    return cursor.lastrowid


def _normalize_ipv4(value: object) -> str | None:
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return None
    return str(address) if isinstance(address, ipaddress.IPv4Address) else None


def _insert_asset_event(
    conn: sqlite3.Connection,
    ip_address: str,
    event_type: str,
    details: str,
    scan_run_id: int | None = None,
) -> None:
    if event_type not in EVENT_LABELS:
        raise ValueError(f"Unsupported asset event: {event_type}")
    conn.execute(
        """
        INSERT INTO asset_events (created_at, ip_address, event_type, details, scan_run_id)
        VALUES (?, ?, ?, ?, ?)
        """,
        (_utc_now(), ip_address, event_type, details[:500], scan_run_id),
    )


def _audit_value(value: object, max_length: int) -> str:
    return " ".join(str(value).split())[:max_length]


def _insert_audit_event(
    conn: sqlite3.Connection,
    actor_role: str,
    action: str,
    target: str,
    outcome: str,
    details: str,
) -> None:
    conn.execute(
        """
        INSERT INTO audit_log (created_at, actor_role, action, target, outcome, details)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            _utc_now(),
            _audit_value(actor_role, 40),
            _audit_value(action, 80),
            _audit_value(target, 200),
            _audit_value(outcome, 40),
            _audit_value(details, 1_000),
        ),
    )


def _prune_change_history(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        DELETE FROM asset_events
        WHERE id NOT IN (
            SELECT id FROM asset_events ORDER BY id DESC LIMIT ?
        )
        """,
        (MAX_ASSET_EVENTS,),
    )
    conn.execute(
        """
        DELETE FROM network_observations
        WHERE id NOT IN (
            SELECT id FROM network_observations ORDER BY id DESC LIMIT ?
        )
        """,
        (MAX_NETWORK_OBSERVATIONS,),
    )


def _prune_audit_log(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        DELETE FROM audit_log
        WHERE id NOT IN (
            SELECT id FROM audit_log ORDER BY id DESC LIMIT ?
        )
        """,
        (MAX_AUDIT_LOG_ENTRIES,),
    )


def _upsert_observed_asset(
    conn: sqlite3.Connection,
    ip_address: str,
    status: str,
    details: str,
    source: str,
    scan_run_id: int | None = None,
) -> str | None:
    previous = conn.execute(
        "SELECT status FROM assets WHERE ip_address = ?", (ip_address,)
    ).fetchone()
    now = _utc_now()
    conn.execute(
        """
        INSERT INTO assets (ip_address, first_seen, last_seen, status, details)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(ip_address) DO UPDATE SET
            last_seen=excluded.last_seen,
            status=excluded.status,
            details=excluded.details
        """,
        (ip_address, now, now, status[:40], details[:1_000]),
    )
    if previous is None:
        _insert_asset_event(
            conn,
            ip_address,
            "new_asset",
            f"First observed during an authorized {source}.",
            scan_run_id,
        )
        return "new_asset"
    if previous["status"] == NOT_OBSERVED_STATUS:
        _insert_asset_event(
            conn,
            ip_address,
            "asset_returned",
            f"Observed again during an authorized {source}.",
            scan_run_id,
        )
        return "asset_returned"
    return None


def add_scan_run(scan_type: str, target: str, summary: str, status: str = "completed") -> int:
    init_db()
    with _connect() as conn:
        return _insert_scan_run(conn, scan_type, target, summary, status)


def upsert_hosts(
    host_rows: Iterable[dict],
    source: str = "host observation",
    scan_run_id: int | None = None,
) -> None:
    init_db()
    with _connect() as conn:
        seen: set[str] = set()
        for row in host_rows:
            ip = _normalize_ipv4(row.get("IP Address", ""))
            if not ip or ip in seen:
                continue
            seen.add(ip)
            status = str(row.get("Status", "Online"))
            details = str(row.get("Details", ""))
            _upsert_observed_asset(conn, ip, status, details, source, scan_run_id)
        _prune_change_history(conn)


def record_network_scan(cidr: str, host_rows: Iterable[dict]) -> NetworkChangeSummary:
    """Persist one normalized network snapshot and calculate asset transitions."""
    init_db()
    network = ipaddress.ip_network(cidr, strict=False)
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("Network change tracking supports IPv4 scans only.")

    normalized_rows: dict[str, dict] = {}
    for row in host_rows:
        ip = _normalize_ipv4(row.get("IP Address", ""))
        if ip and ipaddress.IPv4Address(ip) in network:
            normalized_rows[ip] = row

    observed = tuple(sorted(normalized_rows, key=ipaddress.IPv4Address))
    new_assets: list[str] = []
    returned_assets: list[str] = []
    not_observed_assets: list[str] = []

    with _connect() as conn:
        scan_run_id = _insert_scan_run(conn, "network", str(network), "Saving scan snapshot")
        existing_rows = conn.execute("SELECT ip_address, status FROM assets").fetchall()
        in_scope = {
            row["ip_address"]: row["status"]
            for row in existing_rows
            if _normalize_ipv4(row["ip_address"])
            and ipaddress.IPv4Address(row["ip_address"]) in network
        }

        for ip in observed:
            row = normalized_rows[ip]
            transition = _upsert_observed_asset(
                conn,
                ip,
                str(row.get("Status", "Online")),
                str(row.get("Details", "")),
                "network scan",
                scan_run_id,
            )
            if transition == "new_asset":
                new_assets.append(ip)
            elif transition == "asset_returned":
                returned_assets.append(ip)
            conn.execute(
                """
                INSERT INTO network_observations (
                    scan_run_id, ip_address, observed, status, details
                ) VALUES (?, ?, 1, ?, ?)
                """,
                (
                    scan_run_id,
                    ip,
                    str(row.get("Status", "Online"))[:40],
                    str(row.get("Details", ""))[:1_000],
                ),
            )

        for ip in sorted(set(in_scope) - set(observed), key=ipaddress.IPv4Address):
            details = "No ICMP reply in this scan; availability is not confirmed."
            if in_scope[ip] != NOT_OBSERVED_STATUS:
                conn.execute(
                    "UPDATE assets SET status = ?, details = ? WHERE ip_address = ?",
                    (NOT_OBSERVED_STATUS, details, ip),
                )
                _insert_asset_event(
                    conn,
                    ip,
                    "not_observed",
                    "No reply in the latest scan; ICMP filtering may affect this result.",
                    scan_run_id,
                )
                not_observed_assets.append(ip)
            conn.execute(
                """
                INSERT INTO network_observations (
                    scan_run_id, ip_address, observed, status, details
                ) VALUES (?, ?, 0, ?, ?)
                """,
                (scan_run_id, ip, NOT_OBSERVED_STATUS, details),
            )

        result = NetworkChangeSummary(
            scan_run_id=scan_run_id,
            observed_assets=observed,
            new_assets=tuple(new_assets),
            returned_assets=tuple(returned_assets),
            not_observed_assets=tuple(not_observed_assets),
        )
        conn.execute("UPDATE scan_runs SET summary = ? WHERE id = ?", (result.summary, scan_run_id))
        _prune_change_history(conn)
    return result


def update_asset_ports(
    ip_address: str,
    port_rows: Iterable[dict],
    exposure_score: int,
    exposure_level: str,
    scan_run_id: int | None = None,
) -> None:
    init_db()
    normalized_ip = _normalize_ipv4(ip_address)
    if not normalized_ip:
        raise ValueError("A valid IPv4 asset address is required.")
    now = _utc_now()
    open_ports = [row for row in port_rows if row.get("Status") == "Open"]
    encoded = json.dumps(open_ports, ensure_ascii=False)
    with _connect() as conn:
        previous = conn.execute(
            "SELECT status FROM assets WHERE ip_address = ?", (normalized_ip,)
        ).fetchone()
        conn.execute(
            """
            INSERT INTO assets (
                ip_address, first_seen, last_seen, status, details,
                open_ports, exposure_score, exposure_level
            )
            VALUES (?, ?, ?, 'Seen', 'Port audit completed', ?, ?, ?)
            ON CONFLICT(ip_address) DO UPDATE SET
                last_seen=excluded.last_seen,
                status=excluded.status,
                details=excluded.details,
                open_ports=excluded.open_ports,
                exposure_score=excluded.exposure_score,
                exposure_level=excluded.exposure_level
            """,
            (normalized_ip, now, now, encoded, exposure_score, exposure_level),
        )
        if previous is None:
            _insert_asset_event(
                conn,
                normalized_ip,
                "new_asset",
                "First observed during an authorized port audit.",
                scan_run_id,
            )
        elif previous["status"] == NOT_OBSERVED_STATUS:
            _insert_asset_event(
                conn,
                normalized_ip,
                "asset_returned",
                "Observed again during an authorized port audit.",
                scan_run_id,
            )
        _prune_change_history(conn)


def record_audit_event(
    actor_role: str,
    action: str,
    target: str,
    outcome: str,
    details: str,
) -> None:
    init_db()
    with _connect() as conn:
        _insert_audit_event(conn, actor_role, action, target, outcome, details)
        _prune_audit_log(conn)


def update_asset_context(
    ip_address: str,
    *,
    owner: str,
    department: str,
    location: str,
    criticality: str,
    notes: str,
    actor_role: str,
) -> dict:
    init_db()
    normalized_ip = _normalize_ipv4(ip_address)
    if not normalized_ip:
        raise ValueError("A valid IPv4 asset address is required.")
    normalized_criticality = str(criticality).strip().title()
    if normalized_criticality not in ASSET_CRITICALITIES:
        raise ValueError("Criticality must be Low, Medium, High, or Critical.")

    values = {
        "owner": _audit_value(owner, 120),
        "department": _audit_value(department, 120),
        "location": _audit_value(location, 120),
        "criticality": normalized_criticality,
        "notes": _audit_value(notes, 1_000),
    }
    with _connect() as conn:
        existing = conn.execute(
            "SELECT ip_address FROM assets WHERE ip_address = ?", (normalized_ip,)
        ).fetchone()
        if existing is None:
            raise KeyError(normalized_ip)
        context_updated_at = _utc_now()
        conn.execute(
            """
            UPDATE assets
            SET owner = ?, department = ?, location = ?, criticality = ?,
                notes = ?, context_updated_at = ?
            WHERE ip_address = ?
            """,
            (
                values["owner"],
                values["department"],
                values["location"],
                values["criticality"],
                values["notes"],
                context_updated_at,
                normalized_ip,
            ),
        )
        _insert_audit_event(
            conn,
            actor_role,
            "asset_context_updated",
            normalized_ip,
            "completed",
            f"Asset ownership context updated; criticality={normalized_criticality}.",
        )
        _prune_audit_log(conn)
        row = conn.execute(
            """
            SELECT
                ip_address, first_seen, last_seen, status, details,
                exposure_score, exposure_level, open_ports,
                owner, department, location, criticality, notes, context_updated_at
            FROM assets
            WHERE ip_address = ?
            """,
            (normalized_ip,),
        ).fetchone()
    if row is None:
        raise RuntimeError("Asset context was updated but could not be reloaded.")
    return _asset_record(row)


def recent_scan_runs(limit: int = 30) -> list[dict]:
    init_db()
    safe_limit = max(1, min(int(limit), 200))
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT created_at, scan_type, target, summary, status
            FROM scan_runs
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def recent_asset_events(limit: int = 30) -> list[dict]:
    init_db()
    safe_limit = max(1, min(int(limit), 200))
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT created_at, ip_address, event_type, details, scan_run_id
            FROM asset_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
    events = []
    for row in rows:
        event = dict(row)
        event["event_label"] = EVENT_LABELS.get(event["event_type"], event["event_type"])
        events.append(event)
    return events


def recent_network_observations(limit: int = 100) -> list[dict]:
    init_db()
    safe_limit = max(1, min(int(limit), 1_000))
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT
                observations.scan_run_id,
                runs.created_at,
                runs.target,
                observations.ip_address,
                observations.observed,
                observations.status,
                observations.details
            FROM network_observations AS observations
            JOIN scan_runs AS runs ON runs.id = observations.scan_run_id
            ORDER BY observations.id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def recent_audit_log(limit: int = 100) -> list[dict]:
    init_db()
    safe_limit = max(1, min(int(limit), 1_000))
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT created_at, actor_role, action, target, outcome, details
            FROM audit_log
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def _decode_ports(raw: str | None) -> list[dict]:
    try:
        ports = json.loads(raw or "[]")
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(ports, list):
        return []
    return [item for item in ports if isinstance(item, dict)]


def _asset_record(row: sqlite3.Row) -> dict:
    item = dict(row)
    ports = _decode_ports(item.pop("open_ports", "[]"))
    item["open_port_count"] = len(ports)
    item["open_ports"] = ", ".join(str(port.get("Port")) for port in ports) if ports else "-"
    return item


def asset_port_findings(limit: int = MAX_INVENTORY_ROWS) -> list[dict]:
    """Return saved open-port findings in report/advisor-ready form."""
    init_db()
    safe_limit = max(1, min(int(limit), MAX_INVENTORY_ROWS))
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT ip_address, open_ports
            FROM assets
            WHERE open_ports != '[]'
            ORDER BY ip_address ASC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()

    findings: list[dict] = []
    for row in rows:
        for item in _decode_ports(row["open_ports"]):
            findings.append({**item, "IP Address": row["ip_address"]})
    return findings


def asset_inventory(limit: int = MAX_INVENTORY_ROWS) -> list[dict]:
    init_db()
    safe_limit = max(1, min(int(limit), MAX_INVENTORY_ROWS))
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT
                ip_address, first_seen, last_seen, status, details,
                exposure_score, exposure_level, open_ports,
                owner, department, location, criticality, notes, context_updated_at
            FROM assets
            ORDER BY exposure_score DESC, ip_address ASC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()

    return [_asset_record(row) for row in rows]
