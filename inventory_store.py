from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from config import (
    AUDIT_HMAC_KEY_PLACEHOLDER,
    MAX_ASSET_EVENTS,
    MAX_AUDIT_LOG_ENTRIES,
    MAX_INVENTORY_ROWS,
    MAX_NETWORK_OBSERVATIONS,
    MIN_AUDIT_HMAC_KEY_LENGTH,
)
from intelligence_store import create_intelligence_schema
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
_AUDIT_KEY_SEPARATION_VARIABLES = (
    "NETWATCH_API_KEY",
    "NETWATCH_OPERATOR_KEY",
    "NETWATCH_VIEWER_KEY",
    "OPENAI_API_KEY",
    "NETWATCH_AI_SAFETY_SECRET",
)
_AUDIT_READINESS_CACHE_SECONDS = 5.0
_audit_readiness_cache_lock = threading.Lock()
_audit_readiness_cache_identity = b""
_audit_readiness_cache_deadline = 0.0
_audit_readiness_cache_result = False


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


class AuditIntegrityError(RuntimeError):
    """The retained audit head no longer matches its keyed checkpoint."""


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _connect() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_FILE, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


def database_is_ready() -> bool:
    """Run a bounded local database readiness check without exposing internals."""
    try:
        with _connect() as conn:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'assets'"
            ).fetchone()
        return row is not None
    except (OSError, sqlite3.Error):
        return False


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
                hostname TEXT NOT NULL DEFAULT '',
                device_name TEXT NOT NULL DEFAULT '',
                device_type TEXT NOT NULL DEFAULT '',
                manufacturer TEXT NOT NULL DEFAULT '',
                device_model TEXT NOT NULL DEFAULT '',
                operating_system TEXT NOT NULL DEFAULT '',
                identity_confidence TEXT NOT NULL DEFAULT '',
                identity_evidence TEXT NOT NULL DEFAULT '',
                mac_address TEXT NOT NULL DEFAULT '',
                mac_address_type TEXT NOT NULL DEFAULT '',
                observed_ttl INTEGER,
                identity_updated_at TEXT NOT NULL DEFAULT '',
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
        _ensure_asset_identity_columns(conn)
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
                device_name TEXT NOT NULL DEFAULT '',
                device_type TEXT NOT NULL DEFAULT '',
                manufacturer TEXT NOT NULL DEFAULT '',
                device_model TEXT NOT NULL DEFAULT '',
                operating_system TEXT NOT NULL DEFAULT '',
                identity_confidence TEXT NOT NULL DEFAULT '',
                mac_address TEXT NOT NULL DEFAULT '',
                mac_address_type TEXT NOT NULL DEFAULT '',
                UNIQUE(scan_run_id, ip_address),
                FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
            )
            """)
        _ensure_observation_identity_columns(conn)
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
                actor_id TEXT NOT NULL DEFAULT '',
                auth_method TEXT NOT NULL DEFAULT '',
                request_id TEXT NOT NULL DEFAULT '',
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                outcome TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                previous_hash TEXT NOT NULL DEFAULT '',
                event_hash TEXT NOT NULL DEFAULT ''
            )
            """)
        _ensure_audit_integrity_columns(conn)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_chain_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_event_id INTEGER NOT NULL,
                last_event_hash TEXT NOT NULL,
                state_hmac TEXT NOT NULL,
                updated_at TEXT NOT NULL
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
        create_intelligence_schema(conn)
        conn.execute("PRAGMA user_version = 9")


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


def _ensure_asset_identity_columns(conn: sqlite3.Connection) -> None:
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(assets)").fetchall()}
    columns = {
        "hostname": "TEXT NOT NULL DEFAULT ''",
        "device_name": "TEXT NOT NULL DEFAULT ''",
        "device_type": "TEXT NOT NULL DEFAULT ''",
        "manufacturer": "TEXT NOT NULL DEFAULT ''",
        "device_model": "TEXT NOT NULL DEFAULT ''",
        "operating_system": "TEXT NOT NULL DEFAULT ''",
        "identity_confidence": "TEXT NOT NULL DEFAULT ''",
        "identity_evidence": "TEXT NOT NULL DEFAULT ''",
        "mac_address": "TEXT NOT NULL DEFAULT ''",
        "mac_address_type": "TEXT NOT NULL DEFAULT ''",
        "observed_ttl": "INTEGER",
        "identity_updated_at": "TEXT NOT NULL DEFAULT ''",
    }
    for name, definition in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE assets ADD COLUMN {name} {definition}")


def _ensure_observation_identity_columns(conn: sqlite3.Connection) -> None:
    existing = {
        row["name"] for row in conn.execute("PRAGMA table_info(network_observations)").fetchall()
    }
    columns = {
        "device_name": "TEXT NOT NULL DEFAULT ''",
        "device_type": "TEXT NOT NULL DEFAULT ''",
        "manufacturer": "TEXT NOT NULL DEFAULT ''",
        "device_model": "TEXT NOT NULL DEFAULT ''",
        "operating_system": "TEXT NOT NULL DEFAULT ''",
        "identity_confidence": "TEXT NOT NULL DEFAULT ''",
        "mac_address": "TEXT NOT NULL DEFAULT ''",
        "mac_address_type": "TEXT NOT NULL DEFAULT ''",
    }
    for name, definition in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE network_observations ADD COLUMN {name} {definition}")


def _ensure_audit_integrity_columns(conn: sqlite3.Connection) -> None:
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(audit_log)").fetchall()}
    columns = {
        "actor_id": "TEXT NOT NULL DEFAULT ''",
        "auth_method": "TEXT NOT NULL DEFAULT ''",
        "request_id": "TEXT NOT NULL DEFAULT ''",
        "previous_hash": "TEXT NOT NULL DEFAULT ''",
        "event_hash": "TEXT NOT NULL DEFAULT ''",
    }
    for name, definition in columns.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE audit_log ADD COLUMN {name} {definition}")


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


def _identity_values(row: dict) -> dict[str, object]:
    def text_value(display_key: str, storage_key: str, limit: int) -> str:
        value = str(row.get(display_key, row.get(storage_key, "")) or "").strip()
        return "" if value == "-" else " ".join(value.split())[:limit]

    raw_ttl = row.get("TTL", row.get("observed_ttl"))
    try:
        ttl = int(str(raw_ttl)) if raw_ttl not in {None, "", "-"} else None
    except (TypeError, ValueError):
        ttl = None
    if ttl is not None and not 1 <= ttl <= 255:
        ttl = None

    values: dict[str, object] = {
        "hostname": text_value("Hostname", "hostname", 253),
        "device_name": text_value("Device Name", "device_name", 120),
        "device_type": text_value("Device Type", "device_type", 120),
        "manufacturer": text_value("Manufacturer", "manufacturer", 120),
        "device_model": text_value("Device Model", "device_model", 120),
        "operating_system": text_value("Operating System", "operating_system", 160),
        "identity_confidence": text_value("Identity Confidence", "identity_confidence", 20),
        "identity_evidence": text_value("Identity Evidence", "identity_evidence", 750),
        "mac_address": text_value("MAC Address", "mac_address", 17).upper(),
        "mac_address_type": text_value("MAC Address Type", "mac_address_type", 40),
        "observed_ttl": ttl,
    }
    values["identity_updated_at"] = (
        _utc_now()
        if any(
            values[key]
            for key in (
                "hostname",
                "device_name",
                "device_type",
                "manufacturer",
                "device_model",
                "operating_system",
                "identity_evidence",
            )
        )
        else ""
    )
    return values


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


def _audit_hmac_key() -> bytes | None:
    value = os.getenv("NETWATCH_AUDIT_HMAC_KEY", "").strip()
    if len(value) < MIN_AUDIT_HMAC_KEY_LENGTH or value == AUDIT_HMAC_KEY_PLACEHOLDER:
        return None
    for variable in _AUDIT_KEY_SEPARATION_VARIABLES:
        other = os.getenv(variable, "").strip()
        if other and hmac.compare_digest(value, other):
            return None
    return value.encode("utf-8")


def audit_integrity_enabled() -> bool:
    """Return whether new audit events can be protected with a separate server key."""
    return _audit_hmac_key() is not None


def _audit_event_hash(
    key: bytes,
    *,
    previous_hash: str,
    created_at: str,
    actor_role: str,
    actor_id: str,
    auth_method: str,
    request_id: str,
    action: str,
    target: str,
    outcome: str,
    details: str,
) -> str:
    canonical = json.dumps(
        {
            "action": action,
            "actor_id": actor_id,
            "actor_role": actor_role,
            "auth_method": auth_method,
            "created_at": created_at,
            "details": details,
            "outcome": outcome,
            "request_id": request_id,
            "target": target,
        },
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    )
    payload = f"{previous_hash}.{canonical}".encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _audit_state_hmac(key: bytes, *, event_id: int, event_hash: str) -> str:
    payload = f"netwatch-audit-head-v1:{event_id}:{event_hash}".encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _audit_chain_head_is_current(conn: sqlite3.Connection, key: bytes) -> bool:
    latest = conn.execute(
        "SELECT id, event_hash FROM audit_log ORDER BY id DESC LIMIT 1"
    ).fetchone()
    state = conn.execute(
        "SELECT last_event_id, last_event_hash, state_hmac FROM audit_chain_state WHERE id = 1"
    ).fetchone()
    if latest is None:
        return state is None
    if not str(latest["event_hash"]):
        return state is None
    if state is None:
        return False
    try:
        event_id = int(latest["id"])
        state_event_id = int(state["last_event_id"])
    except (TypeError, ValueError, OverflowError):
        return False
    event_hash = str(latest["event_hash"])
    expected_state_hmac = _audit_state_hmac(key, event_id=event_id, event_hash=event_hash)
    return bool(
        state_event_id == event_id
        and hmac.compare_digest(str(state["last_event_hash"]), event_hash)
        and hmac.compare_digest(str(state["state_hmac"]), expected_state_hmac)
    )


def _audit_chain_is_valid(conn: sqlite3.Connection, key: bytes) -> tuple[bool, int, int]:
    if not conn.in_transaction:
        conn.execute("BEGIN")
    rows = conn.execute("""
        SELECT
            id, created_at, actor_role, actor_id, auth_method, request_id,
            action, target, outcome, details, previous_hash, event_hash
        FROM audit_log
        ORDER BY id ASC
        """).fetchall()

    protected_entries = 0
    legacy_entries = 0
    expected_previous: str | None = None
    valid = True
    protected_seen = False
    for row in rows:
        event_hash = str(row["event_hash"])
        if not event_hash:
            legacy_entries += 1
            if protected_seen:
                valid = False
                break
            continue
        protected_seen = True
        previous_hash = str(row["previous_hash"])
        if expected_previous is not None and not hmac.compare_digest(
            previous_hash, expected_previous
        ):
            valid = False
            break
        calculated = _audit_event_hash(
            key,
            previous_hash=previous_hash,
            created_at=str(row["created_at"]),
            actor_role=str(row["actor_role"]),
            actor_id=str(row["actor_id"]),
            auth_method=str(row["auth_method"]),
            request_id=str(row["request_id"]),
            action=str(row["action"]),
            target=str(row["target"]),
            outcome=str(row["outcome"]),
            details=str(row["details"]),
        )
        if not hmac.compare_digest(event_hash, calculated):
            valid = False
            break
        protected_entries += 1
        expected_previous = event_hash

    if valid:
        valid = _audit_chain_head_is_current(conn, key)
    return valid, protected_entries, legacy_entries


def _audit_readiness_identity(key: bytes) -> bytes:
    database_path = os.fsencode(os.fspath(DB_FILE.absolute()))
    return hashlib.sha256(key + b"\0" + database_path).digest()


def _check_audit_integrity(key: bytes) -> bool:
    try:
        with _connect() as conn:
            valid, _, _ = _audit_chain_is_valid(conn, key)
            return valid
    except (OSError, sqlite3.Error):
        return False


def _invalidate_audit_readiness_cache() -> None:
    global _audit_readiness_cache_deadline
    with _audit_readiness_cache_lock:
        _audit_readiness_cache_deadline = 0.0


def audit_integrity_is_ready(*, use_cache: bool = True) -> bool:
    """Check audit readiness, caching only the public health-check path briefly."""
    global _audit_readiness_cache_deadline
    global _audit_readiness_cache_identity
    global _audit_readiness_cache_result

    key = _audit_hmac_key()
    if key is None:
        return False
    if not use_cache:
        return _check_audit_integrity(key)

    identity = _audit_readiness_identity(key)
    now = time.monotonic()
    with _audit_readiness_cache_lock:
        if _audit_readiness_cache_identity == identity and now < _audit_readiness_cache_deadline:
            return _audit_readiness_cache_result
        result = _check_audit_integrity(key)
        _audit_readiness_cache_identity = identity
        _audit_readiness_cache_result = result
        _audit_readiness_cache_deadline = now + _AUDIT_READINESS_CACHE_SECONDS
        return result


def _insert_audit_event(
    conn: sqlite3.Connection,
    actor_role: str,
    action: str,
    target: str,
    outcome: str,
    details: str,
    *,
    actor_id: str = "",
    auth_method: str = "",
    request_id: str = "",
) -> None:
    values = {
        "created_at": _utc_now(),
        "actor_role": _audit_value(actor_role, 40),
        "actor_id": _audit_value(actor_id, 200),
        "auth_method": _audit_value(auth_method, 40),
        "request_id": _audit_value(request_id, 64),
        "action": _audit_value(action, 80),
        "target": _audit_value(target, 200),
        "outcome": _audit_value(outcome, 40),
        "details": _audit_value(details, 1_000),
    }
    key = _audit_hmac_key()
    previous_hash = ""
    event_hash = ""
    if key is not None:
        if not conn.in_transaction:
            conn.execute("BEGIN IMMEDIATE")
        chain_valid, _, _ = _audit_chain_is_valid(conn, key)
        if not chain_valid:
            raise AuditIntegrityError(
                "The audit chain checkpoint is invalid; protected operations are paused."
            )
        previous = conn.execute(
            "SELECT event_hash FROM audit_log WHERE event_hash != '' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        previous_hash = str(previous["event_hash"]) if previous is not None else "0" * 64
        event_hash = _audit_event_hash(key, previous_hash=previous_hash, **values)
    cursor = conn.execute(
        """
        INSERT INTO audit_log (
            created_at, actor_role, actor_id, auth_method, request_id,
            action, target, outcome, details, previous_hash, event_hash
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            values["created_at"],
            values["actor_role"],
            values["actor_id"],
            values["auth_method"],
            values["request_id"],
            values["action"],
            values["target"],
            values["outcome"],
            values["details"],
            previous_hash,
            event_hash,
        ),
    )
    if key is not None:
        event_id = cursor.lastrowid
        if event_id is None:
            raise RuntimeError("SQLite did not return an ID for the audit event.")
        state_hmac = _audit_state_hmac(key, event_id=event_id, event_hash=event_hash)
        conn.execute(
            """
            INSERT INTO audit_chain_state (
                id, last_event_id, last_event_hash, state_hmac, updated_at
            ) VALUES (1, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                last_event_id=excluded.last_event_id,
                last_event_hash=excluded.last_event_hash,
                state_hmac=excluded.state_hmac,
                updated_at=excluded.updated_at
            """,
            (event_id, event_hash, state_hmac, values["created_at"]),
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
    identity: dict[str, object] | None = None,
) -> str | None:
    previous = conn.execute(
        "SELECT status FROM assets WHERE ip_address = ?", (ip_address,)
    ).fetchone()
    now = _utc_now()
    identity = identity or {}
    conn.execute(
        """
        INSERT INTO assets (
            ip_address, first_seen, last_seen, status, details,
            hostname, device_name, device_type, manufacturer, device_model,
            operating_system, identity_confidence, identity_evidence,
            mac_address, mac_address_type, observed_ttl, identity_updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(ip_address) DO UPDATE SET
            last_seen=excluded.last_seen,
            status=excluded.status,
            details=excluded.details,
            hostname=CASE
                WHEN excluded.hostname != '' THEN excluded.hostname ELSE assets.hostname END,
            device_name=CASE
                WHEN excluded.device_name != ''
                THEN excluded.device_name ELSE assets.device_name END,
            device_type=CASE
                WHEN excluded.device_type != ''
                THEN excluded.device_type ELSE assets.device_type END,
            manufacturer=CASE
                WHEN excluded.manufacturer != ''
                THEN excluded.manufacturer ELSE assets.manufacturer END,
            device_model=CASE
                WHEN excluded.device_model != ''
                THEN excluded.device_model ELSE assets.device_model END,
            operating_system=CASE
                WHEN excluded.operating_system != ''
                THEN excluded.operating_system ELSE assets.operating_system END,
            identity_confidence=CASE
                WHEN excluded.identity_confidence != ''
                THEN excluded.identity_confidence ELSE assets.identity_confidence END,
            identity_evidence=CASE
                WHEN excluded.identity_evidence != ''
                THEN excluded.identity_evidence ELSE assets.identity_evidence END,
            mac_address=CASE
                WHEN excluded.mac_address != ''
                THEN excluded.mac_address ELSE assets.mac_address END,
            mac_address_type=CASE
                WHEN excluded.mac_address_type != ''
                THEN excluded.mac_address_type ELSE assets.mac_address_type END,
            observed_ttl=COALESCE(excluded.observed_ttl, assets.observed_ttl),
            identity_updated_at=CASE
                WHEN excluded.identity_updated_at != ''
                THEN excluded.identity_updated_at ELSE assets.identity_updated_at END
        """,
        (
            ip_address,
            now,
            now,
            status[:40],
            details[:1_000],
            identity.get("hostname", ""),
            identity.get("device_name", ""),
            identity.get("device_type", ""),
            identity.get("manufacturer", ""),
            identity.get("device_model", ""),
            identity.get("operating_system", ""),
            identity.get("identity_confidence", ""),
            identity.get("identity_evidence", ""),
            identity.get("mac_address", ""),
            identity.get("mac_address_type", ""),
            identity.get("observed_ttl"),
            identity.get("identity_updated_at", ""),
        ),
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
            _upsert_observed_asset(
                conn,
                ip,
                status,
                details,
                source,
                scan_run_id,
                _identity_values(row),
            )
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
            identity = _identity_values(row)
            transition = _upsert_observed_asset(
                conn,
                ip,
                str(row.get("Status", "Online")),
                str(row.get("Details", "")),
                "network scan",
                scan_run_id,
                identity,
            )
            if transition == "new_asset":
                new_assets.append(ip)
            elif transition == "asset_returned":
                returned_assets.append(ip)
            conn.execute(
                """
                INSERT INTO network_observations (
                    scan_run_id, ip_address, observed, status, details,
                    device_name, device_type, manufacturer, device_model,
                    operating_system, identity_confidence, mac_address, mac_address_type
                ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_run_id,
                    ip,
                    str(row.get("Status", "Online"))[:40],
                    str(row.get("Details", ""))[:1_000],
                    identity["device_name"],
                    identity["device_type"],
                    identity["manufacturer"],
                    identity["device_model"],
                    identity["operating_system"],
                    identity["identity_confidence"],
                    identity["mac_address"],
                    identity["mac_address_type"],
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
    *,
    actor_id: str = "",
    auth_method: str = "",
    request_id: str = "",
) -> None:
    init_db()
    with _connect() as conn:
        _insert_audit_event(
            conn,
            actor_role,
            action,
            target,
            outcome,
            details,
            actor_id=actor_id,
            auth_method=auth_method,
            request_id=request_id,
        )
        _prune_audit_log(conn)
    _invalidate_audit_readiness_cache()


def update_asset_context(
    ip_address: str,
    *,
    owner: str,
    department: str,
    location: str,
    criticality: str,
    notes: str,
    actor_role: str,
    actor_id: str = "",
    auth_method: str = "",
    request_id: str = "",
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
            actor_id=actor_id,
            auth_method=auth_method,
            request_id=request_id,
        )
        _prune_audit_log(conn)
        row = conn.execute(
            """
            SELECT
                ip_address, first_seen, last_seen, status, details,
                hostname, device_name, device_type, manufacturer, device_model,
                operating_system, identity_confidence, identity_evidence,
                mac_address, mac_address_type, observed_ttl, identity_updated_at,
                exposure_score, exposure_level, open_ports,
                owner, department, location, criticality, notes, context_updated_at
            FROM assets
            WHERE ip_address = ?
            """,
            (normalized_ip,),
        ).fetchone()
    _invalidate_audit_readiness_cache()
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
                observations.details,
                observations.device_name,
                observations.device_type,
                observations.manufacturer,
                observations.device_model,
                observations.operating_system,
                observations.identity_confidence,
                observations.mac_address,
                observations.mac_address_type
            FROM network_observations AS observations
            JOIN scan_runs AS runs ON runs.id = observations.scan_run_id
            ORDER BY observations.id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def recent_audit_log(limit: int = 100, *, include_identity: bool = False) -> list[dict]:
    init_db()
    safe_limit = max(1, min(int(limit), 1_000))
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT
                created_at, actor_role, actor_id, auth_method, request_id,
                action, target, outcome, details,
                CASE WHEN event_hash != '' THEN 1 ELSE 0 END AS integrity_protected
            FROM audit_log
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
    items = [dict(row) for row in rows]
    for item in items:
        item["integrity_protected"] = bool(item["integrity_protected"])
        if not include_identity:
            item.pop("actor_id", None)
            item.pop("request_id", None)
    return items


def verify_audit_integrity() -> dict[str, object]:
    """Verify the retained HMAC chain without returning chain material or secrets."""
    init_db()
    key = _audit_hmac_key()
    if key is None:
        return {
            "status": "unavailable",
            "valid": False,
            "protected_entries": 0,
            "legacy_entries": 0,
            "checked_at": _utc_now(),
        }

    with _connect() as conn:
        valid, protected_entries, legacy_entries = _audit_chain_is_valid(conn, key)

    if not valid:
        status = "invalid"
    elif protected_entries:
        status = "valid"
    elif legacy_entries:
        status = "legacy_only"
    else:
        status = "empty"
    return {
        "status": status,
        "valid": valid,
        "protected_entries": protected_entries,
        "legacy_entries": legacy_entries,
        "checked_at": _utc_now(),
    }


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
    item["hostname"] = item.get("hostname") or "-"
    item["device_name"] = item.get("device_name") or "Unresolved"
    item["device_type"] = item.get("device_type") or "Unclassified device"
    item["manufacturer"] = item.get("manufacturer") or "Unknown"
    item["device_model"] = item.get("device_model") or "Model unavailable"
    item["operating_system"] = item.get("operating_system") or "Unknown"
    item["identity_confidence"] = item.get("identity_confidence") or "Low"
    item["identity_evidence"] = (
        item.get("identity_evidence") or "No naming or OS fingerprint evidence recorded."
    )
    item["mac_address"] = item.get("mac_address") or "-"
    item["mac_address_type"] = item.get("mac_address_type") or "Unavailable"
    item["observed_ttl"] = item["observed_ttl"] if item.get("observed_ttl") is not None else "-"
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
                hostname, device_name, device_type, manufacturer, device_model,
                operating_system, identity_confidence, identity_evidence,
                mac_address, mac_address_type, observed_ttl, identity_updated_at,
                exposure_score, exposure_level, open_ports,
                owner, department, location, criticality, notes, context_updated_at
            FROM assets
            ORDER BY exposure_score DESC, ip_address ASC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()

    return [_asset_record(row) for row in rows]
