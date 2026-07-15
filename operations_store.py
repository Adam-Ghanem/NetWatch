from __future__ import annotations

import sqlite3
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from config import (
    MAINTENANCE_MAX_DURATION_DAYS,
    MAX_MAINTENANCE_WINDOWS,
    MAX_OPERATION_ALERTS,
    MAX_SCAN_POLICIES,
    SCAN_POLICY_MAX_INTERVAL_MINUTES,
    SCAN_POLICY_MIN_INTERVAL_MINUTES,
)

if TYPE_CHECKING:
    from inventory_store import NetworkChangeSummary

ALERT_SEVERITIES = ("Low", "Medium", "High", "Critical")
ALERT_STATUSES = ("open", "acknowledged", "resolved")
ALERT_SLA_HOURS = {"Critical": 4, "High": 24, "Medium": 72, "Low": 168}


@dataclass(frozen=True)
class AlertChangeSummary:
    created: int = 0
    refreshed: int = 0

    @property
    def total(self) -> int:
        return self.created + self.refreshed


class MaintenanceWindowActiveError(RuntimeError):
    def __init__(self, window_name: str):
        self.window_name = window_name
        super().__init__(f"Policy is paused by maintenance window '{window_name}'.")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _after_minutes(minutes: int, *, base: datetime | None = None) -> str:
    moment = base or datetime.now(timezone.utc)
    return (moment + timedelta(minutes=minutes)).isoformat(timespec="seconds")


def _parse_utc(value: str, *, field: str = "Timestamp") -> datetime:
    candidate = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError(f"{field} must be a valid ISO 8601 timestamp.") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a timezone.")
    return parsed.astimezone(timezone.utc)


def _iso_utc(value: str, *, field: str = "Timestamp") -> str:
    return _parse_utc(value, field=field).isoformat(timespec="seconds")


def _alert_due_at(severity: str, created_at: str) -> str:
    base = _parse_utc(created_at, field="Alert timestamp")
    return (base + timedelta(hours=ALERT_SLA_HOURS[severity])).isoformat(timespec="seconds")


def _clean(value: object, max_length: int) -> str:
    return " ".join(str(value).split())[:max_length]


def _database_modules() -> tuple[Any, Any]:
    # Imported lazily so inventory_store can initialize this module's schema
    # without creating an import cycle.
    import inventory_store

    inventory_store.init_db()
    return inventory_store, inventory_store._connect


def _create_alert_table(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE operation_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            last_seen_at TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            target TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open'
                CHECK (status IN ('open', 'acknowledged', 'resolved')),
            scan_run_id INTEGER,
            occurrence_count INTEGER NOT NULL DEFAULT 1
                CHECK (occurrence_count >= 1),
            assigned_to TEXT NOT NULL DEFAULT '',
            due_at TEXT NOT NULL DEFAULT '',
            acknowledged_at TEXT NOT NULL DEFAULT '',
            acknowledged_by TEXT NOT NULL DEFAULT '',
            resolution_note TEXT NOT NULL DEFAULT '',
            resolved_at TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id) ON DELETE SET NULL
        )
        """)


def _ensure_alert_table(conn: sqlite3.Connection) -> None:
    schema_row = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'operation_alerts'"
    ).fetchone()
    if schema_row is None:
        _create_alert_table(conn)
        return

    columns = {
        row["name"] for row in conn.execute("PRAGMA table_info(operation_alerts)").fetchall()
    }
    required = {
        "updated_at",
        "last_seen_at",
        "occurrence_count",
        "assigned_to",
        "due_at",
        "resolution_note",
        "resolved_at",
    }
    schema_sql = str(schema_row["sql"] or "")
    if required.issubset(columns) and "resolved" in schema_sql:
        return

    legacy_rows = conn.execute("SELECT * FROM operation_alerts ORDER BY id").fetchall()
    conn.execute("ALTER TABLE operation_alerts RENAME TO operation_alerts_v3")
    _create_alert_table(conn)
    for row in legacy_rows:
        item = dict(row)
        created_at = str(item["created_at"])
        severity = str(item["severity"])
        conn.execute(
            """
            INSERT INTO operation_alerts (
                id, created_at, updated_at, last_seen_at, severity, category,
                title, target, details, status, scan_run_id, occurrence_count,
                assigned_to, due_at, acknowledged_at, acknowledged_by,
                resolution_note, resolved_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, '', ?, ?, ?, '', '')
            """,
            (
                item["id"],
                created_at,
                created_at,
                created_at,
                severity,
                item["category"],
                item["title"],
                item["target"],
                item.get("details", ""),
                item.get("status", "open"),
                item.get("scan_run_id"),
                _alert_due_at(severity, created_at),
                item.get("acknowledged_at", ""),
                item.get("acknowledged_by", ""),
            ),
        )
    conn.execute("DROP TABLE operation_alerts_v3")


def create_operations_schema(conn: sqlite3.Connection) -> None:
    conn.execute(f"""
        CREATE TABLE IF NOT EXISTS scan_policies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            name TEXT NOT NULL,
            cidr TEXT NOT NULL UNIQUE,
            interval_minutes INTEGER NOT NULL
                CHECK (
                    interval_minutes >= {SCAN_POLICY_MIN_INTERVAL_MINUTES}
                    AND interval_minutes <= {SCAN_POLICY_MAX_INTERVAL_MINUTES}
                ),
            enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
            authorized_by TEXT NOT NULL,
            last_run_at TEXT NOT NULL DEFAULT '',
            next_run_at TEXT NOT NULL DEFAULT '',
            last_status TEXT NOT NULL DEFAULT 'never',
            last_summary TEXT NOT NULL DEFAULT ''
        )
        """)
    _ensure_alert_table(conn)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS maintenance_windows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            name TEXT NOT NULL,
            starts_at TEXT NOT NULL,
            ends_at TEXT NOT NULL,
            reason TEXT NOT NULL DEFAULT '',
            policy_id INTEGER,
            enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
            created_by TEXT NOT NULL,
            FOREIGN KEY(policy_id) REFERENCES scan_policies(id) ON DELETE CASCADE
        )
        """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scan_policies_due " "ON scan_policies(enabled, next_run_at)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_operation_alerts_status " "ON operation_alerts(status, id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_operation_alerts_target " "ON operation_alerts(target, id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_operation_alerts_fingerprint "
        "ON operation_alerts(category, target, status, id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_maintenance_windows_active "
        "ON maintenance_windows(enabled, starts_at, ends_at, policy_id)"
    )


def _policy_record(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    item["enabled"] = bool(item["enabled"])
    return item


def _validate_interval(value: int) -> int:
    interval = int(value)
    if not SCAN_POLICY_MIN_INTERVAL_MINUTES <= interval <= SCAN_POLICY_MAX_INTERVAL_MINUTES:
        raise ValueError(
            f"Interval must be between {SCAN_POLICY_MIN_INTERVAL_MINUTES} and "
            f"{SCAN_POLICY_MAX_INTERVAL_MINUTES} minutes."
        )
    return interval


def create_scan_policy(
    *,
    name: str,
    cidr: str,
    interval_minutes: int,
    enabled: bool,
    authorized_by: str,
) -> dict[str, Any]:
    _, connect = _database_modules()
    policy_name = _clean(name, 120)
    if len(policy_name) < 3:
        raise ValueError("Policy name must contain at least 3 characters.")
    interval = _validate_interval(interval_minutes)
    now = _utc_now()
    next_run_at = _after_minutes(interval) if enabled else ""

    with connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM scan_policies").fetchone()[0]
        if count >= MAX_SCAN_POLICIES:
            raise ValueError(f"At most {MAX_SCAN_POLICIES} scan policies can be stored.")
        try:
            cursor = conn.execute(
                """
                INSERT INTO scan_policies (
                    created_at, updated_at, name, cidr, interval_minutes,
                    enabled, authorized_by, next_run_at, last_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    now,
                    now,
                    policy_name,
                    cidr,
                    interval,
                    int(enabled),
                    _clean(authorized_by, 200),
                    next_run_at,
                    "scheduled" if enabled else "disabled",
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("A scan policy already exists for this CIDR.") from exc
        policy_id = cursor.lastrowid
        if policy_id is None:
            raise RuntimeError("SQLite did not return an ID for the scan policy.")
        row = conn.execute("SELECT * FROM scan_policies WHERE id = ?", (policy_id,)).fetchone()
    if row is None:
        raise RuntimeError("The scan policy was saved but could not be reloaded.")
    return _policy_record(row)


def scan_policies(limit: int = MAX_SCAN_POLICIES) -> list[dict[str, Any]]:
    _, connect = _database_modules()
    safe_limit = max(1, min(int(limit), MAX_SCAN_POLICIES))
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scan_policies ORDER BY enabled DESC, name ASC LIMIT ?",
            (safe_limit,),
        ).fetchall()
    return [_policy_record(row) for row in rows]


def get_scan_policy(policy_id: int) -> dict[str, Any]:
    _, connect = _database_modules()
    with connect() as conn:
        row = conn.execute("SELECT * FROM scan_policies WHERE id = ?", (policy_id,)).fetchone()
    if row is None:
        raise KeyError(policy_id)
    return _policy_record(row)


def update_scan_policy(
    policy_id: int,
    *,
    name: str | None = None,
    interval_minutes: int | None = None,
    enabled: bool | None = None,
) -> dict[str, Any]:
    _, connect = _database_modules()
    with connect() as conn:
        current = conn.execute("SELECT * FROM scan_policies WHERE id = ?", (policy_id,)).fetchone()
        if current is None:
            raise KeyError(policy_id)

        policy_name = current["name"] if name is None else _clean(name, 120)
        if len(policy_name) < 3:
            raise ValueError("Policy name must contain at least 3 characters.")
        interval = (
            int(current["interval_minutes"])
            if interval_minutes is None
            else _validate_interval(interval_minutes)
        )
        is_enabled = bool(current["enabled"]) if enabled is None else bool(enabled)
        schedule_changed = interval != current["interval_minutes"] or (
            is_enabled and not bool(current["enabled"])
        )
        if not is_enabled:
            next_run_at = ""
            last_status = "disabled"
        elif schedule_changed or not current["next_run_at"]:
            next_run_at = _after_minutes(interval)
            last_status = "scheduled"
        else:
            next_run_at = current["next_run_at"]
            last_status = current["last_status"]

        conn.execute(
            """
            UPDATE scan_policies
            SET updated_at = ?, name = ?, interval_minutes = ?, enabled = ?,
                next_run_at = ?, last_status = ?
            WHERE id = ?
            """,
            (
                _utc_now(),
                policy_name,
                interval,
                int(is_enabled),
                next_run_at,
                last_status,
                policy_id,
            ),
        )
        row = conn.execute("SELECT * FROM scan_policies WHERE id = ?", (policy_id,)).fetchone()
    if row is None:
        raise RuntimeError("The scan policy was updated but could not be reloaded.")
    return _policy_record(row)


def _maintenance_record(row: sqlite3.Row, *, now: str) -> dict[str, Any]:
    item = dict(row)
    item["enabled"] = bool(item["enabled"])
    item["active"] = bool(item["enabled"] and str(item["starts_at"]) <= now < str(item["ends_at"]))
    return item


def create_maintenance_window(
    *,
    name: str,
    starts_at: str,
    ends_at: str,
    reason: str,
    policy_id: int | None,
    enabled: bool,
    created_by: str,
) -> dict[str, Any]:
    _, connect = _database_modules()
    window_name = _clean(name, 120)
    if len(window_name) < 3:
        raise ValueError("Maintenance window name must contain at least 3 characters.")
    start = _parse_utc(starts_at, field="Maintenance start")
    end = _parse_utc(ends_at, field="Maintenance end")
    if end <= start:
        raise ValueError("Maintenance end must be after its start.")
    if end - start > timedelta(days=MAINTENANCE_MAX_DURATION_DAYS):
        raise ValueError(f"Maintenance windows cannot exceed {MAINTENANCE_MAX_DURATION_DAYS} days.")
    normalized_start = start.isoformat(timespec="seconds")
    normalized_end = end.isoformat(timespec="seconds")
    now = _utc_now()

    with connect() as conn:
        count = conn.execute("SELECT COUNT(*) FROM maintenance_windows").fetchone()[0]
        if count >= MAX_MAINTENANCE_WINDOWS:
            raise ValueError(
                f"At most {MAX_MAINTENANCE_WINDOWS} maintenance windows can be stored."
            )
        if policy_id is not None:
            policy = conn.execute(
                "SELECT id FROM scan_policies WHERE id = ?", (policy_id,)
            ).fetchone()
            if policy is None:
                raise KeyError(policy_id)
        cursor = conn.execute(
            """
            INSERT INTO maintenance_windows (
                created_at, updated_at, name, starts_at, ends_at, reason,
                policy_id, enabled, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                now,
                now,
                window_name,
                normalized_start,
                normalized_end,
                _clean(reason, 500),
                policy_id,
                int(enabled),
                _clean(created_by, 200),
            ),
        )
        window_id = cursor.lastrowid
        if window_id is None:
            raise RuntimeError("SQLite did not return an ID for the maintenance window.")
        row = conn.execute(
            """
            SELECT mw.*, sp.name AS policy_name, sp.cidr AS policy_cidr
            FROM maintenance_windows mw
            LEFT JOIN scan_policies sp ON sp.id = mw.policy_id
            WHERE mw.id = ?
            """,
            (window_id,),
        ).fetchone()
    if row is None:
        raise RuntimeError("The maintenance window was saved but could not be reloaded.")
    return _maintenance_record(row, now=now)


def maintenance_windows(
    *,
    active_only: bool = False,
    now: str | None = None,
    limit: int = MAX_MAINTENANCE_WINDOWS,
) -> list[dict[str, Any]]:
    _, connect = _database_modules()
    current = _iso_utc(now, field="Current time") if now else _utc_now()
    safe_limit = max(1, min(int(limit), MAX_MAINTENANCE_WINDOWS))
    with connect() as conn:
        if active_only:
            rows = conn.execute(
                """
                SELECT mw.*, sp.name AS policy_name, sp.cidr AS policy_cidr
                FROM maintenance_windows mw
                LEFT JOIN scan_policies sp ON sp.id = mw.policy_id
                WHERE mw.enabled = 1 AND mw.starts_at <= ? AND mw.ends_at > ?
                ORDER BY mw.starts_at DESC, mw.id DESC
                LIMIT ?
                """,
                (current, current, safe_limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT mw.*, sp.name AS policy_name, sp.cidr AS policy_cidr
                FROM maintenance_windows mw
                LEFT JOIN scan_policies sp ON sp.id = mw.policy_id
                ORDER BY mw.enabled DESC, mw.starts_at DESC, mw.id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
    return [_maintenance_record(row, now=current) for row in rows]


def policy_maintenance_windows(
    policy_id: int,
    *,
    now: str | None = None,
) -> list[dict[str, Any]]:
    current = _iso_utc(now, field="Current time") if now else _utc_now()
    return [
        window
        for window in maintenance_windows(active_only=True, now=current)
        if window["policy_id"] is None or int(window["policy_id"]) == int(policy_id)
    ]


def set_maintenance_window_enabled(
    window_id: int,
    *,
    enabled: bool,
) -> dict[str, Any]:
    _, connect = _database_modules()
    now = _utc_now()
    with connect() as conn:
        cursor = conn.execute(
            "UPDATE maintenance_windows SET updated_at = ?, enabled = ? WHERE id = ?",
            (now, int(enabled), window_id),
        )
        if cursor.rowcount == 0:
            raise KeyError(window_id)
        row = conn.execute(
            """
            SELECT mw.*, sp.name AS policy_name, sp.cidr AS policy_cidr
            FROM maintenance_windows mw
            LEFT JOIN scan_policies sp ON sp.id = mw.policy_id
            WHERE mw.id = ?
            """,
            (window_id,),
        ).fetchone()
    if row is None:
        raise RuntimeError("The maintenance window was updated but could not be reloaded.")
    return _maintenance_record(row, now=now)


def _mark_policy_started(conn: sqlite3.Connection, policy_id: int, started_at: str) -> None:
    row = conn.execute(
        "SELECT interval_minutes, enabled FROM scan_policies WHERE id = ?", (policy_id,)
    ).fetchone()
    if row is None:
        raise KeyError(policy_id)
    try:
        started = datetime.fromisoformat(started_at)
    except ValueError:
        started = datetime.now(timezone.utc)
    next_run_at = (
        _after_minutes(int(row["interval_minutes"]), base=started) if row["enabled"] else ""
    )
    conn.execute(
        """
        UPDATE scan_policies
        SET updated_at = ?, last_run_at = ?, next_run_at = ?,
            last_status = 'running', last_summary = ''
        WHERE id = ?
        """,
        (started_at, started_at, next_run_at, policy_id),
    )


def start_scan_policy(policy_id: int) -> dict[str, Any]:
    _, connect = _database_modules()
    now = _utc_now()
    with connect() as conn:
        saved = conn.execute("SELECT id FROM scan_policies WHERE id = ?", (policy_id,)).fetchone()
        if saved is None:
            raise KeyError(policy_id)
        active_window = conn.execute(
            """
            SELECT name FROM maintenance_windows
            WHERE enabled = 1 AND starts_at <= ? AND ends_at > ?
              AND (policy_id IS NULL OR policy_id = ?)
            ORDER BY policy_id IS NULL DESC, starts_at ASC, id ASC
            LIMIT 1
            """,
            (now, now, policy_id),
        ).fetchone()
        if active_window is not None:
            raise MaintenanceWindowActiveError(str(active_window["name"]))
        _mark_policy_started(conn, policy_id, now)
        row = conn.execute("SELECT * FROM scan_policies WHERE id = ?", (policy_id,)).fetchone()
    if row is None:
        raise RuntimeError("The scan policy was started but could not be reloaded.")
    return _policy_record(row)


def claim_due_scan_policies(
    *,
    now: str | None = None,
    limit: int = 1,
) -> list[dict[str, Any]]:
    _, connect = _database_modules()
    claimed_at = now or _utc_now()
    safe_limit = max(1, min(int(limit), 5))
    conn = connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        rows = conn.execute(
            """
            SELECT * FROM scan_policies
            WHERE enabled = 1 AND next_run_at != '' AND next_run_at <= ?
              AND NOT EXISTS (
                  SELECT 1 FROM maintenance_windows mw
                  WHERE mw.enabled = 1
                    AND mw.starts_at <= ? AND mw.ends_at > ?
                    AND (mw.policy_id IS NULL OR mw.policy_id = scan_policies.id)
              )
            ORDER BY next_run_at ASC, id ASC
            LIMIT ?
            """,
            (claimed_at, claimed_at, claimed_at, safe_limit),
        ).fetchall()
        for row in rows:
            _mark_policy_started(conn, int(row["id"]), claimed_at)
        claimed = [
            conn.execute("SELECT * FROM scan_policies WHERE id = ?", (row["id"],)).fetchone()
            for row in rows
        ]
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    return [_policy_record(row) for row in claimed if row is not None]


def complete_scan_policy(policy_id: int, *, status: str, summary: str) -> dict[str, Any]:
    _, connect = _database_modules()
    normalized_status = _clean(status, 40)
    normalized_summary = _clean(summary, 1_000)
    with connect() as conn:
        cursor = conn.execute(
            """
            UPDATE scan_policies
            SET updated_at = ?, last_status = ?, last_summary = ?
            WHERE id = ?
            """,
            (_utc_now(), normalized_status, normalized_summary, policy_id),
        )
        if cursor.rowcount == 0:
            raise KeyError(policy_id)
        row = conn.execute("SELECT * FROM scan_policies WHERE id = ?", (policy_id,)).fetchone()
    if row is None:
        raise RuntimeError("The scan policy result was saved but could not be reloaded.")
    return _policy_record(row)


def _severity_rank(value: str) -> int:
    return ALERT_SEVERITIES.index(value) if value in ALERT_SEVERITIES else 0


def _upsert_alert(
    conn: sqlite3.Connection,
    *,
    severity: str,
    category: str,
    title: str,
    target: str,
    details: str,
    scan_run_id: int | None,
) -> bool:
    if severity not in ALERT_SEVERITIES:
        raise ValueError(f"Unsupported alert severity: {severity}")
    normalized_category = _clean(category, 80)
    normalized_target = _clean(target, 200)
    existing = conn.execute(
        """
        SELECT * FROM operation_alerts
        WHERE category = ? AND target = ? AND status IN ('open', 'acknowledged')
        ORDER BY id DESC LIMIT 1
        """,
        (normalized_category, normalized_target),
    ).fetchone()
    now = _utc_now()
    if existing is not None:
        saved_severity = str(existing["severity"])
        effective_severity = (
            severity
            if _severity_rank(severity) > _severity_rank(saved_severity)
            else saved_severity
        )
        candidate_due_at = _alert_due_at(effective_severity, now)
        current_due_at = str(existing["due_at"] or "")
        due_at = min(current_due_at, candidate_due_at) if current_due_at else candidate_due_at
        conn.execute(
            """
            UPDATE operation_alerts
            SET updated_at = ?, last_seen_at = ?, severity = ?, title = ?,
                details = ?, scan_run_id = ?, occurrence_count = occurrence_count + 1,
                due_at = ?
            WHERE id = ?
            """,
            (
                now,
                now,
                effective_severity,
                _clean(title, 200),
                _clean(details, 1_000),
                scan_run_id,
                due_at,
                existing["id"],
            ),
        )
        return False

    conn.execute(
        """
        INSERT INTO operation_alerts (
            created_at, updated_at, last_seen_at, severity, category, title,
            target, details, scan_run_id, due_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            now,
            now,
            now,
            severity,
            normalized_category,
            _clean(title, 200),
            normalized_target,
            _clean(details, 1_000),
            scan_run_id,
            _alert_due_at(severity, now),
        ),
    )
    return True


def _prune_alerts(conn: sqlite3.Connection) -> None:
    total = int(conn.execute("SELECT COUNT(*) FROM operation_alerts").fetchone()[0])
    excess = max(0, total - MAX_OPERATION_ALERTS)
    if excess == 0:
        return
    conn.execute(
        """
        DELETE FROM operation_alerts
        WHERE id IN (
            SELECT id FROM operation_alerts
            WHERE status = 'resolved' ORDER BY id ASC LIMIT ?
        )
        """,
        (excess,),
    )
    remaining = int(conn.execute("SELECT COUNT(*) FROM operation_alerts").fetchone()[0])
    remaining_excess = max(0, remaining - MAX_OPERATION_ALERTS)
    if remaining_excess:
        conn.execute(
            """
            DELETE FROM operation_alerts
            WHERE id IN (
                SELECT id FROM operation_alerts ORDER BY id ASC LIMIT ?
            )
            """,
            (remaining_excess,),
        )


def create_alerts_for_changes(changes: NetworkChangeSummary) -> AlertChangeSummary:
    _, connect = _database_modules()
    created = 0
    refreshed = 0
    with connect() as conn:
        for ip_address in changes.new_assets:
            was_created = _upsert_alert(
                conn,
                severity="Medium",
                category="new_asset",
                title="Unreviewed asset discovered",
                target=ip_address,
                details=(
                    "Assign an owner and verify that this device is expected on the approved range."
                ),
                scan_run_id=changes.scan_run_id,
            )
            created += int(was_created)
            refreshed += int(not was_created)

        for ip_address in changes.returned_assets:
            was_created = _upsert_alert(
                conn,
                severity="Low",
                category="asset_returned",
                title="Previously absent asset observed again",
                target=ip_address,
                details="Confirm the return is expected and review recent operational changes.",
                scan_run_id=changes.scan_run_id,
            )
            created += int(was_created)
            refreshed += int(not was_created)

        for ip_address in changes.not_observed_assets:
            asset = conn.execute(
                "SELECT owner, criticality FROM assets WHERE ip_address = ?", (ip_address,)
            ).fetchone()
            criticality = asset["criticality"] if asset else "Medium"
            severity = criticality if criticality in {"High", "Critical"} else "Medium"
            owner = asset["owner"] if asset and asset["owner"] else "unassigned owner"
            was_created = _upsert_alert(
                conn,
                severity=severity,
                category="asset_not_observed",
                title=f"{criticality} asset not observed",
                target=ip_address,
                details=(
                    f"Latest scan received no reply; availability is not confirmed. "
                    f"Validate with {owner}."
                ),
                scan_run_id=changes.scan_run_id,
            )
            created += int(was_created)
            refreshed += int(not was_created)

        _prune_alerts(conn)
    return AlertChangeSummary(created=created, refreshed=refreshed)


def _alert_record(row: sqlite3.Row, *, now: str) -> dict[str, Any]:
    item = dict(row)
    item["overdue"] = bool(
        item["status"] != "resolved" and item["due_at"] and str(item["due_at"]) < now
    )
    item["sla_state"] = (
        "resolved"
        if item["status"] == "resolved"
        else ("overdue" if item["overdue"] else "within_sla")
    )
    return item


def recent_alerts(
    *,
    status: str | None = None,
    severity: str | None = None,
    overdue_only: bool = False,
    limit: int = 200,
) -> list[dict[str, Any]]:
    _, connect = _database_modules()
    if status is not None and status not in ALERT_STATUSES:
        raise ValueError("Alert status must be open, acknowledged, or resolved.")
    if severity is not None and severity not in ALERT_SEVERITIES:
        raise ValueError("Unsupported alert severity.")
    safe_limit = max(1, min(int(limit), 1_000))
    now = _utc_now()
    with connect() as conn:
        rows = conn.execute(
            """
            SELECT *
            FROM operation_alerts
            WHERE (? IS NULL OR status = ?)
              AND (? IS NULL OR severity = ?)
              AND (
                  ? = 0
                  OR (status != 'resolved' AND due_at != '' AND due_at < ?)
              )
            ORDER BY
                CASE severity
                    WHEN 'Critical' THEN 4 WHEN 'High' THEN 3
                    WHEN 'Medium' THEN 2 ELSE 1
                END DESC,
                id DESC
            LIMIT ?
            """,
            (
                status,
                status,
                severity,
                severity,
                int(overdue_only),
                now,
                safe_limit,
            ),
        ).fetchall()
    return [_alert_record(row, now=now) for row in rows]


def alert_counts() -> dict[str, int]:
    _, connect = _database_modules()
    counts = {
        "open": 0,
        "acknowledged": 0,
        "resolved": 0,
        "overdue": 0,
        "critical_unresolved": 0,
        "total": 0,
    }
    now = _utc_now()
    with connect() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS count FROM operation_alerts GROUP BY status"
        ).fetchall()
        counts["overdue"] = int(
            conn.execute(
                """
                SELECT COUNT(*) FROM operation_alerts
                WHERE status != 'resolved' AND due_at != '' AND due_at < ?
                """,
                (now,),
            ).fetchone()[0]
        )
        counts["critical_unresolved"] = int(conn.execute("""
                SELECT COUNT(*) FROM operation_alerts
                WHERE severity = 'Critical' AND status != 'resolved'
                """).fetchone()[0])
    for row in rows:
        count = int(row["count"])
        counts[str(row["status"])] = count
        counts["total"] += count
    return counts


def update_operation_alert(
    alert_id: int,
    *,
    actor_role: str,
    status: str | None = None,
    assigned_to: str | None = None,
    resolution_note: str | None = None,
) -> dict[str, Any]:
    _, connect = _database_modules()
    if status is not None and status not in ALERT_STATUSES:
        raise ValueError("Alert status must be open, acknowledged, or resolved.")
    if status is None and assigned_to is None and resolution_note is None:
        raise ValueError("Provide an alert status, assignee, or resolution note.")
    now = _utc_now()
    with connect() as conn:
        current = conn.execute(
            "SELECT * FROM operation_alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        if current is None:
            raise KeyError(alert_id)
        next_status = str(current["status"]) if status is None else status
        next_assignee = (
            str(current["assigned_to"]) if assigned_to is None else _clean(assigned_to, 120)
        )
        next_resolution = (
            str(current["resolution_note"])
            if resolution_note is None
            else _clean(resolution_note, 1_000)
        )
        if next_status == "resolved" and len(next_resolution) < 3:
            raise ValueError("A resolution note is required before resolving an alert.")

        acknowledged_at = str(current["acknowledged_at"])
        acknowledged_by = str(current["acknowledged_by"])
        resolved_at = str(current["resolved_at"])
        if next_status == "open":
            acknowledged_at = ""
            acknowledged_by = ""
            resolved_at = ""
        elif next_status == "acknowledged":
            if not acknowledged_at:
                acknowledged_at = now
                acknowledged_by = _clean(actor_role, 200)
            resolved_at = ""
        elif next_status == "resolved" and not resolved_at:
            resolved_at = now

        conn.execute(
            """
            UPDATE operation_alerts
            SET updated_at = ?, status = ?, assigned_to = ?, resolution_note = ?,
                acknowledged_at = ?, acknowledged_by = ?, resolved_at = ?
            WHERE id = ?
            """,
            (
                now,
                next_status,
                next_assignee,
                next_resolution,
                acknowledged_at,
                acknowledged_by,
                resolved_at,
                alert_id,
            ),
        )
        row = conn.execute(
            "SELECT * FROM operation_alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
    if row is None:
        raise RuntimeError("The alert was updated but could not be reloaded.")
    return _alert_record(row, now=now)


def set_alert_status(alert_id: int, *, status: str, actor_role: str) -> dict[str, Any]:
    return update_operation_alert(alert_id, status=status, actor_role=actor_role)


def operations_metrics() -> dict[str, int]:
    _, connect = _database_modules()
    counts = alert_counts()
    now = _utc_now()
    with connect() as conn:
        assets = int(conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0])
        policies = int(conn.execute("SELECT COUNT(*) FROM scan_policies").fetchone()[0])
        enabled_policies = int(
            conn.execute("SELECT COUNT(*) FROM scan_policies WHERE enabled = 1").fetchone()[0]
        )
        active_maintenance = int(
            conn.execute(
                """
                SELECT COUNT(*) FROM maintenance_windows
                WHERE enabled = 1 AND starts_at <= ? AND ends_at > ?
                """,
                (now, now),
            ).fetchone()[0]
        )
    return {
        "assets": assets,
        "policies": policies,
        "enabled_policies": enabled_policies,
        "active_maintenance": active_maintenance,
        **counts,
    }


def database_backup_bytes() -> bytes:
    _, connect = _database_modules()
    with tempfile.TemporaryDirectory(prefix="netwatch-backup-") as temp_dir:
        backup_path = Path(temp_dir) / "netwatch.sqlite3"
        source = connect()
        destination = sqlite3.connect(backup_path)
        try:
            source.backup(destination)
        finally:
            destination.close()
            source.close()
        if not backup_path.exists():
            raise RuntimeError("SQLite backup did not produce a database file.")
        content = backup_path.read_bytes()
    if not content:
        raise RuntimeError("SQLite backup is empty.")
    return content
