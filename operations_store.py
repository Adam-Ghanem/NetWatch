from __future__ import annotations

import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from config import (
    MAX_OPERATION_ALERTS,
    MAX_SCAN_POLICIES,
    SCAN_POLICY_MAX_INTERVAL_MINUTES,
    SCAN_POLICY_MIN_INTERVAL_MINUTES,
)

if TYPE_CHECKING:
    from inventory_store import NetworkChangeSummary

ALERT_SEVERITIES = ("Low", "Medium", "High", "Critical")
ALERT_STATUSES = ("open", "acknowledged")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _after_minutes(minutes: int, *, base: datetime | None = None) -> str:
    moment = base or datetime.now(timezone.utc)
    return (moment + timedelta(minutes=minutes)).isoformat(timespec="seconds")


def _clean(value: object, max_length: int) -> str:
    return " ".join(str(value).split())[:max_length]


def _database_modules() -> tuple[Any, Any]:
    # Imported lazily so inventory_store can initialize this module's schema
    # without creating an import cycle.
    import inventory_store

    inventory_store.init_db()
    return inventory_store, inventory_store._connect


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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS operation_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            severity TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            target TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'open'
                CHECK (status IN ('open', 'acknowledged')),
            scan_run_id INTEGER,
            acknowledged_at TEXT NOT NULL DEFAULT '',
            acknowledged_by TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id) ON DELETE SET NULL
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
                    _clean(authorized_by, 40),
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
    with connect() as conn:
        _mark_policy_started(conn, policy_id, _utc_now())
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
            ORDER BY next_run_at ASC, id ASC
            LIMIT ?
            """,
            (claimed_at, safe_limit),
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


def _insert_alert(
    conn: sqlite3.Connection,
    *,
    severity: str,
    category: str,
    title: str,
    target: str,
    details: str,
    scan_run_id: int | None,
) -> None:
    if severity not in ALERT_SEVERITIES:
        raise ValueError(f"Unsupported alert severity: {severity}")
    conn.execute(
        """
        INSERT INTO operation_alerts (
            created_at, severity, category, title, target, details, scan_run_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _utc_now(),
            severity,
            _clean(category, 80),
            _clean(title, 200),
            _clean(target, 200),
            _clean(details, 1_000),
            scan_run_id,
        ),
    )


def _prune_alerts(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        DELETE FROM operation_alerts
        WHERE id NOT IN (
            SELECT id FROM operation_alerts ORDER BY id DESC LIMIT ?
        )
        """,
        (MAX_OPERATION_ALERTS,),
    )


def create_alerts_for_changes(changes: NetworkChangeSummary) -> int:
    _, connect = _database_modules()
    created = 0
    with connect() as conn:
        for ip_address in changes.new_assets:
            _insert_alert(
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
            created += 1

        for ip_address in changes.returned_assets:
            _insert_alert(
                conn,
                severity="Low",
                category="asset_returned",
                title="Previously absent asset observed again",
                target=ip_address,
                details="Confirm the return is expected and review recent operational changes.",
                scan_run_id=changes.scan_run_id,
            )
            created += 1

        for ip_address in changes.not_observed_assets:
            asset = conn.execute(
                "SELECT owner, criticality FROM assets WHERE ip_address = ?", (ip_address,)
            ).fetchone()
            criticality = asset["criticality"] if asset else "Medium"
            severity = criticality if criticality in {"High", "Critical"} else "Medium"
            owner = asset["owner"] if asset and asset["owner"] else "unassigned owner"
            _insert_alert(
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
            created += 1

        _prune_alerts(conn)
    return created


def recent_alerts(
    *,
    status: str | None = None,
    limit: int = 200,
) -> list[dict[str, Any]]:
    _, connect = _database_modules()
    if status is not None and status not in ALERT_STATUSES:
        raise ValueError("Alert status must be open or acknowledged.")
    safe_limit = max(1, min(int(limit), 1_000))
    where = "WHERE status = ?" if status else ""
    params: tuple[Any, ...] = (status, safe_limit) if status else (safe_limit,)
    with connect() as conn:
        rows = conn.execute(
            f"""
            SELECT
                id, created_at, severity, category, title, target, details,
                status, scan_run_id, acknowledged_at, acknowledged_by
            FROM operation_alerts
            {where}
            ORDER BY
                CASE severity
                    WHEN 'Critical' THEN 4 WHEN 'High' THEN 3
                    WHEN 'Medium' THEN 2 ELSE 1
                END DESC,
                id DESC
            LIMIT ?
            """,
            params,
        ).fetchall()
    return [dict(row) for row in rows]


def alert_counts() -> dict[str, int]:
    _, connect = _database_modules()
    counts = {"open": 0, "acknowledged": 0, "total": 0}
    with connect() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS count FROM operation_alerts GROUP BY status"
        ).fetchall()
    for row in rows:
        count = int(row["count"])
        counts[str(row["status"])] = count
        counts["total"] += count
    return counts


def set_alert_status(alert_id: int, *, status: str, actor_role: str) -> dict[str, Any]:
    _, connect = _database_modules()
    if status not in ALERT_STATUSES:
        raise ValueError("Alert status must be open or acknowledged.")
    acknowledged_at = _utc_now() if status == "acknowledged" else ""
    acknowledged_by = _clean(actor_role, 40) if status == "acknowledged" else ""
    with connect() as conn:
        cursor = conn.execute(
            """
            UPDATE operation_alerts
            SET status = ?, acknowledged_at = ?, acknowledged_by = ?
            WHERE id = ?
            """,
            (status, acknowledged_at, acknowledged_by, alert_id),
        )
        if cursor.rowcount == 0:
            raise KeyError(alert_id)
        row = conn.execute(
            """
            SELECT
                id, created_at, severity, category, title, target, details,
                status, scan_run_id, acknowledged_at, acknowledged_by
            FROM operation_alerts WHERE id = ?
            """,
            (alert_id,),
        ).fetchone()
    if row is None:
        raise RuntimeError("The alert was updated but could not be reloaded.")
    return dict(row)


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
