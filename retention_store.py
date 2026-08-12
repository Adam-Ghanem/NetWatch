"""Bounded, auditable operational retention controls."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from config import RETENTION_DEFAULT_DAYS, RETENTION_MAX_DELETE_ROWS


def _database_modules() -> tuple[Any, Any]:
    import inventory_store

    inventory_store.init_db()
    return inventory_store, inventory_store._connect


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _timestamp(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds")


def _safe_days(value: int | None) -> int:
    return max(1, min(int(value or RETENTION_DEFAULT_DAYS), 3_650))


def _safe_limit(value: int | None) -> int:
    return max(100, min(int(value or RETENTION_MAX_DELETE_ROWS), RETENTION_MAX_DELETE_ROWS))


def _table_summary(
    conn: Any, name: str, count_sql: str, oldest_sql: str, newest_sql: str
) -> dict[str, Any]:
    return {
        "table": name,
        "count": int(conn.execute(count_sql).fetchone()[0] or 0),
        "oldest": conn.execute(oldest_sql).fetchone()[0] or "",
        "newest": conn.execute(newest_sql).fetchone()[0] or "",
    }


def retention_status(*, now: datetime | None = None) -> dict[str, Any]:
    _, connect = _database_modules()
    current = now or _utc_now()
    with connect() as conn:
        tables = [
            _table_summary(
                conn,
                "asset_events",
                "SELECT COUNT(*) FROM asset_events",
                "SELECT MIN(created_at) FROM asset_events",
                "SELECT MAX(created_at) FROM asset_events",
            ),
            _table_summary(
                conn,
                "network_observations",
                "SELECT COUNT(*) FROM network_observations",
                "SELECT MIN(scan_runs.created_at) FROM network_observations "
                "JOIN scan_runs ON scan_runs.id = network_observations.scan_run_id",
                "SELECT MAX(scan_runs.created_at) FROM network_observations "
                "JOIN scan_runs ON scan_runs.id = network_observations.scan_run_id",
            ),
            _table_summary(
                conn,
                "service_findings",
                "SELECT COUNT(*) FROM service_findings",
                "SELECT MIN(observed_at) FROM service_findings",
                "SELECT MAX(observed_at) FROM service_findings",
            ),
            _table_summary(
                conn,
                "intelligence_events",
                "SELECT COUNT(*) FROM intelligence_events",
                "SELECT MIN(created_at) FROM intelligence_events",
                "SELECT MAX(created_at) FROM intelligence_events",
            ),
            _table_summary(
                conn,
                "enterprise_outbox",
                "SELECT COUNT(*) FROM enterprise_outbox",
                "SELECT MIN(created_at) FROM enterprise_outbox",
                "SELECT MAX(created_at) FROM enterprise_outbox",
            ),
            _table_summary(
                conn,
                "enterprise_jobs",
                "SELECT COUNT(*) FROM enterprise_jobs",
                "SELECT MIN(created_at) FROM enterprise_jobs",
                "SELECT MAX(created_at) FROM enterprise_jobs",
            ),
            _table_summary(
                conn,
                "audit_log",
                "SELECT COUNT(*) FROM audit_log",
                "SELECT MIN(created_at) FROM audit_log",
                "SELECT MAX(created_at) FROM audit_log",
            ),
        ]
    return {
        "generated_at": _timestamp(current),
        "default_older_than_days": RETENTION_DEFAULT_DAYS,
        "max_delete_rows": RETENTION_MAX_DELETE_ROWS,
        "audit_protection": "The retention endpoint never deletes audit_log or audit_chain_state.",
        "tables": tables,
    }


def _eligible_queries(cutoff: str) -> dict[str, tuple[str, tuple[Any, ...]]]:
    return {
        "asset_events": (
            "SELECT id FROM asset_events WHERE created_at < ? ORDER BY id ASC LIMIT ?",
            (cutoff,),
        ),
        "network_observations": (
            """
            SELECT observations.id
            FROM network_observations AS observations
            JOIN scan_runs ON scan_runs.id = observations.scan_run_id
            WHERE scan_runs.created_at < ?
            ORDER BY observations.id ASC LIMIT ?
            """,
            (cutoff,),
        ),
        "service_findings": (
            "SELECT id FROM service_findings WHERE observed_at < ? ORDER BY id ASC LIMIT ?",
            (cutoff,),
        ),
        "intelligence_events": (
            "SELECT id FROM intelligence_events WHERE created_at < ? ORDER BY id ASC LIMIT ?",
            (cutoff,),
        ),
        "enterprise_outbox": (
            "SELECT id FROM enterprise_outbox WHERE created_at < ? "
            "AND delivered_at != '' ORDER BY id ASC LIMIT ?",
            (cutoff,),
        ),
        "enterprise_jobs": (
            "SELECT id FROM enterprise_jobs WHERE created_at < ? "
            "AND status IN ('succeeded', 'failed') ORDER BY id ASC LIMIT ?",
            (cutoff,),
        ),
    }


def cleanup_retention(
    *,
    older_than_days: int | None = None,
    dry_run: bool = True,
    max_rows: int | None = None,
) -> dict[str, Any]:
    days = _safe_days(older_than_days)
    limit = _safe_limit(max_rows)
    cutoff = _timestamp(_utc_now() - timedelta(days=days))
    _, connect = _database_modules()
    candidates = _eligible_queries(cutoff)
    result: dict[str, Any] = {
        "dry_run": bool(dry_run),
        "older_than_days": days,
        "cutoff": cutoff,
        "max_rows": limit,
        "eligible": {},
        "deleted": {},
        "total": 0,
    }
    with connect() as conn:
        for table, (query, parameters) in candidates.items():
            count = int(
                conn.execute(
                    f"SELECT COUNT(*) FROM ({query})",  # noqa: S608
                    (*parameters, limit),
                ).fetchone()[0]
            )
            result["eligible"][table] = count
            if not dry_run and count:
                cursor = conn.execute(
                    f"DELETE FROM {table} WHERE id IN ({query})",  # noqa: S608
                    (*parameters, limit),
                )
                result["deleted"][table] = int(cursor.rowcount)
                result["total"] += int(cursor.rowcount)
            else:
                result["deleted"][table] = 0
    return result
