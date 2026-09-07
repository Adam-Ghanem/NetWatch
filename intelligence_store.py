from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from config import AI_CACHE_TTL_SECONDS, MAX_INTELLIGENCE_EVENTS, MAX_SERVICE_FINDINGS

_SNAPSHOT_HASH = re.compile(r"^[a-f0-9]{64}$")


def _utc_now(moment: datetime | None = None) -> str:
    value = moment or datetime.now(timezone.utc)
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def _clean(value: object, max_length: int) -> str:
    return " ".join(str(value).split())[:max_length]


def _validated_hash(value: str) -> str:
    candidate = str(value).strip().lower()
    if not _SNAPSHOT_HASH.fullmatch(candidate):
        raise ValueError("Snapshot hash must be a lowercase SHA-256 digest.")
    return candidate


def _database_modules() -> tuple[Any, Any]:
    import inventory_store

    inventory_store.init_db()
    return inventory_store, inventory_store._connect


def create_intelligence_schema(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS intelligence_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL DEFAULT '',
            snapshot_hash TEXT NOT NULL,
            model TEXT NOT NULL,
            actor_role TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('completed', 'failed')),
            response_json TEXT NOT NULL DEFAULT '',
            provider_request_id TEXT NOT NULL DEFAULT '',
            input_tokens INTEGER NOT NULL DEFAULT 0 CHECK (input_tokens >= 0),
            output_tokens INTEGER NOT NULL DEFAULT 0 CHECK (output_tokens >= 0),
            error_code TEXT NOT NULL DEFAULT ''
        )
        """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_intelligence_snapshot "
        "ON intelligence_events(snapshot_hash, status, expires_at, id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_intelligence_created "
        "ON intelligence_events(created_at, id)"
    )
    conn.execute("""
        CREATE TABLE IF NOT EXISTS intelligence_daily_usage (
            day_utc TEXT PRIMARY KEY,
            request_count INTEGER NOT NULL DEFAULT 0 CHECK (request_count >= 0),
            updated_at TEXT NOT NULL
        )
        """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tls_service_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_run_id INTEGER NOT NULL,
            ip_address TEXT NOT NULL,
            port INTEGER NOT NULL CHECK(port BETWEEN 1 AND 65535),
            protocol TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            tls_protocol TEXT NOT NULL DEFAULT '',
            tls_cipher TEXT NOT NULL DEFAULT '',
            tls_alpn TEXT NOT NULL DEFAULT '',
            certificate_sha256 TEXT NOT NULL DEFAULT '',
            certificate_not_before TEXT NOT NULL DEFAULT '',
            certificate_not_after TEXT NOT NULL DEFAULT '',
            certificate_status TEXT NOT NULL DEFAULT 'Unknown',
            certificate_days_remaining TEXT NOT NULL DEFAULT '',
            UNIQUE(scan_run_id, ip_address, protocol, port),
            FOREIGN KEY(scan_run_id) REFERENCES scan_runs(id) ON DELETE CASCADE
        )
        """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tls_service_history_asset "
        "ON tls_service_history(ip_address, observed_at, id)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_tls_service_history_scan "
        "ON tls_service_history(scan_run_id, id)"
    )
    conn.execute("DROP TRIGGER IF EXISTS trg_service_findings_tls_history")
    conn.execute(f"""
        CREATE TRIGGER trg_service_findings_tls_history
        AFTER INSERT ON service_findings
        WHEN lower(NEW.status) = 'open'
        BEGIN
            INSERT OR REPLACE INTO tls_service_history (
                scan_run_id, ip_address, port, protocol, observed_at,
                tls_protocol, tls_cipher, tls_alpn, certificate_sha256,
                certificate_not_before, certificate_not_after,
                certificate_status, certificate_days_remaining
            )
            SELECT
                NEW.scan_run_id,
                NEW.ip_address,
                NEW.port,
                NEW.protocol,
                NEW.observed_at,
                substr(COALESCE(json_extract(port.value, '$."TLS Protocol"'), ''), 1, 32),
                substr(COALESCE(json_extract(port.value, '$."TLS Cipher"'), ''), 1, 96),
                substr(COALESCE(json_extract(port.value, '$."TLS ALPN"'), ''), 1, 32),
                CASE
                    WHEN length(lower(COALESCE(json_extract(
                        port.value, '$."TLS Certificate SHA256"'
                    ), ''))) = 64
                    AND lower(COALESCE(json_extract(
                        port.value, '$."TLS Certificate SHA256"'
                    ), '')) NOT GLOB '*[^0-9a-f]*'
                    THEN lower(json_extract(port.value, '$."TLS Certificate SHA256"'))
                    ELSE ''
                END,
                substr(COALESCE(json_extract(
                    port.value, '$."TLS Certificate Not Before"'
                ), ''), 1, 40),
                substr(COALESCE(json_extract(
                    port.value, '$."TLS Certificate Not After"'
                ), ''), 1, 40),
                CASE COALESCE(json_extract(
                    port.value, '$."TLS Certificate Status"'
                ), 'Unknown')
                    WHEN 'Valid' THEN 'Valid'
                    WHEN 'Expired' THEN 'Expired'
                    WHEN 'Not Yet Valid' THEN 'Not Yet Valid'
                    ELSE 'Unknown'
                END,
                substr(COALESCE(json_extract(
                    port.value, '$."TLS Certificate Days Remaining"'
                ), ''), 1, 16)
            FROM assets AS asset, json_each(asset.open_ports) AS port
            WHERE asset.ip_address = NEW.ip_address
              AND CAST(COALESCE(json_extract(port.value, '$.Port'), 0) AS INTEGER) = NEW.port
              AND upper(COALESCE(
                    json_extract(port.value, '$.Protocol'), 'TCP'
              )) = upper(NEW.protocol)
              AND (
                    COALESCE(json_extract(port.value, '$."TLS Protocol"'), '') != ''
                 OR COALESCE(json_extract(port.value, '$."TLS Certificate SHA256"'), '') != ''
                 OR COALESCE(json_extract(port.value, '$."TLS Certificate Status"'), '') != ''
              )
            LIMIT 1;

            DELETE FROM tls_service_history
            WHERE id NOT IN (
                SELECT id FROM tls_service_history
                ORDER BY id DESC LIMIT {int(MAX_SERVICE_FINDINGS)}
            );
        END
        """)


def _prune(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        DELETE FROM intelligence_events
        WHERE id NOT IN (
            SELECT id FROM intelligence_events ORDER BY id DESC LIMIT ?
        )
        """,
        (MAX_INTELLIGENCE_EVENTS,),
    )


def save_intelligence_brief(
    *,
    snapshot_hash: str,
    model: str,
    actor_role: str,
    response: dict[str, Any],
    provider_request_id: str = "",
    input_tokens: int = 0,
    output_tokens: int = 0,
    ttl_seconds: int = AI_CACHE_TTL_SECONDS,
    now: datetime | None = None,
) -> None:
    digest = _validated_hash(snapshot_hash)
    moment = now or datetime.now(timezone.utc)
    created_at = _utc_now(moment)
    expires_at = _utc_now(moment + timedelta(seconds=max(60, int(ttl_seconds))))
    encoded = json.dumps(response, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    if len(encoded) > 32_000:
        raise ValueError("Intelligence brief exceeds the storage limit.")
    _, connect = _database_modules()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO intelligence_events (
                created_at, expires_at, snapshot_hash, model, actor_role, status,
                response_json, provider_request_id, input_tokens, output_tokens
            ) VALUES (?, ?, ?, ?, ?, 'completed', ?, ?, ?, ?)
            """,
            (
                created_at,
                expires_at,
                digest,
                _clean(model, 120),
                _clean(actor_role, 40),
                encoded,
                _clean(provider_request_id, 160),
                max(0, int(input_tokens)),
                max(0, int(output_tokens)),
            ),
        )
        _prune(conn)


def record_intelligence_failure(
    *,
    snapshot_hash: str,
    model: str,
    actor_role: str,
    error_code: str,
    now: datetime | None = None,
) -> None:
    digest = _validated_hash(snapshot_hash)
    _, connect = _database_modules()
    with connect() as conn:
        conn.execute(
            """
            INSERT INTO intelligence_events (
                created_at, snapshot_hash, model, actor_role, status, error_code
            ) VALUES (?, ?, ?, ?, 'failed', ?)
            """,
            (
                _utc_now(now),
                digest,
                _clean(model, 120),
                _clean(actor_role, 40),
                _clean(error_code, 80),
            ),
        )
        _prune(conn)


def cached_intelligence_brief(
    snapshot_hash: str,
    *,
    now: datetime | None = None,
) -> dict[str, Any] | None:
    digest = _validated_hash(snapshot_hash)
    current = _utc_now(now)
    _, connect = _database_modules()
    with connect() as conn:
        row = conn.execute(
            """
            SELECT created_at, expires_at, model, response_json
            FROM intelligence_events
            WHERE snapshot_hash = ? AND status = 'completed' AND expires_at > ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (digest, current),
        ).fetchone()
    if row is None:
        return None
    try:
        response = json.loads(row["response_json"])
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(response, dict):
        return None
    return {
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "model": row["model"],
        "response": response,
    }


def daily_provider_request_count(*, now: datetime | None = None) -> int:
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    day_utc = moment.date().isoformat()
    _, connect = _database_modules()
    with connect() as conn:
        row = conn.execute(
            "SELECT request_count FROM intelligence_daily_usage WHERE day_utc = ?",
            (day_utc,),
        ).fetchone()
    return int(row[0]) if row is not None else 0


def reserve_intelligence_request(
    *,
    daily_limit: int,
    now: datetime | None = None,
) -> bool:
    limit = int(daily_limit)
    if limit < 1:
        return False

    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    day_utc = moment.date().isoformat()
    updated_at = _utc_now(moment)
    retention_cutoff = (moment - timedelta(days=31)).date().isoformat()
    _, connect = _database_modules()
    with connect() as conn:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            "DELETE FROM intelligence_daily_usage WHERE day_utc < ?",
            (retention_cutoff,),
        )
        cursor = conn.execute(
            """
            INSERT INTO intelligence_daily_usage (day_utc, request_count, updated_at)
            VALUES (?, 1, ?)
            ON CONFLICT(day_utc) DO UPDATE SET
                request_count = intelligence_daily_usage.request_count + 1,
                updated_at = excluded.updated_at
            WHERE intelligence_daily_usage.request_count < ?
            """,
            (day_utc, updated_at, limit),
        )
        return cursor.rowcount == 1


def recent_tls_service_history(
    *,
    limit: int = 100,
    ip_address: str | None = None,
) -> list[dict[str, object]]:
    """Return bounded, privacy-preserving TLS service evidence retained across scans."""
    safe_limit = max(1, min(int(limit), 1_000))
    normalized_ip: str | None = None
    if ip_address is not None:
        raw_ip = str(ip_address).strip()
        if not raw_ip or "%" in raw_ip:
            raise ValueError("A valid IPv4 or IPv6 address is required.")
        try:
            normalized_ip = str(ipaddress.ip_address(raw_ip))
        except ValueError as exc:
            raise ValueError("A valid IPv4 or IPv6 address is required.") from exc

    _, connect = _database_modules()
    with connect() as conn:
        if normalized_ip is None:
            rows = conn.execute(
                """
                SELECT
                    scan_run_id, ip_address, port, protocol, observed_at,
                    tls_protocol, tls_cipher, tls_alpn, certificate_sha256,
                    certificate_not_before, certificate_not_after,
                    certificate_status, certificate_days_remaining
                FROM tls_service_history
                ORDER BY id DESC
                LIMIT ?
                """,
                (safe_limit,),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT
                    scan_run_id, ip_address, port, protocol, observed_at,
                    tls_protocol, tls_cipher, tls_alpn, certificate_sha256,
                    certificate_not_before, certificate_not_after,
                    certificate_status, certificate_days_remaining
                FROM tls_service_history
                WHERE ip_address = ?
                ORDER BY id DESC
                LIMIT ?
                """,
                (normalized_ip, safe_limit),
            ).fetchall()
    return [dict(row) for row in rows]


def intelligence_metrics(*, now: datetime | None = None) -> dict[str, int]:
    current = _utc_now(now)
    _, connect = _database_modules()
    with connect() as conn:
        total = int(conn.execute("SELECT COUNT(*) FROM intelligence_events").fetchone()[0])
        completed = int(
            conn.execute(
                "SELECT COUNT(*) FROM intelligence_events WHERE status = 'completed'"
            ).fetchone()[0]
        )
        failed = int(
            conn.execute(
                "SELECT COUNT(*) FROM intelligence_events WHERE status = 'failed'"
            ).fetchone()[0]
        )
        active_cache = int(
            conn.execute(
                """
                SELECT COUNT(DISTINCT snapshot_hash) FROM intelligence_events
                WHERE status = 'completed' AND expires_at > ?
                """,
                (current,),
            ).fetchone()[0]
        )
    return {
        "provider_requests": total,
        "completed": completed,
        "failed": failed,
        "active_cache": active_cache,
    }
