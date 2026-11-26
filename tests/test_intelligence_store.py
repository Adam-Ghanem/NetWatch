from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

import intelligence_store
import inventory_store


def _configure_database(monkeypatch, tmp_path):
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    inventory_store.init_db()


def test_intelligence_cache_is_bounded_metadata_without_prompts(monkeypatch, tmp_path):
    _configure_database(monkeypatch, tmp_path)
    now = datetime(2026, 7, 15, 10, 0, tzinfo=timezone.utc)
    brief = {
        "risk_level": "Low",
        "executive_summary": "No urgent exposure is represented in the saved evidence.",
        "key_observations": ["No open cases are represented."],
        "recommended_actions": [
            {
                "priority": "Monitor",
                "title": "Continue approved monitoring",
                "rationale": "The current evidence is limited.",
                "validation": "Review after the next approved scan.",
            }
        ],
        "limitations": ["Observations are not proof of complete coverage."],
    }

    assert intelligence_store.reserve_intelligence_request(daily_limit=50, now=now)
    intelligence_store.save_intelligence_brief(
        snapshot_hash="a" * 64,
        model="gpt-test-model",
        actor_role="viewer",
        response=brief,
        provider_request_id="resp_123",
        input_tokens=100,
        output_tokens=50,
        ttl_seconds=300,
        now=now,
    )

    cached = intelligence_store.cached_intelligence_brief("a" * 64, now=now)
    assert cached is not None
    assert cached["response"] == brief
    assert cached["model"] == "gpt-test-model"
    assert intelligence_store.daily_provider_request_count(now=now) == 1
    assert intelligence_store.intelligence_metrics(now=now) == {
        "provider_requests": 1,
        "completed": 1,
        "failed": 0,
        "active_cache": 1,
    }
    assert (
        intelligence_store.cached_intelligence_brief(
            "a" * 64,
            now=now + timedelta(minutes=6),
        )
        is None
    )


def test_intelligence_failures_store_only_safe_error_codes(monkeypatch, tmp_path):
    _configure_database(monkeypatch, tmp_path)
    now = datetime(2026, 7, 15, 11, 0, tzinfo=timezone.utc)

    assert intelligence_store.reserve_intelligence_request(daily_limit=50, now=now)
    intelligence_store.record_intelligence_failure(
        snapshot_hash="b" * 64,
        model="gpt-test-model",
        actor_role="operator",
        error_code="provider_unavailable",
        now=now,
    )

    assert intelligence_store.daily_provider_request_count(now=now) == 1
    assert intelligence_store.intelligence_metrics(now=now)["failed"] == 1
    with inventory_store._connect() as conn:
        row = conn.execute("SELECT * FROM intelligence_events").fetchone()
    assert row["error_code"] == "provider_unavailable"
    assert row["response_json"] == ""
    assert "prompt" not in row.keys()


def test_daily_budget_reservation_is_atomic_under_concurrency(monkeypatch, tmp_path):
    _configure_database(monkeypatch, tmp_path)
    now = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)

    with ThreadPoolExecutor(max_workers=8) as pool:
        admitted = list(
            pool.map(
                lambda _: intelligence_store.reserve_intelligence_request(
                    daily_limit=1,
                    now=now,
                ),
                range(8),
            )
        )

    assert admitted.count(True) == 1
    assert admitted.count(False) == 7
    assert intelligence_store.daily_provider_request_count(now=now) == 1


def test_daily_budget_is_independent_from_event_retention(monkeypatch, tmp_path):
    _configure_database(monkeypatch, tmp_path)
    monkeypatch.setattr(intelligence_store, "MAX_INTELLIGENCE_EVENTS", 3)
    now = datetime(2026, 7, 15, 13, 0, tzinfo=timezone.utc)

    for index in range(4):
        assert intelligence_store.reserve_intelligence_request(daily_limit=10, now=now)
        intelligence_store.record_intelligence_failure(
            snapshot_hash=f"{index + 1:x}" * 64,
            model="gpt-test-model",
            actor_role="viewer",
            error_code="provider_unavailable",
            now=now,
        )

    with inventory_store._connect() as conn:
        event_count = conn.execute("SELECT COUNT(*) FROM intelligence_events").fetchone()[0]
    assert event_count == 3
    assert intelligence_store.daily_provider_request_count(now=now) == 4


def test_daily_budget_uses_a_new_counter_for_the_next_utc_day(monkeypatch, tmp_path):
    _configure_database(monkeypatch, tmp_path)
    first_day = datetime(2026, 7, 15, 23, 59, tzinfo=timezone.utc)
    next_day = first_day + timedelta(minutes=2)

    assert intelligence_store.reserve_intelligence_request(daily_limit=1, now=first_day)
    assert not intelligence_store.reserve_intelligence_request(daily_limit=1, now=first_day)
    assert intelligence_store.reserve_intelligence_request(daily_limit=1, now=next_day)
    assert intelligence_store.daily_provider_request_count(now=next_day) == 1



def _assert_sqlite_connections_closed(connections: list[sqlite3.Connection]) -> None:
    assert connections
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
            connection.execute("SELECT 1")


def test_intelligence_store_closes_handles_for_reads_writes_and_schema_init(
    monkeypatch, tmp_path
):
    _configure_database(monkeypatch, tmp_path)
    opened: list[sqlite3.Connection] = []
    original_connect = inventory_store._connect

    def tracked_connect() -> sqlite3.Connection:
        connection = original_connect()
        opened.append(connection)
        return connection

    monkeypatch.setattr(inventory_store, "_connect", tracked_connect)
    now = datetime(2026, 11, 26, 1, 0, tzinfo=timezone.utc)
    completed_digest = "a" * 64
    failed_digest = "b" * 64

    assert intelligence_store.reserve_intelligence_request(daily_limit=5, now=now)
    intelligence_store.save_intelligence_brief(
        snapshot_hash=completed_digest,
        model="gpt-test-model",
        actor_role="viewer",
        response={"risk_level": "Low"},
        now=now,
    )
    intelligence_store.record_intelligence_failure(
        snapshot_hash=failed_digest,
        model="gpt-test-model",
        actor_role="viewer",
        error_code="provider_unavailable",
        now=now,
    )
    assert intelligence_store.cached_intelligence_brief(completed_digest, now=now) is not None
    assert intelligence_store.daily_provider_request_count(now=now) == 1
    assert intelligence_store.recent_tls_service_history(limit=2) == []
    assert intelligence_store.intelligence_metrics(now=now)["provider_requests"] == 2

    # Each operation initializes the schema and opens its own connection.
    # Both handles must be closed before the operation returns.
    assert len(opened) == 14
    _assert_sqlite_connections_closed(opened)


def test_intelligence_store_rolls_back_and_closes_after_operation_failure(
    monkeypatch, tmp_path
):
    _configure_database(monkeypatch, tmp_path)
    opened: list[sqlite3.Connection] = []
    original_connect = inventory_store._connect

    def tracked_connect() -> sqlite3.Connection:
        connection = original_connect()
        opened.append(connection)
        return connection

    monkeypatch.setattr(inventory_store, "_connect", tracked_connect)

    def fail_prune(_connection: sqlite3.Connection) -> None:
        raise RuntimeError("synthetic intelligence-store failure")

    monkeypatch.setattr(intelligence_store, "_prune", fail_prune)
    with pytest.raises(RuntimeError, match="synthetic intelligence-store failure"):
        intelligence_store.save_intelligence_brief(
            snapshot_hash="c" * 64,
            model="gpt-test-model",
            actor_role="viewer",
            response={"risk_level": "Low"},
        )

    assert len(opened) == 2
    _assert_sqlite_connections_closed(opened)

    check = original_connect()
    try:
        row = check.execute(
            "SELECT COUNT(*) FROM intelligence_events WHERE snapshot_hash = ?",
            ("c" * 64,),
        ).fetchone()
    finally:
        check.close()
    assert row[0] == 0
