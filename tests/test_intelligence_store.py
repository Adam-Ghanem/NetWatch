from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

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
