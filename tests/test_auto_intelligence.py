from __future__ import annotations

import hashlib
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import auto_intelligence
import backend.main as api
import intelligence_store
import inventory_store


@pytest.fixture
def isolated_db(monkeypatch, tmp_path: Path):
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    inventory_store.init_db()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def test_auto_analysis_claim_persists_across_calls_and_skips_unchanged(isolated_db):
    start = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
    first, second = _digest("first"), _digest("second")
    first_claim_id = "a" * 32
    assert (
        auto_intelligence.claim_auto_analysis(
            first,
            interval_seconds=3600,
            claim_id=first_claim_id,
            now=start,
        )
        == "claimed"
    )
    assert (
        auto_intelligence.claim_auto_analysis(
            second,
            interval_seconds=3600,
            claim_id="b" * 32,
            now=start + timedelta(seconds=60),
        )
        == "in_progress"
    )
    assert auto_intelligence.finish_auto_analysis(
        first,
        claim_id=first_claim_id,
        success=True,
        now=start + timedelta(minutes=1),
    )
    assert auto_intelligence.auto_analysis_status()["last_outcome"] == "completed"
    assert (
        auto_intelligence.claim_auto_analysis(
            second,
            interval_seconds=3600,
            claim_id="c" * 32,
            now=start + timedelta(minutes=10),
        )
        == "interval"
    )
    assert (
        auto_intelligence.claim_auto_analysis(
            first,
            interval_seconds=3600,
            claim_id="c" * 32,
            now=start + timedelta(days=1),
        )
        == "unchanged"
    )
    assert (
        auto_intelligence.claim_auto_analysis(
            second,
            interval_seconds=3600,
            claim_id="d" * 32,
            now=start + timedelta(hours=1, seconds=1),
        )
        == "claimed"
    )


def test_auto_analysis_failure_throttled_and_later_retryable(isolated_db):
    start = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
    digest = _digest("failure")
    claim_id = "e" * 32
    assert (
        auto_intelligence.claim_auto_analysis(
            digest,
            interval_seconds=3600,
            claim_id=claim_id,
            now=start,
        )
        == "claimed"
    )
    assert auto_intelligence.finish_auto_analysis(
        digest,
        claim_id=claim_id,
        success=False,
        now=start,
    )
    assert auto_intelligence.auto_analysis_status()["last_outcome"] == "failed"
    assert (
        auto_intelligence.claim_auto_analysis(
            digest,
            interval_seconds=3600,
            claim_id="f" * 32,
            now=start + timedelta(minutes=20),
        )
        == "interval"
    )
    assert (
        auto_intelligence.claim_auto_analysis(
            digest,
            interval_seconds=3600,
            claim_id="1" * 32,
            now=start + timedelta(hours=1),
        )
        == "claimed"
    )


def test_auto_analysis_rejects_invalid_digest_and_claim_id(isolated_db):
    with pytest.raises(ValueError, match="digest"):
        auto_intelligence.claim_auto_analysis(
            "192.168.1.10",
            interval_seconds=3600,
            claim_id="a" * 32,
        )
    with pytest.raises(ValueError, match="digest"):
        auto_intelligence.finish_auto_analysis("bad", claim_id="a" * 32, success=True)
    with pytest.raises(ValueError, match="claim ID"):
        auto_intelligence.claim_auto_analysis(
            _digest("valid"),
            interval_seconds=3600,
            claim_id="not-a-token",
        )


def test_auto_analysis_single_winner_across_simultaneous_claims(isolated_db):
    digest = _digest("concurrent")
    now = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
    results: list[str] = []
    lock = threading.Lock()

    def worker(index: int):
        result = auto_intelligence.claim_auto_analysis(
            digest,
            interval_seconds=3600,
            claim_id=f"{index:032x}",
            now=now,
        )
        with lock:
            results.append(result)

    threads = [threading.Thread(target=worker, args=(index + 1,)) for index in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count("claimed") == 1
    assert results.count("in_progress") == 3


def test_auto_analysis_reclaims_expired_legacy_claim_and_fences_stale_finisher(isolated_db):
    start = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
    digest = _digest("stalled")
    first_claim_id = "1" * 32
    second_claim_id = "2" * 32
    with inventory_store._connect() as conn:
        conn.execute("""
            CREATE TABLE intelligence_auto_state (
                id INTEGER PRIMARY KEY CHECK(id = 1),
                last_attempt_at TEXT NOT NULL DEFAULT '',
                last_success_at TEXT NOT NULL DEFAULT '',
                last_success_digest TEXT NOT NULL DEFAULT '',
                pending_digest TEXT NOT NULL DEFAULT '',
                last_outcome TEXT NOT NULL DEFAULT 'never'
            )
        """)
        conn.execute(
            """
            INSERT INTO intelligence_auto_state (
                id, last_attempt_at, pending_digest, last_outcome
            ) VALUES (1, ?, ?, 'in_progress')
            """,
            (start.isoformat(timespec="seconds"), digest),
        )

    assert (
        auto_intelligence.claim_auto_analysis(
            digest,
            interval_seconds=3600,
            claim_id=first_claim_id,
            now=start + timedelta(seconds=60),
        )
        == "in_progress"
    )
    with inventory_store._connect() as conn:
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(intelligence_auto_state)").fetchall()
        }
    assert "pending_claim_id" in columns
    assert (
        auto_intelligence.claim_auto_analysis(
            digest,
            interval_seconds=3600,
            claim_id=second_claim_id,
            now=start + timedelta(seconds=181),
        )
        == "claimed"
    )
    assert not auto_intelligence.finish_auto_analysis(
        digest,
        claim_id=first_claim_id,
        success=True,
        now=start + timedelta(seconds=182),
    )
    assert auto_intelligence.auto_analysis_status()["last_outcome"] == "in_progress"
    assert auto_intelligence.finish_auto_analysis(
        digest,
        claim_id=second_claim_id,
        success=True,
        now=start + timedelta(seconds=183),
    )
    assert auto_intelligence.auto_analysis_status()["last_outcome"] == "completed"


def test_auto_cycle_requires_opt_in_and_healthy_provider(monkeypatch, isolated_db):
    monkeypatch.setattr(api, "AI_AUTO_ANALYSIS_ENABLED", False)
    monkeypatch.setattr(api, "_intelligence_snapshot", lambda: pytest.fail("No snapshot"))
    assert api._run_auto_intelligence_once() == "disabled"
    monkeypatch.setattr(api, "AI_AUTO_ANALYSIS_ENABLED", True)
    monkeypatch.setattr(
        api,
        "enterprise_readiness",
        lambda: {"capabilities": {"local_single_instance_safe": True}},
    )
    monkeypatch.setattr(api, "_intelligence_configuration_is_usable", lambda: False)
    assert api._run_auto_intelligence_once() == "provider_unavailable"
    assert auto_intelligence.auto_analysis_status()["last_outcome"] == "never"


def test_auto_cycle_uses_evidence_only_and_no_repeat_call(monkeypatch, isolated_db):
    monkeypatch.setattr(api, "AI_AUTO_ANALYSIS_ENABLED", True)
    monkeypatch.setattr(api, "AI_AUTO_INTERVAL_SECONDS", 3600)
    monkeypatch.setattr(
        api,
        "enterprise_readiness",
        lambda: {"capabilities": {"local_single_instance_safe": True}},
    )
    monkeypatch.setattr(api, "_intelligence_configuration_is_usable", lambda: True)
    monkeypatch.setattr(api, "audit_integrity_is_ready", lambda **kwargs: True)
    safe_snapshot = {"privacy": {"deidentified": True}, "assets": {"total": 4}}
    monkeypatch.setattr(api, "_intelligence_snapshot", lambda: safe_snapshot)
    requests = []

    def provider(*, refresh, context, snapshot, auto_claim_id):
        requests.append((refresh, context.actor_id, snapshot, auto_claim_id))
        return {"cached": False}

    monkeypatch.setattr(api, "_produce_intelligence_brief", provider)
    assert api._run_auto_intelligence_once() == "completed"
    assert api._run_auto_intelligence_once() == "unchanged"
    assert len(requests) == 1
    assert requests[0][:3] == (False, "netwatch:automatic-analysis", safe_snapshot)
    assert len(requests[0][3]) == 32
    assert all(character in "0123456789abcdef" for character in requests[0][3])
    assert auto_intelligence.auto_analysis_status()["last_outcome"] == "completed"


def test_auto_cycle_reports_superseded_claim_without_false_success(monkeypatch, isolated_db):
    monkeypatch.setattr(api, "AI_AUTO_ANALYSIS_ENABLED", True)
    monkeypatch.setattr(api, "AI_AUTO_INTERVAL_SECONDS", 3600)
    monkeypatch.setattr(
        api,
        "enterprise_readiness",
        lambda: {"capabilities": {"local_single_instance_safe": True}},
    )
    monkeypatch.setattr(api, "_intelligence_configuration_is_usable", lambda: True)
    monkeypatch.setattr(api, "audit_integrity_is_ready", lambda **kwargs: True)
    monkeypatch.setattr(api, "_intelligence_snapshot", lambda: {"assets": {"total": 2}})
    monkeypatch.setattr(api, "_produce_intelligence_brief", lambda **kwargs: {"cached": False})
    monkeypatch.setattr(api, "finish_auto_analysis", lambda *args, **kwargs: False)

    assert api._run_auto_intelligence_once() == "superseded"


def test_auto_cycle_fails_closed_on_provider_error(monkeypatch, isolated_db):
    monkeypatch.setattr(api, "AI_AUTO_ANALYSIS_ENABLED", True)
    monkeypatch.setattr(api, "AI_AUTO_INTERVAL_SECONDS", 3600)
    monkeypatch.setattr(
        api,
        "enterprise_readiness",
        lambda: {"capabilities": {"local_single_instance_safe": True}},
    )
    monkeypatch.setattr(api, "_intelligence_configuration_is_usable", lambda: True)
    monkeypatch.setattr(api, "audit_integrity_is_ready", lambda **kwargs: True)
    monkeypatch.setattr(api, "_intelligence_snapshot", lambda: {"assets": {"total": 2}})

    def provider(**kwargs):
        raise RuntimeError("provider unavailable")

    monkeypatch.setattr(api, "_produce_intelligence_brief", provider)
    assert api._run_auto_intelligence_once() == "failed"
    assert auto_intelligence.auto_analysis_status()["last_outcome"] == "failed"
    assert api._run_auto_intelligence_once() == "interval"



def test_superseded_auto_analysis_claim_cannot_persist_completed_brief(isolated_db):
    start = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
    digest = _digest("superseded-completed")
    old_claim = "a" * 32
    current_claim = "b" * 32
    assert auto_intelligence.claim_auto_analysis(
        digest, interval_seconds=3600, claim_id=old_claim, now=start
    ) == "claimed"
    assert auto_intelligence.claim_auto_analysis(
        digest,
        interval_seconds=3600,
        claim_id=current_claim,
        now=start + timedelta(seconds=181),
    ) == "claimed"

    with pytest.raises(intelligence_store.StaleAutoAnalysisClaim):
        intelligence_store.save_intelligence_brief(
            snapshot_hash=digest,
            model="synthetic-model",
            actor_role="operator",
            response={"executive_summary": "stale result"},
            auto_claim_id=old_claim,
            now=start + timedelta(seconds=182),
        )
    assert intelligence_store.cached_intelligence_brief(
        digest, now=start + timedelta(seconds=183)
    ) is None

    intelligence_store.save_intelligence_brief(
        snapshot_hash=digest,
        model="synthetic-model",
        actor_role="operator",
        response={"executive_summary": "current result"},
        auto_claim_id=current_claim,
        now=start + timedelta(seconds=184),
    )
    cached = intelligence_store.cached_intelligence_brief(
        digest, now=start + timedelta(seconds=185)
    )
    assert cached is not None
    assert cached["response"]["executive_summary"] == "current result"


def test_superseded_auto_analysis_claim_cannot_persist_failure_event(isolated_db):
    start = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
    digest = _digest("superseded-failure")
    old_claim = "c" * 32
    current_claim = "d" * 32
    assert auto_intelligence.claim_auto_analysis(
        digest, interval_seconds=3600, claim_id=old_claim, now=start
    ) == "claimed"
    assert auto_intelligence.claim_auto_analysis(
        digest,
        interval_seconds=3600,
        claim_id=current_claim,
        now=start + timedelta(seconds=181),
    ) == "claimed"

    with pytest.raises(intelligence_store.StaleAutoAnalysisClaim):
        intelligence_store.record_intelligence_failure(
            snapshot_hash=digest,
            model="synthetic-model",
            actor_role="operator",
            error_code="stale_failure",
            auto_claim_id=old_claim,
            now=start + timedelta(seconds=182),
        )
    assert intelligence_store.intelligence_metrics()["failed"] == 0

    intelligence_store.record_intelligence_failure(
        snapshot_hash=digest,
        model="synthetic-model",
        actor_role="operator",
        error_code="current_failure",
        auto_claim_id=current_claim,
        now=start + timedelta(seconds=183),
    )
    assert intelligence_store.intelligence_metrics()["failed"] == 1
