from __future__ import annotations

import hashlib
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import auto_intelligence
import backend.main as api
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
    assert auto_intelligence.claim_auto_analysis(first, interval_seconds=3600, now=start) == (
        "claimed"
    )
    assert (
        auto_intelligence.claim_auto_analysis(
            second, interval_seconds=3600, now=start + timedelta(minutes=10)
        )
        == "interval"
    )
    assert auto_intelligence.finish_auto_analysis(
        first, success=True, now=start + timedelta(minutes=1)
    )
    assert auto_intelligence.auto_analysis_status()["last_outcome"] == "completed"
    assert (
        auto_intelligence.claim_auto_analysis(
            first, interval_seconds=3600, now=start + timedelta(days=1)
        )
        == "unchanged"
    )
    assert (
        auto_intelligence.claim_auto_analysis(
            second, interval_seconds=3600, now=start + timedelta(hours=1, seconds=1)
        )
        == "claimed"
    )


def test_auto_analysis_failure_throttled_and_later_retryable(isolated_db):
    start = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
    digest = _digest("failure")
    assert auto_intelligence.claim_auto_analysis(
        digest, interval_seconds=3600, now=start
    ) == "claimed"
    assert auto_intelligence.finish_auto_analysis(
        digest, success=False, now=start
    )
    assert auto_intelligence.auto_analysis_status()["last_outcome"] == "failed"
    assert auto_intelligence.claim_auto_analysis(
        digest, interval_seconds=3600, now=start + timedelta(minutes=20)
    ) == "interval"
    assert auto_intelligence.claim_auto_analysis(
        digest, interval_seconds=3600, now=start + timedelta(hours=1)
    ) == "claimed"


def test_auto_analysis_rejects_invalid_digest(isolated_db):
    with pytest.raises(ValueError, match="digest"):
        auto_intelligence.claim_auto_analysis("192.168.1.10", interval_seconds=3600)
    with pytest.raises(ValueError, match="digest"):
        auto_intelligence.finish_auto_analysis("bad", success=True)


def test_auto_analysis_single_winner_across_simultaneous_claims(isolated_db):
    digest = _digest("concurrent")
    now = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
    results: list[str] = []
    lock = threading.Lock()

    def worker():
        result = auto_intelligence.claim_auto_analysis(
            digest, interval_seconds=3600, now=now
        )
        with lock:
            results.append(result)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count("claimed") == 1
    assert results.count("interval") == 3


def test_auto_cycle_requires_opt_in_and_healthy_provider(monkeypatch, isolated_db):
    monkeypatch.setattr(api, "AI_AUTO_ANALYSIS_ENABLED", False)
    monkeypatch.setattr(api, "_intelligence_snapshot", lambda: pytest.fail("No snapshot"))
    assert api._run_auto_intelligence_once() == "disabled"
    monkeypatch.setattr(api, "AI_AUTO_ANALYSIS_ENABLED", True)
    monkeypatch.setattr(
        api, "enterprise_readiness",
        lambda: {"capabilities": {"local_single_instance_safe": True}},
    )
    monkeypatch.setattr(api, "_intelligence_configuration_is_usable", lambda: False)
    assert api._run_auto_intelligence_once() == "provider_unavailable"
    assert auto_intelligence.auto_analysis_status()["last_outcome"] == "never"


def test_auto_cycle_uses_evidence_only_and_no_repeat_call(monkeypatch, isolated_db):
    monkeypatch.setattr(api, "AI_AUTO_ANALYSIS_ENABLED", True)
    monkeypatch.setattr(api, "AI_AUTO_INTERVAL_SECONDS", 3600)
    monkeypatch.setattr(
        api, "enterprise_readiness",
        lambda: {"capabilities": {"local_single_instance_safe": True}},
    )
    monkeypatch.setattr(api, "_intelligence_configuration_is_usable", lambda: True)
    monkeypatch.setattr(api, "audit_integrity_is_ready", lambda **kwargs: True)
    safe_snapshot = {"privacy": {"deidentified": True}, "assets": {"total": 4}}
    monkeypatch.setattr(api, "_intelligence_snapshot", lambda: safe_snapshot)
    requests = []

    def provider(*, refresh, context, snapshot):
        requests.append((refresh, context.actor_id, snapshot))
        return {"cached": False}

    monkeypatch.setattr(api, "_produce_intelligence_brief", provider)
    assert api._run_auto_intelligence_once() == "completed"
    assert api._run_auto_intelligence_once() == "unchanged"
    assert requests == [(False, "netwatch:automatic-analysis", safe_snapshot)]
    assert auto_intelligence.auto_analysis_status()["last_outcome"] == "completed"


def test_auto_cycle_fails_closed_on_provider_error(monkeypatch, isolated_db):
    monkeypatch.setattr(api, "AI_AUTO_ANALYSIS_ENABLED", True)
    monkeypatch.setattr(api, "AI_AUTO_INTERVAL_SECONDS", 3600)
    monkeypatch.setattr(
        api, "enterprise_readiness",
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


def test_temporary_black_formatted_code_diagnostics():
    """Temporary diagnostic only: removed after canonical Black diffs are applied."""
    import difflib

    import black

    root = Path(__file__).resolve().parents[1]
    differences = []
    for relative in ("auto_intelligence.py", "tests/test_auto_intelligence.py", "backend/main.py"):
        value = (root / relative).read_text(encoding="utf-8")
        expected = black.format_str(value, mode=black.Mode(line_length=100))
        if expected == value:
            continue
        delta = "\n".join(
            difflib.unified_diff(
                value.splitlines(),
                expected.splitlines(),
                fromfile=relative,
                tofile=f"{relative}:black",
                lineterm="",
            )
        )
        differences.append(delta)
    assert not differences, "\n\n".join(differences)
