"""Regression coverage for bounded pre-authentication failure throttling."""

from __future__ import annotations

import pytest
from fastapi import HTTPException, Request
from fastapi.testclient import TestClient

import auth_throttle
import backend.main as api
import inventory_store
from auth_throttle import AuthenticationFailureLimiter

TEST_API_KEY = "test-secret-with-at-least-32-characters"


def test_failed_attempts_have_rolling_expiry(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(auth_throttle.time, "monotonic", lambda: clock[0])
    limiter = AuthenticationFailureLimiter(max_failures=2, window_seconds=10)

    limiter.record_failure("peer-a")
    assert limiter.retry_after("peer-a") is None
    limiter.record_failure("peer-a")
    assert limiter.retry_after("peer-a") == 10
    assert limiter.retry_after("peer-b") is None

    clock[0] = 1009.2
    assert limiter.retry_after("peer-a") == 1
    clock[0] = 1010.0
    assert limiter.retry_after("peer-a") is None


def test_limiter_has_bounded_peer_storage_and_overflow(monkeypatch):
    monkeypatch.setattr(auth_throttle.time, "monotonic", lambda: 1000.0)
    limiter = AuthenticationFailureLimiter(max_failures=2, window_seconds=60, max_peers=1)
    limiter.record_failure("known")
    limiter.record_failure("unknown-1")
    limiter.record_failure("unknown-2")

    assert len(limiter._failures) == 1
    assert len(limiter._overflow) == 2
    assert limiter.retry_after("unknown-3") is not None
    assert limiter.retry_after("known") is None


def test_stale_peer_slots_are_reclaimed_before_overflow(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(auth_throttle.time, "monotonic", lambda: clock[0])
    limiter = AuthenticationFailureLimiter(max_failures=2, window_seconds=10, max_peers=1)
    limiter.record_failure("old")
    clock[0] += 11
    limiter.record_failure("new")

    assert "old" not in limiter._failures
    assert "new" in limiter._failures
    assert not limiter._overflow


def test_fresh_peer_does_not_inherit_overflow_after_stale_slot_expires(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(auth_throttle.time, "monotonic", lambda: clock[0])
    limiter = AuthenticationFailureLimiter(max_failures=2, window_seconds=10, max_peers=1)

    limiter.record_failure("old-peer")
    clock[0] = 1005.0
    limiter.record_failure("overflow-a")
    limiter.record_failure("overflow-b")
    assert limiter.retry_after("fresh-peer") == 10

    # The old peer has expired but overflow remains active. A fresh peer
    # must not be blocked merely because no new failure triggered cleanup.
    clock[0] = 1010.1
    assert limiter.retry_after("fresh-peer") is None
    assert "old-peer" not in limiter._failures
    # Overflow is shared only while all peer slots are occupied. Once a stale
    # slot is reclaimed, an unrelated peer must not inherit that history.
    assert limiter.retry_after("overflow-a") is None
    # Overflow entries remain until their own expiry.
    assert len(limiter._overflow) == 2
    limiter.record_failure("new-peer")
    assert "new-peer" in limiter._failures
    assert limiter.retry_after("new-peer") is None
    assert limiter.counters()["peer_buckets"] == 1


def test_active_peer_capacity_keeps_overflow_throttled(monkeypatch):
    clock = [2000.0]
    monkeypatch.setattr(auth_throttle.time, "monotonic", lambda: clock[0])
    limiter = AuthenticationFailureLimiter(max_failures=2, window_seconds=10, max_peers=1)

    limiter.record_failure("active-peer")
    limiter.record_failure("overflow-a")
    limiter.record_failure("overflow-b")
    assert limiter.retry_after("new-peer") == 10
    assert limiter.retry_after("active-peer") is None

    clock[0] = 2009.0
    assert limiter.retry_after("new-peer") == 1
    assert limiter.counters()["peer_buckets"] == 1

    clock[0] = 2010.0
    assert limiter.retry_after("new-peer") is None


def test_full_peer_map_sweeps_only_when_a_peer_bucket_can_expire(monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(auth_throttle.time, "monotonic", lambda: clock[0])
    limiter = AuthenticationFailureLimiter(max_failures=2, window_seconds=10, max_peers=2)
    limiter.record_failure("peer-a")
    clock[0] = 1001.0
    limiter.record_failure("peer-b")

    peer_a_bucket = limiter._failures["peer-a"]
    peer_b_bucket = limiter._failures["peer-b"]
    peer_c_bucket = None
    swept_peers = []
    original_expire = limiter._expire

    def track_peer_expiry(events, now):
        if events is peer_a_bucket:
            swept_peers.append("peer-a")
        elif events is peer_b_bucket:
            swept_peers.append("peer-b")
        elif events is peer_c_bucket:
            swept_peers.append("peer-c")
        original_expire(events, now)

    monkeypatch.setattr(limiter, "_expire", track_peer_expiry)

    # Unknown peers still share the overflow budget, but active peer buckets
    # are not rescanned for every failed request before their first expiry.
    for peer in ("overflow-a", "overflow-b", "overflow-c"):
        limiter.record_failure(peer)
    assert limiter.retry_after("fresh-peer") == 10
    assert swept_peers == []
    assert len(limiter._overflow) == 2

    # At the earliest expiry, exactly one sweep reclaims the stale slot.
    clock[0] = 1010.0
    assert limiter.retry_after("fresh-peer") is None
    assert swept_peers == ["peer-a", "peer-b"]
    assert "peer-a" not in limiter._failures
    assert "peer-b" in limiter._failures
    assert len(limiter._overflow) == 2

    # A new peer occupies the reclaimed slot. Neither the read nor write
    # overflow path repeats the O(max_peers) sweep before peer-b can expire.
    clock[0] = 1010.5
    limiter.record_failure("peer-c")
    peer_c_bucket = limiter._failures["peer-c"]
    for peer in ("overflow-d", "overflow-e"):
        limiter.record_failure(peer)
    assert swept_peers == ["peer-a", "peer-b"]

    clock[0] = 1011.0
    assert limiter.retry_after("fresh-peer") is None
    assert swept_peers == ["peer-a", "peer-b", "peer-b", "peer-c"]
    assert "peer-b" not in limiter._failures
    assert limiter._failures["peer-c"] is peer_c_bucket


def test_failed_attempt_history_does_not_contain_credentials():
    limiter = AuthenticationFailureLimiter(max_failures=1)
    limiter.record_failure("127.0.0.1")
    assert limiter.counters() == {"failures": 1, "blocked": 0, "peer_buckets": 1}
    assert set(limiter._failures) == {"127.0.0.1"}
    assert limiter.retry_after("127.0.0.1") is not None
    assert limiter.counters()["blocked"] == 1
    limiter.clear()
    assert limiter.counters() == {"failures": 0, "blocked": 0, "peer_buckets": 0}
    assert limiter.retry_after("127.0.0.1") is None


@pytest.mark.parametrize(
    "kwargs",
    [
        {"max_failures": 0},
        {"window_seconds": 0},
        {"max_peers": 0},
    ],
)
def test_invalid_limiter_settings_are_rejected(kwargs):
    with pytest.raises(ValueError, match="positive"):
        AuthenticationFailureLimiter(**kwargs)


def test_authentication_is_blocked_before_key_validation_and_ignores_forwarded_for(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("NETWATCH_API_KEY", TEST_API_KEY)
    monkeypatch.setenv("NETWATCH_AUDIT_HMAC_KEY", "test-audit-key-with-32-characters-and-more")
    monkeypatch.setenv("NETWATCH_OIDC_ENABLED", "false")
    monkeypatch.delenv("NETWATCH_OPERATOR_KEY", raising=False)
    monkeypatch.delenv("NETWATCH_VIEWER_KEY", raising=False)
    monkeypatch.setattr(inventory_store, "DATA_DIR", tmp_path)
    monkeypatch.setattr(inventory_store, "DB_FILE", tmp_path / "netwatch.db")
    monkeypatch.setattr(
        api,
        "_auth_failure_limiter",
        AuthenticationFailureLimiter(max_failures=2, window_seconds=60),
    )
    api._rate_events.clear()

    with TestClient(api.app, base_url="http://127.0.0.1") as client:
        assert client.get("/api/session", headers={"X-NetWatch-Key": "bad-one"}).status_code == 401
        assert client.get("/api/session", headers={"X-NetWatch-Key": "bad-two"}).status_code == 401
        blocked = client.get(
            "/api/session",
            headers={"X-NetWatch-Key": "bad-three", "X-Forwarded-For": "8.8.8.8"},
        )
        legitimate = client.get("/api/session", headers={"X-NetWatch-Key": TEST_API_KEY})
        health = client.get("/api/health/live")

    assert blocked.status_code == 429
    assert 1 <= int(blocked.headers["retry-after"]) <= 60
    assert "bad-three" not in blocked.text
    assert legitimate.status_code == 429
    assert health.status_code == 200

    # A separate authorized peer can export low-cardinality monitoring data.
    monkeypatch.setattr(
        api,
        "_auth_failure_limiter",
        AuthenticationFailureLimiter(max_failures=5, window_seconds=60),
    )
    with TestClient(api.app, base_url="http://127.0.0.1") as client:
        metrics = client.get("/api/metrics", headers={"X-NetWatch-Key": TEST_API_KEY})
    assert metrics.status_code == 200
    assert "netwatch_auth_failed_attempts_total" in metrics.text
    assert "netwatch_auth_blocked_requests_total" in metrics.text
    assert "netwatch_auth_peer_buckets" in metrics.text
    assert "8.8.8.8" not in metrics.text
    assert TEST_API_KEY not in metrics.text


def test_only_authentication_failures_increment_throttle(monkeypatch):
    limiter = AuthenticationFailureLimiter(max_failures=1, window_seconds=60)
    monkeypatch.setattr(api, "_auth_failure_limiter", limiter)
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/api/session",
            "headers": [],
            "client": ("192.0.2.17", 5555),
        }
    )

    def unavailable(request, key, bearer):
        raise HTTPException(status_code=503, detail="Identity provider unavailable")

    monkeypatch.setattr(api, "_authenticate_api_access", unavailable)
    with pytest.raises(HTTPException) as error:
        api.require_api_access(request, None, None)
    assert error.value.status_code == 503
    assert limiter.retry_after("192.0.2.17") is None

    def invalid(request, key, bearer):
        raise HTTPException(status_code=401, detail="Invalid identity")

    monkeypatch.setattr(api, "_authenticate_api_access", invalid)
    with pytest.raises(HTTPException) as error:
        api.require_api_access(request, None, None)
    assert error.value.status_code == 401
    assert limiter.retry_after("192.0.2.17") is not None
