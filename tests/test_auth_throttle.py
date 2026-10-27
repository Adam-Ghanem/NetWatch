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


def test_failed_attempt_history_does_not_contain_credentials():
    limiter = AuthenticationFailureLimiter(max_failures=1)
    limiter.record_failure("127.0.0.1")
    assert set(limiter._failures) == {"127.0.0.1"}
    assert limiter.retry_after("127.0.0.1") is not None
    limiter.clear()
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
