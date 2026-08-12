from __future__ import annotations

import enterprise_backends
import enterprise_runtime


def test_local_backends_are_ready_by_default(monkeypatch):
    for name in (
        "NETWATCH_DATABASE_BACKEND",
        "NETWATCH_COORDINATION_BACKEND",
        "NETWATCH_OBJECT_STORAGE_BACKEND",
        "NETWATCH_EVENT_SINK",
        "NETWATCH_DATABASE_URL",
        "NETWATCH_REDIS_URL",
        "NETWATCH_S3_BUCKET",
        "NETWATCH_EVENT_SINK_URL",
        "NETWATCH_PUBSUB_TOPIC",
    ):
        monkeypatch.delenv(name, raising=False)

    status = enterprise_runtime.enterprise_readiness()

    assert status["status"] == "ready"
    assert status["safe_to_run_current_process"] is True
    assert status["capabilities"]["backend_probes"]["ready"] is True


def test_shared_service_fails_closed_without_external_backend_contract(monkeypatch):
    monkeypatch.setenv("NETWATCH_ENTERPRISE_MODE", "shared_service")
    monkeypatch.setenv("NETWATCH_DATABASE_BACKEND", "postgresql")
    monkeypatch.setenv("NETWATCH_COORDINATION_BACKEND", "redis")
    monkeypatch.setenv("NETWATCH_OBJECT_STORAGE_BACKEND", "s3")
    monkeypatch.setenv("NETWATCH_EVENT_SINK", "https")
    for name in (
        "NETWATCH_DATABASE_URL",
        "NETWATCH_REDIS_URL",
        "NETWATCH_S3_BUCKET",
        "NETWATCH_EVENT_SINK_URL",
        "NETWATCH_PUBSUB_TOPIC",
    ):
        monkeypatch.delenv(name, raising=False)

    status = enterprise_runtime.enterprise_readiness()
    probes = enterprise_backends.probe_enterprise_backends()

    assert status["status"] == "not_ready"
    assert status["safe_to_run_current_process"] is False
    assert "NETWATCH_DATABASE_URL_missing" in probes["blockers"]
    assert "NETWATCH_REDIS_URL_missing" in probes["blockers"]
    assert "NETWATCH_S3_BUCKET_missing" in probes["blockers"]
    assert "NETWATCH_EVENT_SINK_URL_or_PUBSUB_TOPIC_missing" in probes["blockers"]


def test_unknown_backend_selection_fails_configuration(monkeypatch):
    monkeypatch.setenv("NETWATCH_ENTERPRISE_MODE", "compatibility")
    monkeypatch.setenv("NETWATCH_DATABASE_BACKEND", "unknown")
    status = enterprise_runtime.enterprise_readiness()
    assert status["status"] == "not_ready"
    assert "backend_configuration_invalid" in status["capabilities"]["blockers"]
