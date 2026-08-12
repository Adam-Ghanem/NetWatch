from __future__ import annotations

from readiness_store import readiness_center


def test_readiness_center_fails_closed_by_default(monkeypatch):
    monkeypatch.delenv("NETWATCH_ENTERPRISE_MODE", raising=False)
    monkeypatch.delenv("NETWATCH_TRACK_A_EVIDENCE_VERIFIED", raising=False)
    monkeypatch.delenv("NETWATCH_TRACK_A_EVIDENCE_REFERENCE", raising=False)

    report = readiness_center()

    assert report["active_track"] == "A_single_tenant"
    assert report["status"] == "evidence_pending"
    assert report["score"] == 0
    assert "target_environment_approval" in report["blockers"]


def test_readiness_center_requires_reference_for_declared_score(monkeypatch):
    monkeypatch.setenv("NETWATCH_TRACK_A_EVIDENCE_VERIFIED", "true")
    monkeypatch.delenv("NETWATCH_TRACK_A_EVIDENCE_REFERENCE", raising=False)

    report = readiness_center()

    assert report["status"] == "evidence_pending"
    assert report["score"] == 0


def test_readiness_center_accepts_explicit_operator_declaration(monkeypatch):
    monkeypatch.setenv("NETWATCH_ENTERPRISE_MODE", "shared_service")
    monkeypatch.setenv("NETWATCH_TRACK_B_EVIDENCE_VERIFIED", "true")
    monkeypatch.setenv("NETWATCH_TRACK_B_EVIDENCE_REFERENCE", "change-approval-2026-08-12")

    report = readiness_center()

    assert report["active_track"] == "B_shared_service"
    assert report["status"] == "operator_declared_ready"
    assert report["score"] == 100
    assert report["evidence_reference"] == "change-approval-2026-08-12"
    assert report["track_a"]["status"] == "evidence_pending"
