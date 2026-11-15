"""Reject unknown timezone offsets in every operator evidence field."""

from __future__ import annotations

import pytest

from scripts.measure_restore_drill import measure


@pytest.mark.parametrize("field", ["last_durable", "failure", "ready"])
def test_unknown_offset_fails_closed_for_every_evidence_field(field):
    evidence = {
        "last_durable": "2026-11-15T09:00:00Z",
        "failure": "2026-11-15T09:03:00Z",
        "ready": "2026-11-15T09:05:00Z",
    }
    evidence[field] = evidence[field].replace("Z", "-00:00")

    with pytest.raises(ValueError, match="timezone offset must be known"):
        measure(**evidence)


@pytest.mark.parametrize("field", ["last_durable", "failure", "ready"])
def test_known_zero_offset_is_allowed_for_every_evidence_field(field):
    evidence = {
        "last_durable": "2026-11-15T09:00:00Z",
        "failure": "2026-11-15T09:03:00Z",
        "ready": "2026-11-15T09:05:00Z",
    }
    evidence[field] = evidence[field].replace("Z", "+00:00")

    report = measure(**evidence)
    assert report["observed_rpo_seconds"] == 180.0
    assert report["observed_rto_seconds"] == 120.0
