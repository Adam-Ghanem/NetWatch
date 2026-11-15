from __future__ import annotations

import pytest

from scripts.measure_restore_drill import measure, parse_timestamp


def test_measurement_uses_actual_elapsed_seconds_and_normalizes_offsets():
    result = measure(
        "2026-11-15T10:00:00+01:00",
        "2026-11-15T09:03:00Z",
        "2026-11-15T09:05:30+00:00",
    )
    assert result["observed_rpo_seconds"] == 180.0
    assert result["observed_rto_seconds"] == 150.0
    assert result["last_durable_at"] == "2026-11-15T09:00:00+00:00"
    assert "not production SLA" in str(result["scope"])


@pytest.mark.parametrize(
    "value",
    ["2026-11-15T09:00:00", "not-a-time", "2026-13-15T09:00:00Z"],
)
def test_rejects_naive_or_invalid_timestamps(value):
    with pytest.raises(ValueError, match="timestamp"):
        parse_timestamp(value)


def test_rejects_inconsistent_evidence_order():
    with pytest.raises(ValueError, match="durable"):
        measure(
            "2026-11-15T09:04:00Z",
            "2026-11-15T09:03:00Z",
            "2026-11-15T09:05:00Z",
        )
    with pytest.raises(ValueError, match="readiness"):
        measure(
            "2026-11-15T09:00:00Z",
            "2026-11-15T09:03:00Z",
            "2026-11-15T09:02:00Z",
        )
