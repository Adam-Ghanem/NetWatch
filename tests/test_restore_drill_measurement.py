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


@pytest.mark.parametrize(
    "value",
    ["0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00"],
)
def test_rejects_utc_normalization_overflow(value):
    with pytest.raises(ValueError, match="supported UTC range"):
        parse_timestamp(value)


@pytest.mark.parametrize(
    "value",
    [
        "2026-11-15X09:00:00Z",
        "2026-W46-7T09:00:00Z",
        "2026-11-15 09:00:00+00:00",
        "2026-11-15T09:00Z",
        "2026-11-15T09:00:00+00:00:30",
        "2026-11-15T09:00:00.1234567Z",
        "2026-11-15T09:00:00Z" + " " * 10000,
    ],
)
def test_rejects_ambiguous_or_unbounded_timestamp_formats(value):
    with pytest.raises(ValueError, match="timestamp"):
        parse_timestamp(value)


def test_accepts_fractional_seconds_and_explicit_offset():
    result = measure(
        "2026-11-15T10:00:00.125+01:00",
        "2026-11-15T09:00:01.125Z",
        "2026-11-15T09:00:03.625+00:00",
    )
    assert result["observed_rpo_seconds"] == 1.0
    assert result["observed_rto_seconds"] == 2.5


def test_rejects_unknown_local_offset_rfc3339():
    with pytest.raises(ValueError, match="offset must be known"):
        parse_timestamp("2026-11-15T09:00:00-00:00")
