"""Guard against presenting historical restore evidence as a current release gate."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DRILL = ROOT / "docs" / "track-a-restore-drill.md"


def test_historical_restore_schema_is_not_a_default() -> None:
    document = DRILL.read_text(encoding="utf-8")
    assert "**Date:** 2026-08-12" in document
    assert "historical, environment-specific staging result" in document
    assert "`--expected-schema 10` value below records" in document
    assert "checking the actual application/database migration version" in document
    assert "stop and" in document and "investigate" in document


def test_restore_drill_does_not_claim_production_acceptance() -> None:
    document = DRILL.read_text(encoding="utf-8")
    assert "exact application commit" in document
    assert "trusted digest" in document
    assert "measured" in document and "RTO/RPO" in document
    assert "not in public CI logs or pull requests" in document
    warning = "Do not use this result alone to authorize a production release."
    assert warning in document
