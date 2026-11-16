"""Guard deployment recovery guidance against stale schema-version claims."""

from pathlib import Path


def test_deployment_guide_requires_snapshot_schema_validation():
    guide = (Path(__file__).resolve().parents[1] / "docs" / "deployment.md").read_text(
        encoding="utf-8"
    )
    section = guide.split("## Persistent data", 1)[1].split(
        "## Safe operating procedure", 1
    )[0]
    assert "actual schema version" in section
    assert "--expected-schema" in section
    assert "A mismatch must be investigated rather than bypassed." in section
    assert "advances the SQLite schema to version 9" not in section
