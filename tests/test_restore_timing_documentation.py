"""Keep operator-facing restore timing instructions readable and complete."""

from pathlib import Path


def test_restore_timing_documentation_has_real_line_breaks():
    document = (
        Path(__file__).resolve().parents[1]
        / "docs"
        / "restore-drill-timing-evidence.md"
    ).read_text(encoding="utf-8")
    assert "\\n" not in document
    assert "unknown `-00:00` offsets" in document
    assert "Invalid inputs return CLI exit code 2" in document
    assert "not guaranteed" in document
