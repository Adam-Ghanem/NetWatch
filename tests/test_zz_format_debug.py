from pathlib import Path

import black


def test_temporary_black_diff():
    import difflib

    target = Path(__file__).resolve().parents[1] / "tests/test_auto_intelligence.py"
    raw = target.read_text(encoding="utf-8")
    formatted = black.format_str(raw, mode=black.Mode(line_length=100))
    assert raw == formatted, "\n".join(
        difflib.unified_diff(
            raw.splitlines(), formatted.splitlines(),
            fromfile="current", tofile="black", lineterm=""
        )
    )
