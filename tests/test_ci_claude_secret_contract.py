"""Regression contract for tracked Claude credential detection in Security CI."""

import re
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/security-ci.yml"


def test_security_ci_rejects_secret_like_claude_keys() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    pattern = r"sk-ant-[A-Za-z0-9_-]{20,}"
    assert f"git grep -I -q -E '{pattern}'" in workflow
    assert "exit 1" in workflow.split(pattern, 1)[1].split("fi", 1)[0]

    synthetic_key = "sk-" + "ant-" + ("a" * 24)
    assert re.search(pattern, synthetic_key)
    assert re.search(pattern, "prefix " + synthetic_key + " suffix")
    assert re.search(pattern, "sk-ant-short") is None
    assert re.search(pattern, "ordinary-placeholder") is None
