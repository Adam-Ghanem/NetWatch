"""Regression guard for Security CI checkout credential isolation."""

import re
from pathlib import Path


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/security-ci.yml"


def test_security_ci_checkout_does_not_persist_git_credentials() -> None:
    """Untrusted tests and build steps must not inherit checkout's Git token."""
    workflow = WORKFLOW.read_text(encoding="utf-8")
    match = re.search(
        r"(?m)^      - name: Check out repository\n"
        r"        uses: actions/checkout@v6\n"
        r"        with:\n"
        r"          persist-credentials: false\s*$",
        workflow,
    )
    assert match is not None, "Security CI checkout must disable persisted credentials"
