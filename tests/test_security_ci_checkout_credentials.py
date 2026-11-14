"""Regression guard for Security CI checkout credential isolation."""

from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/security-ci.yml"


def test_security_ci_checkout_does_not_persist_git_credentials() -> None:
    """The checkout step must explicitly disable persisted Git credentials."""
    workflow = WORKFLOW.read_text(encoding="utf-8")
    checkout = workflow.split("uses: actions/checkout@v6", maxsplit=1)
    assert len(checkout) == 2
    step = checkout[1].split("\n      - ", maxsplit=1)[0]
    assert "persist-credentials: false" in step
