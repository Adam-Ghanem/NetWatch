"""Guard Python CI checkout credentials from persistence in the workspace."""

from pathlib import Path


def test_python_ci_checkout_disables_persisted_credentials() -> None:
    path = Path(__file__).resolve().parents[1] / ".github/workflows/python-ci.yml"
    workflow = path.read_text(encoding="utf-8")
    checkout = workflow.split("uses: actions/checkout@v6", 1)[1]
    checkout = checkout.split("\n      - name:", 1)[0]
    assert "persist-credentials: false" in checkout
