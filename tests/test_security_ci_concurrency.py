"""Guard Security CI cancellation policy and main push validation."""

from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "security-ci.yml"


def test_security_ci_cancels_only_superseded_pr_runs() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert (
        "concurrency:\n  group: security-ci-${{ github.workflow }}-"
        "${{ github.event.pull_request.number || github.ref }}"
    ) in workflow
    assert "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in workflow


def test_security_ci_keeps_main_and_pr_triggers_and_read_only_permissions() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "  push:\n    branches: [main]" in workflow
    assert "  pull_request:" in workflow
    assert "permissions:\n  contents: read" in workflow
    assert "    timeout-minutes: 15" in workflow
