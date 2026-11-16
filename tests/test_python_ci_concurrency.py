"""Guard PR-only cancellation of superseded Python CI workflow runs."""

from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github" / "workflows" / "python-ci.yml"


def test_python_ci_concurrency_is_scoped_to_pr_or_ref() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "concurrency:\n  group: python-ci-${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}" in workflow
    assert "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in workflow


def test_python_ci_still_runs_on_main_and_pull_requests() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "  push:\n    branches: [main]" in workflow
    assert "  pull_request:\n    branches: [main]" in workflow
    assert "  contents: read" in workflow
    assert "  id-token: write" in workflow
