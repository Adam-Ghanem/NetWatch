"""Guard OIDC separation between untrusted test execution and coverage upload."""

from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/python-ci.yml"


def test_python_ci_keeps_oidc_out_of_test_job() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    test_job, coverage_job = workflow.split("\n  coverage:\n", maxsplit=1)
    assert "id-token: write" not in test_job
    assert "permissions:\n  contents: read" in test_job
    assert "needs: test" in coverage_job
    assert "permissions:\n      contents: read\n      id-token: write" in coverage_job


def test_coverage_transfer_requires_real_artifact() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    test_job, coverage_job = workflow.split("\n  coverage:\n", maxsplit=1)
    assert "uses: actions/upload-artifact@v4" in test_job
    assert "if-no-files-found: error" in test_job
    assert "name: python-coverage" in test_job
    assert "uses: actions/download-artifact@v4" in coverage_job
    assert "name: python-coverage" in coverage_job
    assert "uses: codecov/codecov-action@v5" in coverage_job
