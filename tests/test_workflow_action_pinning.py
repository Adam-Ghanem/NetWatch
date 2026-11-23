"""Supply-chain regression checks for GitHub Actions workflow references."""

from __future__ import annotations

import re
from pathlib import Path

WORKFLOW_DIR = Path(__file__).resolve().parents[1] / ".github" / "workflows"
ACTION_REFERENCE = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$"
)
VERSION_COMMENT = re.compile(r"^v[0-9]+(?:\.[0-9]+(?:\.[0-9]+)?)?$")
USES_LINE = re.compile(r"^\s*uses:\s*(\S+?)(?:\s+#\s*(\S.*))?\s*$")
SETUP_NODE_V6 = "actions/setup-node@249970729cb0ef3589644e2896645e5dc5ba9c38 # v6"
CODECOV_ACTION_V6 = "codecov/codecov-action@fb8b3582c8e4def4969c97caa2f19720cb33a72f # v6"
UPLOAD_ARTIFACT_V7 = (
    "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7"
)
DOWNLOAD_ARTIFACT_V8 = (
    "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8"
)


def test_external_workflow_actions_are_pinned_to_full_commit_shas() -> None:
    workflow_files = list(WORKFLOW_DIR.glob("*.yml"))
    workflow_files.extend(WORKFLOW_DIR.glob("*.yaml"))
    if not workflow_files:
        raise AssertionError("Expected at least one GitHub Actions workflow.")

    checked_actions: list[str] = []
    for workflow in sorted(workflow_files):
        lines = workflow.read_text(encoding="utf-8").splitlines()
        for line_number, line in enumerate(lines, 1):
            if not line.lstrip().startswith("uses:"):
                continue

            location = f"{workflow.name}:{line_number}"
            match = USES_LINE.fullmatch(line)
            if match is None:
                raise AssertionError(f"{location}: unsupported uses syntax.")

            reference, version_comment = match.groups()
            if reference.startswith(("./", "docker://")):
                continue
            if not ACTION_REFERENCE.fullmatch(reference):
                raise AssertionError(
                    f"{location}: external actions must use a full 40-character commit SHA."
                )
            if not version_comment or not VERSION_COMMENT.fullmatch(version_comment):
                raise AssertionError(f"{location}: add a version comment such as '# v4'.")
            checked_actions.append(reference)

    if not checked_actions:
        raise AssertionError("Expected at least one external workflow action.")


def test_security_ci_uses_node24_action_without_implicit_package_cache() -> None:
    workflow = (WORKFLOW_DIR / "security-ci.yml").read_text(encoding="utf-8")

    assert f"uses: {SETUP_NODE_V6}" in workflow
    assert 'node-version: "22"' in workflow
    assert "package-manager-cache: false" in workflow


def test_python_ci_uses_reviewed_codecov_v6_with_isolated_oidc() -> None:
    workflow = (WORKFLOW_DIR / "python-ci.yml").read_text(encoding="utf-8")
    assert "\n  coverage:\n" in workflow
    test_job, coverage_job = workflow.split("\n  coverage:\n", maxsplit=1)

    assert "id-token: write" not in test_job
    assert "permissions:\n      contents: read\n      id-token: write" in coverage_job
    assert "needs: test" in coverage_job

    assert f"uses: {UPLOAD_ARTIFACT_V7}" in test_job
    assert "name: python-coverage" in test_job
    assert "path: coverage.xml" in test_job
    assert "if-no-files-found: error" in test_job
    assert "retention-days: 1" in test_job

    assert f"uses: {DOWNLOAD_ARTIFACT_V8}" in coverage_job
    assert "name: python-coverage" in coverage_job
    assert f"uses: {CODECOV_ACTION_V6}" in coverage_job
    assert "use_oidc: true" in coverage_job
    assert "fail_ci_if_error: false" in coverage_job
