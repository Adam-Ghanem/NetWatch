"""Supply-chain regression checks for GitHub Actions workflow references."""

from __future__ import annotations

import re
from pathlib import Path

WORKFLOW_DIR = Path(__file__).resolve().parents[1] / ".github" / "workflows"
ACTION_REFERENCE = re.compile(
    r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+"
    r"(?:/[A-Za-z0-9_.-]+)*@[0-9a-f]{40}$"
)
VERSION_COMMENT = re.compile(r"^v[0-9]+(?:\.[0-9]+(?:\.[0-9]+)?)?$")
USES_LINE = re.compile(r"^\s*uses:\s*(\S+?)(?:\s+#\s*(\S.*))?\s*$")


def test_external_workflow_actions_are_pinned_to_full_commit_shas() -> None:
    workflow_files = list(WORKFLOW_DIR.glob("*.yml"))
    workflow_files.extend(WORKFLOW_DIR.glob("*.yaml"))
    assert workflow_files, "Expected at least one GitHub Actions workflow."

    checked_actions: list[str] = []
    for workflow in sorted(workflow_files):
        lines = workflow.read_text(encoding="utf-8").splitlines()
        for line_number, line in enumerate(lines, 1):
            if not line.lstrip().startswith("uses:"):
                continue

            match = USES_LINE.fullmatch(line)
            location = f"{workflow.name}:{line_number}"
            assert match is not None, f"{location}: unsupported uses syntax."
            reference, version_comment = match.groups()
            if reference.startswith(("./", "docker://")):
                continue

            assert ACTION_REFERENCE.fullmatch(reference), (
                f"{location}: external actions must use a full 40-character commit SHA."
            )
            assert version_comment and VERSION_COMMENT.fullmatch(version_comment), (
                f"{location}: add a version comment such as '# v4'."
            )
            checked_actions.append(reference)

    assert checked_actions, "Expected at least one external workflow action."
