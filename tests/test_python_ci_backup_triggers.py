"""Guard the Python CI trigger contract for stacked backup PRs.

Run: python -m pytest -q tests/test_python_ci_backup_triggers.py
No network, credentials, or additional YAML parser required.
"""

from pathlib import Path


def test_python_ci_covers_stacked_backup_pr_targets():
    workflow = Path(__file__).resolve().parents[1] / ".github/workflows/python-ci.yml"
    content = workflow.read_text(encoding="utf-8")
    trigger_section = content.split("\npermissions:", 1)[0]
    push, pull_request = trigger_section.split("\n  pull_request:", 1)
    assert "branches: [main]" in push
    assert "      - main" in pull_request
    assert "      - 'test/backup-*'" in pull_request
    assert "      - 'feat/backup-*'" in pull_request
