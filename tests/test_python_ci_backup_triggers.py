"""Guard the Python CI trigger contract for stacked backup PRs.

Run: python -m pytest -q tests/test_python_ci_backup_triggers.py
No network or credentials required.
"""

from pathlib import Path

import yaml


def test_python_ci_covers_stacked_backup_pr_targets():
    workflow = Path(__file__).resolve().parents[1] / ".github/workflows/python-ci.yml"
    config = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    # PyYAML may parse the unquoted YAML 1.1 "on" key as boolean True.
    events = config.get("on", config.get(True, {}))
    branches = events["pull_request"]["branches"]
    assert "main" in branches
    assert "test/backup-*" in branches
    assert "feat/backup-*" in branches
    assert events["push"]["branches"] == ["main"]
