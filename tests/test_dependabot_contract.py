"""Regression contract for bounded dependency-update coverage."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_dependabot_tracks_python_and_actions_without_automatic_merges() -> None:
    config = (ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
    assert config.startswith("version: 2\n")
    assert config.count("package-ecosystem:") == 2
    assert 'package-ecosystem: "pip"' in config
    assert 'package-ecosystem: "github-actions"' in config
    assert config.count('directory: "/"') == 2
    assert config.count('interval: "weekly"') == 2
    assert config.count("open-pull-requests-limit: 5") == 2
    assert config.count('          - "minor"') == 2
    assert config.count('          - "patch"') == 2
    assert "auto-merge" not in config
