"""Regression contract for bounded dependency-update coverage."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_dependabot_tracks_python_and_actions_without_automatic_merges() -> None:
    config_path = ROOT / ".github" / "dependabot.yml"
    config_text = config_path.read_text(encoding="utf-8")
    config = yaml.safe_load(config_text)

    assert config["version"] == 2
    updates = config["updates"]
    assert len(updates) == 2
    assert {entry["package-ecosystem"] for entry in updates} == {
        "pip",
        "github-actions",
    }
    for entry in updates:
        assert entry["directory"] == "/"
        assert entry["schedule"]["interval"] == "weekly"
        assert entry["open-pull-requests-limit"] == 5
        groups = entry["groups"]
        assert len(groups) == 1
        group = next(iter(groups.values()))
        assert group["update-types"] == ["minor", "patch"]
    assert "auto-merge" not in config_text
