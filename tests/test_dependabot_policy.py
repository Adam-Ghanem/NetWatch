from pathlib import Path

POLICY = Path(__file__).resolve().parents[1] / ".github" / "dependabot.yml"


def test_dependabot_covers_pip_and_actions_with_bounded_prs():
    policy = POLICY.read_text(encoding="utf-8")
    assert policy.startswith("version: 2\n")
    assert policy.count("package-ecosystem:") == 2
    assert 'package-ecosystem: "pip"' in policy
    assert 'package-ecosystem: "github-actions"' in policy
    assert policy.count('directory: "/"') == 2
    assert policy.count('interval: "weekly"') == 2
    assert policy.count("open-pull-requests-limit: 3") == 2


def test_dependabot_does_not_auto_merge_or_run_code():
    policy = POLICY.read_text(encoding="utf-8")
    assert "auto-merge" not in policy
    assert "command:" not in policy
    assert "insecure-external-code-execution" not in policy
