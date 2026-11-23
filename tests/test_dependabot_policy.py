import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / ".github" / "dependabot.yml"
DOCKERFILES = (ROOT / "Dockerfile", ROOT / "Dockerfile.enterprise")


def test_dependabot_covers_pip_actions_and_docker_with_bounded_prs():
    policy = POLICY.read_text(encoding="utf-8")
    assert policy.startswith("version: 2\n")
    assert policy.count("package-ecosystem:") == 3
    assert 'package-ecosystem: "pip"' in policy
    assert 'package-ecosystem: "github-actions"' in policy
    assert 'package-ecosystem: "docker"' in policy
    assert policy.count('directory: "/"') == 3
    assert policy.count('interval: "weekly"') == 3
    assert policy.count("open-pull-requests-limit: 3") == 3


def test_dockerfiles_pin_the_same_patch_level_multi_platform_python_image():
    references = []
    for path in DOCKERFILES:
        lines = [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip().startswith("FROM ")
        ]
        assert len(lines) == 1
        match = re.fullmatch(
            r"FROM (python:3\.12\.\d+-slim-trixie)@(sha256:[0-9a-f]{64})",
            lines[0],
        )
        assert match, f"{path.name} must pin a patch-level Python tag and SHA-256 digest"
        references.append(match.groups())
    assert references[0] == references[1]


def test_dependabot_does_not_auto_merge_or_run_code():
    policy = POLICY.read_text(encoding="utf-8")
    assert "auto-merge" not in policy
    assert "command:" not in policy
    assert "insecure-external-code-execution" not in policy
