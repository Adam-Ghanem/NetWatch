"""Regression contract for secrets excluded from Docker build context.

Docker's pattern matcher is not emulated here; these assertions pin the
security-sensitive ignore rules and their ordering.
"""

from pathlib import Path


def test_docker_context_excludes_environment_variants():
    lines = Path(".dockerignore").read_text(encoding="utf-8").splitlines()
    rules = [
        line.strip() for line in lines if line.strip() and not line.startswith("#")
    ]
    for rule in (".env", ".env*", "**/.env", "**/.env*"):
        assert rule in rules, f"Missing Docker build-context exclusion: {rule}"

    # The sole environment-file exception is the public configuration example.
    exceptions = [rule for rule in rules if rule.startswith("!")]
    assert exceptions == ["!.env.example"]
    assert rules.index("!.env.example") > rules.index("**/.env*")


def test_docker_context_keeps_existing_secret_exclusions():
    rules = Path(".dockerignore").read_text(encoding="utf-8").splitlines()
    assert ".streamlit/secrets.toml" in rules
    assert ".git" in rules
