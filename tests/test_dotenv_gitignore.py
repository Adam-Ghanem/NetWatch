"""Regression contract for Git's actual dotenv ignore matching."""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _ignored(path: str) -> bool:
    result = subprocess.run(
        [
            "git",
            "-c",
            "core.excludesFile=/dev/null",
            "check-ignore",
            "--no-index",
            "--quiet",
            path,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    assert result.returncode in (0, 1)
    return result.returncode == 0


def test_private_dotenv_files_are_ignored() -> None:
    private_paths = (
        ".env",
        ".env.local",
        ".env.production",
        "config/.env",
        "config/.env.staging",
        "config/deep/.env.production",
    )
    for path in private_paths:
        assert _ignored(path), path


def test_public_dotenv_templates_are_versionable() -> None:
    public_paths = (
        ".env.example",
        ".env.sample",
        ".env.template",
        "config/.env.example",
        "config/.env.production.example",
        "config/deep/.env.staging.sample",
        "config/.env.production.template",
    )
    for path in public_paths:
        assert not _ignored(path), path
