"""Regression contract for Git's actual dotenv ignore matching."""

import subprocess
from pathlib import Path

import pytest


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
    assert result.returncode in (0, 1), result.stderr.decode(errors="replace")
    return result.returncode == 0


@pytest.mark.parametrize(
    "path",
    [
        ".env",
        ".env.local",
        ".env.production",
        "config/.env",
        "config/.env.staging",
        "config/deep/.env.production",
    ],
)
def test_private_dotenv_files_are_ignored(path: str) -> None:
    assert _ignored(path)


@pytest.mark.parametrize(
    "path",
    [
        ".env.example",
        ".env.sample",
        ".env.template",
        "config/.env.example",
        "config/.env.production.example",
        "config/deep/.env.staging.sample",
        "config/.env.production.template",
    ],
)
def test_public_dotenv_templates_are_versionable(path: str) -> None:
    assert not _ignored(path)
