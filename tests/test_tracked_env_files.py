"""Regression tests for the tracked dotenv file security gate."""

import subprocess
from unittest.mock import patch

from scripts.check_tracked_env_files import is_private_env_path, main


def test_private_env_variants_are_rejected():
    for path in (".env", ".env.local", ".env.production", "config/.env", "nested/.env.staging"):
        assert is_private_env_path(path)


def test_documented_templates_are_allowed():
    for path in (".env.example", "config/.env.production.example", ".env.sample", ".env.template", "README.md"):
        assert not is_private_env_path(path)


def test_git_tracked_paths_are_checked_with_nul_delimiters(capsys):
    output = b".env.example\0nested/.env.production\0other file.txt\0"
    with patch("scripts.check_tracked_env_files.subprocess.run", return_value=subprocess.CompletedProcess([], 0, stdout=output)):
        assert main() == 1
    assert "nested/.env.production" in capsys.readouterr().err


def test_safe_repository_passes():
    with patch("scripts.check_tracked_env_files.subprocess.run", return_value=subprocess.CompletedProcess([], 0, stdout=b".env.example\0README.md\0")):
        assert main() == 0
