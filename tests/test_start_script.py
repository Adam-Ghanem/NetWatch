from __future__ import annotations

import stat
from pathlib import Path

import scripts.start as launcher


def test_launcher_generates_key_and_defaults(monkeypatch, tmp_path: Path):
    env_file = tmp_path / ".env"
    monkeypatch.setattr(launcher, "ENV_FILE", env_file)

    key = launcher.ensure_configuration()
    values = launcher.read_env()

    assert len(key) >= 32
    assert values["NETWATCH_API_KEY"] == key
    assert values["NETWATCH_ALLOWED_ORIGINS"] == "http://127.0.0.1:8000,http://localhost:8000"
    assert values["NETWATCH_MAX_CONCURRENT_SCANS"] == "1"
    assert env_file.exists()


def test_launcher_preserves_existing_key_and_extra_values(monkeypatch, tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "NETWATCH_API_KEY=existing-secret\nCUSTOM_SETTING=keep-me\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(launcher, "ENV_FILE", env_file)

    key = launcher.ensure_configuration()
    values = launcher.read_env()

    assert key == "existing-secret"
    assert values["CUSTOM_SETTING"] == "keep-me"


def test_launcher_replaces_placeholder_key(monkeypatch, tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "NETWATCH_API_KEY=replace-with-a-long-random-secret\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(launcher, "ENV_FILE", env_file)

    key = launcher.ensure_configuration()

    assert key != "replace-with-a-long-random-secret"
    assert len(key) >= 32


def test_launcher_uses_private_posix_permissions_when_supported(monkeypatch, tmp_path: Path):
    env_file = tmp_path / ".env"
    monkeypatch.setattr(launcher, "ENV_FILE", env_file)

    launcher.ensure_configuration()
    mode = stat.S_IMODE(env_file.stat().st_mode)

    assert mode & 0o077 == 0
