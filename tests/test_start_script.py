from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

import scripts.start as launcher


def test_launcher_generates_key_and_defaults(monkeypatch, tmp_path: Path):
    env_file = tmp_path / ".env"
    monkeypatch.setattr(launcher, "ENV_FILE", env_file)

    key = launcher.ensure_configuration()
    values = launcher.read_env()

    assert len(key) >= 32
    assert values["NETWATCH_API_KEY"] == key
    assert values["NETWATCH_OPERATOR_KEY"] == ""
    assert values["NETWATCH_VIEWER_KEY"] == ""
    assert values["NETWATCH_ALLOWED_HOSTS"] == "127.0.0.1,localhost"
    assert values["NETWATCH_ALLOWED_ORIGINS"] == "http://127.0.0.1:8000,http://localhost:8000"
    assert values["NETWATCH_MAX_CONCURRENT_SCANS"] == "1"
    assert values["NETWATCH_SCHEDULER_ENABLED"] == "false"
    assert values["NETWATCH_SCHEDULER_POLL_SECONDS"] == "30"
    assert values["NETWATCH_AI_ENABLED"] == "true"
    assert values["NETWATCH_AI_MODEL"] == "gpt-5.6-luna"
    assert values["NETWATCH_AI_DAILY_REQUEST_LIMIT"] == "50"
    assert len(values["NETWATCH_AI_SAFETY_SECRET"]) >= 32
    assert len(values["NETWATCH_AI_SUBJECT_ID"]) >= 16
    assert values["NETWATCH_AI_SAFETY_SECRET"] != values["NETWATCH_API_KEY"]
    assert env_file.exists()


def test_launcher_preserves_existing_key_and_extra_values(monkeypatch, tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "NETWATCH_API_KEY=existing-secret-with-at-least-32-characters\n"
        "NETWATCH_AI_SAFETY_SECRET=existing-independent-safety-secret-value\n"
        "NETWATCH_AI_SUBJECT_ID=existing_subject_12345\n"
        "CUSTOM_SETTING=keep-me\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(launcher, "ENV_FILE", env_file)

    key = launcher.ensure_configuration()
    values = launcher.read_env()

    assert key == "existing-secret-with-at-least-32-characters"
    assert values["NETWATCH_AI_SAFETY_SECRET"] == "existing-independent-safety-secret-value"
    assert values["NETWATCH_AI_SUBJECT_ID"] == "existing_subject_12345"
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


def test_launcher_replaces_weak_existing_key(monkeypatch, tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text("NETWATCH_API_KEY=too-short\n", encoding="utf-8")
    monkeypatch.setattr(launcher, "ENV_FILE", env_file)

    key = launcher.ensure_configuration()

    assert key != "too-short"
    assert len(key) >= launcher.MIN_API_KEY_LENGTH


def test_launcher_separates_provider_and_safety_credentials(monkeypatch, tmp_path: Path):
    env_file = tmp_path / ".env"
    provider_key = "provider-key-with-at-least-thirty-two-characters"
    env_file.write_text(
        f"NETWATCH_API_KEY=existing-secret-with-at-least-32-characters\n"
        f"OPENAI_API_KEY={provider_key}\n"
        f"NETWATCH_AI_SAFETY_SECRET={provider_key}\n"
        "NETWATCH_AI_SUBJECT_ID=replace-with-an-opaque-random-subject\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(launcher, "ENV_FILE", env_file)

    launcher.ensure_configuration()
    values = launcher.read_env()

    assert values["OPENAI_API_KEY"] == provider_key
    assert values["NETWATCH_AI_SAFETY_SECRET"] != provider_key
    assert len(values["NETWATCH_AI_SAFETY_SECRET"]) >= 32
    assert values["NETWATCH_AI_SUBJECT_ID"] != launcher.AI_SUBJECT_PLACEHOLDER
    assert len(values["NETWATCH_AI_SUBJECT_ID"]) >= 16


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not portable to Windows")
def test_launcher_uses_private_posix_permissions_when_supported(monkeypatch, tmp_path: Path):
    env_file = tmp_path / ".env"
    monkeypatch.setattr(launcher, "ENV_FILE", env_file)

    launcher.ensure_configuration()
    mode = stat.S_IMODE(env_file.stat().st_mode)

    assert mode & 0o077 == 0
