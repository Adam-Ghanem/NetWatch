import os
import subprocess
import sys
from pathlib import Path

import pytest

import config


def test_env_int_applies_lower_and_upper_bounds(monkeypatch):
    monkeypatch.setenv("NETWATCH_TEST_INT", "0")
    assert config._env_int("NETWATCH_TEST_INT", 5, minimum=1, maximum=10) == 1

    monkeypatch.setenv("NETWATCH_TEST_INT", "999")
    assert config._env_int("NETWATCH_TEST_INT", 5, minimum=1, maximum=10) == 10


def test_env_nonnegative_int_fail_closed_uses_default_and_accepts_zero(monkeypatch):
    name = "NETWATCH_TEST_BUDGET"
    monkeypatch.delenv(name, raising=False)
    assert config._env_nonnegative_int_fail_closed(name, 50, maximum=10_000) == 50

    monkeypatch.setenv(name, "0")
    assert config._env_nonnegative_int_fail_closed(name, 50, maximum=10_000) == 0

    monkeypatch.setenv(name, "250")
    assert config._env_nonnegative_int_fail_closed(name, 50, maximum=10_000) == 250


def test_env_nonnegative_int_fail_closed_handles_long_decimal_values(monkeypatch):
    name = "NETWATCH_TEST_BUDGET"
    monkeypatch.setenv(name, "9" * 5_000)
    assert config._env_nonnegative_int_fail_closed(name, 50, maximum=10_000) == 0

    monkeypatch.setenv(name, "0" * 5_000 + "1")
    assert config._env_nonnegative_int_fail_closed(name, 50, maximum=10_000) == 1


@pytest.mark.parametrize("raw", ["", "invalid", "-1", "10001", "1.5", "１２"])
def test_env_nonnegative_int_fail_closed_disables_invalid_budgets(monkeypatch, raw):
    name = "NETWATCH_TEST_BUDGET"
    monkeypatch.setenv(name, raw)
    assert config._env_nonnegative_int_fail_closed(name, 50, maximum=10_000) == 0


@pytest.mark.parametrize("raw", ["invalid", "0", "10001", "9" * 5_000])
def test_invalid_or_zero_ai_daily_budget_disables_ai_in_fresh_process(raw):
    env = os.environ.copy()
    env["NETWATCH_AI_ENABLED"] = "true"
    env["NETWATCH_AI_DAILY_REQUEST_LIMIT"] = raw
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import config; print(config.AI_DAILY_REQUEST_LIMIT, config.AI_ENABLED)",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env=env,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )

    assert completed.stdout.strip() == "0 False"


def test_compose_preserves_explicit_empty_daily_ai_budget():
    compose_path = Path(__file__).resolve().parents[1] / "docker-compose.yml"
    compose = compose_path.read_text(encoding="utf-8")
    budget_line = ""
    for line in compose.splitlines():
        if "NETWATCH_AI_DAILY_REQUEST_LIMIT:" in line:
            budget_line = line
            break

    assert budget_line
    assert "${NETWATCH_AI_DAILY_REQUEST_LIMIT-50}" in budget_line
    assert ":-" not in budget_line


def test_env_csv_ignores_a_global_wildcard(monkeypatch):
    defaults = ("localhost",)
    monkeypatch.setenv("NETWATCH_TEST_CSV", "*")

    assert config._env_csv("NETWATCH_TEST_CSV", defaults) == defaults


def test_env_bool_accepts_known_values_and_fails_closed(monkeypatch):
    monkeypatch.setenv("NETWATCH_TEST_BOOL", "yes")
    assert config._env_bool("NETWATCH_TEST_BOOL") is True

    monkeypatch.setenv("NETWATCH_TEST_BOOL", "off")
    assert config._env_bool("NETWATCH_TEST_BOOL", True) is False

    monkeypatch.setenv("NETWATCH_TEST_BOOL", "unexpected")
    assert config._env_bool("NETWATCH_TEST_BOOL", True) is False
