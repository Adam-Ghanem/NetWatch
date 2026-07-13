import config


def test_env_int_applies_lower_and_upper_bounds(monkeypatch):
    monkeypatch.setenv("NETWATCH_TEST_INT", "0")
    assert config._env_int("NETWATCH_TEST_INT", 5, minimum=1, maximum=10) == 1

    monkeypatch.setenv("NETWATCH_TEST_INT", "999")
    assert config._env_int("NETWATCH_TEST_INT", 5, minimum=1, maximum=10) == 10


def test_env_csv_ignores_a_global_wildcard(monkeypatch):
    defaults = ("localhost",)
    monkeypatch.setenv("NETWATCH_TEST_CSV", "*")

    assert config._env_csv("NETWATCH_TEST_CSV", defaults) == defaults
