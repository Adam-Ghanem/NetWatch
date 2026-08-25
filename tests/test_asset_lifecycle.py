from asset_lifecycle import lifecycle_state, lifecycle_summary


def test_lifecycle_states():
    assert lifecycle_state(last_seen=None, now=100) == "new"
    assert lifecycle_state(last_seen=99, now=100) == "active"
    assert lifecycle_state(last_seen=0, now=86400) == "stale"
    assert lifecycle_state(last_seen=0, now=604800) == "retired"


def test_lifecycle_summary():
    result = lifecycle_summary([
        {"last_seen": 99},
        {"last_seen": 0},
        {},
    ], now=100)
    assert result == {"new": 1, "active": 1, "stale": 1, "retired": 0}
