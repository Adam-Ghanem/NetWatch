import pytest

from change_window import changes_in_window


def test_window_is_inclusive_and_preserves_event_data():
    events = [{"timestamp": 10, "kind": "open"}, {"timestamp": 20, "kind": "close"}, {"timestamp": 30}]
    assert changes_in_window(events, start=10, end=20) == events[:2]


def test_invalid_window_is_rejected():
    with pytest.raises(ValueError):
        changes_in_window([], start=20, end=10)
