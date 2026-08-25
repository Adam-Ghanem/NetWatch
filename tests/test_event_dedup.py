from event_dedup import deduplicate_events, event_fingerprint


def test_timestamp_does_not_change_event_identity():
    a = {"asset": "a1", "kind": "new_port", "port": 443, "timestamp": 10}
    b = {"asset": "a1", "kind": "new_port", "port": 443, "timestamp": 20}
    assert event_fingerprint(a) == event_fingerprint(b)


def test_duplicate_events_are_removed():
    events = [
        {"asset": "a1", "kind": "new_port", "port": 443, "timestamp": 1},
        {"asset": "a1", "kind": "new_port", "port": 443, "timestamp": 2},
        {"asset": "a1", "kind": "new_service", "service": "https", "timestamp": 3},
    ]
    assert len(deduplicate_events(events)) == 2
