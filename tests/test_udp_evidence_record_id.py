import uuid

import netwatch_udp


def test_udp_evidence_ids_are_stable_unique_and_authoritative() -> None:
    rows = [
        {
            "Service": "DNS",
            "Port": 53,
            "Status": "Open",
            "Evidence ID": "spoofed",
        },
        {
            "Service": "NTP",
            "Port": 123,
            "Status": "Open|Filtered",
        },
    ]

    first = netwatch_udp._normalized_rows(
        "192.168.1.10",
        rows,
        observed_at="2026-09-12T17:00:00.000Z",
        run_id="run-123",
    )
    second = netwatch_udp._normalized_rows(
        "192.168.1.10",
        rows,
        observed_at="2026-09-12T17:00:01.000Z",
        run_id="run-123",
    )

    assert first[0]["Evidence ID"] == second[0]["Evidence ID"]
    assert first[1]["Evidence ID"] == second[1]["Evidence ID"]
    assert first[0]["Evidence ID"] != first[1]["Evidence ID"]
    assert first[0]["Evidence ID"] != "spoofed"
    uuid.UUID(str(first[0]["Evidence ID"]), version=5)
    uuid.UUID(str(first[1]["Evidence ID"]), version=5)
