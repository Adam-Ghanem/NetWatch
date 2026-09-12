from __future__ import annotations

import netwatch_udp


def test_normalized_udp_evidence_has_explicit_event_type() -> None:
    rows = netwatch_udp._normalized_rows(
        "192.168.1.10",
        [
            {
                "Status": "Open",
                "Port": 53,
                "Protocol": "UDP",
                "Service": "DNS",
            }
        ],
        observed_at="2026-09-12T00:00:00.000Z",
        run_id="11111111-1111-1111-1111-111111111111",
    )

    assert rows[0]["Event Type"] == "udp_service_evidence"
