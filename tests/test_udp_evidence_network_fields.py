from __future__ import annotations

from netwatch_udp import _normalized_rows


def test_normalized_udp_evidence_exposes_destination_and_protocol_fields() -> None:
    rows = [
        {
            "Port": 53,
            "Protocol": "UDP",
            "Service": "DNS",
            "Status": "Open",
            "Service Confidence": "High",
        }
    ]

    normalized = _normalized_rows(
        "fd00::53",
        rows,
        observed_at="2026-09-12T03:00:00.000Z",
        run_id="11111111-1111-4111-8111-111111111111",
    )

    assert normalized[0]["Destination Address"] == "fd00::53"
    assert normalized[0]["Destination Port"] == 53
    assert normalized[0]["Network Transport"] == "udp"
    assert normalized[0]["Network Protocol"] == "dns"
    assert normalized[0]["Address Family"] == "IPv6"
