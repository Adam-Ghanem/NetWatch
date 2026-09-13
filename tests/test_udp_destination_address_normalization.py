from __future__ import annotations

import netwatch_udp


def test_ipv6_destination_address_is_canonicalized_without_rewriting_target() -> None:
    expanded = "2001:0db8:0:0:0:0:0:10"

    rows = netwatch_udp._normalized_rows(
        expanded,
        [{"Port": 53, "Service": "DNS", "Status": "Open"}],
        observed_at="2026-09-13T00:00:00.000Z",
        run_id="run-123",
    )

    assert rows[0]["Target"] == expanded
    assert rows[0]["Destination Address"] == "2001:db8::10"
    assert rows[0]["Address Family"] == "IPv6"
