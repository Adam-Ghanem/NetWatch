from __future__ import annotations

import netwatch_udp


def test_udp_evidence_id_canonicalizes_equivalent_ipv6_targets_within_run() -> None:
    row = [{"Service": "DNS", "Port": 53, "Status": "Open"}]

    expanded = netwatch_udp._normalized_rows(
        "2001:0db8:0:0:0:0:0:10",
        row,
        run_id="run-one",
        observed_at="2026-09-13T00:00:00.000Z",
    )[0]
    compressed = netwatch_udp._normalized_rows(
        "2001:db8::10",
        row,
        run_id="run-one",
        observed_at="2026-09-13T00:00:01.000Z",
    )[0]
    other_run = netwatch_udp._normalized_rows(
        "2001:db8::10",
        row,
        run_id="run-two",
        observed_at="2026-09-13T00:00:02.000Z",
    )[0]

    assert expanded["Evidence ID"] == compressed["Evidence ID"]
    assert expanded["Evidence ID"] != other_run["Evidence ID"]
