import uuid

import netwatch_udp


def test_udp_service_key_is_stable_across_runs_and_protected() -> None:
    rows = [
        {
            "Service": "DNS",
            "Port": 53,
            "Status": "Open",
            "Service Key": "spoofed",
        }
    ]

    first = netwatch_udp._normalized_rows(
        "192.168.1.10",
        rows,
        observed_at="2026-09-12T20:00:00.000Z",
        run_id="run-one",
    )
    second = netwatch_udp._normalized_rows(
        "192.168.1.10",
        rows,
        observed_at="2026-09-12T20:05:00.000Z",
        run_id="run-two",
    )

    assert first[0]["Service Key"] == second[0]["Service Key"]
    assert first[0]["Service Key"] != "spoofed"
    assert first[0]["Evidence ID"] != second[0]["Evidence ID"]
    assert uuid.UUID(str(first[0]["Service Key"])).version == 5


def test_udp_service_key_distinguishes_endpoints_and_canonicalizes_ipv6() -> None:
    dns = netwatch_udp._normalized_rows(
        "2001:0db8:0:0:0:0:0:10",
        [{"Service": "DNS", "Port": 53, "Status": "Open"}],
        run_id="run-one",
    )[0]
    same_dns = netwatch_udp._normalized_rows(
        "2001:db8::10",
        [{"Service": "DNS", "Port": 53, "Status": "Open"}],
        run_id="run-two",
    )[0]
    ntp = netwatch_udp._normalized_rows(
        "2001:db8::10",
        [{"Service": "NTP", "Port": 123, "Status": "Open"}],
        run_id="run-three",
    )[0]
    other_host = netwatch_udp._normalized_rows(
        "2001:db8::11",
        [{"Service": "DNS", "Port": 53, "Status": "Open"}],
        run_id="run-four",
    )[0]

    assert dns["Service Key"] == same_dns["Service Key"]
    assert dns["Service Key"] != ntp["Service Key"]
    assert dns["Service Key"] != other_host["Service Key"]
