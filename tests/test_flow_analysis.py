from flow_analysis import summarize_flows


def test_bidirectional_packets_are_merged_and_directional_stats_preserved():
    records = [
        {
            "captured_at": "2026-08-31T03:00:00+00:00",
            "protocol": "TCP",
            "source_ip": "10.0.0.2",
            "destination_ip": "10.0.0.8",
            "source_port": 53000,
            "destination_port": 443,
            "tcp_flags": "SYN",
            "length_bytes": 60,
        },
        {
            "captured_at": "2026-08-31T03:00:00.020+00:00",
            "protocol": "TCP",
            "source_ip": "10.0.0.8",
            "destination_ip": "10.0.0.2",
            "source_port": 443,
            "destination_port": 53000,
            "tcp_flags": "ACK,SYN",
            "length_bytes": 60,
        },
        {
            "captured_at": "2026-08-31T03:00:00.040+00:00",
            "protocol": "TCP",
            "source_ip": "10.0.0.2",
            "destination_ip": "10.0.0.8",
            "source_port": 53000,
            "destination_port": 443,
            "tcp_flags": "ACK",
            "length_bytes": 52,
        },
    ]

    flows = summarize_flows(records)

    assert len(flows) == 1
    flow = flows[0]
    assert flow["packets"] == 3
    assert flow["bytes"] == 172
    assert {flow["a_to_b_packets"], flow["b_to_a_packets"]} == {1, 2}
    assert flow["duration_ms"] == 40
    assert flow["tcp_state"] == "established"
    assert isinstance(flow["flow_id"], str)
    assert len(flow["flow_id"]) == 16


def test_flow_reports_originator_responder_and_service_hint():
    records = [
        {
            "captured_at": "2026-08-31T03:10:00+00:00",
            "protocol": "TCP",
            "source_ip": "10.0.0.25",
            "destination_ip": "10.0.0.5",
            "source_port": 54000,
            "destination_port": 443,
            "tcp_flags": "SYN",
            "length_bytes": 60,
        },
        {
            "captured_at": "2026-08-31T03:10:00.015+00:00",
            "protocol": "TCP",
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.25",
            "source_port": 443,
            "destination_port": 54000,
            "tcp_flags": "ACK,SYN",
            "length_bytes": 60,
        },
        {
            "captured_at": "2026-08-31T03:10:00.030+00:00",
            "protocol": "TCP",
            "source_ip": "10.0.0.25",
            "destination_ip": "10.0.0.5",
            "source_port": 54000,
            "destination_port": 443,
            "tcp_flags": "ACK",
            "length_bytes": 52,
        },
    ]

    flow = summarize_flows(records)[0]

    assert flow["originator"] == {"ip": "10.0.0.25", "port": 54000}
    assert flow["responder"] == {"ip": "10.0.0.5", "port": 443}
    assert flow["originator_packets"] == 2
    assert flow["originator_bytes"] == 112
    assert flow["responder_packets"] == 1
    assert flow["responder_bytes"] == 60
    assert flow["service"] == "https"


def test_udp_service_hint_uses_destination_well_known_port():
    flow = summarize_flows(
        [
            {
                "protocol": "UDP",
                "source_ip": "192.168.1.20",
                "destination_ip": "192.168.1.1",
                "source_port": 53000,
                "destination_port": 53,
                "length_bytes": 74,
            }
        ]
    )[0]

    assert flow["originator"] == {"ip": "192.168.1.20", "port": 53000}
    assert flow["responder"] == {"ip": "192.168.1.1", "port": 53}
    assert flow["service"] == "dns"


def test_ports_separate_flows_and_rst_wins_state():
    records = [
        {
            "protocol": "TCP",
            "source_ip": "10.0.0.2",
            "destination_ip": "10.0.0.8",
            "source_port": 50000,
            "destination_port": 443,
            "tcp_flags": "ACK",
            "length_bytes": 100,
        },
        {
            "protocol": "TCP",
            "source_ip": "10.0.0.2",
            "destination_ip": "10.0.0.8",
            "source_port": 50001,
            "destination_port": 443,
            "tcp_flags": "RST",
            "length_bytes": 60,
        },
    ]

    flows = summarize_flows(records)

    assert len(flows) == 2
    assert {flow["tcp_state"] for flow in flows} == {"established", "reset"}


def test_limit_is_bounded():
    try:
        summarize_flows([], limit=0)
    except ValueError as exc:
        assert "between 1 and 1000" in str(exc)
    else:
        raise AssertionError("expected validation failure")
