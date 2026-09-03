from __future__ import annotations

import pytest

from flow_display_filter import FlowDisplayFilterError, compile_flow_filter, filter_flows


def _flow(
    flow_id: str,
    source: str,
    destination: str,
    *,
    protocol: str = "TCP",
    service: str = "https",
    state: str = "established",
    packets: int = 4,
    bytes_total: int = 400,
) -> dict[str, object]:
    return {
        "flow_id": flow_id,
        "originator": {"ip": source, "port": 50_000},
        "responder": {"ip": destination, "port": 443},
        "protocol": protocol,
        "service": service,
        "tcp_state": state,
        "packets": packets,
        "bytes": bytes_total,
        "duration_ms": 250,
    }


def test_filters_compound_metadata_expression() -> None:
    flows = [
        _flow("f1", "10.0.0.10", "1.1.1.1", bytes_total=2_500),
        _flow(
            "f2",
            "10.0.0.20",
            "1.1.1.1",
            service="dns",
            protocol="UDP",
            bytes_total=180,
        ),
        _flow("f3", "10.0.0.10", "8.8.8.8", service="http", bytes_total=900),
    ]

    result = filter_flows(
        flows,
        "ip == 10.0.0.10 and protocol == tcp and bytes >= 1000",
        limit=100,
    )

    assert [item["flow_id"] for item in result] == ["f1"]


def test_supports_or_not_and_parentheses() -> None:
    flows = [
        _flow("f1", "10.0.0.10", "1.1.1.1", service="https"),
        _flow(
            "f2",
            "10.0.0.20",
            "1.1.1.1",
            service="dns",
            protocol="UDP",
        ),
        _flow("f3", "10.0.0.30", "8.8.8.8", service="ssh"),
    ]

    result = filter_flows(
        flows,
        "(service == dns or service == https) and not ip == 10.0.0.20",
    )

    assert [item["flow_id"] for item in result] == ["f1"]


def test_numeric_fields_support_ordered_comparisons() -> None:
    flows = [
        _flow("small", "10.0.0.10", "1.1.1.1", packets=2, bytes_total=80),
        _flow(
            "large",
            "10.0.0.20",
            "1.1.1.1",
            packets=40,
            bytes_total=8_000,
        ),
    ]

    result = filter_flows(flows, "packets > 10 and bytes <= 10000")

    assert [item["flow_id"] for item in result] == ["large"]


def test_wireshark_style_endpoint_and_transport_aliases_are_directional() -> None:
    tcp = _flow("tcp", "10.0.0.10", "1.1.1.1")
    udp = _flow("udp", "10.0.0.20", "8.8.8.8", protocol="UDP", service="dns")
    udp["responder"] = {"ip": "8.8.8.8", "port": 53}

    source_match = filter_flows([tcp, udp], "ip.src == 10.0.0.10 and tcp.dstport == 443")
    destination_match = filter_flows([tcp, udp], "ip.dst == 8.8.8.8 and udp.port == 53")

    assert [item["flow_id"] for item in source_match] == ["tcp"]
    assert [item["flow_id"] for item in destination_match] == ["udp"]


def test_zeek_style_connection_aliases_map_to_flow_identity_and_roles() -> None:
    flows = [
        _flow("f1", "10.0.0.10", "1.1.1.1"),
        _flow("f2", "10.0.0.20", "8.8.8.8", protocol="UDP", service="dns"),
    ]

    result = filter_flows(
        flows,
        "id.orig_h == 10.0.0.20 and id.resp_h == 8.8.8.8 and "
        "id.orig_p == 50000 and proto == udp and uid == f2",
    )

    assert [item["flow_id"] for item in result] == ["f2"]


def test_transport_aliases_do_not_match_the_wrong_protocol() -> None:
    udp = _flow("udp", "10.0.0.20", "8.8.8.8", protocol="UDP", service="dns")
    udp["responder"] = {"ip": "8.8.8.8", "port": 443}

    assert filter_flows([udp], "tcp.port == 443") == []


def test_filter_compiler_is_bounded_and_rejects_unknown_fields() -> None:
    with pytest.raises(FlowDisplayFilterError, match="Unsupported field"):
        compile_flow_filter("payload == secret")

    with pytest.raises(FlowDisplayFilterError, match="too long"):
        compile_flow_filter("service == https " * 300)

    with pytest.raises(ValueError, match="between 1 and 1000"):
        filter_flows([], "protocol == tcp", limit=1001)


def test_filter_never_adds_or_exposes_payload_data() -> None:
    flow = _flow("f1", "10.0.0.10", "1.1.1.1")
    flow["payload"] = "secret"

    result = filter_flows([flow], "service == https")

    assert len(result) == 1
    assert "payload" not in result[0]
