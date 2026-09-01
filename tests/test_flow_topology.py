from __future__ import annotations

import pytest

from flow_topology import TopologyLimits, build_flow_topology


FLOWS = [
    {
        "flow_id": "flow-https",
        "originator": {"ip": "192.168.1.10", "port": 51000},
        "responder": {"ip": "192.168.1.1", "port": 443},
        "protocol": "tcp",
        "service": "https",
        "packets": 8,
        "bytes": 1200,
        "originator_packets": 5,
        "originator_bytes": 700,
        "responder_packets": 3,
        "responder_bytes": 500,
        "payload": "must-never-leak",
    },
    {
        "flow_id": "flow-dns",
        "originator": {"ip": "192.168.1.10", "port": 53000},
        "responder": {"ip": "2001:4860:4860::8888", "port": 53},
        "protocol": "udp",
        "service": "dns",
        "packets": 2,
        "bytes": 180,
        "originator_packets": 1,
        "originator_bytes": 70,
        "responder_packets": 1,
        "responder_bytes": 110,
        "raw": "must-never-leak",
    },
]


def test_build_flow_topology_aggregates_directional_nodes_edges_and_device_evidence():
    result = build_flow_topology(
        FLOWS,
        devices=[
            {
                "ip_address": "192.168.1.10",
                "device_name": "analyst-laptop",
                "device_type": "workstation",
                "manufacturer": "Example Vendor",
                "identity_confidence": "high",
                "identity_source": "arp+oui",
            }
        ],
    )

    assert result["payload_retained"] is False
    assert result["node_count"] == 3
    assert result["edge_count"] == 2

    laptop = next(
        node for node in result["nodes"] if node["ip_address"] == "192.168.1.10"
    )
    assert laptop["sent_bytes"] == 770
    assert laptop["received_bytes"] == 610
    assert laptop["conversation_count"] == 2
    assert laptop["services"] == ["dns", "https"]
    assert laptop["device"] == {
        "name": "analyst-laptop",
        "type": "workstation",
        "manufacturer": "Example Vendor",
        "confidence": "high",
        "source": "arp+oui",
    }

    ipv6 = next(
        node
        for node in result["nodes"]
        if node["ip_address"] == "2001:4860:4860::8888"
    )
    assert ipv6["ip_version"] == 6
    assert ipv6["is_private"] is False

    https_edge = next(
        edge for edge in result["edges"] if edge["services"] == ["https"]
    )
    assert https_edge["source"] == "192.168.1.10"
    assert https_edge["target"] == "192.168.1.1"
    assert https_edge["bytes"] == 1200
    assert https_edge["flow_ids"] == ["flow-https"]
    assert "payload" not in str(result).lower()
    assert "must-never-leak" not in str(result)


def test_flow_topology_enforces_deterministic_resource_bounds():
    limited = build_flow_topology(
        FLOWS,
        limits=TopologyLimits(
            max_flows=1,
            max_nodes=2,
            max_edges=1,
            max_flow_ids_per_edge=1,
        ),
    )

    assert limited["processed_flow_count"] == 1
    assert limited["input_flow_count"] == 2
    assert limited["truncated"] is True
    assert limited["node_count"] <= 2
    assert limited["edge_count"] <= 1

    with pytest.raises(ValueError, match="max_flows"):
        build_flow_topology(FLOWS, limits=TopologyLimits(max_flows=0))
    with pytest.raises(ValueError, match="max_nodes"):
        build_flow_topology(FLOWS, limits=TopologyLimits(max_nodes=1001))
