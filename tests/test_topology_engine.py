from topology_engine import build_topology, topology_changes


def test_build_topology_uses_explicit_gateway_evidence():
    graph = build_topology(
        [
            {"ip_address": "192.168.1.10", "hostname": "workstation", "device_type": "Computer"},
            {"ip_address": "192.168.1.1", "hostname": "router", "device_type": "Network gateway"},
        ],
        [{"ip_address": "192.168.1.10", "gateway_ip": "192.168.1.1", "interface": "eth0"}],
    )

    assert {node["id"] for node in graph["nodes"]} == {"192.168.1.1", "192.168.1.10"}
    assert graph["edges"] == [
        {
            "source": "192.168.1.10",
            "target": "192.168.1.1",
            "relation": "gateway",
            "confidence": "high",
            "evidence": "neighbor-table: eth0",
        }
    ]


def test_topology_changes_are_deterministic():
    previous = {
        "nodes": [{"id": "10.0.0.1"}, {"id": "10.0.0.2"}],
        "edges": [{"source": "10.0.0.2", "target": "10.0.0.1", "relation": "gateway"}],
    }
    current = {
        "nodes": [{"id": "10.0.0.1"}, {"id": "10.0.0.3"}],
        "edges": [{"source": "10.0.0.3", "target": "10.0.0.1", "relation": "gateway"}],
    }

    changes = topology_changes(previous, current)
    assert [item["id"] for item in changes["nodes_added"]] == ["10.0.0.3"]
    assert [item["id"] for item in changes["nodes_removed"]] == ["10.0.0.2"]
    assert changes["edges_added"][0]["source"] == "10.0.0.3"
    assert changes["edges_removed"][0]["source"] == "10.0.0.2"


def test_topology_does_not_invent_relationships_from_assets_only():
    graph = build_topology(
        [
            {"ip_address": "192.168.1.10", "device_type": "Computer"},
            {"ip_address": "192.168.1.20", "device_type": "Computer"},
        ]
    )
    assert graph["edges"] == []
