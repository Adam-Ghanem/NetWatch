from flow_investigation import build_flow_investigation
from flow_query import FlowQuery


def test_investigation_scopes_tcp_completeness_to_selected_flows() -> None:
    flows = [
        {
            "flow_id": "complete-https",
            "protocol": "TCP",
            "service": "https",
            "originator": {"ip": "192.168.1.10", "port": 51000},
            "responder": {"ip": "192.168.1.20", "port": 443},
            "endpoint_a": {"ip": "192.168.1.10", "port": 51000},
            "endpoint_b": {"ip": "192.168.1.20", "port": 443},
            "tcp_history": [">S", "<SA", ">A", ">D", "<D", ">F", "<F"],
            "tcp_state": "closing",
            "bytes": 1000,
        },
        {
            "flow_id": "incomplete-ssh",
            "protocol": "TCP",
            "service": "ssh",
            "originator": {"ip": "192.168.1.10", "port": 52000},
            "responder": {"ip": "192.168.1.30", "port": 22},
            "endpoint_a": {"ip": "192.168.1.10", "port": 52000},
            "endpoint_b": {"ip": "192.168.1.30", "port": 22},
            "tcp_history": [">S"],
            "tcp_state": "opening",
            "bytes": 60,
        },
    ]

    result = build_flow_investigation(
        flows,
        query=FlowQuery(service="https", limit=100),
    )

    completeness = result["tcp_completeness"]
    assert completeness["flow_count"] == 1
    assert completeness["tcp_flow_count"] == 1
    assert completeness["complete_with_data_flow_count"] == 1
    assert completeness["incomplete_flow_count"] == 0
    assert result["payload_retained"] is False
