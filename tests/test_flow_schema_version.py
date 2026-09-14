import csv
import io
import json

from flow_export import export_flows_csv, export_flows_json, export_flows_ndjson


def _flow() -> dict[str, object]:
    return {
        "flow_id": "flow-1",
        "community_id": "1:example",
        "protocol": "TCP",
        "originator": {"ip": "192.0.2.10", "port": 51_515},
        "responder": {"ip": "192.0.2.20", "port": 443},
        "packets": 2,
        "bytes": 120,
    }


def test_flow_exports_publish_stable_schema_identity() -> None:
    payload = json.loads(export_flows_json([_flow()]).decode("utf-8"))
    assert payload["schema_version"] == "netwatch.flow.v1"
    assert payload["evidence_source"] == "netwatch.flow_analysis"
    assert payload["flows"][0]["schema_version"] == "netwatch.flow.v1"
    assert payload["flows"][0]["evidence_source"] == "netwatch.flow_analysis"

    event = json.loads(export_flows_ndjson([_flow()]).decode("utf-8"))
    assert event["schema_version"] == "netwatch.flow.v1"
    assert event["evidence_source"] == "netwatch.flow_analysis"

    rows = list(csv.DictReader(io.StringIO(export_flows_csv([_flow()]).decode("utf-8"))))
    assert rows[0]["schema_version"] == "netwatch.flow.v1"
    assert rows[0]["evidence_source"] == "netwatch.flow_analysis"
