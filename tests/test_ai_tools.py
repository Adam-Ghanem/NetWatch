from ai_tools import asset_snapshot_tool, findings_tool


def test_asset_snapshot_is_allowlisted():
    result = asset_snapshot_tool({"id": "a1", "ip": "192.0.2.1", "secret": "never", "services": [22]})
    assert result == {"id": "a1", "ip": "192.0.2.1", "services": [22]}
    assert "secret" not in result


def test_findings_are_bounded():
    findings = [{"kind": str(i)} for i in range(30)]
    result = findings_tool(findings, limit=999)
    assert result["count"] == 30
    assert len(result["findings"]) == 20
