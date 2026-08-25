from intelligence_api import asset_intelligence


def test_asset_intelligence_combines_fingerprint_and_behavior():
    result = asset_intelligence(
        asset={
            "id": "asset-1",
            "hostname": "Pixel-8",
            "manufacturer": "Google",
            "device_family": "Pixel",
        },
        findings=[{"kind": "new_port", "severity": "high"}],
    )
    assert result["asset_id"] == "asset-1"
    assert result["fingerprint"]["platform"] == "Android"
    assert result["behavior"]["total"] == 1
    assert result["behavior"]["risk_score"] == 20


def test_asset_intelligence_handles_sparse_asset():
    result = asset_intelligence(asset={"ip": "192.0.2.10"})
    assert result["asset_id"] == "192.0.2.10"
    assert result["fingerprint"]["platform"] == "Unknown"
    assert result["behavior"]["total"] == 0
