from pathlib import Path

APP_CORE = Path("frontend/app-core.js")


def _source() -> str:
    return APP_CORE.read_text(encoding="utf-8")


def test_inventory_service_table_surfaces_persisted_detection_evidence() -> None:
    source = _source()
    for field in (
        "{ key: 'service_detection', label: 'Detection' }",
        "{ key: 'service_product', label: 'Product' }",
        "{ key: 'service_version', label: 'Version' }",
        "{ key: 'service_confidence', label: 'Confidence', chip: true }",
    ):
        assert field in source


def test_port_audit_surfaces_response_backed_service_evidence() -> None:
    source = _source()
    for field in (
        "{ key: 'Service Detection', label: 'Detection' }",
        "{ key: 'Service Product', label: 'Product' }",
        "{ key: 'Service Version', label: 'Version' }",
        "{ key: 'Service Confidence', label: 'Confidence', chip: true }",
    ):
        assert field in source


def test_asset_timeline_empty_state_is_dual_stack_truthful() -> None:
    source = _source()
    assert "This IPv4 address is valid" not in source
    assert "This valid IP address is not saved in inventory" in source
