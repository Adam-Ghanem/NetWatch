from __future__ import annotations

import json

import pytest

import capture_cli


def test_analyze_routes_pcapng_to_bounded_importer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def fake_import(data: bytes, *, packet_limit: int) -> dict[str, object]:
        seen["data"] = data
        seen["packet_limit"] = packet_limit
        return {"source": "pcapng", "flows": [], "payload_retained": False}

    monkeypatch.setattr(capture_cli, "import_pcapng_bytes", fake_import)

    result = capture_cli.analyze_capture_bytes(
        b"\x0a\x0d\x0d\x0aexample", packet_limit=17
    )

    assert result["source"] == "pcapng"
    assert seen == {"data": b"\x0a\x0d\x0d\x0aexample", "packet_limit": 17}


def test_analyze_routes_classic_pcap_to_bounded_importer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def fake_import(data: bytes, *, max_packets: int) -> dict[str, object]:
        seen["data"] = data
        seen["max_packets"] = max_packets
        return {"source": "pcap", "flows": [], "payload_retained": False}

    monkeypatch.setattr(capture_cli, "import_pcap_metadata", fake_import)

    result = capture_cli.analyze_capture_bytes(
        b"\xd4\xc3\xb2\xa1example", packet_limit=23
    )

    assert result["source"] == "pcap"
    assert seen == {"data": b"\xd4\xc3\xb2\xa1example", "max_packets": 23}


def test_analyze_rejects_unknown_capture_format() -> None:
    with pytest.raises(ValueError, match="Unsupported capture format"):
        capture_cli.analyze_capture_bytes(b"not-a-capture")


def test_analyze_rejects_packet_limit_outside_safety_bound() -> None:
    with pytest.raises(ValueError, match="Packet limit"):
        capture_cli.analyze_capture_bytes(b"\xd4\xc3\xb2\xa1", packet_limit=0)


def test_json_render_forces_payload_retention_false() -> None:
    rendered = capture_cli.render_capture_result(
        {"source": "pcap", "payload_retained": True, "flows": []},
        output_format="json",
    )

    payload = json.loads(rendered)
    assert payload["source"] == "pcap"
    assert payload["payload_retained"] is False


def test_csv_render_reuses_formula_safe_flow_export() -> None:
    rendered = capture_cli.render_capture_result(
        {
            "flows": [
                {
                    "flow_id": "=danger",
                    "protocol": "TCP",
                    "service": "https",
                    "packets": 2,
                    "bytes": 128,
                    "endpoint_a": {"ip": "10.0.0.1", "port": 50000},
                    "endpoint_b": {"ip": "10.0.0.2", "port": 443},
                }
            ]
        },
        output_format="csv",
        flow_limit=1,
    )

    text = rendered.decode("utf-8")
    assert "flow_id" in text
    assert "'=danger" in text
    assert "10.0.0.2" in text


def test_render_rejects_unknown_output_format() -> None:
    with pytest.raises(ValueError, match="Output format"):
        capture_cli.render_capture_result({}, output_format="xml")
