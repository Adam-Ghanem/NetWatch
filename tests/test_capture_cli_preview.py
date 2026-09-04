from __future__ import annotations

import json

import pytest

from capture_cli import build_capture_preview, render_capture_preview


def test_capture_preview_is_compact_metadata_only() -> None:
    result = {
        "source": "pcap",
        "captured_packets": 12,
        "flow_count": 3,
        "duration_seconds": 4,
        "protocols": [{"protocol": "TCP", "packets": 12}],
        "pcap_version": "2.4",
        "linktype": 1,
        "processed_records": 12,
        "truncated_by_limit": True,
        "payload_retained": False,
        "packets": [{"number": 1, "payload": "must-not-escape"}],
        "flows": [{"protocol": "TCP", "raw": "must-not-escape"}],
    }

    preview = build_capture_preview(result, capture_bytes=4096)

    assert preview == {
        "source": "pcap",
        "capture_bytes": 4096,
        "captured_packets": 12,
        "flow_count": 3,
        "duration_seconds": 4,
        "protocols": [{"protocol": "TCP", "packets": 12}],
        "truncated_by_limit": True,
        "payload_retained": False,
        "pcap_version": "2.4",
        "linktype": 1,
        "processed_records": 12,
    }
    assert "packets" not in preview
    assert "flows" not in preview
    assert "payload" not in preview
    assert "raw" not in preview


def test_capture_preview_json_is_deterministic_and_excludes_rows() -> None:
    rendered = render_capture_preview(
        {
            "source": "pcapng",
            "captured_packets": 2,
            "flow_count": 1,
            "duration_seconds": 0,
            "protocols": [],
            "packets": [{"number": 1}],
            "flows": [{"protocol": "UDP"}],
        },
        capture_bytes=128,
    )

    decoded = json.loads(rendered)
    assert decoded["source"] == "pcapng"
    assert decoded["capture_bytes"] == 128
    assert decoded["payload_retained"] is False
    assert "packets" not in decoded
    assert "flows" not in decoded
    assert rendered.endswith(b"\n")


def test_capture_preview_rejects_negative_size() -> None:
    preview = build_capture_preview({}, capture_bytes=-1)
    assert preview["capture_bytes"] == 0
