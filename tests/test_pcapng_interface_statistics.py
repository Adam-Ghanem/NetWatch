from __future__ import annotations

import struct

import pytest

from pcapng_import import import_pcapng_bytes


def _block(block_type: int, body: bytes) -> bytes:
    padding = b"\x00" * ((4 - len(body) % 4) % 4)
    total_length = 12 + len(body) + len(padding)
    return (
        struct.pack("<II", block_type, total_length)
        + body
        + padding
        + struct.pack("<I", total_length)
    )


def _section_header() -> bytes:
    return (
        struct.pack("<I", 0x0A0D0D0A)
        + struct.pack("<I", 28)
        + b"\x4d\x3c\x2b\x1a"
        + struct.pack("<HHq", 1, 0, -1)
        + struct.pack("<I", 28)
    )


def _interface_description() -> bytes:
    return _block(1, struct.pack("<HHI", 1, 0, 65_535))


def _option(code: int, value: bytes) -> bytes:
    padding = b"\x00" * ((4 - len(value) % 4) % 4)
    return struct.pack("<HH", code, len(value)) + value + padding


def _statistics(interface_id: int = 0) -> bytes:
    timestamp_units = 2_000_000
    body = struct.pack(
        "<III",
        interface_id,
        timestamp_units >> 32,
        timestamp_units & 0xFFFFFFFF,
    )
    body += _option(2, struct.pack("<Q", 1_000_000))
    body += _option(3, struct.pack("<Q", 2_000_000))
    body += _option(4, struct.pack("<Q", 120))
    body += _option(5, struct.pack("<Q", 7))
    body += _option(7, struct.pack("<Q", 3))
    body += struct.pack("<HH", 0, 0)
    return _block(5, body)


def test_import_pcapng_exposes_bounded_interface_statistics() -> None:
    result = import_pcapng_bytes(_section_header() + _interface_description() + _statistics())

    assert result["interface_statistics_count"] == 1
    assert result["payload_retained"] is False
    row = result["interface_statistics"][0]
    assert row["section"] == 1
    assert row["interface_id"] == 0
    assert row["received_packets"] == 120
    assert row["dropped_packets"] == 7
    assert row["os_dropped_packets"] == 3
    assert row["filter_accepted_packets"] is None
    assert row["user_delivered_packets"] is None
    assert row["capture_started_at"].startswith("1970-01-01T00:00:01")
    assert row["capture_ended_at"].startswith("1970-01-01T00:00:02")
    assert row["recorded_at"].startswith("1970-01-01T00:00:02")


def test_import_pcapng_rejects_statistics_for_unknown_interface() -> None:
    data = _section_header() + _interface_description() + _statistics(interface_id=1)

    with pytest.raises(ValueError, match="statistics reference an unknown interface"):
        import_pcapng_bytes(data)
