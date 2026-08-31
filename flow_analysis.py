from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Iterable


_SERVICE_PORTS = {
    ("TCP", 22): "ssh",
    ("TCP", 25): "smtp",
    ("TCP", 53): "dns",
    ("UDP", 53): "dns",
    ("UDP", 67): "dhcp",
    ("UDP", 68): "dhcp",
    ("TCP", 80): "http",
    ("TCP", 110): "pop3",
    ("UDP", 123): "ntp",
    ("TCP", 143): "imap",
    ("TCP", 389): "ldap",
    ("UDP", 389): "ldap",
    ("TCP", 443): "https",
    ("UDP", 443): "quic",
    ("TCP", 445): "smb",
    ("UDP", 5353): "mdns",
}


def _int(value: object) -> int:
    try:
        return int(str(value or 0))
    except (TypeError, ValueError):
        return 0


def _timestamp(value: object) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _endpoint(ip: object, port: object) -> tuple[str, int]:
    return str(ip or "-"), _int(port)


def _endpoint_dict(endpoint: tuple[str, int]) -> dict[str, object]:
    return {"ip": endpoint[0], "port": endpoint[1] or None}


def _flow_id(protocol: str, left: tuple[str, int], right: tuple[str, int]) -> str:
    raw = f"{protocol}|{left[0]}|{left[1]}|{right[0]}|{right[1]}".encode()
    return hashlib.blake2s(raw, digest_size=8).hexdigest()


def _service(protocol: str, responder: tuple[str, int]) -> str:
    return _SERVICE_PORTS.get((protocol, responder[1]), "-")


def summarize_flows(
    records: Iterable[dict[str, object]],
    limit: int = 100,
) -> list[dict[str, object]]:
    """Build bidirectional, metadata-only flow summaries from packet records.

    Endpoints are canonicalized so both directions of the same TCP/UDP 5-tuple are
    merged. The first observed sender is treated as the originator and the first
    observed destination as the responder. Service hints are conservative and are
    derived only from a small set of well-known responder ports. No packet payload
    is retained or reconstructed.
    """
    if limit < 1 or limit > 1000:
        raise ValueError("Flow limit must be between 1 and 1000.")

    flows: dict[tuple[str, tuple[str, int], tuple[str, int]], dict[str, object]] = {}
    for record in records:
        protocol = str(record.get("protocol") or "Unknown").upper()
        source = _endpoint(record.get("source_ip"), record.get("source_port"))
        destination = _endpoint(
            record.get("destination_ip"), record.get("destination_port")
        )
        left, right = sorted((source, destination))
        key = (protocol, left, right)
        timestamp = _timestamp(record.get("captured_at"))
        size = _int(record.get("length_bytes"))

        flow = flows.setdefault(
            key,
            {
                "flow_id": _flow_id(protocol, left, right),
                "protocol": protocol,
                "endpoint_a": _endpoint_dict(left),
                "endpoint_b": _endpoint_dict(right),
                "originator": _endpoint_dict(source),
                "responder": _endpoint_dict(destination),
                "service": _service(protocol, destination),
                "packets": 0,
                "bytes": 0,
                "a_to_b_packets": 0,
                "a_to_b_bytes": 0,
                "b_to_a_packets": 0,
                "b_to_a_bytes": 0,
                "originator_packets": 0,
                "originator_bytes": 0,
                "responder_packets": 0,
                "responder_bytes": 0,
                "first_seen": None,
                "last_seen": None,
                "duration_ms": 0,
                "tcp_state": "-",
            },
        )
        flow["packets"] = _int(flow["packets"]) + 1
        flow["bytes"] = _int(flow["bytes"]) + size
        direction = "a_to_b" if source == left else "b_to_a"
        flow[f"{direction}_packets"] = _int(flow[f"{direction}_packets"]) + 1
        flow[f"{direction}_bytes"] = _int(flow[f"{direction}_bytes"]) + size

        originator = flow["originator"]
        if isinstance(originator, dict) and source == (
            str(originator.get("ip") or "-"),
            _int(originator.get("port")),
        ):
            flow["originator_packets"] = _int(flow["originator_packets"]) + 1
            flow["originator_bytes"] = _int(flow["originator_bytes"]) + size
        else:
            flow["responder_packets"] = _int(flow["responder_packets"]) + 1
            flow["responder_bytes"] = _int(flow["responder_bytes"]) + size

        if timestamp is not None:
            iso = timestamp.isoformat(timespec="milliseconds")
            first = _timestamp(flow["first_seen"])
            last = _timestamp(flow["last_seen"])
            if first is None or timestamp < first:
                flow["first_seen"] = iso
            if last is None or timestamp > last:
                flow["last_seen"] = iso
            first = _timestamp(flow["first_seen"])
            last = _timestamp(flow["last_seen"])
            if first and last:
                flow["duration_ms"] = max(
                    0,
                    int((last - first).total_seconds() * 1000),
                )

        if protocol == "TCP":
            flags = {
                flag
                for flag in str(record.get("tcp_flags") or "").split(",")
                if flag and flag != "-"
            }
            state = str(flow["tcp_state"])
            if "RST" in flags:
                flow["tcp_state"] = "reset"
            elif "FIN" in flags:
                flow["tcp_state"] = "closing"
            elif "SYN" in flags and "ACK" in flags:
                flow["tcp_state"] = "establishing"
            elif "SYN" in flags:
                flow["tcp_state"] = "opening"
            elif "ACK" in flags and state in {"-", "opening", "establishing"}:
                flow["tcp_state"] = "established"

    return sorted(
        flows.values(),
        key=lambda item: (
            -_int(item["bytes"]),
            -_int(item["packets"]),
            str(item["flow_id"]),
        ),
    )[:limit]
