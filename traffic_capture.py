from __future__ import annotations

import ipaddress
import socket
import struct
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from config import MAX_CAPTURE_PACKETS, MAX_CAPTURE_SECONDS
from device_identity import infer_device_identity, normalize_mac
from flow_analysis import summarize_flows
from flow_correlation import CorrelationPolicy, correlate_flow_events
from ipv6_extension_headers import locate_ipv6_transport
from protocol_metadata import extract_protocol_event

CAPTURE_PROTOCOLS = ("all", "tcp", "udp", "icmp", "arp")
SYS_CLASS_NET = Path("/sys/class/net")
ETHERNET_ALL_PROTOCOLS = 0x0003
_MAX_CAPTURE_PROTOCOL_EVENTS = 1_000


class CaptureUnavailableError(RuntimeError):
    """Live packet metadata capture is unavailable in this runtime."""


class CapturePermissionError(CaptureUnavailableError):
    """The runtime lacks the permission required for packet capture."""


@dataclass(frozen=True)
class CaptureFilter:
    protocol: str = "all"
    ip_address: str = ""
    port: int | None = None


def build_capture_filter(
    *,
    protocol: object = "all",
    ip_address: object = "",
    port: object = None,
) -> CaptureFilter:
    normalized_protocol = str(protocol or "all").strip().lower()
    if normalized_protocol not in CAPTURE_PROTOCOLS:
        raise ValueError(f"Protocol must be one of: {', '.join(CAPTURE_PROTOCOLS)}.")

    normalized_ip = ""
    if str(ip_address or "").strip():
        try:
            normalized_ip = str(ipaddress.ip_address(str(ip_address).strip()))
        except ValueError as exc:
            raise ValueError(
                "The traffic IP filter must be a literal IPv4 or IPv6 address."
            ) from exc

    normalized_port: int | None = None
    if port not in {None, ""}:
        try:
            normalized_port = int(str(port).strip())
        except (TypeError, ValueError) as exc:
            raise ValueError("The traffic port filter must be an integer.") from exc
        if normalized_port < 1 or normalized_port > 65_535:
            raise ValueError("The traffic port filter must be between 1 and 65535.")
        if normalized_protocol in {"icmp", "arp"}:
            raise ValueError("Port filters apply only to TCP, UDP, or all protocols.")

    return CaptureFilter(normalized_protocol, normalized_ip, normalized_port)


def _interface_names() -> list[str]:
    names: set[str] = set()
    try:
        names.update(
            path.name
            for path in SYS_CLASS_NET.iterdir()
            if path.is_dir() and 0 < len(path.name) <= 64
        )
    except OSError:
        pass
    if not names:
        try:
            names.update(name for _, name in socket.if_nameindex() if name and len(str(name)) <= 64)
        except OSError:
            pass
    return sorted(names)


def _interface_mac(name: str) -> str:
    try:
        value = (SYS_CLASS_NET / name / "address").read_text(encoding="ascii").strip()
    except OSError:
        return "-"
    return normalize_mac(value) or "-"


def _interface_ipv4(name: str) -> str:
    try:
        import fcntl

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as handle:
            request = struct.pack("256s", name.encode("ascii", errors="ignore")[:15])
            response = fcntl.ioctl(handle.fileno(), 0x8915, request)
        return socket.inet_ntoa(response[20:24])
    except (ImportError, OSError):
        return "-"


def capture_interfaces() -> list[dict[str, object]]:
    return [
        {
            "name": name,
            "ipv4_address": _interface_ipv4(name),
            "mac_address": _interface_mac(name),
            "loopback": name.lower() in {"lo", "lo0"},
        }
        for name in _interface_names()
    ]


def _default_interface(available: list[str]) -> str:
    try:
        route_lines = Path("/proc/net/route").read_text(encoding="ascii").splitlines()
    except OSError:
        route_lines = []
    for line in route_lines[1:]:
        fields = line.split()
        if len(fields) >= 4 and fields[1] == "00000000":
            try:
                is_up = int(fields[3], 16) & 1
            except ValueError:
                is_up = 0
            if is_up and fields[0] in available:
                return fields[0]
    non_loopback = [name for name in available if name.lower() not in {"lo", "lo0"}]
    return non_loopback[0] if non_loopback else available[0]


def resolve_capture_interface(requested: object) -> str:
    available = [str(item["name"]) for item in capture_interfaces()]
    if not available:
        raise CaptureUnavailableError("No capture interfaces are available.")
    value = str(requested or "").strip()
    if value in {"", "auto"}:
        return _default_interface(available)
    if value not in available:
        raise ValueError("Select one of the interfaces reported by NetWatch.")
    return value


def _mac_from_bytes(value: bytes) -> str:
    if len(value) != 6:
        return "-"
    return normalize_mac(":".join(f"{octet:02X}" for octet in value)) or "-"


def _tcp_flags(value: int) -> str:
    labels = (
        (0x80, "CWR"),
        (0x40, "ECE"),
        (0x20, "URG"),
        (0x10, "ACK"),
        (0x08, "PSH"),
        (0x04, "RST"),
        (0x02, "SYN"),
        (0x01, "FIN"),
    )
    return ",".join(label for mask, label in labels if value & mask) or "-"


def _transport_metadata(
    frame: bytes,
    *,
    offset: int,
    protocol_number: int,
) -> tuple[str, int | None, int | None, str]:
    if protocol_number == 6 and len(frame) >= offset + 14:
        source_port, destination_port = struct.unpack("!HH", frame[offset : offset + 4])
        return "TCP", source_port, destination_port, _tcp_flags(frame[offset + 13])
    if protocol_number == 17 and len(frame) >= offset + 4:
        source_port, destination_port = struct.unpack("!HH", frame[offset : offset + 4])
        return "UDP", source_port, destination_port, "-"
    if protocol_number == 1:
        return "ICMP", None, None, "-"
    if protocol_number == 58:
        return "ICMPv6", None, None, "-"
    return "", None, None, "-"


def parse_ethernet_frame(
    frame: bytes,
    sequence: int,
    *,
    captured_at: datetime | None = None,
) -> dict[str, object] | None:
    if len(frame) < 14:
        return None
    destination_mac = _mac_from_bytes(frame[0:6])
    source_mac = _mac_from_bytes(frame[6:12])
    ether_type = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    vlan_id: int | None = None
    if ether_type in {0x8100, 0x88A8} and len(frame) >= 18:
        vlan_tag, ether_type = struct.unpack("!HH", frame[14:18])
        vlan_id = vlan_tag & 0x0FFF
        offset = 18

    source_ip = "-"
    destination_ip = "-"
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags = "-"
    protocol = "Ethernet"
    transport_offset: int | None = None
    ipv6_extension_headers: tuple[str, ...] = ()
    ipv6_fragmented = False
    ipv6_first_fragment = True
    ipv6_transport_complete = True

    if ether_type == 0x0806 and len(frame) >= offset + 28:
        protocol = "ARP"
        hardware_length = frame[offset + 4]
        protocol_length = frame[offset + 5]
        if hardware_length == 6 and protocol_length == 4:
            source_ip = socket.inet_ntop(socket.AF_INET, frame[offset + 14 : offset + 18])
            destination_ip = socket.inet_ntop(socket.AF_INET, frame[offset + 24 : offset + 28])
    elif ether_type == 0x0800 and len(frame) >= offset + 20:
        version_and_ihl = frame[offset]
        version = version_and_ihl >> 4
        header_length = (version_and_ihl & 0x0F) * 4
        if version != 4 or header_length < 20 or len(frame) < offset + header_length:
            return None
        source_ip = socket.inet_ntop(socket.AF_INET, frame[offset + 12 : offset + 16])
        destination_ip = socket.inet_ntop(socket.AF_INET, frame[offset + 16 : offset + 20])
        protocol_number = frame[offset + 9]
        transport_offset = offset + header_length
        protocol, source_port, destination_port, tcp_flags = _transport_metadata(
            frame,
            offset=transport_offset,
            protocol_number=protocol_number,
        )
        protocol = protocol or "IPv4"
    elif ether_type == 0x86DD and len(frame) >= offset + 40:
        if frame[offset] >> 4 != 6:
            return None
        source_ip = socket.inet_ntop(socket.AF_INET6, frame[offset + 8 : offset + 24])
        destination_ip = socket.inet_ntop(socket.AF_INET6, frame[offset + 24 : offset + 40])
        protocol = "IPv6"
        location = locate_ipv6_transport(
            frame,
            ipv6_offset=offset,
            next_header=frame[offset + 6],
        )
        ipv6_extension_headers = location.extension_headers
        ipv6_fragmented = location.fragmented
        ipv6_first_fragment = location.first_fragment
        ipv6_transport_complete = location.complete
        if location.complete and (not location.fragmented or location.first_fragment):
            transport_offset = location.transport_offset
            transport_protocol, source_port, destination_port, tcp_flags = _transport_metadata(
                frame,
                offset=transport_offset,
                protocol_number=location.protocol_number,
            )
            protocol = transport_protocol or protocol

    timestamp = captured_at or datetime.now(timezone.utc)
    captured_at_value = timestamp.astimezone(timezone.utc).isoformat(timespec="milliseconds")
    source_endpoint = source_ip
    destination_endpoint = destination_ip
    if source_port is not None:
        source_endpoint = f"{source_endpoint}:{source_port}"
    if destination_port is not None:
        destination_endpoint = f"{destination_endpoint}:{destination_port}"
    summary = f"{source_endpoint} → {destination_endpoint}"
    if tcp_flags != "-":
        summary = f"{summary} · flags {tcp_flags}"

    record: dict[str, object] = {
        "number": sequence,
        "captured_at": captured_at_value,
        "protocol": protocol,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "source_mac": source_mac,
        "destination_mac": destination_mac,
        "source_port": source_port,
        "destination_port": destination_port,
        "tcp_flags": tcp_flags,
        "vlan_id": vlan_id,
        "ipv6_extension_headers": list(ipv6_extension_headers),
        "ipv6_fragmented": ipv6_fragmented,
        "ipv6_first_fragment": ipv6_first_fragment,
        "ipv6_transport_complete": ipv6_transport_complete,
        "length_bytes": len(frame),
        "summary": summary[:300],
    }
    protocol_event = extract_protocol_event(
        frame,
        transport_offset=transport_offset,
        protocol=protocol,
        source_port=source_port,
        destination_port=destination_port,
    )
    if protocol_event is not None:
        record["_protocol_event"] = protocol_event
    return record


def packet_matches(record: dict[str, object], capture_filter: CaptureFilter) -> bool:
    protocol = str(record.get("protocol", "")).lower()
    if capture_filter.protocol != "all":
        if capture_filter.protocol == "icmp":
            if protocol not in {"icmp", "icmpv6"}:
                return False
        elif protocol != capture_filter.protocol:
            return False
    if capture_filter.ip_address and capture_filter.ip_address not in {
        record.get("source_ip"),
        record.get("destination_ip"),
    }:
        return False
    if capture_filter.port is not None and capture_filter.port not in {
        record.get("source_port"),
        record.get("destination_port"),
    }:
        return False
    return True


def _int_value(value: object) -> int:
    try:
        return int(str(value or 0))
    except ValueError:
        return 0


def _conversation_rows(records: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    conversations: dict[tuple[str, str, str], dict[str, int]] = defaultdict(
        lambda: {"packets": 0, "bytes": 0}
    )
    for record in records:
        key = (
            str(record.get("source_ip", "-")),
            str(record.get("destination_ip", "-")),
            str(record.get("protocol", "Unknown")),
        )
        conversations[key]["packets"] += 1
        conversations[key]["bytes"] += _int_value(record.get("length_bytes", 0))
    rows = [
        {
            "source": key[0],
            "destination": key[1],
            "protocol": key[2],
            **values,
        }
        for key, values in conversations.items()
    ]
    return sorted(
        rows,
        key=lambda item: (-_int_value(item["bytes"]), -_int_value(item["packets"])),
    )[:25]


def _device_rows(records: Iterable[dict[str, object]]) -> list[dict[str, object]]:
    evidence: dict[str, dict[str, object]] = {}
    for record in records:
        for side in ("source", "destination"):
            mac_address = normalize_mac(record.get(f"{side}_mac", ""))
            ip_address = str(record.get(f"{side}_ip", "-"))
            if not mac_address or ip_address == "-":
                continue
            item = evidence.setdefault(
                mac_address,
                {"mac_address": mac_address, "ip_addresses": set(), "packets": 0},
            )
            ip_values = item["ip_addresses"]
            if isinstance(ip_values, set):
                ip_values.add(ip_address)
            item["packets"] = _int_value(item["packets"]) + 1

    rows: list[dict[str, object]] = []
    for item in evidence.values():
        identity = infer_device_identity(item["mac_address"])
        ip_values = item["ip_addresses"]
        rows.append(
            {
                **identity.as_dict(),
                "ip_addresses": ", ".join(sorted(ip_values)) if isinstance(ip_values, set) else "-",
                "packets": item["packets"],
            }
        )
    return sorted(
        rows,
        key=lambda item: (-_int_value(item["packets"]), str(item["mac_address"])),
    )[:50]


def _endpoint_tuple(value: object) -> tuple[str, int]:
    if not isinstance(value, dict):
        return "-", 0
    return str(value.get("ip") or "-"), _int_value(value.get("port"))


def _flow_lookup_key(record: dict[str, object]) -> tuple[str, tuple[str, int], tuple[str, int]]:
    source = (
        str(record.get("source_ip") or "-"),
        _int_value(record.get("source_port")),
    )
    destination = (
        str(record.get("destination_ip") or "-"),
        _int_value(record.get("destination_port")),
    )
    left, right = sorted((source, destination))
    return str(record.get("protocol") or "Unknown").upper(), left, right


def _correlate_capture_protocol_events(
    flows: list[dict[str, object]],
    records: Iterable[dict[str, object]],
) -> list[dict[str, object]]:
    flow_ids: dict[tuple[str, tuple[str, int], tuple[str, int]], str] = {}
    for flow in flows:
        left = _endpoint_tuple(flow.get("endpoint_a"))
        right = _endpoint_tuple(flow.get("endpoint_b"))
        key = (str(flow.get("protocol") or "Unknown").upper(), left, right)
        flow_id = str(flow.get("flow_id") or "")
        if flow_id:
            flow_ids[key] = flow_id

    events: list[dict[str, object]] = []
    for record in records:
        raw_event = record.get("_protocol_event")
        if not isinstance(raw_event, dict):
            continue
        correlated_flow_id = flow_ids.get(_flow_lookup_key(record))
        if not correlated_flow_id:
            continue
        event = dict(raw_event)
        event["flow_id"] = correlated_flow_id
        event["timestamp"] = str(record.get("captured_at") or "")
        events.append(event)
        if len(events) >= _MAX_CAPTURE_PROTOCOL_EVENTS:
            break

    if not events:
        return flows
    correlated = correlate_flow_events(
        flows,
        events,
        policy=CorrelationPolicy(
            max_flows=100,
            max_events=_MAX_CAPTURE_PROTOCOL_EVENTS,
            max_events_per_flow=100,
        ),
    )
    return correlated["flows"]


def summarize_capture(
    records: list[dict[str, object]],
    *,
    interface: str,
    duration_seconds: int,
    capture_filter: CaptureFilter,
) -> dict[str, Any]:
    protocol_counts = Counter(str(record["protocol"]) for record in records)
    total_bytes = sum(_int_value(record["length_bytes"]) for record in records)
    flows = summarize_flows(records, limit=100)
    flows = _correlate_capture_protocol_events(flows, records)
    packets = [
        {key: value for key, value in record.items() if key != "_protocol_event"}
        for record in records
    ]
    return {
        "interface": interface,
        "duration_seconds": duration_seconds,
        "captured_packets": len(records),
        "captured_bytes": total_bytes,
        "payload_retained": False,
        "filter": {
            "protocol": capture_filter.protocol,
            "ip_address": capture_filter.ip_address,
            "port": capture_filter.port,
        },
        "protocols": [
            {"protocol": protocol, "packets": count}
            for protocol, count in sorted(
                protocol_counts.items(), key=lambda item: (-item[1], item[0])
            )
        ],
        "flow_count": len(flows),
        "flows": flows,
        "conversations": _conversation_rows(records),
        "devices": _device_rows(records),
        "packets": packets,
        "visibility_note": (
            "A normal switched interface usually sees traffic to or from this NetWatch host. "
            "Full-segment visibility requires an approved SPAN/mirror port or network sensor."
        ),
    }


def capture_traffic(
    *,
    interface: object,
    duration_seconds: int,
    max_packets: int,
    capture_filter: CaptureFilter,
) -> dict[str, Any]:
    if duration_seconds < 1 or duration_seconds > MAX_CAPTURE_SECONDS:
        raise ValueError(f"Capture duration must be between 1 and {MAX_CAPTURE_SECONDS} seconds.")
    if max_packets < 1 or max_packets > MAX_CAPTURE_PACKETS:
        raise ValueError(f"Packet limit must be between 1 and {MAX_CAPTURE_PACKETS}.")
    if not hasattr(socket, "AF_PACKET"):
        raise CaptureUnavailableError("Live capture currently requires a Linux packet sensor.")
    selected_interface = resolve_capture_interface(interface)
    records: list[dict[str, object]] = []
    deadline = time.monotonic() + duration_seconds
    capture_socket: socket.socket | None = None

    try:
        capture_socket = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(ETHERNET_ALL_PROTOCOLS),
        )
        capture_socket.bind((selected_interface, 0))
    except PermissionError as exc:
        if capture_socket is not None:
            capture_socket.close()
        raise CapturePermissionError(
            "Packet capture permission is unavailable. NET_RAW/root capture access is required."
        ) from exc
    except OSError as exc:
        if capture_socket is not None:
            capture_socket.close()
        message = str(exc).lower()
        if "permission" in message or "not permitted" in message:
            raise CapturePermissionError(
                "Packet capture permission is unavailable. NET_RAW/root capture access is required."
            ) from exc
        raise CaptureUnavailableError("Packet capture could not start on this interface.") from exc

    if capture_socket is None:  # pragma: no cover - defensive type/runtime guard
        raise CaptureUnavailableError("Packet capture could not start on this interface.")
    try:
        while len(records) < max_packets and time.monotonic() < deadline:
            remaining = max(0.01, deadline - time.monotonic())
            capture_socket.settimeout(min(0.5, remaining))
            try:
                frame, _ = capture_socket.recvfrom(65_535)
            except TimeoutError:
                continue
            record = parse_ethernet_frame(
                frame,
                len(records) + 1,
                captured_at=datetime.now(timezone.utc),
            )
            if record is not None and packet_matches(record, capture_filter):
                records.append(record)
    except OSError as exc:
        raise CaptureUnavailableError("Packet capture stopped on the selected interface.") from exc
    finally:
        capture_socket.close()

    return summarize_capture(
        records,
        interface=selected_interface,
        duration_seconds=duration_seconds,
        capture_filter=capture_filter,
    )
