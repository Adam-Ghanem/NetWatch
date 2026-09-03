from __future__ import annotations

import base64
import hashlib
import ipaddress
import struct

_PROTOCOL_NUMBERS = {"TCP": 6, "UDP": 17}


def community_flow_id(
    protocol: object,
    source_ip: object,
    destination_ip: object,
    source_port: object,
    destination_port: object,
    *,
    seed: int = 0,
) -> str:
    """Return a Community ID v1 hash for a TCP/UDP flow tuple.

    This intentionally supports only TCP and UDP because NetWatch flow summaries
    do not currently retain the ICMP type/code fields required for standards-
    compliant ICMP Community IDs. Invalid or unsupported tuples return an empty
    string rather than producing a misleading identifier.
    """

    normalized_protocol = str(protocol or "").strip().upper()
    protocol_number = _PROTOCOL_NUMBERS.get(normalized_protocol)
    if protocol_number is None:
        return ""
    if seed < 0 or seed > 65_535:
        raise ValueError("Community ID seed must be between 0 and 65535.")

    try:
        source_address = ipaddress.ip_address(str(source_ip).strip())
        destination_address = ipaddress.ip_address(str(destination_ip).strip())
        source_port_number = int(str(source_port).strip())
        destination_port_number = int(str(destination_port).strip())
    except (TypeError, ValueError):
        return ""

    if source_address.version != destination_address.version:
        return ""
    if not 0 <= source_port_number <= 65_535 or not 0 <= destination_port_number <= 65_535:
        return ""

    source_key = (source_address.packed, source_port_number)
    destination_key = (destination_address.packed, destination_port_number)
    if destination_key < source_key:
        source_address, destination_address = destination_address, source_address
        source_port_number, destination_port_number = destination_port_number, source_port_number

    digest = hashlib.sha1(
        b"".join(
            (
                struct.pack("!H", seed),
                source_address.packed,
                destination_address.packed,
                struct.pack("!B", protocol_number),
                b"\x00",
                struct.pack("!H", source_port_number),
                struct.pack("!H", destination_port_number),
            )
        )
    ).digest()
    return "1:" + base64.b64encode(digest).decode("ascii")
