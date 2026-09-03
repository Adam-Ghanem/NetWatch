from __future__ import annotations

from dataclasses import dataclass

MAX_EXTENSION_HEADERS = 8
MAX_EXTENSION_BYTES = 256

_EXTENSION_NAMES = {
    0: "hop_by_hop",
    43: "routing",
    44: "fragment",
    51: "authentication",
    60: "destination_options",
}


@dataclass(frozen=True)
class IPv6TransportLocation:
    """Bounded metadata describing the upper-layer header in an IPv6 packet."""

    protocol_number: int
    transport_offset: int
    extension_headers: tuple[str, ...]
    fragmented: bool
    first_fragment: bool
    complete: bool
    findings: tuple[str, ...] = ()


def locate_ipv6_transport(
    packet: bytes,
    *,
    ipv6_offset: int,
    next_header: int,
    max_extension_headers: int = MAX_EXTENSION_HEADERS,
    max_extension_bytes: int = MAX_EXTENSION_BYTES,
) -> IPv6TransportLocation:
    """Walk common IPv6 extension headers without inspecting packet payload.

    The walker is deliberately bounded. It understands the RFC 8200 Hop-by-Hop,
    Routing, Fragment, Destination Options and Authentication header layouts.
    ESP is treated as opaque, and non-initial fragments never claim a transport
    header because it is not present in those fragments.

    Conservative parser findings describe structural conditions that can matter
    during defensive analysis. They are metadata only and never require payload
    inspection.
    """

    if ipv6_offset < 0 or ipv6_offset + 40 > len(packet):
        raise ValueError("A complete IPv6 base header is required.")
    if max_extension_headers < 0 or max_extension_headers > 32:
        raise ValueError("max_extension_headers must be between 0 and 32.")
    if max_extension_bytes < 0 or max_extension_bytes > 4096:
        raise ValueError("max_extension_bytes must be between 0 and 4096.")

    offset = ipv6_offset + 40
    current = int(next_header)
    names: list[str] = []
    findings: list[str] = []
    extension_bytes = 0
    fragmented = False
    first_fragment = True
    seen_hop_by_hop = False
    seen_fragment = False

    def result(*, complete: bool) -> IPv6TransportLocation:
        return IPv6TransportLocation(
            current,
            offset,
            tuple(names),
            fragmented,
            first_fragment,
            complete,
            tuple(findings),
        )

    while current in _EXTENSION_NAMES:
        if len(names) >= max_extension_headers:
            findings.append("extension_header_limit_reached")
            return result(complete=False)
        if offset + 2 > len(packet):
            findings.append("truncated_extension_header")
            return result(complete=False)

        name = _EXTENSION_NAMES[current]
        if current == 0:
            if seen_hop_by_hop:
                findings.append("duplicate_hop_by_hop")
            if names:
                findings.append("hop_by_hop_not_first")
            seen_hop_by_hop = True
        elif current == 44:
            if seen_fragment:
                findings.append("duplicate_fragment")
            seen_fragment = True

        names.append(name)
        following = packet[offset]

        if current == 44:
            header_length = 8
            if offset + header_length > len(packet):
                fragmented = True
                first_fragment = False
                findings.append("truncated_fragment_header")
                return result(complete=False)
            fragment_field = int.from_bytes(
                packet[offset + 2 : offset + 4],
                "big",
            )
            fragment_offset = (fragment_field >> 3) & 0x1FFF
            fragmented = True
            first_fragment = fragment_offset == 0
            current = following
            offset += header_length
            extension_bytes += header_length
            if not first_fragment:
                return result(complete=True)
        elif current == 51:
            header_length = (packet[offset + 1] + 2) * 4
            if header_length < 8 or offset + header_length > len(packet):
                findings.append("invalid_authentication_header_length")
                return result(complete=False)
            current = following
            offset += header_length
            extension_bytes += header_length
        else:
            header_length = (packet[offset + 1] + 1) * 8
            if header_length < 8 or offset + header_length > len(packet):
                findings.append("invalid_extension_header_length")
                return result(complete=False)
            current = following
            offset += header_length
            extension_bytes += header_length

        if extension_bytes > max_extension_bytes:
            findings.append("extension_byte_limit_reached")
            return result(complete=False)

    # ESP is encrypted/opaque; No Next Header explicitly terminates the chain.
    if current == 50:
        findings.append("opaque_esp")
        return result(complete=False)
    if current == 59:
        findings.append("no_next_header")
        return result(complete=False)
    return result(complete=True)
