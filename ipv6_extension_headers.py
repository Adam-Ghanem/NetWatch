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
    extension_bytes = 0
    fragmented = False
    first_fragment = True

    while current in _EXTENSION_NAMES:
        if len(names) >= max_extension_headers:
            return IPv6TransportLocation(
                current,
                offset,
                tuple(names),
                fragmented,
                first_fragment,
                False,
            )
        if offset + 2 > len(packet):
            return IPv6TransportLocation(
                current,
                offset,
                tuple(names),
                fragmented,
                first_fragment,
                False,
            )

        names.append(_EXTENSION_NAMES[current])
        following = packet[offset]

        if current == 44:
            header_length = 8
            if offset + header_length > len(packet):
                return IPv6TransportLocation(
                    current,
                    offset,
                    tuple(names),
                    True,
                    False,
                    False,
                )
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
                return IPv6TransportLocation(
                    current,
                    offset,
                    tuple(names),
                    True,
                    False,
                    True,
                )
        elif current == 51:
            header_length = (packet[offset + 1] + 2) * 4
            if header_length < 8 or offset + header_length > len(packet):
                return IPv6TransportLocation(
                    current,
                    offset,
                    tuple(names),
                    fragmented,
                    first_fragment,
                    False,
                )
            current = following
            offset += header_length
            extension_bytes += header_length
        else:
            header_length = (packet[offset + 1] + 1) * 8
            if header_length < 8 or offset + header_length > len(packet):
                return IPv6TransportLocation(
                    current,
                    offset,
                    tuple(names),
                    fragmented,
                    first_fragment,
                    False,
                )
            current = following
            offset += header_length
            extension_bytes += header_length

        if extension_bytes > max_extension_bytes:
            return IPv6TransportLocation(
                current,
                offset,
                tuple(names),
                fragmented,
                first_fragment,
                False,
            )

    # ESP is encrypted/opaque; No Next Header explicitly terminates the chain.
    complete = current not in {50, 59}
    return IPv6TransportLocation(
        current,
        offset,
        tuple(names),
        fragmented,
        first_fragment,
        complete,
    )
