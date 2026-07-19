from __future__ import annotations

import ipaddress
import re
import secrets
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

_MAC_PATTERN = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class DeviceIdentity:
    device_name: str
    hostname: str
    device_type: str
    operating_system: str
    confidence: str
    evidence: str
    mac_address: str
    ttl: int | None

    def as_scan_fields(self) -> dict[str, object]:
        return {
            "Device Name": self.device_name,
            "Hostname": self.hostname or "-",
            "Device Type": self.device_type,
            "Operating System": self.operating_system,
            "Identity Confidence": self.confidence,
            "Identity Evidence": self.evidence,
            "MAC Address": self.mac_address or "-",
            "TTL": self.ttl if self.ttl is not None else "-",
        }


def _safe_text(value: object, max_length: int = 253) -> str:
    cleaned = _CONTROL_CHARACTERS.sub("", str(value or "")).strip().rstrip(".")
    return cleaned[:max_length]


def _usable_hostname(value: object) -> str:
    candidate = _safe_text(value)
    if not candidate or candidate in {"-", "unknown", "unresolved"}:
        return ""
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return candidate
    return ""


def reverse_hostname(ip_address: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
    except OSError:
        return ""
    return _usable_hostname(hostname)


def _valid_mac(value: object) -> str:
    candidate = _safe_text(value, 17).upper()
    if not _MAC_PATTERN.fullmatch(candidate) or candidate == "00:00:00:00:00:00":
        return ""
    return candidate


def neighbor_mac_address(ip_address: str) -> str:
    """Read a same-segment MAC from Linux's local ARP cache when available."""
    try:
        rows = Path("/proc/net/arp").read_text(encoding="utf-8").splitlines()[1:]
    except (OSError, UnicodeError):
        return ""
    for row in rows:
        fields = row.split()
        if len(fields) >= 4 and fields[0] == ip_address:
            return _valid_mac(fields[3])
    return ""


def _encoded_netbios_name(name: str = "*", suffix: int = 0x00) -> bytes:
    raw_name = name.upper()[:15].ljust(15).encode("ascii", errors="replace") + bytes([suffix])
    encoded = bytearray()
    for value in raw_name:
        encoded.extend((ord("A") + (value >> 4), ord("A") + (value & 0x0F)))
    return bytes([len(encoded)]) + bytes(encoded) + b"\x00"


def _skip_dns_name(payload: bytes, offset: int) -> int:
    while offset < len(payload):
        length = payload[offset]
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += 1
        if length == 0:
            return offset
        offset += length
    raise ValueError("Truncated encoded name")


def parse_netbios_node_status(payload: bytes, transaction_id: bytes) -> tuple[str, str]:
    """Return a unique workstation/server name and MAC from an NBSTAT response."""
    if len(payload) < 12 or payload[:2] != transaction_id:
        return "", ""
    question_count, answer_count = struct.unpack("!HH", payload[4:8])
    offset = 12
    try:
        for _ in range(question_count):
            offset = _skip_dns_name(payload, offset) + 4
        for _ in range(answer_count):
            offset = _skip_dns_name(payload, offset)
            if offset + 10 > len(payload):
                return "", ""
            record_type, _, _, data_length = struct.unpack("!HHIH", payload[offset : offset + 10])
            offset += 10
            record_data = payload[offset : offset + data_length]
            offset += data_length
            if record_type != 0x0021 or not record_data:
                continue
            name_count = record_data[0]
            names_end = 1 + (name_count * 18)
            if names_end > len(record_data):
                return "", ""
            candidates: list[tuple[int, str]] = []
            for index in range(name_count):
                start = 1 + (index * 18)
                raw_name = record_data[start : start + 15]
                suffix = record_data[start + 15]
                flags = struct.unpack("!H", record_data[start + 16 : start + 18])[0]
                is_group = bool(flags & 0x8000)
                decoded = _safe_text(raw_name.decode("ascii", errors="ignore"), 15).strip()
                if decoded and not is_group and suffix in {0x00, 0x20}:
                    candidates.append((2 if suffix == 0x00 else 1, decoded))
            mac = _valid_mac(
                ":".join(f"{byte:02X}" for byte in record_data[names_end : names_end + 6])
            )
            name = max(candidates, default=(0, ""))[1]
            return name, mac
    except (IndexError, struct.error, ValueError):
        return "", ""
    return "", ""


def query_netbios_identity(ip_address: str, timeout: float = 0.25) -> tuple[str, str]:
    """Make one bounded local NBSTAT query for Windows-compatible identity evidence."""
    try:
        address = ipaddress.ip_address(ip_address)
    except ValueError:
        return "", ""
    if not isinstance(address, ipaddress.IPv4Address) or not (
        address.is_private or address.is_loopback or address.is_link_local
    ):
        return "", ""

    transaction_id = secrets.token_bytes(2)
    header = transaction_id + struct.pack("!HHHHH", 0, 1, 0, 0, 0)
    packet = header + _encoded_netbios_name() + struct.pack("!HH", 0x0021, 0x0001)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(max(0.05, min(float(timeout), 1.0)))
        try:
            sock.sendto(packet, (str(address), 137))
            response, source = sock.recvfrom(4_096)
        except (OSError, socket.timeout):
            return "", ""
    if source[0] != str(address):
        return "", ""
    return parse_netbios_node_status(response, transaction_id)


def _contains(value: str, tokens: tuple[str, ...]) -> bool:
    return any(token in value for token in tokens)


def _name_classification(name: str) -> tuple[str, str] | None:
    normalized = name.lower().replace("_", "-")
    if _contains(normalized, ("iphone", "ipad", "ipod")):
        return "Phone / tablet", "iOS or iPadOS (probable)"
    if _contains(
        normalized,
        ("android", "pixel", "galaxy", "redmi", "xiaomi", "poco", "oneplus", "oppo", "vivo"),
    ):
        return "Phone / tablet", "Android (probable)"
    if _contains(normalized, ("macbook", "imac", "mac-mini", "macmini")):
        return "Computer", "macOS (probable)"
    if _contains(normalized, ("chromebook", "chromeos")):
        return "Computer", "ChromeOS (probable)"
    if _contains(normalized, ("desktop-", "laptop-", "win-", "windows", "surface")):
        return "Computer", "Windows (probable)"
    if _contains(normalized, ("ubuntu", "debian", "fedora", "raspberrypi", "raspberry-pi")):
        return "Computer / server", "Linux (probable)"
    if _contains(
        normalized,
        ("printer", "brother", "epson", "laserjet", "deskjet", "officejet", "pixma"),
    ):
        return "Printer / multifunction device", "Embedded printer firmware"
    if _contains(normalized, ("synology", "diskstation", "qnap", "truenas")):
        return "Network storage", "NAS operating system (probable)"
    if _contains(
        normalized,
        (
            "router",
            "gateway",
            "openwrt",
            "mikrotik",
            "ubnt",
            "unifi",
            "tp-link",
            "tplink",
            "deco",
            "archer",
        ),
    ):
        return "Router / access point", "Network appliance OS (probable)"
    if _contains(normalized, ("camera", "ipcam", "nvr", "dvr", "hikvision", "dahua")):
        return "Camera / video recorder", "Embedded firmware"
    if _contains(
        normalized,
        ("smarttv", "smart-tv", "chromecast", "firetv", "fire-tv", "appletv", "apple-tv", "roku"),
    ):
        return "TV / media device", "Embedded or TV operating system"
    return None


def infer_device_identity(
    ip_address: str,
    *,
    ttl: int | None,
    hostname: str = "",
    netbios_name: str = "",
    mac_address: str = "",
) -> DeviceIdentity:
    resolved_hostname = _usable_hostname(hostname)
    resolved_netbios = _usable_hostname(netbios_name)
    resolved_mac = _valid_mac(mac_address)
    device_name = resolved_hostname or resolved_netbios or "Unresolved"
    classified = _name_classification(device_name)

    evidence = []
    if resolved_hostname:
        evidence.append(f"Reverse DNS: {resolved_hostname}")
    if resolved_netbios:
        evidence.append(f"NetBIOS: {resolved_netbios}")
    if ttl is not None:
        evidence.append(f"Observed TTL: {ttl}")
    if resolved_mac:
        evidence.append(f"Local MAC evidence: {resolved_mac}")

    if classified:
        device_type, operating_system = classified
        confidence = "High" if ttl is not None or resolved_netbios else "Medium"
    elif resolved_netbios:
        device_type = "Computer / server"
        operating_system = "Windows (probable)"
        confidence = "High"
    elif ttl is None:
        device_type = "Unclassified device"
        operating_system = "Unknown"
        confidence = "Low"
    elif ttl <= 64:
        device_type = "Computer, mobile, or network device"
        operating_system = "Linux/Unix-like or embedded (possible)"
        confidence = "Low"
    elif ttl <= 128:
        device_type = "Computer or server"
        operating_system = "Windows-like (possible)"
        confidence = "Low"
    else:
        device_type = "Network device or appliance"
        operating_system = "Network appliance or unknown"
        confidence = "Low"

    return DeviceIdentity(
        device_name=device_name,
        hostname=resolved_hostname,
        device_type=device_type,
        operating_system=operating_system,
        confidence=confidence,
        evidence="; ".join(evidence)[:500] or "No naming or OS fingerprint evidence returned.",
        mac_address=resolved_mac,
        ttl=ttl,
    )


def discover_device_identity(
    ip_address: str,
    *,
    ttl: int | None,
    hostname: str | None = None,
) -> DeviceIdentity:
    try:
        resolved_hostname = reverse_hostname(ip_address) if hostname is None else hostname
    except (OSError, ValueError):  # pragma: no cover - platform resolver variance
        resolved_hostname = ""
    try:
        netbios_name, netbios_mac = query_netbios_identity(ip_address)
    except (OSError, TypeError, ValueError):  # pragma: no cover - optional local evidence
        netbios_name, netbios_mac = "", ""
    try:
        neighbor_mac = neighbor_mac_address(ip_address)
    except (OSError, UnicodeError):  # pragma: no cover - optional local evidence
        neighbor_mac = ""
    mac_address = netbios_mac or neighbor_mac
    return infer_device_identity(
        ip_address,
        ttl=ttl,
        hostname=resolved_hostname,
        netbios_name=netbios_name,
        mac_address=mac_address,
    )
