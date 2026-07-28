from __future__ import annotations

import csv
import ipaddress
import os
import platform
import re
import secrets
import socket
import struct
import subprocess
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

_MAC_PATTERN = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_MAC_INLINE_PATTERN = re.compile(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_VENDOR_DATABASE_MAX_BYTES = 32 * 1024 * 1024
_VENDOR_DATABASE_MAX_ENTRIES = 100_000
_STANDARD_VENDOR_DATABASES = (
    "/usr/share/ieee-data/oui.csv",
    "/usr/share/ieee-data/oui.txt",
    "/usr/share/nmap/nmap-mac-prefixes",
    "/usr/local/share/nmap/nmap-mac-prefixes",
    "/usr/share/misc/oui.txt",
)


@dataclass(frozen=True)
class DeviceIdentity:
    device_name: str
    hostname: str
    device_type: str
    manufacturer: str
    device_model: str
    operating_system: str
    confidence: str
    evidence: str
    mac_address: str
    mac_address_type: str
    ttl: int | None

    def as_scan_fields(self) -> dict[str, object]:
        return {
            "Device Name": self.device_name,
            "Hostname": self.hostname or "-",
            "Device Type": self.device_type,
            "Manufacturer": self.manufacturer,
            "Device Model": self.device_model,
            "Operating System": self.operating_system,
            "Identity Confidence": self.confidence,
            "Identity Evidence": self.evidence,
            "MAC Address": self.mac_address or "-",
            "MAC Address Type": self.mac_address_type,
            "TTL": self.ttl if self.ttl is not None else "-",
        }


@dataclass(frozen=True)
class _NameProfile:
    device_type: str
    operating_system: str
    manufacturer: str
    device_model: str


def _safe_text(value: object, max_length: int = 253) -> str:
    cleaned = _CONTROL_CHARACTERS.sub("", str(value or "")).strip().rstrip(".")
    return cleaned[:max_length]


def _usable_hostname(value: object) -> str:
    candidate = _safe_text(value)
    if not candidate or candidate.lower() in {"-", "unknown", "unresolved"}:
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
    candidate = _safe_text(value, 17).replace("-", ":").upper()
    if not _MAC_PATTERN.fullmatch(candidate) or candidate == "00:00:00:00:00:00":
        return ""
    first_octet = int(candidate[:2], 16)
    if first_octet & 0x01:
        return ""
    return candidate


def mac_address_type(mac_address: str) -> str:
    normalized = _valid_mac(mac_address)
    if not normalized:
        return "Unavailable"
    if int(normalized[:2], 16) & 0x02:
        return "Private / randomized"
    return "Globally assigned"


def _linux_route_is_direct(ip_address: str) -> bool:
    """Return False when Linux reaches the target through a gateway.

    Container bridges can proxy ARP for remote LAN targets. Treating that bridge
    MAC as the endpoint MAC would assign the same false identity to every device.
    """

    try:
        target = int(ipaddress.IPv4Address(ip_address))
        rows = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
    except (OSError, UnicodeError, ValueError):
        return True

    best_prefix = -1
    selected_gateway: int | None = None
    for row in rows:
        fields = row.split()
        if len(fields) < 8:
            continue
        try:
            destination = int.from_bytes(bytes.fromhex(fields[1]), "little")
            gateway = int.from_bytes(bytes.fromhex(fields[2]), "little")
            flags = int(fields[3], 16)
            mask = int.from_bytes(bytes.fromhex(fields[7]), "little")
        except (ValueError, OverflowError):
            continue
        if not flags & 0x01 or target & mask != destination & mask:
            continue
        prefix = mask.bit_count()
        if prefix > best_prefix:
            best_prefix = prefix
            selected_gateway = gateway

    if selected_gateway is None:
        return True
    return selected_gateway == 0 or selected_gateway == target


def _linux_arp_cache_mac(ip_address: str) -> str:
    try:
        rows = Path("/proc/net/arp").read_text(encoding="utf-8").splitlines()[1:]
    except (OSError, UnicodeError):
        return ""
    for row in rows:
        fields = row.split()
        if len(fields) < 4 or fields[0] != ip_address:
            continue
        try:
            complete = bool(int(fields[2], 16) & 0x02)
        except ValueError:
            complete = False
        return _valid_mac(fields[3]) if complete else ""
    return ""


def _arp_command(ip_address: str) -> list[str]:
    system = platform.system().lower()
    if system == "windows":
        return ["arp", "-a", ip_address]
    if system in {"darwin", "freebsd", "openbsd", "netbsd"}:
        return ["arp", "-n", ip_address]
    return ["arp", "-n", ip_address]


def _system_arp_mac(ip_address: str, timeout: float = 0.75) -> str:
    try:
        result = subprocess.run(
            _arp_command(ip_address),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=max(0.1, min(float(timeout), 2.0)),
            check=False,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        return ""
    for match in _MAC_INLINE_PATTERN.findall(result.stdout):
        normalized = _valid_mac(match)
        if normalized:
            return normalized
    return ""


def neighbor_mac_address(ip_address: str) -> str:
    """Return a same-segment endpoint MAC without mislabeling routed targets."""

    try:
        address = ipaddress.ip_address(ip_address)
    except ValueError:
        return ""
    if not isinstance(address, ipaddress.IPv4Address) or not (
        address.is_private or address.is_loopback or address.is_link_local
    ):
        return ""
    if platform.system().lower() == "linux":
        if not _linux_route_is_direct(str(address)):
            return ""
        cached = _linux_arp_cache_mac(str(address))
        if cached:
            return cached
    return _system_arp_mac(str(address))


def _normalize_vendor_prefix(value: object) -> str:
    normalized = re.sub(r"[^0-9A-Fa-f]", "", str(value or "")).upper()
    return normalized if len(normalized) in {6, 7, 9} else ""


@lru_cache(maxsize=8)
def _load_vendor_prefixes(path_text: str) -> dict[str, str]:
    path = Path(path_text)
    try:
        if not path.is_file() or path.stat().st_size > _VENDOR_DATABASE_MAX_BYTES:
            return {}
        contents = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}

    prefixes: dict[str, str] = {}
    first_line = contents.splitlines()[0] if contents else ""
    if "Assignment" in first_line and "Organization Name" in first_line:
        for row in csv.DictReader(contents.splitlines()):
            prefix = _normalize_vendor_prefix(row.get("Assignment"))
            vendor = _safe_text(row.get("Organization Name"), 120)
            if prefix and vendor:
                prefixes[prefix] = vendor
            if len(prefixes) >= _VENDOR_DATABASE_MAX_ENTRIES:
                break
        return prefixes

    for line in contents.splitlines():
        nmap_match = re.match(r"^\s*([0-9A-Fa-f]{6})\s+(.+?)\s*$", line)
        ieee_match = re.match(
            r"^\s*([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){2})\s+" r"\((?:hex|base 16)\)\s+(.+?)\s*$",
            line,
            flags=re.IGNORECASE,
        )
        match = ieee_match or nmap_match
        if not match:
            continue
        prefix = _normalize_vendor_prefix(match.group(1))
        vendor = _safe_text(match.group(2), 120)
        if prefix and vendor:
            prefixes[prefix] = vendor
        if len(prefixes) >= _VENDOR_DATABASE_MAX_ENTRIES:
            break
    return prefixes


def _vendor_database_paths(configured_path: str | None = None) -> tuple[str, ...]:
    candidates = [
        configured_path or "",
        os.getenv("NETWATCH_OUI_DATABASE", "").strip(),
        *_STANDARD_VENDOR_DATABASES,
    ]
    seen: set[str] = set()
    paths = []
    for candidate in candidates:
        if not candidate:
            continue
        normalized = str(Path(candidate).expanduser())
        if normalized not in seen:
            seen.add(normalized)
            paths.append(normalized)
    return tuple(paths)


def resolve_mac_vendor(mac_address: str, database_path: str | None = None) -> str:
    """Resolve a global MAC locally; private/randomized addresses are never guessed."""

    normalized = _valid_mac(mac_address)
    if not normalized or mac_address_type(normalized) != "Globally assigned":
        return ""
    compact = normalized.replace(":", "")
    for path in _vendor_database_paths(database_path):
        prefixes = _load_vendor_prefixes(path)
        for prefix_length in (9, 7, 6):
            vendor = prefixes.get(compact[:prefix_length])
            if vendor:
                return vendor
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


def _model_family(name: str, token: str, label: str) -> str:
    words = re.findall(r"[A-Za-z0-9+]+", name.replace(".local", "", 1), flags=re.IGNORECASE)
    lowered = [word.lower() for word in words]
    try:
        index = lowered.index(token)
    except ValueError:
        return f"{label} family"
    suffix = words[index + 1 : index + 5]
    return " ".join([label, *suffix])[:80] if suffix else f"{label} family"


def _name_classification(name: str) -> _NameProfile | None:
    normalized = name.lower().replace("_", "-")
    if "iphone" in normalized:
        return _NameProfile(
            "Phone / tablet", "iOS (probable)", "Apple", _model_family(name, "iphone", "iPhone")
        )
    if "ipad" in normalized:
        return _NameProfile(
            "Phone / tablet",
            "iPadOS (probable)",
            "Apple",
            _model_family(name, "ipad", "iPad"),
        )
    if "ipod" in normalized:
        return _NameProfile(
            "Media device", "iOS (probable)", "Apple", _model_family(name, "ipod", "iPod")
        )
    if "pixel" in normalized:
        return _NameProfile(
            "Phone / tablet",
            "Android (probable)",
            "Google",
            _model_family(name, "pixel", "Pixel"),
        )
    if "galaxy" in normalized:
        return _NameProfile(
            "Phone / tablet",
            "Android (probable)",
            "Samsung",
            _model_family(name, "galaxy", "Galaxy"),
        )
    samsung_model = re.search(r"\bSM-[A-Z0-9-]{3,20}\b", name, flags=re.IGNORECASE)
    if samsung_model:
        return _NameProfile(
            "Phone / tablet",
            "Android (probable)",
            "Samsung",
            samsung_model.group(0).upper(),
        )
    for token, label, manufacturer in (
        ("redmi", "Redmi", "Xiaomi"),
        ("xiaomi", "Xiaomi", "Xiaomi"),
        ("poco", "POCO", "Xiaomi"),
        ("oneplus", "OnePlus", "OnePlus"),
        ("oppo", "OPPO", "OPPO"),
        ("vivo", "vivo", "vivo"),
    ):
        if token in normalized:
            return _NameProfile(
                "Phone / tablet",
                "Android (probable)",
                manufacturer,
                _model_family(name, token, label),
            )
    if "android" in normalized:
        return _NameProfile("Phone / tablet", "Android (probable)", "Unknown", "Android device")
    if _contains(normalized, ("macbook", "imac", "mac-mini", "macmini")):
        label = "MacBook" if "macbook" in normalized else "Mac"
        return _NameProfile("Computer", "macOS (probable)", "Apple", f"{label} family")
    if _contains(normalized, ("chromebook", "chromeos")):
        return _NameProfile("Computer", "ChromeOS (probable)", "Unknown", "Chromebook")
    if _contains(normalized, ("desktop-", "laptop-", "win-", "windows", "surface")):
        manufacturer = "Microsoft" if "surface" in normalized else "Unknown"
        model = "Surface family" if "surface" in normalized else "Windows computer"
        return _NameProfile("Computer", "Windows (probable)", manufacturer, model)
    if _contains(normalized, ("ubuntu", "debian", "fedora", "raspberrypi", "raspberry-pi")):
        manufacturer = "Raspberry Pi" if "raspberry" in normalized else "Unknown"
        return _NameProfile("Computer / server", "Linux (probable)", manufacturer, "Linux device")
    if _contains(
        normalized,
        ("printer", "brother", "epson", "laserjet", "deskjet", "officejet", "pixma"),
    ):
        manufacturer = next(
            (
                label
                for token, label in (
                    ("brother", "Brother"),
                    ("epson", "Epson"),
                    ("laserjet", "HP"),
                    ("deskjet", "HP"),
                    ("officejet", "HP"),
                    ("pixma", "Canon"),
                )
                if token in normalized
            ),
            "Unknown",
        )
        return _NameProfile(
            "Printer / multifunction device",
            "Embedded printer firmware",
            manufacturer,
            "Printer family",
        )
    if _contains(normalized, ("synology", "diskstation", "qnap", "truenas")):
        manufacturer = "Synology" if _contains(normalized, ("synology", "diskstation")) else "QNAP"
        if "truenas" in normalized:
            manufacturer = "Unknown"
        return _NameProfile(
            "Network storage", "NAS operating system (probable)", manufacturer, "NAS appliance"
        )
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
        manufacturer = next(
            (
                label
                for token, label in (
                    ("mikrotik", "MikroTik"),
                    ("ubnt", "Ubiquiti"),
                    ("unifi", "Ubiquiti"),
                    ("tp-link", "TP-Link"),
                    ("tplink", "TP-Link"),
                    ("deco", "TP-Link"),
                    ("archer", "TP-Link"),
                )
                if token in normalized
            ),
            "Unknown",
        )
        return _NameProfile(
            "Router / access point",
            "Network appliance OS (probable)",
            manufacturer,
            "Network appliance",
        )
    if _contains(normalized, ("camera", "ipcam", "nvr", "dvr", "hikvision", "dahua")):
        manufacturer = (
            "Hikvision"
            if "hikvision" in normalized
            else ("Dahua" if "dahua" in normalized else "Unknown")
        )
        return _NameProfile(
            "Camera / video recorder", "Embedded firmware", manufacturer, "Video device"
        )
    if _contains(
        normalized,
        ("smarttv", "smart-tv", "chromecast", "firetv", "fire-tv", "appletv", "apple-tv", "roku"),
    ):
        manufacturer = next(
            (
                label
                for token, label in (
                    ("chromecast", "Google"),
                    ("firetv", "Amazon"),
                    ("fire-tv", "Amazon"),
                    ("appletv", "Apple"),
                    ("apple-tv", "Apple"),
                    ("roku", "Roku"),
                )
                if token in normalized
            ),
            "Unknown",
        )
        return _NameProfile(
            "TV / media device",
            "Embedded or TV operating system",
            manufacturer,
            "Media device",
        )
    return None


def infer_device_identity(
    ip_address: str,
    *,
    ttl: int | None,
    hostname: str = "",
    netbios_name: str = "",
    mac_address: str = "",
    vendor_database_path: str | None = None,
) -> DeviceIdentity:
    resolved_hostname = _usable_hostname(hostname)
    resolved_netbios = _usable_hostname(netbios_name)
    resolved_mac = _valid_mac(mac_address)
    resolved_mac_type = mac_address_type(resolved_mac)
    device_name = resolved_hostname or resolved_netbios or "Unresolved"
    classified = _name_classification(device_name)
    mac_vendor = resolve_mac_vendor(resolved_mac, vendor_database_path)

    evidence = []
    if resolved_hostname:
        evidence.append(f"Reverse DNS: {resolved_hostname}")
    if resolved_netbios:
        evidence.append(f"NetBIOS: {resolved_netbios}")
    if ttl is not None:
        evidence.append(f"Observed TTL: {ttl}")
    if resolved_mac:
        evidence.append(f"Same-segment MAC: {resolved_mac}")
        evidence.append(f"MAC type: {resolved_mac_type}")
    if mac_vendor:
        evidence.append(f"Local OUI vendor: {mac_vendor}")
    elif resolved_mac_type == "Private / randomized":
        evidence.append("OUI vendor unavailable because the MAC is private/randomized")

    if classified:
        device_type = classified.device_type
        operating_system = classified.operating_system
        manufacturer = (
            classified.manufacturer
            if classified.manufacturer != "Unknown"
            else (mac_vendor or "Unknown")
        )
        device_model = classified.device_model
        confidence = "High" if ttl is not None or resolved_netbios else "Medium"
    elif resolved_netbios:
        device_type = "Computer / server"
        operating_system = "Windows (probable)"
        manufacturer = mac_vendor or "Unknown"
        device_model = "Model unavailable"
        confidence = "High"
    elif ttl is None:
        device_type = "Unclassified device"
        operating_system = "Unknown"
        manufacturer = mac_vendor or "Unknown"
        device_model = "Model unavailable"
        confidence = "Medium" if mac_vendor else "Low"
    elif ttl <= 64:
        device_type = "Computer, mobile, or network device"
        operating_system = "Linux/Unix-like or embedded (possible)"
        manufacturer = mac_vendor or "Unknown"
        device_model = "Model unavailable"
        confidence = "Low"
    elif ttl <= 128:
        device_type = "Computer or server"
        operating_system = "Windows-like (possible)"
        manufacturer = mac_vendor or "Unknown"
        device_model = "Model unavailable"
        confidence = "Low"
    else:
        device_type = "Network device or appliance"
        operating_system = "Network appliance or unknown"
        manufacturer = mac_vendor or "Unknown"
        device_model = "Model unavailable"
        confidence = "Low"

    return DeviceIdentity(
        device_name=device_name,
        hostname=resolved_hostname,
        device_type=device_type,
        manufacturer=manufacturer,
        device_model=device_model,
        operating_system=operating_system,
        confidence=confidence,
        evidence="; ".join(evidence)[:750] or "No naming or OS fingerprint evidence returned.",
        mac_address=resolved_mac,
        mac_address_type=resolved_mac_type,
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
