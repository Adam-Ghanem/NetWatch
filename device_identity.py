from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
from dataclasses import asdict, dataclass
from functools import lru_cache
from typing import Iterable

from netaddr import EUI
from netaddr.core import NotRegisteredError

_MAC_PATTERN = re.compile(r"^[0-9A-F]{12}$")
_MAC_INPUT_PATTERN = re.compile(r"^[0-9A-Fa-f:.-]+$")
_SAFE_HOSTNAME_PATTERN = re.compile(r"[^A-Za-z0-9._ -]+")
_UNUSABLE_NEIGHBOR_STATES = {"FAILED", "INCOMPLETE", "NOARP"}


@dataclass(frozen=True)
class NeighborEntry:
    ip_address: str
    mac_address: str
    interface: str
    state: str
    source: str


@dataclass(frozen=True)
class DeviceIdentity:
    hostname: str
    mac_address: str
    manufacturer: str
    device_name: str
    device_type: str
    device_family: str
    identity_confidence: str
    identity_source: str
    randomized_mac: bool

    def as_dict(self) -> dict[str, object]:
        return asdict(self)

    def as_scan_fields(self) -> dict[str, object]:
        return {
            "Hostname": self.hostname,
            "MAC Address": self.mac_address,
            "Manufacturer": self.manufacturer,
            "Device Name": self.device_name,
            "Device Type": self.device_type,
            "Device Family": self.device_family,
            "Identity Confidence": self.identity_confidence,
            "Identity Source": self.identity_source,
            "Randomized MAC": self.randomized_mac,
        }


def normalize_mac(value: object) -> str:
    raw = str(value or "").strip()
    if not raw or not _MAC_INPUT_PATTERN.fullmatch(raw):
        return ""
    compact = re.sub(r"[:.-]", "", raw).upper()
    if not _MAC_PATTERN.fullmatch(compact):
        return ""
    octets = [compact[index : index + 2] for index in range(0, 12, 2)]
    if octets == ["00"] * 6 or octets == ["FF"] * 6:
        return ""
    first_octet = int(octets[0], 16)
    if first_octet & 1:
        return ""
    return ":".join(octets)


def is_locally_administered_mac(mac_address: object) -> bool:
    normalized = normalize_mac(mac_address)
    return bool(normalized and int(normalized[:2], 16) & 2)


def _safe_hostname(value: object) -> str:
    hostname = " ".join(str(value or "").strip().split())
    hostname = _SAFE_HOSTNAME_PATTERN.sub("", hostname)[:120]
    return "" if hostname in {"", "-"} else hostname


@lru_cache(maxsize=4_096)
def _registered_manufacturer(normalized_mac: str) -> str:
    try:
        organization = str(EUI(normalized_mac).oui.registration().org).strip()
    except (NotRegisteredError, ValueError):
        return "Unknown"
    return " ".join(organization.split())[:160] or "Unknown"


def manufacturer_for_mac(mac_address: object) -> str:
    normalized = normalize_mac(mac_address)
    if not normalized:
        return "Unknown"
    if is_locally_administered_mac(normalized):
        return "Private / randomized"
    return _registered_manufacturer(normalized)


def infer_device_identity(
    mac_address: object = "",
    hostname: object = "",
    *,
    manufacturer: object = "",
) -> DeviceIdentity:
    normalized_mac = normalize_mac(mac_address)
    safe_hostname = _safe_hostname(hostname)
    randomized = is_locally_administered_mac(normalized_mac)
    vendor = " ".join(str(manufacturer or "").split())[:160]
    if not vendor or vendor == "Unknown":
        vendor = manufacturer_for_mac(normalized_mac)

    hostname_key = safe_hostname.lower()
    vendor_key = vendor.lower()
    device_name = safe_hostname
    device_type = "Unknown device"
    device_family = "Unknown"
    confidence = "Low"
    sources: list[str] = []

    hostname_rules: tuple[tuple[tuple[str, ...], str, str, str], ...] = (
        (("iphone",), "iPhone", "Mobile device", "Apple iPhone"),
        (("ipad",), "iPad", "Tablet", "Apple iPad"),
        (("macbook", "imac", "mac-mini", "mac mini"), "Mac", "Computer", "Apple Mac"),
        (("apple-tv", "appletv"), "Apple TV", "Media device", "Apple TV"),
        (("redmi",), "Redmi", "Mobile device", "Xiaomi Redmi"),
        (("xiaomi", "poco"), "Xiaomi / POCO", "Mobile device", "Xiaomi mobile device"),
        (("pixel",), "Google Pixel", "Mobile device", "Google Pixel"),
        (("galaxy",), "Samsung Galaxy", "Mobile device", "Samsung Galaxy"),
        (("printer", "epson", "laserjet", "deskjet"), "Network printer", "Printer", "Printer"),
        (("router", "gateway", "openwrt"), "Network gateway", "Network device", "Router"),
        (("camera", "cam-"), "IP camera", "Camera", "IP camera"),
    )
    for markers, name, kind, family in hostname_rules:
        if any(marker in hostname_key for marker in markers):
            device_name = safe_hostname or name
            device_type = kind
            device_family = family
            confidence = "High"
            sources.append("hostname")
            break

    if device_family == "Unknown":
        vendor_rules: tuple[tuple[tuple[str, ...], str, str, str], ...] = (
            (("apple",), "Apple device", "Personal device", "Apple device"),
            (("xiaomi", "beijing xiaomi"), "Xiaomi / Redmi device", "Personal device", "Xiaomi"),
            (("samsung",), "Samsung device", "Personal device", "Samsung"),
            (("google",), "Google device", "Personal device", "Google"),
            (("huawei", "honor"), "Huawei / Honor device", "Personal device", "Huawei"),
            (("oppo", "oneplus", "realme"), "OPPO family device", "Personal device", "OPPO"),
            (("tp-link", "tplink"), "TP-Link network device", "Network device", "TP-Link"),
            (("zte",), "ZTE network device", "Network device", "ZTE"),
            (("ubiquiti",), "Ubiquiti network device", "Network device", "Ubiquiti"),
            (("cisco",), "Cisco network device", "Network device", "Cisco"),
            (("intel", "dell", "lenovo", "hewlett", "asustek"), "Computer", "Computer", "Computer"),
            (("raspberry",), "Raspberry Pi", "Computer", "Raspberry Pi"),
            (("amazon",), "Amazon device", "IoT / media device", "Amazon"),
        )
        for markers, name, kind, family in vendor_rules:
            if any(marker in vendor_key for marker in markers):
                device_name = safe_hostname or name
                device_type = kind
                device_family = family
                confidence = "Medium"
                sources.append("MAC OUI")
                break

    if safe_hostname and "hostname" not in sources:
        device_name = safe_hostname
        confidence = "Medium" if device_family != "Unknown" else "Low"
        sources.insert(0, "hostname")
    if (
        normalized_mac
        and vendor not in {"Unknown", "Private / randomized"}
        and "MAC OUI" not in sources
    ):
        sources.append("MAC OUI")
    if randomized:
        sources.append("locally administered MAC")
        if device_family == "Unknown":
            device_name = safe_hostname or "Private-address device"
            device_type = "Personal device"
    elif normalized_mac and not sources:
        sources.append("neighbor table")

    return DeviceIdentity(
        hostname=safe_hostname or "-",
        mac_address=normalized_mac or "-",
        manufacturer=vendor or "Unknown",
        device_name=device_name or "Unknown device",
        device_type=device_type,
        device_family=device_family,
        identity_confidence=confidence,
        identity_source=", ".join(dict.fromkeys(sources)) or "insufficient evidence",
        randomized_mac=randomized,
    )


def parse_neighbor_output(output: str, source: str) -> list[NeighborEntry]:
    entries: list[NeighborEntry] = []
    seen: set[tuple[str, str]] = set()
    for raw_line in str(output or "").splitlines():
        line = " ".join(raw_line.split())
        if not line:
            continue

        ip_value = ""
        mac_value = ""
        interface = ""
        state = ""

        ip_neigh = re.search(
            r"^(?P<ip>\S+)\s+dev\s+(?P<iface>\S+).*?\blladdr\s+(?P<mac>[0-9A-Fa-f:.-]+)"
            r"(?:\s+(?P<state>[A-Z]+))?",
            line,
        )
        arp_unix = re.search(
            r"\((?P<ip>[^)]+)\)\s+at\s+(?P<mac>[0-9A-Fa-f:.-]+)" r"(?:.*?\bon\s+(?P<iface>\S+))?",
            line,
            flags=re.IGNORECASE,
        )
        arp_windows = re.search(
            r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+" r"(?P<mac>[0-9A-Fa-f-]{17})\s+(?P<state>\w+)$",
            line,
        )
        match = ip_neigh or arp_unix or arp_windows
        if match:
            values = match.groupdict()
            ip_value = values.get("ip") or ""
            mac_value = values.get("mac") or ""
            interface = values.get("iface") or ""
            state = (values.get("state") or "").upper()

        try:
            address = ipaddress.ip_address(ip_value)
        except ValueError:
            continue
        normalized_mac = normalize_mac(mac_value)
        if not isinstance(address, ipaddress.IPv4Address) or not normalized_mac:
            continue
        if state in _UNUSABLE_NEIGHBOR_STATES:
            continue
        key = (str(address), normalized_mac)
        if key in seen:
            continue
        seen.add(key)
        entries.append(
            NeighborEntry(
                ip_address=str(address),
                mac_address=normalized_mac,
                interface=interface[:64],
                state=state or "KNOWN",
                source=source[:40],
            )
        )
    return entries


def read_neighbor_table() -> list[NeighborEntry]:
    commands: tuple[tuple[tuple[str, ...], str], ...]
    if shutil.which("ip"):
        commands = ((("ip", "neigh", "show"), "ip-neigh"),)
    elif shutil.which("arp"):
        arp_arguments = ("arp", "-a") if os.name == "nt" else ("arp", "-an")
        commands = ((arp_arguments, "arp"),)
    else:
        return []
    entries: list[NeighborEntry] = []
    seen: set[tuple[str, str]] = set()
    for command, source in commands:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                check=False,
                text=True,
                timeout=2.0,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        for entry in parse_neighbor_output(result.stdout, source):
            key = (entry.ip_address, entry.mac_address)
            if key not in seen:
                seen.add(key)
                entries.append(entry)
        if entries:
            break
    return entries


def neighbor_map(entries: Iterable[NeighborEntry] | None = None) -> dict[str, NeighborEntry]:
    values = list(read_neighbor_table() if entries is None else entries)
    return {entry.ip_address: entry for entry in values}


def identity_for_ip(
    ip_address: str,
    *,
    hostname: object = "",
    entries: Iterable[NeighborEntry] | None = None,
) -> DeviceIdentity:
    try:
        target = str(ipaddress.IPv4Address(ip_address))
    except ValueError:
        return infer_device_identity(hostname=hostname)
    entry = neighbor_map(entries).get(target)
    return infer_device_identity(
        mac_address=entry.mac_address if entry else "",
        hostname=hostname,
    )


def enrich_host_rows(
    rows: Iterable[dict],
    *,
    entries: Iterable[NeighborEntry] | None = None,
) -> list[dict]:
    lookup = neighbor_map(entries)
    enriched: list[dict] = []
    for row in rows:
        item = dict(row)
        ip_address = str(item.get("IP Address", "")).strip()
        entry = lookup.get(ip_address)
        identity = infer_device_identity(
            entry.mac_address if entry else "",
            hostname=item.get("Hostname", ""),
        )
        item.update(identity.as_scan_fields())
        enriched.append(item)
    return enriched


def reverse_hostname(ip_address: str) -> str:
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
    except OSError:
        return "-"
    return _safe_hostname(hostname) or "-"
