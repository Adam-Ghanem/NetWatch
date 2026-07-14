"""Configuration for NetWatch."""

from __future__ import annotations

import os

APP_NAME = "NetWatch"
APP_VERSION = "1.1.0"

MAX_HOSTS_PER_SCAN = 256
MAX_WORKERS = 64
MAX_INVENTORY_ROWS = 2_000
MAX_ASSET_EVENTS = 5_000
MAX_NETWORK_OBSERVATIONS = 50_000
DEFAULT_TIMEOUT = 0.6
MIN_API_KEY_LENGTH = 32
DEFAULT_API_KEY_PLACEHOLDER = "replace-with-a-long-random-secret"


def _env_int(
    name: str,
    default: int,
    minimum: int = 1,
    maximum: int | None = None,
) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
        value = int(raw)
    except ValueError:
        value = default
    value = max(minimum, value)
    return min(value, maximum) if maximum is not None else value


def _env_csv(name: str, defaults: tuple[str, ...]) -> tuple[str, ...]:
    values = tuple(
        value.strip()
        for value in os.getenv(name, ",".join(defaults)).split(",")
        if value.strip() and value.strip() != "*"
    )
    return values or defaults


API_ALLOWED_ORIGINS = _env_csv(
    "NETWATCH_ALLOWED_ORIGINS",
    ("http://127.0.0.1:8000", "http://localhost:8000"),
)
API_ALLOWED_HOSTS = _env_csv(
    "NETWATCH_ALLOWED_HOSTS",
    ("127.0.0.1", "localhost"),
)
API_DOCS_ENABLED = os.getenv("NETWATCH_API_DOCS", "false").strip().lower() in {"1", "true", "yes"}
API_RATE_LIMIT_REQUESTS = _env_int("NETWATCH_RATE_LIMIT_REQUESTS", 30, maximum=1_000)
API_RATE_LIMIT_WINDOW_SECONDS = _env_int("NETWATCH_RATE_LIMIT_WINDOW_SECONDS", 60, maximum=3_600)
MAX_CONCURRENT_SCANS = _env_int("NETWATCH_MAX_CONCURRENT_SCANS", 1, maximum=8)
PORT_SCAN_WORKERS = _env_int("NETWATCH_PORT_SCAN_WORKERS", 12, maximum=MAX_WORKERS)

COMMON_PORTS = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP Alternate",
}

HIGH_RISK_PORTS = {21, 23, 445, 3389, 3306, 5432}
MEDIUM_RISK_PORTS = {22, 25, 53, 80, 110, 143, 8080}
