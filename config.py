"""Runtime configuration for NetWatch."""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "NetWatch"
APP_VERSION = "0.8.0"

PROJECT_ROOT = Path(__file__).resolve().parent


def _runtime_path(variable: str, default: str) -> Path:
    configured = Path(os.getenv(variable, default)).expanduser()
    if configured.is_absolute():
        return configured
    return PROJECT_ROOT / configured


DATA_DIR = _runtime_path("NETWATCH_DATA_DIR", "data")
LOG_DIR = _runtime_path("NETWATCH_LOG_DIR", "logs")

DEFAULT_CORS_ORIGINS = (
    "http://127.0.0.1:5500",
    "http://localhost:5500",
)
DEFAULT_API_HOSTS = ("127.0.0.1", "localhost", "testserver")


def api_cors_origins() -> list[str]:
    """Return explicit browser origins; wildcard CORS is never enabled."""
    raw = os.getenv("NETWATCH_CORS_ORIGINS", ",".join(DEFAULT_CORS_ORIGINS))
    origins = [origin.strip().rstrip("/") for origin in raw.split(",")]
    return [origin for origin in origins if origin and origin != "*"] or list(
        DEFAULT_CORS_ORIGINS
    )


def api_allowed_hosts() -> list[str]:
    """Return explicit Host header values accepted by the local API."""
    raw = os.getenv("NETWATCH_API_HOSTS", ",".join(DEFAULT_API_HOSTS))
    hosts = [host.strip() for host in raw.split(",")]
    return [host for host in hosts if host and host != "*"] or list(DEFAULT_API_HOSTS)


MAX_HOSTS_PER_SCAN = 256
MAX_WORKERS = 64
DEFAULT_TIMEOUT = 0.6
MAX_HISTORY_LIMIT = 200
MAX_INVENTORY_LIMIT = 2_000

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
