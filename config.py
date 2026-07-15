"""Configuration for NetWatch."""

from __future__ import annotations

import os

APP_NAME = "NetWatch"
APP_VERSION = "1.5.0"

MAX_HOSTS_PER_SCAN = 256
MAX_WORKERS = 64
MAX_INVENTORY_ROWS = 2_000
MAX_ASSET_EVENTS = 5_000
MAX_NETWORK_OBSERVATIONS = 50_000
MAX_AUDIT_LOG_ENTRIES = 10_000
MAX_OPERATION_ALERTS = 5_000
MAX_SCAN_POLICIES = 50
MAX_MAINTENANCE_WINDOWS = 100
MAX_INTELLIGENCE_EVENTS = 1_000
MAINTENANCE_MAX_DURATION_DAYS = 31
SCAN_POLICY_MIN_INTERVAL_MINUTES = 15
SCAN_POLICY_MAX_INTERVAL_MINUTES = 10_080
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


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "true" if default else "false").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    return default


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
SCHEDULER_ENABLED = _env_bool("NETWATCH_SCHEDULER_ENABLED", False)
SCHEDULER_POLL_SECONDS = _env_int("NETWATCH_SCHEDULER_POLL_SECONDS", 30, minimum=5, maximum=300)
AI_ENABLED = _env_bool("NETWATCH_AI_ENABLED", True)
AI_MODEL = os.getenv("NETWATCH_AI_MODEL", "gpt-5.6-luna").strip() or "gpt-5.6-luna"
AI_TIMEOUT_SECONDS = _env_int("NETWATCH_AI_TIMEOUT_SECONDS", 25, minimum=5, maximum=60)
AI_MAX_OUTPUT_TOKENS = _env_int("NETWATCH_AI_MAX_OUTPUT_TOKENS", 1_200, minimum=256, maximum=4_000)
AI_MAX_CONCURRENT_REQUESTS = _env_int(
    "NETWATCH_AI_MAX_CONCURRENT_REQUESTS", 2, minimum=1, maximum=8
)
AI_RATE_LIMIT_REQUESTS = _env_int("NETWATCH_AI_RATE_LIMIT_REQUESTS", 5, minimum=1, maximum=100)
AI_RATE_LIMIT_WINDOW_SECONDS = _env_int(
    "NETWATCH_AI_RATE_LIMIT_WINDOW_SECONDS", 600, minimum=60, maximum=86_400
)
AI_DAILY_REQUEST_LIMIT = _env_int("NETWATCH_AI_DAILY_REQUEST_LIMIT", 50, minimum=1, maximum=10_000)
AI_CACHE_TTL_SECONDS = _env_int("NETWATCH_AI_CACHE_TTL_SECONDS", 900, minimum=60, maximum=86_400)

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
