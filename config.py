"""Basic configuration for NetWatch."""

APP_NAME = "NetWatch"
APP_VERSION = "0.4.0"

MAX_HOSTS_PER_SCAN = 256
MAX_WORKERS = 64
DEFAULT_TIMEOUT = 0.6

# Common services checked by the app. The list is intentionally short
# because this project is for local/admin practice, not aggressive scanning.
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
