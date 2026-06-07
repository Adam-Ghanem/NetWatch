from __future__ import annotations

import platform
import subprocess
from typing import Tuple

from security import validate_target_ip


def ping_host(ip: str, timeout: int = 3) -> Tuple[bool, str]:
    """Ping a validated local/private IP once and return (is_online, message)."""
    validation = validate_target_ip(ip)
    if not validation.ok:
        return False, validation.error or "Invalid target"

    target = validation.value or ip.strip()
    system = platform.system().lower()

    if system == "windows":
        command = ["ping", "-n", "1", "-w", str(timeout * 1000), target]
    else:
        command = ["ping", "-c", "1", "-W", str(timeout), target]

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout + 2,
            check=False,
        )
        if result.returncode == 0:
            return True, "Host is online"
        return False, "Host is offline or blocking ICMP"
    except subprocess.TimeoutExpired:
        return False, "Ping request timed out"
    except Exception as exc:  # pragma: no cover
        return False, f"Ping error: {exc}"
