from __future__ import annotations

import platform
import subprocess
from typing import Tuple

from security import validate_target_ip


def _ping_command(ip: str, timeout: int) -> list[str]:
    system = platform.system().lower()
    if system == "windows":
        return ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
    return ["ping", "-c", "1", "-W", str(timeout), ip]


def ping_host_raw(ip: str, timeout: int = 3) -> subprocess.CompletedProcess[str]:
    """Run one validated local ping and return the raw process result."""
    validation = validate_target_ip(ip)
    if not validation.ok:
        return subprocess.CompletedProcess(
            args=["ping", ip],
            returncode=2,
            stdout="",
            stderr=validation.error or "Invalid target",
        )

    target = validation.value or ip.strip()
    command = _ping_command(target, timeout)
    return subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=timeout + 2,
        check=False,
    )


def ping_host(ip: str, timeout: int = 3) -> Tuple[bool, str]:
    """Ping a validated local/private IP once and return (is_online, message)."""
    try:
        result = ping_host_raw(ip, timeout=timeout)
        if result.returncode == 0:
            return True, "Host is online"
        message = result.stderr.strip() or "Host is offline or blocking ICMP"
        return False, message
    except subprocess.TimeoutExpired:
        return False, "Ping request timed out"
    except Exception as exc:  # pragma: no cover
        return False, f"Ping error: {exc}"
