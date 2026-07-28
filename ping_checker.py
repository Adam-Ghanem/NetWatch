from __future__ import annotations

import platform
import re
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
            output = f"{result.stdout}\n{result.stderr}"
            evidence = ["Host is online"]
            ttl_match = re.search(r"ttl[= ]([0-9]+)", output, flags=re.IGNORECASE)
            latency_match = re.search(
                r"time[=<]([0-9]+(?:\.[0-9]+)?)\s*ms",
                output,
                flags=re.IGNORECASE,
            )
            if ttl_match:
                evidence.append(f"TTL={ttl_match.group(1)}")
            if latency_match:
                evidence.append(f"latency={latency_match.group(1)} ms")
            return True, "; ".join(evidence)
        message = result.stderr.strip() or "Host is offline or blocking ICMP"
        return False, message
    except subprocess.TimeoutExpired:
        return False, "Ping request timed out"
    except Exception as exc:  # pragma: no cover
        return False, f"Ping error: {exc}"
