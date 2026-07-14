from __future__ import annotations

import os
import secrets
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env"
MIN_API_KEY_LENGTH = 32
DEFAULTS = {
    "NETWATCH_OPERATOR_KEY": "",
    "NETWATCH_VIEWER_KEY": "",
    "NETWATCH_ALLOWED_HOSTS": "127.0.0.1,localhost",
    "NETWATCH_ALLOWED_ORIGINS": "http://127.0.0.1:8000,http://localhost:8000",
    "NETWATCH_API_DOCS": "false",
    "NETWATCH_MAX_CONCURRENT_SCANS": "1",
    "NETWATCH_RATE_LIMIT_REQUESTS": "30",
    "NETWATCH_RATE_LIMIT_WINDOW_SECONDS": "60",
    "NETWATCH_PORT_SCAN_WORKERS": "12",
    "NETWATCH_SCHEDULER_ENABLED": "false",
    "NETWATCH_SCHEDULER_POLL_SECONDS": "30",
}


def read_env() -> dict[str, str]:
    values: dict[str, str] = {}
    if not ENV_FILE.exists():
        return values
    for raw_line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        clean_key = key.strip()
        if clean_key:
            values[clean_key] = value.strip()
    return values


def write_env(values: dict[str, str]) -> None:
    preferred = ["NETWATCH_API_KEY", *DEFAULTS.keys()]
    extras = sorted(key for key in values if key not in preferred)
    ordered = [key for key in preferred if key in values] + extras
    lines = ["# Local NetWatch settings. Do not commit this file."]
    lines.extend(f"{key}={values[key]}" for key in ordered)
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(ENV_FILE, 0o600)
    except (OSError, NotImplementedError):
        # Some Windows and mounted filesystems do not support POSIX modes.
        pass


def ensure_configuration() -> str:
    values = read_env()
    current_key = values.get("NETWATCH_API_KEY", "")
    if len(current_key) < MIN_API_KEY_LENGTH or current_key == "replace-with-a-long-random-secret":
        values["NETWATCH_API_KEY"] = secrets.token_urlsafe(32)
    for key, default in DEFAULTS.items():
        values.setdefault(key, default)
    write_env(values)
    return values["NETWATCH_API_KEY"]


def run(command: list[str]) -> None:
    subprocess.run(command, cwd=ROOT, check=True)


def main() -> int:
    api_key = ensure_configuration()
    try:
        run(["docker", "compose", "version"])
        run(["docker", "compose", "up", "-d", "--build", "netwatch"])
    except FileNotFoundError:
        print(
            "Docker was not found. Install Docker Desktop or Docker Engine first.", file=sys.stderr
        )
        return 1
    except subprocess.CalledProcessError as exc:
        print(f"Docker command failed with exit code {exc.returncode}.", file=sys.stderr)
        return exc.returncode

    print("\nNetWatch is ready.")
    print("URL:     http://127.0.0.1:8000")
    print(f"Admin key: {api_key}")
    print("The key is stored in .env and is required by the dashboard connection screen.")
    print("Optional Operator and Viewer keys can also be configured in .env.")
    print("Scheduled policy execution is opt-in with NETWATCH_SCHEDULER_ENABLED=true.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
