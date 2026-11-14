"""Reject tracked environment files that may contain deployment credentials."""

from pathlib import PurePosixPath
import subprocess
import sys


def is_private_env_path(path: str) -> bool:
    """Detect root and nested dotenv variants; allow explicit templates."""
    name = PurePosixPath(path).name
    if name != ".env" and not name.startswith(".env."):
        return False
    return not name.endswith((".example", ".sample", ".template"))


def main() -> int:
    result = subprocess.run(
        ["git", "ls-files", "-z"], check=True, capture_output=True
    )
    paths = [p.decode("utf-8", errors="surrogateescape") for p in result.stdout.split(b"\0") if p]
    offenders = [path for path in paths if is_private_env_path(path)]
    if offenders:
        print("Tracked private dotenv files are prohibited:", file=sys.stderr)
        for path in offenders:
            print(f"  {path}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
