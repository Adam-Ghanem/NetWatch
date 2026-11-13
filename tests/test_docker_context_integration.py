"""Exercise Docker's actual .dockerignore matcher using synthetic, non-secret files.

This optional integration test needs a working Docker daemon with BuildKit.
No production image, network access, credentials, or provider API is used.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest


def test_synthetic_docker_context_excludes_environment_secrets(tmp_path):
    require_docker = os.environ.get("NETWATCH_REQUIRE_DOCKER_CONTEXT") == "1"

    def unavailable(reason):
        if require_docker:
            pytest.fail(reason)
        pytest.skip(reason)

    if shutil.which("docker") is None:
        unavailable("Docker CLI is unavailable")

    try:
        daemon = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        unavailable("Docker daemon is unavailable")
    if daemon.returncode != 0:
        unavailable("Docker daemon is unavailable")

    context = tmp_path / "context"
    context.mkdir()
    (context / ".dockerignore").write_text(
        Path(".dockerignore").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (context / "Dockerfile").write_text(
        "FROM scratch\nCOPY . /payload/\n", encoding="utf-8"
    )
    (context / ".env.example").write_text("PUBLIC_EXAMPLE=1\n", encoding="utf-8")
    for name in (".env", ".env.local", ".env.production"):
        (context / name).write_text("SYNTHETIC_SECRET=1\n", encoding="utf-8")
    nested = context / "nested"
    nested.mkdir()
    (nested / ".env.staging").write_text(
        "SYNTHETIC_SECRET=1\n", encoding="utf-8"
    )
    (nested / ".env.example").write_text(
        "SYNTHETIC_SECRET=1\n", encoding="utf-8"
    )
    (context / "public.txt").write_text("visible\n", encoding="utf-8")

    output = tmp_path / "export"
    output.mkdir()
    env = os.environ.copy()
    env["DOCKER_BUILDKIT"] = "1"
    result = subprocess.run(
        [
            "docker",
            "build",
            "--network",
            "none",
            "--progress",
            "plain",
            "--output",
            f"type=local,dest={output}",
            str(context),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=env,
    )
    assert result.returncode == 0, (
        "Synthetic offline Docker context build failed: "
        + result.stderr[-2000:]
    )
    payload = output / "payload"
    assert (payload / ".env.example").is_file()
    assert (payload / "public.txt").is_file()
    for name in (".env", ".env.local", ".env.production"):
        assert not (payload / name).exists(), f"Leaked: {name}"
    assert not (payload / "nested" / ".env.staging").exists()
    assert not (payload / "nested" / ".env.example").exists()
