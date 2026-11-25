#!/usr/bin/env python3
"""Encrypt a verified offline backup with age without writing plaintext copies."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Sequence

_CHUNK_BYTES = 1024 * 1024
_MAX_RECIPIENTS = 8
_AGE_RECIPIENT = re.compile(r"^age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}$")


class BackupEncryptionError(ValueError):
    """Raised when a backup cannot be encrypted safely."""


def _normalize_digest(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(char not in "0123456789abcdef" for char in normalized):
        raise BackupEncryptionError("Expected SHA-256 must be exactly 64 hexadecimal characters.")
    return normalized


def _normalize_recipients(values: Sequence[str]) -> tuple[str, ...]:
    recipients = tuple(value.strip() for value in values)
    if not recipients or len(recipients) > _MAX_RECIPIENTS:
        raise BackupEncryptionError("Provide between one and eight age X25519 recipients.")
    if len(set(recipients)) != len(recipients):
        raise BackupEncryptionError("Duplicate age recipients are not allowed.")
    if any(_AGE_RECIPIENT.fullmatch(value) is None for value in recipients):
        raise BackupEncryptionError("Each recipient must be a valid-format age X25519 public key.")
    return recipients


def _same_file_state(left: os.stat_result, right: os.stat_result) -> bool:
    return (
        left.st_dev,
        left.st_ino,
        left.st_size,
        left.st_mtime_ns,
        left.st_ctime_ns,
    ) == (
        right.st_dev,
        right.st_ino,
        right.st_size,
        right.st_mtime_ns,
        right.st_ctime_ns,
    )


def _open_source(path_value: str | Path) -> tuple[Path, int, os.stat_result]:
    path = Path(path_value).expanduser().absolute()
    try:
        path_before = path.lstat()
    except OSError as exc:
        raise BackupEncryptionError("Input backup is missing or unavailable.") from exc
    if stat.S_ISLNK(path_before.st_mode) or not stat.S_ISREG(path_before.st_mode):
        raise BackupEncryptionError("Input backup must be a regular non-symlink file.")
    if path_before.st_size <= 0:
        raise BackupEncryptionError("Input backup must not be empty.")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BackupEncryptionError("Input backup cannot be opened safely.") from exc
    try:
        opened = os.fstat(descriptor)
    except OSError as exc:
        os.close(descriptor)
        raise BackupEncryptionError("Input backup cannot be opened safely.") from exc

    if not stat.S_ISREG(opened.st_mode) or not _same_file_state(path_before, opened):
        os.close(descriptor)
        raise BackupEncryptionError("Input backup changed before encryption.")
    return path, descriptor, opened


def _ensure_source_unchanged(path: Path, descriptor: int, original: os.stat_result) -> None:
    try:
        descriptor_state = os.fstat(descriptor)
        path_state = path.lstat()
    except OSError as exc:
        raise BackupEncryptionError("Input backup changed during encryption.") from exc
    if (
        stat.S_ISLNK(path_state.st_mode)
        or not stat.S_ISREG(path_state.st_mode)
        or not _same_file_state(original, descriptor_state)
        or not _same_file_state(original, path_state)
    ):
        raise BackupEncryptionError("Input backup changed during encryption.")


def _child_environment() -> dict[str, str]:
    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "LANG": "C",
        "LC_ALL": "C",
    }
    if os.name == "nt":
        for name in ("SYSTEMROOT", "WINDIR", "PATHEXT"):
            if name in os.environ:
                environment[name] = os.environ[name]
    return environment


def _terminate(process: subprocess.Popen[bytes]) -> None:
    if process.stdin is not None and not process.stdin.closed:
        try:
            process.stdin.close()
        except OSError:
            pass
    if process.poll() is None:
        try:
            process.kill()
        except OSError:
            pass
    process.wait()


def encrypt_backup(
    input_path: str | Path,
    output_path: str | Path,
    *,
    recipients: Sequence[str],
    expected_sha256: str,
) -> dict[str, object]:
    """Stream a digest-pinned input to age and publish ciphertext without overwrite."""
    expected = _normalize_digest(expected_sha256)
    normalized_recipients = _normalize_recipients(recipients)
    if os.name != "posix":
        raise BackupEncryptionError(
            "Run this helper on a POSIX host with restrictive file permissions."
        )

    source_path, source_fd, original_state = _open_source(input_path)
    temporary_path: Path | None = None
    try:
        output_value = Path(output_path).expanduser()
        if output_value.name in {"", ".", ".."}:
            raise BackupEncryptionError("Encrypted output path is invalid.")
        try:
            output_parent = output_value.parent.resolve(strict=True)
        except OSError as exc:
            raise BackupEncryptionError("Encrypted output directory must already exist.") from exc
        if not output_parent.is_dir():
            raise BackupEncryptionError("Encrypted output directory must already exist.")
        target = output_parent / output_value.name
        try:
            resolved_source = source_path.resolve(strict=True)
        except OSError as exc:
            raise BackupEncryptionError("Input backup changed during encryption.") from exc
        if target == resolved_source:
            raise BackupEncryptionError("Input and encrypted output must be different files.")
        if os.path.lexists(target):
            raise BackupEncryptionError("Encrypted output already exists; refusing to overwrite.")

        age_binary = shutil.which("age")
        if age_binary is None:
            raise BackupEncryptionError("The age executable is not installed or not on PATH.")

        try:
            temporary_fd, temporary_name = tempfile.mkstemp(
                prefix=".netwatch-age-", suffix=".tmp", dir=output_parent
            )
        except OSError as exc:
            raise BackupEncryptionError("Cannot create a private temporary output.") from exc
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(temporary_fd, 0o600)
        except OSError as exc:
            os.close(temporary_fd)
            raise BackupEncryptionError("Cannot restrict temporary output permissions.") from exc

        command = [age_binary]
        for recipient in normalized_recipients:
            command.extend(["-r", recipient])

        digest = hashlib.sha256()
        copied = 0
        try:
            with os.fdopen(temporary_fd, "wb") as encrypted_stream:
                try:
                    process = subprocess.Popen(
                        command,
                        stdin=subprocess.PIPE,
                        stdout=encrypted_stream,
                        stderr=subprocess.DEVNULL,
                        env=_child_environment(),
                        close_fds=True,
                    )
                except OSError as exc:
                    raise BackupEncryptionError("The age executable could not be started.") from exc

                process_stdin = process.stdin
                if process_stdin is None:
                    _terminate(process)
                    raise BackupEncryptionError("The age process did not accept input.")

                try:
                    with os.fdopen(os.dup(source_fd), "rb") as source_stream:
                        for chunk in iter(lambda: source_stream.read(_CHUNK_BYTES), b""):
                            digest.update(chunk)
                            copied += len(chunk)
                            process_stdin.write(chunk)
                    process_stdin.close()
                    return_code = process.wait()
                except BaseException:
                    _terminate(process)
                    raise

                if return_code != 0:
                    raise BackupEncryptionError("age encryption failed; no output was published.")
                encrypted_stream.flush()
                os.fsync(encrypted_stream.fileno())
        except BackupEncryptionError:
            raise
        except OSError as exc:
            raise BackupEncryptionError("age encryption failed; no output was published.") from exc

        _ensure_source_unchanged(source_path, source_fd, original_state)
        actual_digest = digest.hexdigest()
        if copied != original_state.st_size or not hmac.compare_digest(actual_digest, expected):
            raise BackupEncryptionError("Input bytes do not match the trusted SHA-256 digest.")
        try:
            encrypted_size = temporary_path.stat().st_size
        except OSError as exc:
            raise BackupEncryptionError("age output could not be verified.") from exc
        if encrypted_size <= 0:
            raise BackupEncryptionError("age produced an empty encrypted output.")

        try:
            # A same-directory hard link is atomic and fails if the destination exists.
            os.link(temporary_path, target)
        except FileExistsError as exc:
            raise BackupEncryptionError(
                "Encrypted output already exists; refusing to overwrite."
            ) from exc
        except OSError as exc:
            raise BackupEncryptionError(
                "Destination filesystem does not support safe no-overwrite publication."
            ) from exc
        try:
            temporary_path.unlink()
        except OSError:
            # The published ciphertext is valid; a leftover temporary ciphertext is non-sensitive.
            pass
        temporary_path = None

        if os.name == "posix":
            try:
                directory_fd = os.open(output_parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                # Some filesystems do not support directory fsync; ciphertext is already fsynced.
                pass

        return {
            "encrypted": True,
            "input_name": source_path.name,
            "output_name": target.name,
            "bytes": copied,
            "sha256": actual_digest,
            "recipient_count": len(normalized_recipients),
            "output_mode": "0600",
            "overwrite": False,
        }
    finally:
        os.close(source_fd)
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("backup", type=Path, help="Verified offline backup file.")
    parser.add_argument("encrypted_output", type=Path, help="New .age output path.")
    parser.add_argument(
        "--recipient",
        action="append",
        required=True,
        help="Age X25519 public recipient; repeat for independent recovery recipients.",
    )
    parser.add_argument(
        "--expected-sha256",
        required=True,
        help="Digest from a separately trusted channel.",
    )
    args = parser.parse_args(argv)
    try:
        report = encrypt_backup(
            args.backup,
            args.encrypted_output,
            recipients=args.recipient,
            expected_sha256=args.expected_sha256,
        )
    except BackupEncryptionError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 2
    except (OSError, subprocess.SubprocessError):
        print(json.dumps({"ok": False, "error": "Backup encryption failed safely."}, indent=2))
        return 2
    print(json.dumps({"ok": True, **report}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
