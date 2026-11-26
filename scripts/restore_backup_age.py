#!/usr/bin/env python3
"""Restore an age-encrypted NetWatch backup into a new, verified plaintext file."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import selectors
import stat
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Sequence

from scripts.encrypt_backup_age import (
    _AGE_EXIT_TIMEOUT_SECONDS,
    _CHUNK_BYTES,
    _child_environment,
    _ensure_source_unchanged,
    _fsync_output_directory,
    _normalize_digest,
    _open_source,
    _resolve_age_binary,
    _same_file_state,
    _terminate,
    _verify_age_binary_digest,
    BackupEncryptionError,
)

_RESTORE_OUTPUT_STALL_TIMEOUT_SECONDS = 30.0


class BackupRestoreError(ValueError):
    """Raised when an encrypted backup cannot be restored safely."""


def _open_identity(path_value: str | Path) -> tuple[Path, int, os.stat_result]:
    requested = Path(path_value).expanduser().absolute()
    try:
        requested_state = requested.lstat()
    except OSError as exc:
        raise BackupRestoreError("The recovery identity file is unavailable.") from exc
    if stat.S_ISLNK(requested_state.st_mode) or not stat.S_ISREG(requested_state.st_mode):
        raise BackupRestoreError("The recovery identity must be a regular non-symlink file.")

    try:
        path = requested.resolve(strict=True)
        path_state = path.lstat()
    except OSError as exc:
        raise BackupRestoreError("The recovery identity file is unavailable.") from exc
    if not _same_file_state(requested_state, path_state):
        raise BackupRestoreError("The recovery identity changed before it could be opened.")

    mode = stat.S_IMODE(path_state.st_mode)
    if (
        path_state.st_uid not in {0, os.geteuid()}
        or mode & 0o077
        or mode & 0o111
        or mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX)
        or not mode & stat.S_IRUSR
    ):
        raise BackupRestoreError(
            "The recovery identity must be root- or user-owned and owner-readable only."
        )

    directory = path.parent
    while True:
        try:
            directory_state = directory.lstat()
        except OSError as exc:
            raise BackupRestoreError("The recovery identity path is not trusted.") from exc
        if not stat.S_ISDIR(directory_state.st_mode):
            raise BackupRestoreError("The recovery identity path contains a non-directory.")
        if directory_state.st_uid not in {0, os.geteuid()}:
            raise BackupRestoreError("The recovery identity path has an untrusted owner.")
        writable = directory_state.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        sticky = directory_state.st_mode & stat.S_ISVTX
        if writable and not sticky:
            raise BackupRestoreError(
                "The recovery identity path contains an untrusted writable directory."
            )
        parent = directory.parent
        if parent == directory:
            break
        directory = parent

    nofollow_flag = getattr(os, "O_NOFOLLOW", None)
    if nofollow_flag is None:
        raise BackupRestoreError(
            "This host cannot safely open the recovery identity without O_NOFOLLOW."
        )
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | nofollow_flag
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BackupRestoreError("The recovery identity cannot be opened safely.") from exc
    try:
        opened = os.fstat(descriptor)
    except OSError as exc:
        os.close(descriptor)
        raise BackupRestoreError("The recovery identity cannot be opened safely.") from exc
    if not stat.S_ISREG(opened.st_mode) or not _same_file_state(path_state, opened):
        os.close(descriptor)
        raise BackupRestoreError("The recovery identity changed while it was opened.")
    return path, descriptor, opened


def _ensure_identity_unchanged(
    path: Path, descriptor: int, original: os.stat_result
) -> None:
    try:
        descriptor_state = os.fstat(descriptor)
        path_state = path.lstat()
    except OSError as exc:
        raise BackupRestoreError("The recovery identity changed during restoration.") from exc
    if not _same_file_state(original, descriptor_state) or not _same_file_state(
        original, path_state
    ):
        raise BackupRestoreError("The recovery identity changed during restoration.")


def _identity_descriptor_path(descriptor: int) -> str:
    for directory in (Path("/proc/self/fd"), Path("/dev/fd")):
        if directory.is_dir():
            return str(directory / str(descriptor))
    raise BackupRestoreError("This host does not expose inherited file descriptors to child tools.")


def _validate_output_directory(path: Path) -> None:
    """Require a trusted directory chain for no-overwrite plaintext publication."""
    directory = path
    while True:
        try:
            directory_state = directory.lstat()
        except OSError as exc:
            raise BackupRestoreError(
                "Restored output directory path is unavailable."
            ) from exc
        if not stat.S_ISDIR(directory_state.st_mode):
            raise BackupRestoreError(
                "Restored output directory path contains a non-directory component."
            )
        if directory_state.st_uid not in {0, os.geteuid()}:
            raise BackupRestoreError(
                "Restored output directory path has an untrusted owner."
            )
        writable = directory_state.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        sticky = directory_state.st_mode & stat.S_ISVTX
        if writable and not sticky:
            raise BackupRestoreError(
                "Restored output directory path contains an untrusted writable directory."
            )
        parent = directory.parent
        if parent == directory:
            break
        directory = parent


def restore_backup(
    encrypted_path: str | Path,
    output_path: str | Path,
    *,
    identity_path: str | Path,
    expected_sha256: str,
    expected_age_sha256: str | None = None,
) -> dict[str, object]:
    """Decrypt to a private temporary file and publish only after digest verification."""
    if os.name != "posix":
        raise BackupRestoreError(
            "Run this helper on a POSIX host with restrictive file permissions."
        )
    try:
        expected = _normalize_digest(expected_sha256)
    except BackupEncryptionError as exc:
        raise BackupRestoreError("Expected plaintext SHA-256 is invalid.") from exc

    try:
        source_path, source_fd, source_state = _open_source(encrypted_path)
    except BackupEncryptionError as exc:
        raise BackupRestoreError("Encrypted input must be a non-empty regular file.") from exc

    identity_fd: int | None = None
    temporary_path: Path | None = None
    try:
        identity, opened_identity_fd, identity_state = _open_identity(identity_path)
        identity_fd = opened_identity_fd
        try:
            if os.path.samefile(identity, source_path):
                raise BackupRestoreError("The encrypted input and recovery identity must differ.")
        except OSError as exc:
            raise BackupRestoreError(
                "The encrypted input and identity cannot be compared."
            ) from exc

        output_value = Path(output_path).expanduser()
        if output_value.name in {"", ".", ".."}:
            raise BackupRestoreError("Restored output path is invalid.")
        try:
            output_parent = output_value.parent.resolve(strict=True)
        except OSError as exc:
            raise BackupRestoreError("Restored output directory must already exist.") from exc
        if not output_parent.is_dir():
            raise BackupRestoreError("Restored output directory must already exist.")
        _validate_output_directory(output_parent)
        target = output_parent / output_value.name
        try:
            resolved_source = source_path.resolve(strict=True)
        except OSError as exc:
            raise BackupRestoreError("Encrypted input changed before restoration.") from exc
        if target == resolved_source or target == identity:
            raise BackupRestoreError("Restored output must be a new file.")
        if os.path.lexists(target):
            raise BackupRestoreError("Restored output already exists; refusing to overwrite.")

        try:
            age_binary = _resolve_age_binary()
            age_binary_digest = _verify_age_binary_digest(age_binary, expected_age_sha256)
        except BackupEncryptionError as exc:
            raise BackupRestoreError(
                "The age executable could not be trusted or verified."
            ) from exc

        identity_fd_reference = _identity_descriptor_path(opened_identity_fd)

        try:
            temporary_fd, temporary_name = tempfile.mkstemp(
                prefix=".netwatch-restore-", suffix=".tmp", dir=output_parent
            )
        except OSError as exc:
            raise BackupRestoreError("Cannot create a private temporary restore output.") from exc
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(temporary_fd, 0o600)
        except OSError as exc:
            os.close(temporary_fd)
            raise BackupRestoreError("Cannot restrict temporary restore permissions.") from exc

        command = [age_binary, "-d", "-i", identity_fd_reference]
        digest = hashlib.sha256()
        restored_bytes = 0
        max_plaintext_bytes = source_state.st_size

        try:
            with os.fdopen(temporary_fd, "wb") as restored_stream:
                try:
                    process = subprocess.Popen(
                        command,
                        stdin=source_fd,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL,
                        env=_child_environment(),
                        close_fds=True,
                        pass_fds=(opened_identity_fd,),
                        start_new_session=True,
                    )
                except OSError as exc:
                    raise BackupRestoreError(
                        "The age decryption process could not be started."
                    ) from exc

                stdout = process.stdout
                if stdout is None:
                    _terminate(process)
                    raise BackupRestoreError("The age decryption output pipe could not be created.")

                try:
                    stdout_fd = stdout.fileno()
                    os.set_blocking(stdout_fd, False)
                    last_progress = time.monotonic()
                    with selectors.DefaultSelector() as reader:
                        reader.register(stdout_fd, selectors.EVENT_READ)
                        while True:
                            remaining = _RESTORE_OUTPUT_STALL_TIMEOUT_SECONDS - (
                                time.monotonic() - last_progress
                            )
                            if remaining <= 0:
                                raise BackupRestoreError(
                                    "age stopped producing plaintext; restore timed out."
                                )
                            events = reader.select(remaining)
                            if not events:
                                raise BackupRestoreError(
                                    "age stopped producing plaintext; restore timed out."
                                )
                            try:
                                chunk = os.read(stdout_fd, _CHUNK_BYTES)
                            except BlockingIOError:
                                continue
                            if not chunk:
                                reader.unregister(stdout_fd)
                                stdout.close()
                                break
                            last_progress = time.monotonic()
                            restored_bytes += len(chunk)
                            if restored_bytes > max_plaintext_bytes:
                                raise BackupRestoreError(
                                    "age plaintext exceeded the encrypted input size limit."
                                )
                            digest.update(chunk)
                            restored_stream.write(chunk)

                    try:
                        return_code = process.wait(timeout=_AGE_EXIT_TIMEOUT_SECONDS)
                    except subprocess.TimeoutExpired as exc:
                        raise BackupRestoreError(
                            "age did not exit after producing plaintext; restore timed out."
                        ) from exc
                except BaseException:
                    _terminate(process)
                    raise

                if return_code != 0:
                    _terminate(process)
                    raise BackupRestoreError("age decryption failed; no plaintext was published.")
                restored_stream.flush()
                os.fsync(restored_stream.fileno())
        except BackupRestoreError:
            raise
        except (OSError, subprocess.SubprocessError) as exc:
            raise BackupRestoreError("Backup restoration failed safely.") from exc

        try:
            _ensure_source_unchanged(source_path, source_fd, source_state)
        except BackupEncryptionError as exc:
            raise BackupRestoreError("Encrypted input changed during restoration.") from exc
        _ensure_identity_unchanged(identity, opened_identity_fd, identity_state)
        actual_digest = digest.hexdigest()
        if restored_bytes <= 0 or not hmac.compare_digest(actual_digest, expected):
            raise BackupRestoreError(
                "Restored plaintext does not match the trusted SHA-256 digest."
            )

        try:
            os.link(temporary_path, target)
        except FileExistsError as exc:
            raise BackupRestoreError(
                "Restored output already exists; refusing to overwrite."
            ) from exc
        except OSError as exc:
            raise BackupRestoreError(
                "Destination filesystem does not support safe no-overwrite publication."
            ) from exc
        try:
            temporary_path.unlink()
        except OSError as exc:
            try:
                target.unlink()
            except OSError:
                pass
            raise BackupRestoreError(
                "Could not safely finalize the restored plaintext file."
            ) from exc
        temporary_path = None

        directory_fsync = _fsync_output_directory(output_parent)
        report: dict[str, object] = {
            "restored": True,
            "input_name": source_path.name,
            "output_name": target.name,
            "bytes": restored_bytes,
            "sha256": actual_digest,
            "output_mode": "0600",
            "overwrite": False,
            "directory_fsync": directory_fsync,
            "durability_confirmed": directory_fsync == "confirmed",
        }
        if directory_fsync != "confirmed":
            report["durability_warning"] = (
                "Plaintext was fsynced and atomically published, but destination-directory "
                "fsync was not confirmed."
            )
        if age_binary_digest is not None:
            report["age_binary_sha256"] = age_binary_digest
        return report
    finally:
        os.close(source_fd)
        if identity_fd is not None:
            os.close(identity_fd)
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("encrypted_backup", type=Path, help="Encrypted .age backup file.")
    parser.add_argument("restored_output", type=Path, help="New plaintext output path.")
    parser.add_argument(
        "--identity",
        required=True,
        type=Path,
        help="Private identity file outside NetWatch.",
    )
    parser.add_argument(
        "--expected-sha256",
        required=True,
        help="Plaintext digest from a separately trusted recovery record.",
    )
    parser.add_argument(
        "--age-binary-sha256",
        help="Optional age executable digest from a separately trusted release record.",
    )
    args = parser.parse_args(argv)
    try:
        report = restore_backup(
            args.encrypted_backup,
            args.restored_output,
            identity_path=args.identity,
            expected_sha256=args.expected_sha256,
            expected_age_sha256=args.age_binary_sha256,
        )
    except BackupRestoreError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        return 2
    except (OSError, subprocess.SubprocessError):
        print(json.dumps({"ok": False, "error": "Backup restoration failed safely."}, indent=2))
        return 2
    print(json.dumps({"ok": True, **report}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
