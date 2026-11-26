from __future__ import annotations

import errno
import hashlib
import os
import stat
import sys
from pathlib import Path

import pytest

from scripts import restore_backup_age as restorer


pytestmark = pytest.mark.skipif(os.name != "posix", reason="requires POSIX file descriptors")


def _fake_age(
    tmp_path: Path,
    monkeypatch,
    *,
    plaintext: bytes = b"restored synthetic backup",
    behavior: str = "success",
) -> None:
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir(exist_ok=True)
    executable = binary_dir / "age"
    executable.write_text(
        f"""#!{sys.executable}
import sys

if sys.argv[1:3] != ["-d", "-i"]:
    raise SystemExit(90)
try:
    identity = open(sys.argv[3], "rb").read()
except OSError:
    raise SystemExit(91)
if identity != b"synthetic recovery identity":
    raise SystemExit(92)
ciphertext = sys.stdin.buffer.read()
if {behavior!r} == "failure":
    raise SystemExit(7)
if {behavior!r} == "oversize":
    sys.stdout.buffer.write(b"x" * (len(ciphertext) + 1))
elif {behavior!r} == "corrupt":
    sys.stdout.buffer.write(b"unexpected plaintext")
else:
    sys.stdout.buffer.write({plaintext!r})
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(binary_dir) + os.pathsep + os.environ.get("PATH", ""))


def _inputs(tmp_path: Path) -> tuple[Path, Path, bytes]:
    encrypted = tmp_path / "backup.sqlite3.age"
    encrypted.write_bytes(b"synthetic-age-ciphertext-with-overhead")
    identity = tmp_path / "recovery-identity.txt"
    identity.write_bytes(b"synthetic recovery identity")
    identity.chmod(0o600)
    return encrypted, identity, b"restored synthetic backup"


def test_restores_only_after_trusted_plaintext_digest_matches(tmp_path, monkeypatch):
    encrypted, identity, plaintext = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch, plaintext=plaintext)
    output = tmp_path / "restored.sqlite3"

    report = restorer.restore_backup(
        encrypted,
        output,
        identity_path=identity,
        expected_sha256=hashlib.sha256(plaintext).hexdigest(),
    )

    assert output.read_bytes() == plaintext
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert report["restored"] is True
    assert report["sha256"] == hashlib.sha256(plaintext).hexdigest()
    assert report["overwrite"] is False
    assert report["output_mode"] == "0600"
    assert list(tmp_path.glob(".netwatch-restore-*")) == []


def test_rejects_wrong_plaintext_digest_without_publishing(tmp_path, monkeypatch):
    encrypted, identity, plaintext = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch, plaintext=plaintext)
    output = tmp_path / "restored.sqlite3"

    with pytest.raises(restorer.BackupRestoreError, match="trusted SHA-256"):
        restorer.restore_backup(
            encrypted,
            output,
            identity_path=identity,
            expected_sha256="0" * 64,
        )

    assert not output.exists()
    assert list(tmp_path.glob(".netwatch-restore-*")) == []


@pytest.mark.parametrize("behavior", ["failure", "oversize", "corrupt"])
def test_rejects_failed_or_unbounded_age_output(tmp_path, monkeypatch, behavior):
    encrypted, identity, plaintext = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch, plaintext=plaintext, behavior=behavior)
    output = tmp_path / "restored.sqlite3"
    expected = hashlib.sha256(plaintext).hexdigest()

    with pytest.raises(restorer.BackupRestoreError):
        restorer.restore_backup(
            encrypted,
            output,
            identity_path=identity,
            expected_sha256=expected,
        )

    assert not output.exists()
    assert list(tmp_path.glob(".netwatch-restore-*")) == []


def test_rejects_extended_access_acl_on_identity_before_launch(tmp_path, monkeypatch):
    encrypted, identity, _ = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch)
    output = tmp_path / "restored.sqlite3"
    monkeypatch.setattr(restorer.sys, "platform", "linux")
    monkeypatch.setattr(
        restorer.os, "getxattr", lambda descriptor, attribute: b"extended-acl"
    )

    def unexpected_popen(*args, **kwargs):
        pytest.fail("age must not start with an ACL-accessible recovery identity")

    monkeypatch.setattr(restorer.subprocess, "Popen", unexpected_popen)
    with pytest.raises(restorer.BackupRestoreError, match="extended ACL"):
        restorer.restore_backup(
            encrypted,
            output,
            identity_path=identity,
            expected_sha256=hashlib.sha256(b"restored synthetic backup").hexdigest(),
        )

    assert not output.exists()


def test_fails_closed_when_identity_acl_metadata_cannot_be_checked(
    tmp_path, monkeypatch
):
    encrypted, identity, _ = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch)
    output = tmp_path / "restored.sqlite3"
    monkeypatch.setattr(restorer.sys, "platform", "linux")
    monkeypatch.setattr(restorer.os, "getxattr", None)

    def unexpected_popen(*args, **kwargs):
        pytest.fail("age must not start when identity ACL metadata cannot be checked")

    monkeypatch.setattr(restorer.subprocess, "Popen", unexpected_popen)
    with pytest.raises(
        restorer.BackupRestoreError, match="ACL metadata cannot be verified"
    ):
        restorer.restore_backup(
            encrypted,
            output,
            identity_path=identity,
            expected_sha256=hashlib.sha256(b"restored synthetic backup").hexdigest(),
        )

    assert not output.exists()


def test_rejects_identity_acl_added_during_restore_before_publication(
    tmp_path, monkeypatch
):
    encrypted, identity, plaintext = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch, plaintext=plaintext)
    output = tmp_path / "restored.sqlite3"
    identity_state = identity.stat()
    no_acl_error = getattr(errno, "ENODATA", errno.EIO)
    identity_checks = 0

    def fake_getxattr(descriptor, attribute):
        nonlocal identity_checks
        current = os.fstat(descriptor)
        if (current.st_dev, current.st_ino) == (
            identity_state.st_dev,
            identity_state.st_ino,
        ):
            identity_checks += 1
            if identity_checks > 1:
                return b"extended-acl"
        raise OSError(no_acl_error, "no ACL")

    monkeypatch.setattr(restorer.sys, "platform", "linux")
    monkeypatch.setattr(restorer.os, "getxattr", fake_getxattr)
    with pytest.raises(restorer.BackupRestoreError, match="ACL changed"):
        restorer.restore_backup(
            encrypted,
            output,
            identity_path=identity,
            expected_sha256=hashlib.sha256(plaintext).hexdigest(),
        )

    assert not output.exists()
    assert list(tmp_path.glob(".netwatch-restore-*")) == []


def test_rejects_group_or_world_accessible_identity_before_launch(tmp_path, monkeypatch):
    encrypted, identity, _ = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch)
    identity.chmod(0o644)
    output = tmp_path / "restored.sqlite3"

    def unexpected_popen(*args, **kwargs):
        pytest.fail("age must not start with a group/world-accessible recovery identity")

    monkeypatch.setattr(restorer.subprocess, "Popen", unexpected_popen)
    with pytest.raises(restorer.BackupRestoreError, match="owner-readable only"):
        restorer.restore_backup(
            encrypted,
            output,
            identity_path=identity,
            expected_sha256=hashlib.sha256(b"restored synthetic backup").hexdigest(),
        )

    assert not output.exists()


def test_rejects_special_mode_bits_on_identity(tmp_path, monkeypatch):
    encrypted, identity, _ = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch)
    identity.chmod(0o4600)
    if not identity.stat().st_mode & stat.S_ISUID:
        pytest.skip("filesystem does not preserve the setuid bit")
    output = tmp_path / "restored.sqlite3"

    def unexpected_popen(*args, **kwargs):
        pytest.fail("age must not start with special mode bits on the recovery identity")

    monkeypatch.setattr(restorer.subprocess, "Popen", unexpected_popen)
    with pytest.raises(restorer.BackupRestoreError, match="owner-readable only"):
        restorer.restore_backup(
            encrypted,
            output,
            identity_path=identity,
            expected_sha256=hashlib.sha256(b"restored synthetic backup").hexdigest(),
        )

    assert not output.exists()


@pytest.mark.parametrize(
    "acl_attribute",
    ["system.posix_acl_access", "system.posix_acl_default"],
)
def test_rejects_extended_acl_on_restore_directory_before_launch(
    tmp_path, monkeypatch, acl_attribute
):
    encrypted, identity, _ = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch)
    output_directory = tmp_path / "acl-output"
    output_directory.mkdir()
    output = output_directory / "restored.sqlite3"
    directory_state = output_directory.stat()
    no_acl_error = getattr(errno, "ENODATA", errno.EIO)

    def fake_getxattr(descriptor, attribute):
        current = os.fstat(descriptor)
        if (
            (current.st_dev, current.st_ino)
            == (directory_state.st_dev, directory_state.st_ino)
            and attribute == acl_attribute
        ):
            return b"extended-acl"
        raise OSError(no_acl_error, "no ACL")

    monkeypatch.setattr(restorer.sys, "platform", "linux")
    monkeypatch.setattr(restorer.os, "getxattr", fake_getxattr)

    def unexpected_popen(*args, **kwargs):
        pytest.fail("age must not start in a directory with an extended ACL")

    monkeypatch.setattr(restorer.subprocess, "Popen", unexpected_popen)
    with pytest.raises(restorer.BackupRestoreError, match="extended ACL"):
        restorer.restore_backup(
            encrypted,
            output,
            identity_path=identity,
            expected_sha256=hashlib.sha256(b"restored synthetic backup").hexdigest(),
        )

    assert not output.exists()
    assert list(output_directory.iterdir()) == []


def test_rejects_untrusted_output_directory_before_launch(tmp_path, monkeypatch):
    encrypted, identity, _ = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch)
    output_directory = tmp_path / "shared-output"
    output_directory.mkdir()
    output_directory.chmod(0o777)
    output = output_directory / "restored.sqlite3"

    def unexpected_popen(*args, **kwargs):
        pytest.fail("age must not start with an untrusted restore output directory")

    monkeypatch.setattr(restorer.subprocess, "Popen", unexpected_popen)
    with pytest.raises(restorer.BackupRestoreError, match="untrusted writable directory"):
        restorer.restore_backup(
            encrypted,
            output,
            identity_path=identity,
            expected_sha256=hashlib.sha256(b"restored synthetic backup").hexdigest(),
        )

    assert not output.exists()
    assert list(output_directory.iterdir()) == []


def test_allows_sticky_shared_output_directory(tmp_path, monkeypatch):
    encrypted, identity, plaintext = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch, plaintext=plaintext)
    output_directory = tmp_path / "sticky-output"
    output_directory.mkdir()
    output_directory.chmod(0o1777)
    output = output_directory / "restored.sqlite3"

    report = restorer.restore_backup(
        encrypted,
        output,
        identity_path=identity,
        expected_sha256=hashlib.sha256(plaintext).hexdigest(),
    )

    assert output.read_bytes() == plaintext
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert report["restored"] is True


def test_rejects_symlink_identity(tmp_path, monkeypatch):
    encrypted, identity, _ = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch)
    alias = tmp_path / "identity-link.txt"
    alias.symlink_to(identity)
    output = tmp_path / "restored.sqlite3"

    with pytest.raises(restorer.BackupRestoreError, match="non-symlink"):
        restorer.restore_backup(
            encrypted,
            output,
            identity_path=alias,
            expected_sha256=hashlib.sha256(b"restored synthetic backup").hexdigest(),
        )

    assert not output.exists()


def test_refuses_to_overwrite_existing_restore(tmp_path, monkeypatch):
    encrypted, identity, _ = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch)
    output = tmp_path / "restored.sqlite3"
    output.write_bytes(b"existing file")

    def unexpected_popen(*args, **kwargs):
        pytest.fail("age must not start when the destination already exists")

    monkeypatch.setattr(restorer.subprocess, "Popen", unexpected_popen)
    with pytest.raises(restorer.BackupRestoreError, match="already exists"):
        restorer.restore_backup(
            encrypted,
            output,
            identity_path=identity,
            expected_sha256=hashlib.sha256(b"restored synthetic backup").hexdigest(),
        )

    assert output.read_bytes() == b"existing file"


def test_cli_forwards_identity_and_binary_digest(tmp_path, monkeypatch, capsys):
    captured = {}

    def fake_restore_backup(encrypted, output, **kwargs):
        captured["encrypted"] = encrypted
        captured["output"] = output
        captured.update(kwargs)
        return {"restored": True, "sha256": kwargs["expected_sha256"]}

    monkeypatch.setattr(restorer, "restore_backup", fake_restore_backup)
    result = restorer.main(
        [
            "backup.sqlite3.age",
            "restored.sqlite3",
            "--identity",
            "/secure/recovery/identity.txt",
            "--expected-sha256",
            "a" * 64,
            "--age-binary-sha256",
            "b" * 64,
        ]
    )

    assert result == 0
    assert captured["identity_path"] == Path("/secure/recovery/identity.txt")
    assert captured["expected_age_sha256"] == "b" * 64
    assert '"ok": true' in capsys.readouterr().out


def test_rejects_symlinked_output_directory_component(tmp_path, monkeypatch):
    encrypted, identity, _ = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch)
    real_directory = tmp_path / "real-output"
    real_directory.mkdir()
    alias = tmp_path / "output-alias"
    alias.symlink_to(real_directory, target_is_directory=True)
    output = alias / "restored.sqlite3"

    def unexpected_popen(*args, **kwargs):
        pytest.fail("age must not start through a symlinked output directory")

    monkeypatch.setattr(restorer.subprocess, "Popen", unexpected_popen)
    with pytest.raises(restorer.BackupRestoreError, match="cannot be opened safely"):
        restorer.restore_backup(
            encrypted,
            output,
            identity_path=identity,
            expected_sha256=hashlib.sha256(b"restored synthetic backup").hexdigest(),
        )

    assert list(real_directory.iterdir()) == []


def test_directory_swap_during_decryption_never_publishes_to_replacement(
    tmp_path, monkeypatch
):
    encrypted, identity, plaintext = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch, plaintext=plaintext)
    output_directory = tmp_path / "output"
    replacement_directory = tmp_path / "replacement"
    moved_directory = tmp_path / "original-output"
    output_directory.mkdir()
    replacement_directory.mkdir()
    output = output_directory / "restored.sqlite3"
    original_popen = restorer.subprocess.Popen

    def swap_directory_after_launch(*args, **kwargs):
        process = original_popen(*args, **kwargs)
        output_directory.rename(moved_directory)
        replacement_directory.rename(output_directory)
        return process

    monkeypatch.setattr(restorer.subprocess, "Popen", swap_directory_after_launch)
    with pytest.raises(restorer.BackupRestoreError, match="changed during restoration"):
        restorer.restore_backup(
            encrypted,
            output,
            identity_path=identity,
            expected_sha256=hashlib.sha256(plaintext).hexdigest(),
        )

    assert list(moved_directory.iterdir()) == []
    assert list(output_directory.iterdir()) == []



def test_rejects_extended_acl_on_identity_ancestor_directory_before_launch(
    tmp_path, monkeypatch
):
    encrypted, identity, _ = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch)
    output = tmp_path / "restored.sqlite3"
    ancestor_state = identity.parent.stat()
    no_acl_error = getattr(errno, "ENODATA", errno.EIO)

    def fake_getxattr(descriptor, attribute):
        current = os.fstat(descriptor)
        if (
            (current.st_dev, current.st_ino)
            == (ancestor_state.st_dev, ancestor_state.st_ino)
            and attribute == "system.posix_acl_access"
        ):
            return b"extended-acl"
        raise OSError(no_acl_error, "no ACL")

    monkeypatch.setattr(restorer.sys, "platform", "linux")
    monkeypatch.setattr(restorer.os, "getxattr", fake_getxattr)

    def unexpected_popen(*args, **kwargs):
        pytest.fail("age must not start when an identity ancestor has an extended ACL")

    monkeypatch.setattr(restorer.subprocess, "Popen", unexpected_popen)
    with pytest.raises(restorer.BackupRestoreError, match="Recovery identity directory"):
        restorer.restore_backup(
            encrypted,
            output,
            identity_path=identity,
            expected_sha256=hashlib.sha256(b"restored synthetic backup").hexdigest(),
        )

    assert not output.exists()


def test_rejects_identity_ancestor_acl_added_during_restore_before_publication(
    tmp_path, monkeypatch
):
    encrypted, identity, plaintext = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch, plaintext=plaintext)
    output = tmp_path / "restored.sqlite3"
    ancestor_state = identity.parent.stat()
    no_acl_error = getattr(errno, "ENODATA", errno.EIO)
    process_started = False
    original_popen = restorer.subprocess.Popen

    def fake_getxattr(descriptor, attribute):
        current = os.fstat(descriptor)
        if (
            process_started
            and (current.st_dev, current.st_ino)
            == (ancestor_state.st_dev, ancestor_state.st_ino)
            and attribute == "system.posix_acl_access"
        ):
            return b"extended-acl"
        raise OSError(no_acl_error, "no ACL")

    def tracked_popen(*args, **kwargs):
        nonlocal process_started
        process = original_popen(*args, **kwargs)
        process_started = True
        return process

    monkeypatch.setattr(restorer.sys, "platform", "linux")
    monkeypatch.setattr(restorer.os, "getxattr", fake_getxattr)
    monkeypatch.setattr(restorer.subprocess, "Popen", tracked_popen)
    with pytest.raises(
        restorer.BackupRestoreError, match="Recovery identity directory"
    ):
        restorer.restore_backup(
            encrypted,
            output,
            identity_path=identity,
            expected_sha256=hashlib.sha256(plaintext).hexdigest(),
        )

    assert process_started
    assert not output.exists()
    assert list(tmp_path.glob(".netwatch-restore-*")) == []


def test_fails_closed_when_identity_acl_xattr_is_unsupported(tmp_path, monkeypatch):
    encrypted, identity, _ = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch)
    identity_state = identity.stat()
    no_acl_error = getattr(errno, "ENODATA", errno.EIO)
    unsupported_error = getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)

    def fake_getxattr(descriptor, attribute):
        current = os.fstat(descriptor)
        if (
            (current.st_dev, current.st_ino) == (identity_state.st_dev, identity_state.st_ino)
            and attribute == "system.posix_acl_access"
        ):
            raise OSError(unsupported_error, "ACL xattrs unsupported")
        raise OSError(no_acl_error, "no ACL")

    def unexpected_popen(*args, **kwargs):
        pytest.fail("age must not start when identity ACL metadata is unverifiable")

    monkeypatch.setattr(restorer.sys, "platform", "linux")
    monkeypatch.setattr(restorer.os, "getxattr", fake_getxattr)
    monkeypatch.setattr(restorer.subprocess, "Popen", unexpected_popen)
    output = tmp_path / "restored.sqlite3"

    with pytest.raises(restorer.BackupRestoreError, match="ACL metadata cannot be verified"):
        restorer.restore_backup(
            encrypted,
            output,
            identity_path=identity,
            expected_sha256=hashlib.sha256(b"restored synthetic backup").hexdigest(),
        )

    assert not output.exists()


def test_fails_closed_when_destination_acl_xattr_is_unsupported(tmp_path, monkeypatch):
    encrypted, identity, _ = _inputs(tmp_path)
    _fake_age(tmp_path, monkeypatch)
    output_directory = tmp_path / "restore-output"
    output_directory.mkdir()
    output_directory_state = output_directory.stat()
    no_acl_error = getattr(errno, "ENODATA", errno.EIO)
    unsupported_error = getattr(errno, "EOPNOTSUPP", errno.ENOTSUP)

    def fake_getxattr(descriptor, attribute):
        current = os.fstat(descriptor)
        if (
            (current.st_dev, current.st_ino)
            == (output_directory_state.st_dev, output_directory_state.st_ino)
            and attribute == "system.posix_acl_default"
        ):
            raise OSError(unsupported_error, "ACL xattrs unsupported")
        raise OSError(no_acl_error, "no ACL")

    def unexpected_popen(*args, **kwargs):
        pytest.fail("age must not start when destination ACL metadata is unverifiable")

    monkeypatch.setattr(restorer.sys, "platform", "linux")
    monkeypatch.setattr(restorer.os, "getxattr", fake_getxattr)
    monkeypatch.setattr(restorer.subprocess, "Popen", unexpected_popen)
    output = output_directory / "restored.sqlite3"

    with pytest.raises(restorer.BackupRestoreError, match="ACL metadata cannot be verified"):
        restorer.restore_backup(
            encrypted,
            output,
            identity_path=identity,
            expected_sha256=hashlib.sha256(b"restored synthetic backup").hexdigest(),
        )

    assert not output.exists()
    assert list(output_directory.iterdir()) == []
