from __future__ import annotations

import hashlib
import os
import stat
import sys
from pathlib import Path

import pytest

from scripts import encrypt_backup_age as encryptor


def _recipient(char: str = "q") -> str:
    return "age1" + char * 58


def _fake_age(tmp_path: Path, monkeypatch, *, recipients, exit_code: int = 0) -> None:
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir(exist_ok=True)
    executable = binary_dir / "age"
    expected_args = []
    for recipient in recipients:
        expected_args.extend(["-r", recipient])
    executable.write_text(
        f"""#!{sys.executable}
import hashlib
import sys

if sys.argv[1:] != {expected_args!r}:
    raise SystemExit(98)
payload = sys.stdin.buffer.read()
if {exit_code}:
    raise SystemExit({exit_code})
sys.stdout.buffer.write(b"AGE-TEST" + bytes([0]) + hashlib.sha256(payload).digest())
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(binary_dir) + os.pathsep + os.environ.get("PATH", ""))


def test_encrypts_digest_pinned_input_for_multiple_recipients(tmp_path, monkeypatch):
    recipients = [_recipient("q"), _recipient("p")]
    _fake_age(tmp_path, monkeypatch, recipients=recipients)
    source = tmp_path / "backup.sqlite3"
    original = b"synthetic verified SQLite snapshot"
    source.write_bytes(original)
    output = tmp_path / "backup.sqlite3.age"

    report = encryptor.encrypt_backup(
        source,
        output,
        recipients=recipients,
        expected_sha256=hashlib.sha256(original).hexdigest().upper(),
    )

    assert output.read_bytes().startswith(b"AGE-TEST" + bytes([0]))
    assert original not in output.read_bytes()
    assert source.read_bytes() == original
    assert report["sha256"] == hashlib.sha256(original).hexdigest()
    assert report["recipient_count"] == 2
    assert report["overwrite"] is False
    if os.name == "posix":
        assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert list(tmp_path.glob(".netwatch-age-*")) == []


def test_rejects_digest_mismatch_and_removes_partial_ciphertext(tmp_path, monkeypatch):
    recipients = [_recipient()]
    _fake_age(tmp_path, monkeypatch, recipients=recipients)
    source = tmp_path / "backup.sqlite3"
    source.write_bytes(b"backup bytes")
    output = tmp_path / "backup.age"

    with pytest.raises(encryptor.BackupEncryptionError, match="trusted SHA-256"):
        encryptor.encrypt_backup(
            source, output, recipients=recipients, expected_sha256="0" * 64
        )

    assert not output.exists()
    assert list(tmp_path.glob(".netwatch-age-*")) == []


def test_rejects_existing_output_without_overwriting(tmp_path, monkeypatch):
    recipients = [_recipient()]
    _fake_age(tmp_path, monkeypatch, recipients=recipients)
    source = tmp_path / "backup.sqlite3"
    source.write_bytes(b"backup bytes")
    output = tmp_path / "backup.age"
    output.write_bytes(b"existing ciphertext")

    with pytest.raises(encryptor.BackupEncryptionError, match="already exists"):
        encryptor.encrypt_backup(
            source,
            output,
            recipients=recipients,
            expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )

    assert output.read_bytes() == b"existing ciphertext"


def test_rejects_symlink_input(tmp_path, monkeypatch):
    recipients = [_recipient()]
    _fake_age(tmp_path, monkeypatch, recipients=recipients)
    real_source = tmp_path / "real.sqlite3"
    real_source.write_bytes(b"backup bytes")
    symlink = tmp_path / "backup.sqlite3"
    symlink.symlink_to(real_source)
    output = tmp_path / "backup.age"

    with pytest.raises(encryptor.BackupEncryptionError, match="regular non-symlink"):
        encryptor.encrypt_backup(
            symlink,
            output,
            recipients=recipients,
            expected_sha256=hashlib.sha256(b"backup bytes").hexdigest(),
        )

    assert not output.exists()


def test_rejects_malformed_or_duplicate_recipients(tmp_path):
    source = tmp_path / "backup.sqlite3"
    source.write_bytes(b"backup bytes")
    output = tmp_path / "backup.age"
    digest = hashlib.sha256(source.read_bytes()).hexdigest()

    with pytest.raises(encryptor.BackupEncryptionError, match="age X25519"):
        encryptor.encrypt_backup(
            source, output, recipients=["not-a-recipient"], expected_sha256=digest
        )
    with pytest.raises(encryptor.BackupEncryptionError, match="Duplicate"):
        encryptor.encrypt_backup(
            source, output, recipients=[_recipient(), _recipient()], expected_sha256=digest
        )


def test_age_failure_does_not_publish_or_leave_temporary_output(tmp_path, monkeypatch):
    recipients = [_recipient()]
    _fake_age(tmp_path, monkeypatch, recipients=recipients, exit_code=7)
    source = tmp_path / "backup.sqlite3"
    source.write_bytes(b"backup bytes")
    output = tmp_path / "backup.age"

    with pytest.raises(encryptor.BackupEncryptionError, match="age encryption failed"):
        encryptor.encrypt_backup(
            source,
            output,
            recipients=recipients,
            expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )

    assert not output.exists()
    assert list(tmp_path.glob(".netwatch-age-*")) == []


def test_rejects_source_mutation_while_age_streams(tmp_path, monkeypatch):
    recipients = [_recipient()]
    _fake_age(tmp_path, monkeypatch, recipients=recipients)
    source = tmp_path / "backup.sqlite3"
    original = b"original backup bytes"
    source.write_bytes(original)
    output = tmp_path / "backup.age"
    real_popen = encryptor.subprocess.Popen

    def mutate_after_descriptor_open(*args, **kwargs):
        source.write_bytes(b"mutated backup bytes")
        return real_popen(*args, **kwargs)

    monkeypatch.setattr(encryptor.subprocess, "Popen", mutate_after_descriptor_open)
    with pytest.raises(encryptor.BackupEncryptionError, match="changed during encryption"):
        encryptor.encrypt_backup(
            source,
            output,
            recipients=recipients,
            expected_sha256=hashlib.sha256(original).hexdigest(),
        )

    assert not output.exists()
    assert list(tmp_path.glob(".netwatch-age-*")) == []


def test_rejects_dangling_output_symlink_without_replacing_it(tmp_path, monkeypatch):
    recipients = [_recipient()]
    _fake_age(tmp_path, monkeypatch, recipients=recipients)
    source = tmp_path / "backup.sqlite3"
    source.write_bytes(b"backup bytes")
    output = tmp_path / "backup.age"
    output.symlink_to(tmp_path / "missing-target.age")

    with pytest.raises(encryptor.BackupEncryptionError, match="already exists"):
        encryptor.encrypt_backup(
            source,
            output,
            recipients=recipients,
            expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )

    assert output.is_symlink()
    assert not output.resolve().exists()


def test_requires_age_executable_before_creating_output(tmp_path, monkeypatch):
    source = tmp_path / "backup.sqlite3"
    source.write_bytes(b"backup bytes")
    output = tmp_path / "backup.age"
    monkeypatch.setattr(encryptor.shutil, "which", lambda _: None)

    with pytest.raises(encryptor.BackupEncryptionError, match="not installed"):
        encryptor.encrypt_backup(
            source,
            output,
            recipients=[_recipient()],
            expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )

    assert not output.exists()
    assert list(tmp_path.glob(".netwatch-age-*")) == []


def test_rejects_output_path_that_aliases_the_input(tmp_path, monkeypatch):
    recipients = [_recipient()]
    _fake_age(tmp_path, monkeypatch, recipients=recipients)
    source = tmp_path / "backup.sqlite3"
    original = b"backup bytes"
    source.write_bytes(original)

    with pytest.raises(encryptor.BackupEncryptionError, match="different files"):
        encryptor.encrypt_backup(
            source,
            source,
            recipients=recipients,
            expected_sha256=hashlib.sha256(original).hexdigest(),
        )

    assert source.read_bytes() == original
