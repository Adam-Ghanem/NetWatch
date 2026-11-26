from __future__ import annotations

import hashlib
import os
import stat
import sys
import time
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
        encryptor.encrypt_backup(source, output, recipients=recipients, expected_sha256="0" * 64)

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


def test_rejects_group_or_world_writable_age_executable(tmp_path, monkeypatch):
    recipients = [_recipient()]
    _fake_age(tmp_path, monkeypatch, recipients=recipients)
    executable = tmp_path / "bin" / "age"
    executable.chmod(0o777)
    source = tmp_path / "backup.sqlite3"
    source.write_bytes(b"backup bytes")
    output = tmp_path / "backup.age"

    with pytest.raises(
        encryptor.BackupEncryptionError, match="must not be group- or world-writable"
    ):
        encryptor.encrypt_backup(
            source,
            output,
            recipients=recipients,
            expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )

    assert not output.exists()
    assert list(tmp_path.glob(".netwatch-age-*")) == []


def test_rejects_age_executable_in_untrusted_writable_directory(tmp_path, monkeypatch):
    recipients = [_recipient()]
    binary_dir = tmp_path / "unsafe-bin"
    binary_dir.mkdir()
    executable = binary_dir / "age"
    executable.write_text(
        f"""#!{sys.executable}
import sys

sys.stdin.buffer.read()
sys.stdout.buffer.write(b"ciphertext")
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    binary_dir.chmod(0o777)
    monkeypatch.setenv("PATH", str(binary_dir))
    source = tmp_path / "backup.sqlite3"
    source.write_bytes(b"backup bytes")
    output = tmp_path / "backup.age"

    with pytest.raises(
        encryptor.BackupEncryptionError, match="group- or world-writable directory"
    ):
        encryptor.encrypt_backup(
            source,
            output,
            recipients=recipients,
            expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )

    assert not output.exists()
    assert list(tmp_path.glob(".netwatch-age-*")) == []


def test_resolves_age_symlink_to_trusted_executable(tmp_path, monkeypatch):
    recipients = [_recipient()]
    _fake_age(tmp_path, monkeypatch, recipients=recipients)
    real_executable = tmp_path / "bin" / "age"
    alias_dir = tmp_path / "alias-bin"
    alias_dir.mkdir()
    (alias_dir / "age").symlink_to(real_executable)
    monkeypatch.setenv("PATH", str(alias_dir))
    source = tmp_path / "backup.sqlite3"
    source.write_bytes(b"backup bytes")
    output = tmp_path / "backup.age"

    report = encryptor.encrypt_backup(
        source,
        output,
        recipients=recipients,
        expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    )

    assert report["encrypted"] is True
    assert output.exists()


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


def _fake_age_that_stalls(tmp_path: Path, monkeypatch, *, consume_input: bool) -> None:
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir(exist_ok=True)
    executable = binary_dir / "age"
    consume = "sys.stdin.buffer.read()\n" if consume_input else ""
    executable.write_text(
        f"""#!{sys.executable}
import sys
import time

{consume}time.sleep(5)
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(binary_dir) + os.pathsep + os.environ.get("PATH", ""))


def test_times_out_when_age_stops_consuming_input(tmp_path, monkeypatch):
    _fake_age_that_stalls(tmp_path, monkeypatch, consume_input=False)
    monkeypatch.setattr(encryptor, "_AGE_INPUT_STALL_TIMEOUT_SECONDS", 0.05)
    source = tmp_path / "backup.sqlite3"
    source.write_bytes(b"x" * (2 * 1024 * 1024))
    output = tmp_path / "backup.age"

    with pytest.raises(encryptor.BackupEncryptionError, match="stopped accepting input"):
        encryptor.encrypt_backup(
            source,
            output,
            recipients=[_recipient()],
            expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )

    assert not output.exists()
    assert list(tmp_path.glob(".netwatch-age-*")) == []


def test_times_out_when_age_does_not_exit_after_input_closes(tmp_path, monkeypatch):
    _fake_age_that_stalls(tmp_path, monkeypatch, consume_input=True)
    monkeypatch.setattr(encryptor, "_AGE_EXIT_TIMEOUT_SECONDS", 0.05)
    source = tmp_path / "backup.sqlite3"
    source.write_bytes(b"small backup")
    output = tmp_path / "backup.age"

    with pytest.raises(encryptor.BackupEncryptionError, match="did not finish after input closed"):
        encryptor.encrypt_backup(
            source,
            output,
            recipients=[_recipient()],
            expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )

    assert not output.exists()
    assert list(tmp_path.glob(".netwatch-age-*")) == []


def _fake_age_that_expands_output(
    tmp_path: Path, monkeypatch, *, output_bytes: int
) -> None:
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir(exist_ok=True)
    executable = binary_dir / "age"
    executable.write_text(
        f"""#!{sys.executable}
import sys

sys.stdin.buffer.read()
sys.stdout.buffer.write(b"x" * {output_bytes})
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(binary_dir) + os.pathsep + os.environ.get("PATH", ""))


def test_rejects_age_output_above_bounded_ciphertext_envelope(tmp_path, monkeypatch):
    source = tmp_path / "backup.sqlite3"
    source.write_bytes(b"x")
    source_size = source.stat().st_size
    output_limit = source_size + max(
        encryptor._AGE_OUTPUT_OVERHEAD_BYTES,
        source_size // encryptor._AGE_OUTPUT_OVERHEAD_RATIO_DIVISOR,
    )
    _fake_age_that_expands_output(
        tmp_path, monkeypatch, output_bytes=output_limit + 1
    )
    output = tmp_path / "backup.age"
    processes = []
    real_popen = encryptor.subprocess.Popen

    def capture_process(*args, **kwargs):
        process = real_popen(*args, **kwargs)
        processes.append(process)
        return process

    monkeypatch.setattr(encryptor.subprocess, "Popen", capture_process)
    with pytest.raises(
        encryptor.BackupEncryptionError, match="safe ciphertext size limit"
    ):
        encryptor.encrypt_backup(
            source,
            output,
            recipients=[_recipient()],
            expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )

    assert len(processes) == 1
    assert processes[0].poll() is not None
    assert not output.exists()
    assert list(tmp_path.glob(".netwatch-age-*")) == []


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires POSIX process groups")
def test_timeout_kills_age_descendants_that_keep_stdout_open(tmp_path, monkeypatch):
    binary_dir = tmp_path / "bin"
    binary_dir.mkdir()
    executable = binary_dir / "age"
    child_pid_file = tmp_path / "descendant.pid"
    survivor_marker = tmp_path / "descendant-survived"
    executable.write_text(
        f"""#!{sys.executable}
import os
import sys
import time

sys.stdin.buffer.read()
child_pid = os.fork()
if child_pid == 0:
    time.sleep(1.0)
    with open({str(survivor_marker)!r}, "w", encoding="utf-8") as stream:
        stream.write("survived")
    os._exit(0)
with open({str(child_pid_file)!r}, "w", encoding="utf-8") as stream:
    stream.write(str(child_pid))
""",
        encoding="utf-8",
    )
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(binary_dir) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setattr(encryptor, "_AGE_EXIT_TIMEOUT_SECONDS", 0.5)

    source = tmp_path / "backup.sqlite3"
    source.write_bytes(b"small backup")
    output = tmp_path / "backup.age"

    with pytest.raises(
        encryptor.BackupEncryptionError, match="did not finish after input closed"
    ):
        encryptor.encrypt_backup(
            source,
            output,
            recipients=[_recipient()],
            expected_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        )

    deadline = time.monotonic() + 1.0
    while not child_pid_file.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert child_pid_file.exists()
    time.sleep(1.1)
    assert not survivor_marker.exists()
    assert not output.exists()
    assert list(tmp_path.glob(".netwatch-age-*")) == []
