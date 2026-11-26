from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from scripts.encrypt_backup_age import encrypt_backup
from scripts.restore_backup_age import restore_backup


@pytest.mark.skipif(sys.platform != "linux", reason="the restore helper currently requires Linux ACL checks")
def test_real_age_cli_encrypts_and_restores_a_sqlite_snapshot(tmp_path):
    age_binary = shutil.which("age")
    age_keygen = shutil.which("age-keygen")
    if not age_binary or not age_keygen:
        if os.environ.get("NETWATCH_REQUIRE_AGE_INTEROP") == "1":
            pytest.fail("Security CI requires the real age and age-keygen executables.")
        pytest.skip("install age and age-keygen to run the real interoperability test")

    identity = tmp_path / "ephemeral-recovery-identity.txt"
    generated = subprocess.run(
        [age_keygen, "-o", str(identity)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert generated.returncode == 0, "age-keygen could not create an ephemeral test identity"
    identity.chmod(0o600)

    recipient_result = subprocess.run(
        [age_keygen, "-y", str(identity)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert recipient_result.returncode == 0, "age-keygen could not derive the test recipient"
    recipient = recipient_result.stdout.strip()
    assert recipient.startswith("age1") and len(recipient) == 62

    snapshot = tmp_path / "snapshot.sqlite3"
    connection = sqlite3.connect(snapshot)
    try:
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute(
            "CREATE TABLE assets (id INTEGER PRIMARY KEY, name TEXT NOT NULL)"
        )
        connection.executemany(
            "INSERT INTO assets(name) VALUES (?)",
            [("router-lab",), ("switch-lab",)],
        )
        connection.commit()
    finally:
        connection.close()

    plaintext = snapshot.read_bytes()
    expected_sha256 = hashlib.sha256(plaintext).hexdigest()
    encrypted = tmp_path / "snapshot.sqlite3.age"
    encryption_report = encrypt_backup(
        snapshot,
        encrypted,
        recipients=[recipient],
        expected_sha256=expected_sha256,
    )

    assert encryption_report["encrypted"] is True
    assert encrypted.is_file()
    assert encrypted.read_bytes() != plaintext
    assert stat.S_IMODE(encrypted.stat().st_mode) == 0o600

    restore_directory = tmp_path / "restore"
    restore_directory.mkdir(mode=0o700)
    restored = restore_directory / "restored.sqlite3"
    restore_report = restore_backup(
        encrypted,
        restored,
        identity_path=identity,
        expected_sha256=expected_sha256,
        max_plaintext_bytes=len(plaintext),
    )

    assert restore_report["restored"] is True
    assert restored.read_bytes() == plaintext
    assert stat.S_IMODE(restored.stat().st_mode) == 0o600
    assert list(tmp_path.glob(".netwatch-age-*")) == []
    assert list(restore_directory.glob(".netwatch-restore-*")) == []

    restored_connection = sqlite3.connect(f"file:{restored}?mode=ro", uri=True)
    try:
        rows = restored_connection.execute(
            "SELECT name FROM assets ORDER BY id"
        ).fetchall()
    finally:
        restored_connection.close()
    assert rows == [("router-lab",), ("switch-lab",)]
