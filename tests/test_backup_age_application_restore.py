from __future__ import annotations

import hashlib
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
from contextlib import closing
from pathlib import Path

import pytest

import inventory_store
from scripts.encrypt_backup_age import encrypt_backup
from scripts.restore_backup_age import restore_backup

_AUDIT_HMAC_KEY = "netwatch-age-restore-test-key-with-at-least-32-characters"


def _create_age_identity(tmp_path: Path) -> tuple[Path, str]:
    age_binary = shutil.which("age")
    age_keygen = shutil.which("age-keygen")
    if not age_binary or not age_keygen:
        if os.environ.get("NETWATCH_REQUIRE_AGE_INTEROP") == "1":
            pytest.fail("Security CI requires the real age and age-keygen executables.")
        pytest.skip(
            "install age and age-keygen to run the real application restore test"
        )

    identity = tmp_path / "ephemeral-application-recovery-identity.txt"
    generated = subprocess.run(
        [age_keygen, "-o", str(identity)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert generated.returncode == 0, (
        "age-keygen could not create an ephemeral test identity"
    )
    identity.chmod(0o600)

    recipient_result = subprocess.run(
        [age_keygen, "-y", str(identity)],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )
    assert recipient_result.returncode == 0, (
        "age-keygen could not derive the test recipient"
    )
    recipient = recipient_result.stdout.strip()
    assert recipient.startswith("age1") and len(recipient) == 62
    return identity, recipient


@pytest.mark.skipif(
    sys.platform != "linux",
    reason="the restore helper currently requires Linux ACL checks",
)
def test_real_age_restore_preserves_netwatch_inventory_and_audit_chain(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    identity, recipient = _create_age_identity(tmp_path)

    source_directory = tmp_path / "source"
    source_directory.mkdir(mode=0o700)
    source_database = source_directory / "netwatch.db"
    monkeypatch.setattr(inventory_store, "DATA_DIR", source_directory)
    monkeypatch.setattr(inventory_store, "DB_FILE", source_database)
    monkeypatch.setenv("NETWATCH_AUDIT_HMAC_KEY", _AUDIT_HMAC_KEY)

    inventory_store.init_db()
    inventory_store.upsert_hosts(
        [
            {
                "IP Address": "192.168.50.10",
                "Status": "Online",
                "Details": "synthetic restore fixture",
            }
        ],
        source="synthetic recovery test",
    )
    inventory_store.record_audit_event(
        "admin",
        "restore_fixture_created",
        "192.168.50.10",
        "completed",
        "Synthetic local recovery fixture.",
        actor_id="test:restore",
        auth_method="test",
        request_id="age-application-restore",
    )

    original_integrity = inventory_store.verify_audit_integrity()
    assert original_integrity["status"] == "valid"
    expected_protected_entries = original_integrity["protected_entries"]
    assert isinstance(expected_protected_entries, int)
    assert expected_protected_entries >= 1

    snapshot = tmp_path / "netwatch-snapshot.sqlite3"
    with closing(sqlite3.connect(source_database)) as source:
        with closing(sqlite3.connect(snapshot)) as destination:
            source.backup(destination)
    snapshot.chmod(0o600)

    snapshot_uri = f"{snapshot.as_uri()}?mode=ro"
    with closing(sqlite3.connect(snapshot_uri, uri=True)) as connection:
        integrity = connection.execute("PRAGMA integrity_check").fetchone()
        source_schema = int(connection.execute("PRAGMA user_version").fetchone()[0])
    assert integrity == ("ok",)
    assert source_schema > 0

    plaintext = snapshot.read_bytes()
    expected_sha256 = hashlib.sha256(plaintext).hexdigest()
    encrypted = tmp_path / "netwatch-snapshot.sqlite3.age"
    encryption_report = encrypt_backup(
        snapshot,
        encrypted,
        recipients=[recipient],
        expected_sha256=expected_sha256,
    )
    assert encryption_report["encrypted"] is True
    assert stat.S_IMODE(encrypted.stat().st_mode) == 0o600

    restore_directory = tmp_path / "restored"
    restore_directory.mkdir(mode=0o700)
    restored = restore_directory / "netwatch.db"
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

    monkeypatch.setattr(inventory_store, "DATA_DIR", restore_directory)
    monkeypatch.setattr(inventory_store, "DB_FILE", restored)
    restored_integrity = inventory_store.verify_audit_integrity()
    restored_inventory = inventory_store.asset_inventory()

    assert restored_integrity["status"] == "valid"
    restored_protected_entries = restored_integrity["protected_entries"]
    assert isinstance(restored_protected_entries, int)
    assert restored_protected_entries == expected_protected_entries
    assert len(restored_inventory) == 1
    assert restored_inventory[0]["ip_address"] == "192.168.50.10"
    assert restored_inventory[0]["status"] == "Online"

    restored_uri = f"{restored.as_uri()}?mode=ro"
    with closing(sqlite3.connect(restored_uri, uri=True)) as connection:
        restored_schema = int(connection.execute("PRAGMA user_version").fetchone()[0])
    assert restored_schema == source_schema
    assert list(tmp_path.glob(".netwatch-age-*")) == []
    assert list(restore_directory.glob(".netwatch-restore-*")) == []
