from __future__ import annotations

import json
import os
import sqlite3

import pytest

from enterprise_store import create_enterprise_schema
from scripts.audit_enterprise_queue_errors import AuditFailure, audit_database, main


def _database(path, *, job_errors=(), outbox_errors=()):
    connection = sqlite3.connect(path)
    create_enterprise_schema(connection)
    for index, error in enumerate(job_errors):
        connection.execute(
            """
            INSERT INTO enterprise_jobs (
                created_at, available_at, job_type, dedupe_key, payload, last_error
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "2026-11-26T00:00:00+00:00",
                "2026-11-26T00:00:00+00:00",
                "approved",
                f"job-{index}",
                "{}",
                error,
            ),
        )
    for index, error in enumerate(outbox_errors):
        connection.execute(
            """
            INSERT INTO enterprise_outbox (
                created_at, available_at, topic, event_type, aggregate_id,
                dedupe_key, payload, last_error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "2026-11-26T00:00:00+00:00",
                "2026-11-26T00:00:00+00:00",
                "alerts",
                "created",
                f"alert-{index}",
                f"event-{index}",
                "{}",
                error,
            ),
        )
    connection.commit()
    connection.close()


def test_audit_counts_legacy_errors_without_echoing_or_mutating(tmp_path):
    database = tmp_path / "offline-copy.sqlite3"
    job_secret = "Authorization: Bearer synthetic-job-token"
    outbox_secret = "https://hooks.example.test/synthetic-outbox-token"
    _database(
        database,
        job_errors=(job_secret, "timeout", ""),
        outbox_errors=(outbox_secret, "connection_error", ""),
    )
    before = database.read_bytes()

    report = audit_database(database)
    rendered = json.dumps(report)

    assert report == {
        "ok": False,
        "legacy_error_rows": 2,
        "tables": {
            "enterprise_jobs": {"rows": 3, "legacy_error_rows": 1},
            "enterprise_outbox": {"rows": 3, "legacy_error_rows": 1},
        },
    }
    assert job_secret not in rendered
    assert outbox_secret not in rendered
    assert database.read_bytes() == before
    assert not (tmp_path / "offline-copy.sqlite3-wal").exists()
    assert not (tmp_path / "offline-copy.sqlite3-shm").exists()


def test_audit_accepts_only_allowlisted_or_empty_errors(tmp_path):
    database = tmp_path / "clean-copy.sqlite3"
    _database(
        database,
        job_errors=("timeout", "runtime_error", ""),
        outbox_errors=("connection_error", "worker_error", ""),
    )

    report = audit_database(database)

    assert report["ok"] is True
    assert report["legacy_error_rows"] == 0


def test_audit_rejects_symlinked_database(tmp_path):
    database = tmp_path / "source.sqlite3"
    _database(database)
    link = tmp_path / "linked.sqlite3"
    link.symlink_to(database)

    with pytest.raises(AuditFailure) as caught:
        audit_database(link)

    assert caught.value.code == "unsafe_database_file"


def test_audit_rejects_sqlite_sidecars(tmp_path):
    database = tmp_path / "offline-copy.sqlite3"
    _database(database)
    (tmp_path / "offline-copy.sqlite3-wal").write_bytes(b"synthetic sidecar")

    with pytest.raises(AuditFailure) as caught:
        audit_database(database)

    assert caught.value.code == "sqlite_sidecar_present"


def test_audit_rejects_incomplete_queue_schema(tmp_path):
    database = tmp_path / "incomplete.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)")
    connection.commit()
    connection.close()

    with pytest.raises(AuditFailure) as caught:
        audit_database(database)

    assert caught.value.code == "enterprise_queue_schema_missing"


def test_cli_reports_counts_without_printing_legacy_values(tmp_path, capsys):
    database = tmp_path / "legacy.sqlite3"
    secret = "Bearer cli-synthetic-secret"
    _database(database, job_errors=(secret,))

    result = main([str(database)])
    output = capsys.readouterr().out

    assert result == 1
    assert '"legacy_error_rows": 1' in output
    assert secret not in output



def test_audit_rejects_database_metadata_change_during_read(tmp_path, monkeypatch):
    database = tmp_path / "changing.sqlite3"
    _database(database)
    import scripts.audit_enterprise_queue_errors as audit_module

    original_connect = audit_module.sqlite3.connect

    def connect_then_touch(*args, **kwargs):
        connection = original_connect(*args, **kwargs)
        current = database.stat()
        os.utime(database, ns=(current.st_atime_ns, current.st_mtime_ns + 1_000_000))
        return connection

    monkeypatch.setattr(audit_module.sqlite3, "connect", connect_then_touch)

    with pytest.raises(AuditFailure) as caught:
        audit_database(database)

    assert caught.value.code == "database_changed_during_audit"
