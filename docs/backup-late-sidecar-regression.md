# Late SQLite sidecar regression

The offline verifier requires a stopped, standalone SQLite backup. It checks for `-wal`, `-shm`, and `-journal` files before opening the database **and again** after SQLite checks. A sidecar that appears during verification invalidates the standalone-snapshot assumption.

`tests/test_backup_verify.py::test_backup_rejects_sidecar_created_during_verification` simulates each sidecar appearing at the second guard and verifies that the verifier fails closed without changing the backup. Run `python -m pytest -q tests/test_backup_verify.py` from the repository root.

This is a deterministic regression test, **not** a concurrency-proof or authenticated restore test. A file can still change outside the checked windows; produce backups using a stopped writer or SQLite's supported backup mechanism, and verify a separately trusted SHA-256 digest. Do not interpret this check as evidence of encryption, off-host rotation, audit-HMAC validation, or application recovery.
