# Offline snapshot linked-evidence regression

Run `python -m pytest -q tests/test_backup_restored_records.py` on the backup-hardening branch.

The test initializes the real NetWatch SQLite schema in a temporary directory,
inserts synthetic RFC 5737 inventory and linked scan/observation evidence, exports
a consistent SQLite snapshot, normalizes its journal mode, verifies its schema
and SHA-256, and reads the linked records back through an independent read-only
SQLite connection. It asserts the snapshot bytes remain unchanged and no SQLite
sidecars are left behind.

This is an isolated data-level recovery regression, **not** an authenticated API
restore drill, audit-HMAC validation, encrypted off-host recovery, or proof of
production RTO/RPO. It performs no network scans or external API calls.
