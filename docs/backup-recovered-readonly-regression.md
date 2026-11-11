# Recovered snapshot read-only regression

Run `python -m pytest -q tests/test_backup_recovered_readonly.py` in the normal development test environment.

The test creates a real-schema database with synthetic documentation-range inventory data, exports a standalone SQLite snapshot, simulates source-directory loss, verifies its SHA-256 and schema, reads the evidence through an independent SQLite `mode=ro` connection, and asserts a write is refused. It also checks snapshot bytes and absence of journal sidecars.

This verifies a **read-only consumer contract**, not operating-system file permissions: another process with write access can still change the snapshot. It does not prove authenticated application restoration, off-host backup protection, encryption, audit-HMAC key recovery, or recovery time and recovery point objectives. Never run against live network targets or production data.
