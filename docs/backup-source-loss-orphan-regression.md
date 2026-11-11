# Source-loss orphan-evidence regression

Run `python -m pytest -q tests/test_backup_restored_records.py` in an isolated test environment. The new negative case initializes the real inventory schema, writes a synthetic observation with a missing scan parent using a test-only SQLite connection, exports a standalone snapshot, and makes the source directory unavailable. It then supplies the snapshot's matching SHA-256 to the offline verifier and requires a foreign-key violation rather than a success report. Snapshot bytes must remain unchanged.

This test proves the verifier rejects one type of internally inconsistent recovered evidence even with a matching digest. The digest is computed locally for the test, **not** a demonstration of an independently trusted checksum. It does not test authenticated application restoration, HMAC key recovery, encrypted off-host backups, or RTO/RPO. No real networks or production data are used.
