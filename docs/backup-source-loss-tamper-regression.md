# Recovered snapshot tamper regression

Run `python -m pytest -q tests/test_backup_recovered_tamper.py` from the repository root.

The test builds a synthetic schema-11 inventory, takes a standalone SQLite snapshot, records its SHA-256 as a separately trusted reference, and removes the source directory. It first verifies the recovered snapshot, then changes an asset status using a normal SQLite transaction. The database remains structurally valid; verification must reject the modified snapshot against the original digest without changing its bytes or creating SQLite sidecars.

**Operator boundary:** A digest computed from the same untrusted recovered file cannot authenticate that file. Preserve the expected digest through a separate trusted channel. This test does not validate audit-HMAC key recovery, encryption, authenticated application login, off-host retention, RTO/RPO, or filesystem race resistance. No live network or provider API access is needed.
