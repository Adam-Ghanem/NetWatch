# Offline backup source-loss regression

Run `python -m pytest -q tests/test_backup_restored_records.py` on this stacked branch.

The regression creates a real schema-11 SQLite database with synthetic RFC 5737 inventory, scan and observation evidence, takes a standalone backup, and checks its expected SHA-256 and schema. It then **renames the source data directory** to simulate the original data volume becoming unavailable before querying the recovered snapshot through a separate read-only SQLite connection. The linked evidence must remain readable without the original database or its WAL files.

This is a synthetic, isolated **data-level** source-loss test. It does not delete user data, contact networks, validate application authentication or audit HMAC keys, test encrypted off-host storage, or establish RTO/RPO. A production recovery procedure still requires a separately managed key, an authenticated application restore drill, and operator approval.
