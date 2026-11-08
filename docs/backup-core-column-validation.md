# Offline backup core-column gate

The read-only SQLite backup verifier rejects snapshots missing `assets.ip_address` or `scan_runs.created_at`, even when all required table names exist and `PRAGMA integrity_check` succeeds. These columns are used by the inventory and scan-history runtime paths. This is a **minimal compatibility check**, not a full migration or application restore test.

Run `python3 scripts/verify_sqlite_backup.py <standalone-backup> --expected-schema 10` on an isolated offline copy. Do not point the verifier at a live database. A passing report still requires a controlled staging restore, readiness check and authenticated inventory/history smoke test before recovery approval. No active network scans or remediation are performed.
