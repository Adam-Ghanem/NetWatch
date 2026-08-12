# Track A Local Restore Drill

**Date:** 2026-08-12  
**Environment:** Isolated local staging process on `127.0.0.1:18000` with a temporary database under `/tmp/netwatch-stage-100`  
**Scope:** Snapshot creation, read-only verification, replacement on the isolated copy, readiness, inventory access, and post-restore integrity.

## Procedure and result

1. The Admin database-backup endpoint produced a 200,704-byte SQLite snapshot.
2. `scripts/verify_sqlite_backup.py --expected-schema 10` returned `integrity: ok`, `schema_version: 10`, and `read_only: true`.
3. The isolated staging database was stopped, replaced with the verified snapshot, and started again. No live user database was touched.
4. `/api/health/ready` returned `status: ready`, `database: ready`, `access: ready`, and `audit_integrity: ready`.
5. Authenticated `/api/inventory` returned HTTP 200 after restore.
6. A second read-only verification returned `integrity: ok` and `schema_version: 10`; the restored audit log contained the expected backup operation evidence.

**Drill result:** **Passed for local single-tenant snapshot/restore verification.**

## Boundary

This result does not prove off-host backup rotation, managed key recovery, cross-zone recovery, a production RTO/RPO, or a multi-tenant PostgreSQL restore. Those remain Track A external-environment gates and Track B requirements.
