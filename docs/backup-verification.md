# Verify a NetWatch SQLite backup before a restore

NetWatch supports a **single-instance SQLite** deployment. The Admin dashboard
can download a consistent snapshot. The verifier below works **offline** and
**read-only**; it never modifies or restores a database.

## What the verifier checks

- SQLite page integrity (PRAGMA integrity_check)
- A positive NetWatch schema version and an optional exact expected version
- Presence of critical tables: assets, scan_runs, network_observations,
  audit_log, operation_alerts, and service_findings
- SQLite foreign-key consistency (PRAGMA foreign_key_check)
- Row counts for those tables
- SHA-256 fingerprint; optionally match a digest supplied through a separately
  trusted channel
- Whether the file changed during verification (file identity, size,
  modification time, and a second SHA-256 digest after SQLite checks)
- Reject symbolic links and multiply hard-linked backup files (which can share
  writes with another path), as well as SQLite `-wal`, `-shm`, or `-journal`
  sidecars (including dangling symlinks); verify a standalone export rather
  than a multi-file live database

A missing required table, broken reference, failed integrity check, unexpected
version, or mismatched digest returns a nonzero process exit code.

## Run it

First download a **snapshot** through the Admin dashboard. Do not point this
tool at a live database file or copy a running SQLite database with a normal
filesystem copy; WAL state may be incomplete. The verifier rejects sidecars, symbolic links and hard-linked files, but this does not eliminate all concurrent replacement or
filesystem race conditions. The second digest catches same-size, same-mtime
content changes between the two reads, but not changes reversed before the
second read or replacement-and-restore races. File identity checks catch
many atomic replacements but cannot prevent concurrent filesystem races.
Use a trusted, stopped,
access-controlled snapshot.

~~~bash
python scripts/verify_sqlite_backup.py --expected-schema 11 backup.sqlite3
~~~

The current `inventory_store.init_db()` schema is **11**. The examples above
are for snapshots from that version; for an older, intentionally retained
snapshot, use its actual schema version and validate migration compatibility
in isolated staging. Do not disable the version check to force a restore.

Record the SHA-256 in the JSON result in your recovery register. After
transferring the backup, verify the destination against the digest from a
separately authenticated channel:

~~~bash
python scripts/verify_sqlite_backup.py \
  --expected-schema 11 \
  --expected-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  backup.sqlite3
~~~

Replace the example digest with the actual one printed by your first check.
Exit code 0 means these local checks passed. Exit code 2 means verification
failed. **Do not restore** if any check fails.

## Restore drill

1. Keep the original database and the downloaded snapshot in protected storage.
2. Verify the offline snapshot with this command.
3. Stop an isolated **staging** instance before replacing its data volume;
   never overwrite a live database.
4. Start the staging instance using the correct separately managed audit key
   and app secrets.
5. Check /api/health/ready, authenticated inventory, policy/case records,
   audit-chain integrity and application behavior.
6. Record the actual recovery time, tested backup age and reviewer approval.

See [the prior local restore drill](track-a-restore-drill.md) for a dated
example. That older result is not proof of recovery on a production platform.

## Security limits

SHA-256 detects accidental transfer errors only when its expected digest comes
from an independent trusted channel. It is **not a signature**, does not prove
who created the backup, and cannot detect a malicious replacement accompanied
by an altered digest. These checks do not verify the NetWatch audit HMAC chain;
that requires the application and the original signing key.

The verifier also does **not** encrypt backups, upload/rotate them off-host,
provide RTO/RPO guarantees, or establish multi-tenant/multi-replica readiness.
Use approved encrypted backup storage and exercise a real recovery procedure
before making production resilience claims.
