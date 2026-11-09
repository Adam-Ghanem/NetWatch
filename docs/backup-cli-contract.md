# Offline backup verifier CLI contract

The `scripts/verify_sqlite_backup.py` command emits one JSON document to stdout.
A successful verification returns exit code `0` with `"ok": true`; an invalid
snapshot, digest mismatch, schema mismatch, or SQLite read error returns exit
code `2` with `"ok": false` and an error string. Callers must check **both**
the process exit code and the JSON status; they must never interpret an error
report as proof that recovery is possible.

`tests/test_backup_cli_contract.py` checks this interface without touching
production data. It stubs the verifier to isolate CLI argument forwarding and
JSON/exit-code behavior; actual SQLite snapshot and digest checks are covered
separately by `tests/test_backup_runtime_snapshot.py`.

The CLI does not restore a database, authenticate an application, validate
audit HMAC chains, or guarantee an RTO/RPO. Use the isolated staging drill in
`docs/backup-verification.md` before making recovery claims.
