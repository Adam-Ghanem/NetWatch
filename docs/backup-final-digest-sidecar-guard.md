# Final-digest SQLite sidecar race guard

The offline backup verifier already rejects SQLite `-wal`, `-shm`, and
`-journal` sidecars before and after database inspection. Its final SHA-256
pass occurs after the second sidecar check. A sidecar created during that
final read previously escaped the standalone-snapshot guard.

The verifier now repeats the standalone check **after** the final digest
comparison. Regression tests inject each sidecar type during the second
hash pass and require a failure without changing the backup bytes.

Run: `pytest -q tests/test_backup_verify.py`.

This is defense in depth, **not** a race-free filesystem transaction.
The source must remain stopped and immutable throughout verification.
A successful result does not authenticate the source, validate audit
HMAC keys, guarantee application restore, or replace encrypted off-host
backups and controlled recovery drills. No network activity is needed.
