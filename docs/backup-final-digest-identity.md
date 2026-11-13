# Post-hash backup file identity guard

The offline verifier already checks snapshot identity after SQLite inspection, then computes a second SHA-256 digest. An atomic replacement **during that final digest** could previously leave a same-content, same-mtime replacement undetected.

The verifier now checks device/inode identity, size and nanosecond mtime **after** the final digest and standalone-sidecar check. A synthetic regression replaces the snapshot during the second hash with identical bytes and timestamps; verification must fail without modifying the replacement's contents.

Run `pytest -q tests/test_backup_verify.py -k atomic_replacement_during_final_digest` or the full backup test module. GitHub Python/Security CI should also run on this PR head.

This is a narrow defense-in-depth check, **not** a race-free filesystem snapshot, source authenticity proof, audit-HMAC validation, or a complete application restore drill. A hostile writer could still change the file after the last check or restore it between observations. Keep backup files and parent directories access-controlled, and verify only stopped immutable snapshots in isolated staging. No live network scans or production restoration are performed.
