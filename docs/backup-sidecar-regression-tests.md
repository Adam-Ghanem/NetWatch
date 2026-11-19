# SQLite sidecar regression coverage

This stacked test-only change validates the fail-closed sidecar guard proposed in PR #252. The parameterized test rejects adjacent `-wal`, `-shm`, and `-journal` files. A separate test keeps a real WAL connection open after a committed write, ensuring the verifier rejects uncheckpointed data. A clean WAL close/checkpoint verifies that standalone snapshots still pass.

Run `python -m pytest -q tests/test_backup_verify.py` on this branch. The tests use temporary synthetic databases only; never run this against live production databases or delete active SQLite sidecars to force a pass. These tests do **not** prove application restore, off-host recovery, or race-free verification. Parent PRs #199, #249, #250, and #252 require review before this stack can merge.
