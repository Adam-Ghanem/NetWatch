# Real offline backup CLI rejection regressions

Run `pytest -q tests/test_backup_cli_real_failures.py` to exercise the actual verifier and CLI boundary (without mocking `verify`). The isolated temporary-file cases cover a missing snapshot, an empty snapshot, and a malformed trusted SHA-256 argument. Each must return exit code 2 and a parseable JSON object with `ok: false`, without a success digest.

These checks require no network access, credentials, live database, or paid provider. They complement the stubbed success/failure CLI contract tests and the real SQLite snapshot smoke tests. They do **not** demonstrate full application restore, audit HMAC validation, authenticated recovery, or production RTO/RPO. Treat any nonzero verifier exit as a hard stop; use a separately trusted digest and an isolated staging recovery drill before restoring data.
