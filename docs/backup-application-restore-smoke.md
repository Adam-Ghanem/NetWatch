# Isolated application-level backup restore smoke

Run the regression with:

```bash
pytest -q tests/test_api.py -k isolated_snapshot_boots_application
```

The test creates a private schema-11 SQLite database with synthetic RFC 5737
inventory, scan, observation, and HMAC-protected audit evidence. It creates a
consistent standalone snapshot with SQLite's backup API, renames the original
data directory to simulate source-volume loss, and starts the real FastAPI
application lifespan against the restored copy.

The smoke checks:

- Public `/api/health/ready` reports database, access, and audit integrity ready.
- Authenticated `/api/inventory`, `/api/history`, and `/api/observations`
  return the synthetic records from the restored database.
- The retained audit chain validates with a separately configured test-only
  audit key; the key is not stored in the SQLite snapshot.

All records and keys are test fixtures. The test performs no network scan,
capture, external provider call, or production data access.

## Limits

This is an automated application-level smoke test on an isolated local
filesystem. It does not exercise Docker/Kubernetes volume orchestration,
off-host encryption or key escrow, production permissions, a real operator
restore procedure, or measured RTO/RPO. It is stronger than a raw SQLite
read-back test, but it is **not production disaster-recovery acceptance**.
