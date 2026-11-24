# Isolated application-level backup restore smoke

Run the regression with:

```bash
pytest -q tests/test_api.py -k isolated_snapshot_boots_application
```

The test creates a private schema-11 SQLite database with synthetic RFC 5737
inventory, scan, observation, service-finding, operational alert/case, disabled
scan-policy, maintenance-window, and HMAC-protected audit evidence. It creates
a consistent standalone snapshot with SQLite's backup API, renames the original
data directory to simulate source-volume loss, and starts the real FastAPI
application lifespan against the restored copy.

The smoke checks:

- Public `/api/health/ready` reports database, access, and audit integrity ready.
- Authenticated `/api/inventory`, `/api/history`, and `/api/observations`
  return the synthetic records from the restored database.
- Authenticated `/api/service-findings` returns the restored service evidence.
- Authenticated `/api/alerts` returns the restored operational alert; the
  operator-only resolution workflow can assign and resolve that case after
  restore, and the updated audit chain remains valid.
- Authenticated `/api/scan-policies` and `/api/maintenance-windows` retain
  the disabled authorized policy and its maintenance-window relationship.
- The audit HMAC key remains external to the snapshot. Missing or incorrect
  key material keeps readiness at HTTP 503; readiness returns only after the
  matching key is supplied separately.
- The test replaces the network scanner with a failure guard; no scan is run.

All records and keys are test fixtures. The test performs no network scan,
capture, external provider call, notification delivery, or production data
access.

## Limits

This is an automated application-level smoke test on an isolated local
filesystem. It does not exercise Docker/Kubernetes volume orchestration,
off-host encryption or key escrow, production permissions, a real operator
restore procedure, or measured RTO/RPO. It is stronger than a raw SQLite
read-back test, but it is **not production disaster-recovery acceptance**.
