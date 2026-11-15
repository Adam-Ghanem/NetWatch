# Isolated restore drill: timing evidence

This **offline, read-only** helper calculates two observed intervals from
operator-recorded timestamps. It does not create, verify, or restore backups,
contact an API, or assert that an application is healthy.

Run only after an authorized isolated staging restore with synthetic data:

```bash
python scripts/measure_restore_drill.py \
  --last-durable 2026-11-15T09:00:00Z \
  --failure 2026-11-15T09:03:00Z \
  --ready 2026-11-15T09:05:30Z
```

Record the source of each timestamp alongside the JSON output:

- **last-durable:** newest independently verified, restorable evidence
  recovered in staging (not merely the most recent backup attempt).
- **failure:** simulated failure start, from the drill operator's clock.
- **ready:** time authenticated readiness, inventory access, and audit
  integrity were **actually confirmed** after the isolated restore.

Use full `YYYY-MM-DDTHH:MM:SS` timestamps with `Z` or `+HH:MM`/`-HH:MM` offsets; optional fractional seconds are limited to six digits. Week dates, spaces or arbitrary date/time separators, offset seconds, and extra trailing data are rejected rather than silently normalized.\n\nThe helper rejects missing timezone offsets, UTC normalization overflow at the
minimum/maximum supported calendar dates, and impossible event ordering.
Invalid inputs return CLI exit code 2 with no JSON evidence output.
Its observed RPO proxy is failure minus last durable evidence; observed RTO
proxy is ready minus failure. These are *drill observations*, not guaranteed
production RPO/RTO, a measured data-loss count, or proof of recovery.

For acceptance, separately retain backup hash/verification results, schema
version, authenticated API checks, audit-chain evidence, operator sign-off,
and clock synchronization details. Do not include credentials, personal
inventory, production databases, or secrets in the evidence bundle.
See [Track A restore drill](track-a-restore-drill.md) for a historical local
drill; its schema version and timing are not a current production baseline.
