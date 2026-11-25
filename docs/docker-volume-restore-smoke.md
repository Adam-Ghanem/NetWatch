# Docker named-volume restore smoke

NetWatch's Security CI runs a disposable Docker recovery smoke against the
production image built by the same workflow:

```bash
docker build -t netwatch-ci .
bash scripts/smoke_docker_volume_restore.sh netwatch-ci
```

The script creates temporary API and audit-HMAC keys, disables AI, the hourly
analysis scheduler, scan scheduler, and webhook delivery, and starts NetWatch
with the same non-root/read-only-container boundary used by Compose. All
containers and helper processes use Docker's `none` network, so the smoke
cannot reach external systems or perform a network scan.

It inserts only synthetic documentation-range data (`192.0.2.10`) directly
into a temporary SQLite database, plus a synthetic HMAC-protected audit event.
After stopping the application, it creates a consistent snapshot with
SQLite's backup API from a read-only source-volume mount. It then removes the
source data and log volumes, restores the snapshot into a newly created named
volume with the image's non-root ownership, and starts a fresh NetWatch
container.

The restored application must pass all of these checks:

- `/api/health/ready` returns HTTP 200;
- authenticated `/api/inventory` contains the synthetic asset marker;
- the retained audit HMAC chain verifies as `valid`;
- the audit key bytes are not present in the SQLite database file;
- the snapshot passes SQLite integrity and foreign-key checks before restore.

The script uses ephemeral random test keys and removes its containers and
volumes on exit. It does not read a developer's `.env`, production database,
or managed secret.

## Limits

This is a real Docker named-volume restore regression on one CI runner. The
snapshot volume is on the same Docker daemon; this does **not** establish
encrypted off-host backup, managed-secret escrow, cross-host disaster
recovery, Kubernetes volume recovery, operator acceptance, or measured
RTO/RPO. A controlled staging drill and independently stored recovery keys
remain required before production recovery can be accepted.
