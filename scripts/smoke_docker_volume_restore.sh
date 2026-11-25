#!/usr/bin/env bash
set -Eeuo pipefail

IMAGE="${1:-netwatch-ci}"
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker CLI is required for the named-volume restore smoke." >&2
  exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 is required to create ephemeral smoke-test keys." >&2
  exit 2
fi
docker image inspect "$IMAGE" >/dev/null

RUN_SUFFIX="${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-1}-$$"
PREFIX="netwatch-volume-restore-${RUN_SUFFIX}"
SOURCE_VOLUME="${PREFIX}-source-data"
SOURCE_LOG_VOLUME="${PREFIX}-source-logs"
SNAPSHOT_VOLUME="${PREFIX}-snapshot"
RESTORE_VOLUME="${PREFIX}-restored-data"
RESTORE_LOG_VOLUME="${PREFIX}-restored-logs"
SOURCE_CONTAINER="${PREFIX}-source"
RESTORE_CONTAINER="${PREFIX}-restored"

API_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
AUDIT_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
APP_UID="$(docker run --rm --network none --entrypoint id "$IMAGE" -u)"
APP_GID="$(docker run --rm --network none --entrypoint id "$IMAGE" -g)"

cleanup() {
  local container
  local volume
  for container in "$SOURCE_CONTAINER" "$RESTORE_CONTAINER"; do
    docker rm -f "$container" >/dev/null 2>&1 || true
  done
  for volume in \
    "$SOURCE_VOLUME" "$SOURCE_LOG_VOLUME" "$SNAPSHOT_VOLUME" \
    "$RESTORE_VOLUME" "$RESTORE_LOG_VOLUME"; do
    docker volume rm "$volume" >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

create_app() {
  local container_name="$1"
  local data_volume="$2"
  local logs_volume="$3"

  docker run -d \
    --name "$container_name" \
    --network none \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=268435456 \
    --pids-limit 256 \
    --security-opt no-new-privileges:true \
    --cap-drop ALL \
    --cap-add NET_RAW \
    --init \
    --mount "type=volume,src=${data_volume},dst=/app/data" \
    --mount "type=volume,src=${logs_volume},dst=/app/logs" \
    --env "NETWATCH_API_KEY=${API_KEY}" \
    --env "NETWATCH_AUDIT_HMAC_KEY=${AUDIT_KEY}" \
    --env "NETWATCH_AI_ENABLED=false" \
    --env "NETWATCH_AI_AUTO_ANALYSIS_ENABLED=false" \
    --env "NETWATCH_SCHEDULER_ENABLED=false" \
    --env "NETWATCH_WEBHOOK_URL=" \
    --env "NETWATCH_SLACK_WEBHOOK_URL=" \
    --env "NETWATCH_ALLOWED_HOSTS=127.0.0.1,localhost" \
    "$IMAGE" >/dev/null
}

wait_ready() {
  local container_name="$1"
  local attempt
  for attempt in $(seq 1 45); do
    if docker exec "$container_name" python -c \
      'import urllib.request; urllib.request.urlopen("http://127.0.0.1:8000/api/health/ready", timeout=2).read()' \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  docker logs "$container_name" >&2 || true
  echo "NetWatch did not become ready in the isolated restore smoke." >&2
  return 1
}

assert_application_evidence() {
  local container_name="$1"
  docker exec -i "$container_name" python - <<'PY'
import json
import os
import urllib.request
from pathlib import Path

with urllib.request.urlopen(
    "http://127.0.0.1:8000/api/health/ready", timeout=3
) as response:
    if response.status != 200:
        raise SystemExit("readiness endpoint did not return HTTP 200")

request = urllib.request.Request(
    "http://127.0.0.1:8000/api/inventory",
    headers={"X-NetWatch-Key": os.environ["NETWATCH_API_KEY"]},
)
with urllib.request.urlopen(request, timeout=3) as response:
    payload = json.load(response)
if "192.0.2.10" not in json.dumps(payload, sort_keys=True):
    raise SystemExit("authenticated inventory omitted the synthetic restore marker")

import inventory_store

integrity = inventory_store.verify_audit_integrity()
if integrity.get("status") != "valid":
    raise SystemExit("restored audit HMAC chain did not verify")
database_bytes = Path("/app/data/netwatch.db").read_bytes()
if os.environ["NETWATCH_AUDIT_HMAC_KEY"].encode("utf-8") in database_bytes:
    raise SystemExit("audit key material was unexpectedly embedded in SQLite")
PY
}

docker volume create "$SOURCE_VOLUME" >/dev/null
docker volume create "$SOURCE_LOG_VOLUME" >/dev/null
create_app "$SOURCE_CONTAINER" "$SOURCE_VOLUME" "$SOURCE_LOG_VOLUME"
wait_ready "$SOURCE_CONTAINER"

docker exec -i "$SOURCE_CONTAINER" python - <<'PY'
import sqlite3
from contextlib import closing

with closing(sqlite3.connect("/app/data/netwatch.db")) as connection:
    connection.execute("PRAGMA foreign_keys = ON")
    with connection:
        scan = connection.execute(
            """
            INSERT INTO scan_runs (created_at, scan_type, target, summary, status)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "2026-11-25T00:00:00+00:00",
                "restore-smoke",
                "192.0.2.0/24",
                "Synthetic Docker volume recovery fixture",
                "completed",
            ),
        )
        scan_run_id = scan.lastrowid
        connection.execute(
            """
            INSERT INTO assets (ip_address, first_seen, last_seen, status, details)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "192.0.2.10",
                "2026-11-25T00:00:00+00:00",
                "2026-11-25T00:00:00+00:00",
                "Online",
                "Synthetic restore marker; no network scan was performed.",
            ),
        )
        connection.execute(
            """
            INSERT INTO network_observations
                (scan_run_id, ip_address, observed, status, details)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                scan_run_id,
                "192.0.2.10",
                1,
                "Online",
                "Synthetic restore marker; no network scan was performed.",
            ),
        )
PY

docker exec "$SOURCE_CONTAINER" python -c \
  "import inventory_store; inventory_store.record_audit_event('admin', 'docker_volume_restore_smoke', '192.0.2.10', 'completed', 'Synthetic restore fixture; no network scan.'); assert inventory_store.verify_audit_integrity()['status'] == 'valid'"
assert_application_evidence "$SOURCE_CONTAINER"

# Stop the application before taking the offline SQLite snapshot.
docker stop --time 10 "$SOURCE_CONTAINER" >/dev/null
docker rm "$SOURCE_CONTAINER" >/dev/null
docker volume create "$SNAPSHOT_VOLUME" >/dev/null

# Use SQLite's backup API from a read-only source mount, not a live-file copy.
docker run --rm --network none --user 0 \
  --mount "type=volume,src=${SOURCE_VOLUME},dst=/source,readonly" \
  --mount "type=volume,src=${SNAPSHOT_VOLUME},dst=/snapshot" \
  --entrypoint python "$IMAGE" -c '
import sqlite3
from contextlib import closing

with closing(sqlite3.connect("file:/source/netwatch.db?mode=ro", uri=True)) as source:
    with closing(sqlite3.connect("/snapshot/netwatch.db")) as destination:
        source.backup(destination)
        destination.commit()

with closing(sqlite3.connect("file:/snapshot/netwatch.db?mode=ro", uri=True)) as snapshot:
    if snapshot.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise SystemExit("snapshot integrity_check failed")
    if snapshot.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise SystemExit("snapshot foreign_key_check failed")
    if snapshot.execute(
        "SELECT 1 FROM assets WHERE ip_address = ?", ("192.0.2.10",)
    ).fetchone() is None:
        raise SystemExit("snapshot omitted the synthetic asset marker")
'

# Simulate source-volume loss; only the independent snapshot volume remains.
docker volume rm "$SOURCE_VOLUME" "$SOURCE_LOG_VOLUME" >/dev/null
docker volume create "$RESTORE_VOLUME" >/dev/null
docker volume create "$RESTORE_LOG_VOLUME" >/dev/null

# Restore into a fresh volume with the image's non-root ownership.
docker run --rm --network none --user 0 \
  --env "NETWATCH_APP_UID=${APP_UID}" \
  --env "NETWATCH_APP_GID=${APP_GID}" \
  --mount "type=volume,src=${SNAPSHOT_VOLUME},dst=/snapshot,readonly" \
  --mount "type=volume,src=${RESTORE_VOLUME},dst=/restore" \
  --entrypoint python "$IMAGE" -c '
import os
import shutil

uid = int(os.environ["NETWATCH_APP_UID"])
gid = int(os.environ["NETWATCH_APP_GID"])
destination = "/restore/netwatch.db"
shutil.copyfile("/snapshot/netwatch.db", destination)
os.chown("/restore", uid, gid)
os.chmod("/restore", 0o700)
os.chown(destination, uid, gid)
os.chmod(destination, 0o600)
'

create_app "$RESTORE_CONTAINER" "$RESTORE_VOLUME" "$RESTORE_LOG_VOLUME"
wait_ready "$RESTORE_CONTAINER"
assert_application_evidence "$RESTORE_CONTAINER"

echo "Docker named-volume restore smoke passed: source volume removed, SQLite snapshot restored into a fresh volume, authenticated inventory and audit HMAC verified."
