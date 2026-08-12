from __future__ import annotations

import sqlite3

from enterprise_store import (
    claim_jobs,
    claim_outbox_events,
    complete_job,
    create_enterprise_schema,
    enqueue_job,
    enqueue_outbox_event,
    enterprise_queue_status,
    fail_job,
    mark_outbox_delivered,
)


def _connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    create_enterprise_schema(conn)
    return conn


def test_outbox_is_idempotent_and_claimed_once_until_stale():
    conn = _connection()
    first = enqueue_outbox_event(
        conn,
        topic="operations.alerts",
        event_type="alert_created",
        aggregate_id="alert:7",
        dedupe_key="alert-created:7",
        payload={"alert_id": 7, "severity": "High"},
    )
    second = enqueue_outbox_event(
        conn,
        topic="operations.alerts",
        event_type="alert_created",
        aggregate_id="alert:7",
        dedupe_key="alert-created:7",
        payload={"alert_id": 7, "severity": "High"},
    )

    assert first == second
    claimed = claim_outbox_events(conn, consumer_id="worker-a", now="2026-08-12T10:00:00+00:00")
    assert [event["id"] for event in claimed] == [first]
    assert claim_outbox_events(conn, consumer_id="worker-b", now="2026-08-12T10:01:00+00:00") == []
    assert mark_outbox_delivered(conn, event_id=first, consumer_id="worker-b") is False
    assert mark_outbox_delivered(conn, event_id=first, consumer_id="worker-a") is True
    assert enterprise_queue_status(conn)["outbox_delivered"] == 1


def test_stale_outbox_claim_can_be_recovered():
    conn = _connection()
    event_id = enqueue_outbox_event(
        conn,
        topic="operations.alerts",
        event_type="alert_created",
        aggregate_id="alert:8",
        dedupe_key="alert-created:8",
        payload={"alert_id": 8},
    )
    assert claim_outbox_events(conn, consumer_id="worker-a", now="2026-08-12T10:00:00+00:00")
    recovered = claim_outbox_events(conn, consumer_id="worker-b", now="2026-08-12T10:06:00+00:00")
    assert [event["id"] for event in recovered] == [event_id]
    assert recovered[0]["claimed_by"] == "worker-b"


def test_jobs_are_idempotent_and_fail_after_bounded_attempts():
    conn = _connection()
    job_id = enqueue_job(
        conn,
        job_type="network_scan",
        dedupe_key="scan:default:42",
        payload={"scan_policy_id": 42},
        max_attempts=2,
    )
    assert (
        enqueue_job(
            conn,
            job_type="network_scan",
            dedupe_key="scan:default:42",
            payload={"scan_policy_id": 42},
            max_attempts=2,
        )
        == job_id
    )
    claimed = claim_jobs(conn, worker_id="worker-a", now="2026-08-12T10:00:00+00:00")
    assert [job["id"] for job in claimed] == [job_id]
    assert fail_job(
        conn,
        job_id=job_id,
        worker_id="worker-a",
        error="temporary failure",
        retry_at="2026-08-12T10:01:00+00:00",
    )
    claimed_again = claim_jobs(conn, worker_id="worker-a", now="2026-08-12T10:01:00+00:00")
    assert [job["id"] for job in claimed_again] == [job_id]
    assert fail_job(conn, job_id=job_id, worker_id="worker-a", error="permanent failure")
    assert enterprise_queue_status(conn)["jobs_failed"] == 1


def test_completed_jobs_are_not_claimed_again():
    conn = _connection()
    job_id = enqueue_job(
        conn,
        job_type="audit_export",
        dedupe_key="audit-export:1",
        payload={"tenant_id": "default"},
    )
    assert claim_jobs(conn, worker_id="worker-a")
    assert complete_job(conn, job_id=job_id, worker_id="worker-a") is True
    assert claim_jobs(conn, worker_id="worker-b") == []
    assert enterprise_queue_status(conn)["jobs_succeeded"] == 1
