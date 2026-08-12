from __future__ import annotations

import sqlite3

from enterprise_store import create_enterprise_schema, enqueue_job, enqueue_outbox_event
from enterprise_worker import process_jobs_once, publish_outbox_once, run_poll_loop


def _connection() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    create_enterprise_schema(conn)
    return conn


def test_process_jobs_once_runs_allowlisted_handler_and_completes():
    conn = _connection()
    enqueue_job(conn, job_type="approved", dedupe_key="job-1", payload={"value": 7})
    conn.commit()
    seen: list[dict[str, object]] = []

    result = process_jobs_once(
        conn,
        worker_id="worker-a",
        handlers={"approved": seen.append},
    )

    row = conn.execute("SELECT status, attempts FROM enterprise_jobs").fetchone()
    assert result.claimed == result.succeeded == 1
    assert result.failed == 0
    assert row["status"] == "succeeded"
    assert row["attempts"] == 1
    assert seen == [{"value": 7}]


def test_process_jobs_once_records_unknown_handler_failure_and_retries():
    conn = _connection()
    enqueue_job(
        conn,
        job_type="not-approved",
        dedupe_key="job-unknown",
        payload={},
        max_attempts=2,
    )
    conn.commit()

    result = process_jobs_once(conn, worker_id="worker-a", handlers={})

    row = conn.execute("SELECT status, attempts, last_error FROM enterprise_jobs").fetchone()
    assert result.claimed == 1
    assert result.failed == 1
    assert result.dead_lettered == 0
    assert row["status"] == "pending"
    assert row["attempts"] == 1
    assert "approved handler" in row["last_error"]


def test_process_jobs_once_marks_last_failure_dead_letter():
    conn = _connection()
    enqueue_job(
        conn,
        job_type="broken",
        dedupe_key="job-broken",
        payload={},
        max_attempts=1,
    )
    conn.commit()

    result = process_jobs_once(conn, worker_id="worker-a", handlers={})

    row = conn.execute("SELECT status, attempts FROM enterprise_jobs").fetchone()
    assert result.dead_lettered == 1
    assert row["status"] == "failed"
    assert row["attempts"] == 1


def test_publish_outbox_once_acknowledges_event_and_stops_duplicate_delivery():
    conn = _connection()
    enqueue_outbox_event(
        conn,
        topic="alerts",
        event_type="created",
        aggregate_id="alert-1",
        dedupe_key="event-1",
        payload={"severity": "High"},
    )
    conn.commit()
    published: list[dict[str, object]] = []

    first = publish_outbox_once(conn, consumer_id="consumer-a", publisher=published.append)
    second = publish_outbox_once(conn, consumer_id="consumer-a", publisher=published.append)

    assert first.claimed == first.succeeded == 1
    assert second.claimed == 0
    assert published[0]["payload"] == {"severity": "High"}


def test_run_poll_loop_is_bounded():
    calls = 0

    def cycle():
        nonlocal calls
        calls += 1
        return None

    result = run_poll_loop(cycle, poll_seconds=0, max_cycles=2)

    assert calls == 2
    assert result == [None, None]
