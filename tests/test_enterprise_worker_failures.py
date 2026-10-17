import sqlite3
from datetime import datetime, timedelta, timezone

from enterprise_store import create_enterprise_schema, enqueue_job, enqueue_outbox_event
from enterprise_worker import process_jobs_once, publish_outbox_once


def test_failed_job_and_outbox_are_deferred():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    create_enterprise_schema(conn)
    enqueue_job(conn, job_type="approved", dedupe_key="j", payload={})
    enqueue_outbox_event(
        conn,
        topic="alerts",
        event_type="created",
        aggregate_id="1",
        dedupe_key="e",
        payload={},
    )
    conn.commit()

    def broken(_payload):
        raise ValueError("do not persist this value")

    job = process_jobs_once(conn, worker_id="worker", handlers={"approved": broken})
    event = publish_outbox_once(conn, consumer_id="worker", publisher=broken)
    assert job.failed == event.failed == 1
    for table in ("enterprise_jobs", "enterprise_outbox"):
        row = conn.execute(f"SELECT available_at, last_error FROM {table}").fetchone()
        assert row["last_error"] == "Worker handler failed (ValueError)."
        available = datetime.fromisoformat(row["available_at"])
        now = datetime.now(timezone.utc)
        assert now < available < now + timedelta(minutes=2)
