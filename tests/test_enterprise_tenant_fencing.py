from __future__ import annotations

import sqlite3

import pytest

from enterprise_store import (
    claim_jobs,
    claim_outbox_events,
    complete_job,
    create_enterprise_schema,
    enqueue_job,
    enqueue_outbox_event,
    fail_job,
    mark_outbox_delivered,
    mark_outbox_failed,
)
from enterprise_worker import process_jobs_once, publish_outbox_once


def _db():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    create_enterprise_schema(conn)
    return conn


def test_claims_do_not_cross_tenants_or_default_scope():
    conn = _db()
    for tenant in ("red", "blue"):
        enqueue_job(conn, job_type="approved", dedupe_key=f"j-{tenant}", payload={}, tenant_id=tenant)
        enqueue_outbox_event(
            conn, topic="alert", event_type="new", aggregate_id=tenant,
            dedupe_key=f"e-{tenant}", payload={}, tenant_id=tenant,
        )
    assert claim_jobs(conn, worker_id="w") == []
    assert claim_outbox_events(conn, consumer_id="w") == []
    assert [j["tenant_id"] for j in claim_jobs(conn, worker_id="w", tenant_id="red")] == ["red"]
    assert [e["tenant_id"] for e in claim_outbox_events(
        conn, consumer_id="w", tenant_id="blue"
    )] == ["blue"]


def test_worker_defaults_cannot_publish_other_tenant_evidence():
    conn = _db()
    enqueue_job(conn, job_type="approved", dedupe_key="other", payload={}, tenant_id="other")
    enqueue_outbox_event(
        conn, topic="alert", event_type="new", aggregate_id="other",
        dedupe_key="other-event", payload={}, tenant_id="other",
    )
    seen = []
    assert process_jobs_once(conn, worker_id="w", handlers={"approved": seen.append}).claimed == 0
    assert publish_outbox_once(conn, consumer_id="w", publisher=seen.append).claimed == 0
    assert seen == []


def test_stale_job_ack_is_fenced_even_when_worker_id_reused():
    conn = _db()
    job_id = enqueue_job(
        conn, job_type="approved", dedupe_key="j", payload={},
        available_at="2026-10-17T09:59:00+00:00",
    )
    first = claim_jobs(conn, worker_id="same", now="2026-10-17T10:00:00+00:00")[0]
    second = claim_jobs(conn, worker_id="same", now="2026-10-17T10:06:00+00:00")[0]
    assert second["attempts"] == first["attempts"] + 1
    assert not complete_job(conn, job_id=job_id, worker_id="same", expected_attempts=first["attempts"])
    assert not fail_job(
        conn, job_id=job_id, worker_id="same",
        expected_attempts=first["attempts"], error="stale",
    )
    assert complete_job(conn, job_id=job_id, worker_id="same", expected_attempts=second["attempts"])


def test_stale_outbox_ack_is_fenced_even_when_consumer_id_reused():
    conn = _db()
    event_id = enqueue_outbox_event(
        conn, topic="alerts", event_type="new", aggregate_id="1",
        dedupe_key="e", payload={}, available_at="2026-10-17T09:59:00+00:00",
    )
    first = claim_outbox_events(conn, consumer_id="same", now="2026-10-17T10:00:00+00:00")[0]
    second = claim_outbox_events(conn, consumer_id="same", now="2026-10-17T10:06:00+00:00")[0]
    assert second["attempts"] == first["attempts"] + 1
    assert not mark_outbox_delivered(
        conn, event_id=event_id, consumer_id="same", expected_attempts=first["attempts"]
    )
    assert not mark_outbox_failed(
        conn, event_id=event_id, consumer_id="same",
        expected_attempts=first["attempts"], error="stale",
    )
    assert mark_outbox_delivered(
        conn, event_id=event_id, consumer_id="same", expected_attempts=second["attempts"]
    )


def test_cross_tenant_dedupe_cannot_return_another_tenant_row_id():
    conn = _db()
    enqueue_job(conn, job_type="a", dedupe_key="shared", payload={}, tenant_id="red")
    enqueue_outbox_event(
        conn, topic="a", event_type="b", aggregate_id="1",
        dedupe_key="shared", payload={}, tenant_id="red",
    )
    with pytest.raises(ValueError, match="another tenant"):
        enqueue_job(conn, job_type="a", dedupe_key="shared", payload={}, tenant_id="blue")
    with pytest.raises(ValueError, match="another tenant"):
        enqueue_outbox_event(
            conn, topic="a", event_type="b", aggregate_id="1",
            dedupe_key="shared", payload={}, tenant_id="blue",
        )
    with pytest.raises(ValueError, match="tenant_id"):
        claim_jobs(conn, worker_id="w", tenant_id="")
