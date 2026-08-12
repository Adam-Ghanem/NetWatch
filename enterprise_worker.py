from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable

from enterprise_store import (
    claim_jobs,
    complete_job,
    fail_job,
    mark_outbox_delivered,
    mark_outbox_failed,
)

JobHandler = Callable[[dict[str, Any]], None]
EventPublisher = Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class WorkerCycleResult:
    claimed: int
    succeeded: int
    failed: int
    dead_lettered: int


def _safe_error(error: BaseException) -> str:
    return " ".join(str(error).split())[:500] or error.__class__.__name__


def process_jobs_once(
    conn: Any,
    *,
    worker_id: str,
    handlers: dict[str, JobHandler],
    limit: int = 10,
) -> WorkerCycleResult:
    claimed = claim_jobs(conn, worker_id=worker_id, limit=limit)
    succeeded = 0
    failed = 0
    dead_lettered = 0
    for job in claimed:
        handler = handlers.get(str(job.get("job_type", "")))
        try:
            if handler is None:
                raise RuntimeError("No approved handler is registered for this job type.")
            handler(dict(job.get("payload") or {}))
        except Exception as error:  # noqa: BLE001 - worker must record and continue per item
            failed += 1
            if int(job.get("attempts", 0)) >= int(job.get("max_attempts", 1)):
                dead_lettered += 1
            fail_job(
                conn,
                job_id=int(job["id"]),
                worker_id=worker_id,
                error=_safe_error(error),
            )
        else:
            if complete_job(conn, job_id=int(job["id"]), worker_id=worker_id):
                succeeded += 1
    conn.commit()
    return WorkerCycleResult(len(claimed), succeeded, failed, dead_lettered)


def publish_outbox_once(
    conn: Any,
    *,
    consumer_id: str,
    publisher: EventPublisher,
    limit: int = 100,
) -> WorkerCycleResult:
    from enterprise_store import claim_outbox_events

    claimed = claim_outbox_events(conn, consumer_id=consumer_id, limit=limit)
    succeeded = 0
    failed = 0
    dead_lettered = 0
    for event in claimed:
        try:
            publisher(dict(event))
        except Exception as error:  # noqa: BLE001 - delivery failure is persisted per event
            failed += 1
            if int(event.get("attempts", 0)) >= 12:
                dead_lettered += 1
            mark_outbox_failed(
                conn,
                event_id=int(event["id"]),
                consumer_id=consumer_id,
                error=_safe_error(error),
            )
        else:
            if mark_outbox_delivered(
                conn,
                event_id=int(event["id"]),
                consumer_id=consumer_id,
            ):
                succeeded += 1
    conn.commit()
    return WorkerCycleResult(len(claimed), succeeded, failed, dead_lettered)


def run_poll_loop(
    cycle: Callable[[], WorkerCycleResult],
    *,
    poll_seconds: float = 1.0,
    max_cycles: int | None = None,
) -> list[WorkerCycleResult]:
    """Run a bounded loop; callers own connection lifecycle and shutdown signals."""
    safe_poll = max(0.1, min(float(poll_seconds), 60.0))
    safe_cycles = None if max_cycles is None else max(1, min(int(max_cycles), 10_000))
    results: list[WorkerCycleResult] = []
    cycles = 0
    while safe_cycles is None or cycles < safe_cycles:
        results.append(cycle())
        cycles += 1
        if safe_cycles is None or cycles < safe_cycles:
            time.sleep(safe_poll)
    return results
