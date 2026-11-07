# Durable notification receipt crash-recovery checks

The opt-in SQLite receipt queue uses **at-least-once** delivery. A remote
webhook may accept an event immediately before the worker crashes; the next
worker may send it again. Downstream consumers should deduplicate by the stable
`event_id` rather than assuming exactly-once transport.

Regression tests in `tests/test_notification_receipt_crash_recovery.py` cover:

- A stale claimed receipt becomes eligible for a new worker after the claim
  timeout, with an incremented attempt counter.
- A stale claim already at the retry limit transitions to `dead` without
  another outbound request.
- A stale worker that returns after another worker has reclaimed and delivered
  the receipt cannot overwrite the newer worker's acknowledgement.

Run `pytest -q tests/test_notification_receipt_crash_recovery.py` and the
repository's full Python/Security CI before accepting changes. These tests use
a local temporary SQLite database and a stubbed delivery function; they make
no external requests and do not prove multi-instance high availability.

Operationally, inspect admin-only receipt status for growing `pending` or
`dead` counts and investigate channel configuration and downstream idempotency.
Do not requeue dead receipts blindly: doing so may produce duplicate alerts.
