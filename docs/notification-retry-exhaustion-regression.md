# Durable notification terminal retry regression

The isolated synthetic tests in `tests/test_notification_retry_exhaustion.py` exercise the existing SQLite receipt retry budget without sending HTTP requests.

- A pending receipt already at `MAX_DELIVERY_ATTEMPTS` is marked `dead`, with claim metadata cleared, without calling a delivery provider.
- A receipt at `MAX_DELIVERY_ATTEMPTS - 1` is delivered to a mocked failing provider once, becomes `dead`, and is not claimed on the following cycle.

The cycle result's `dead` counter includes receipts newly dead-lettered by the pre-claim exhaustion sweep, even though those rows are not provider claims. A later cycle does not count the same transition again; use the status endpoint for the current dead-letter backlog.

Run with `python -m pytest -q tests/test_notification_retry_exhaustion.py` in the project test environment. These tests check terminal transitions, not cross-process concurrency, live provider behavior, or recovery of an actual deployment. The existing at-least-once semantics remain: successful provider acceptance before a process crash can still produce a duplicate delivery. Operators must keep downstream `event_id` deduplication and alert on dead receipts. No runtime retry policy or configuration is changed by this PR.
