# Enterprise queue failure safety

Job handlers and outbox publishers may raise exceptions containing sensitive
integration configuration, endpoint URLs or network evidence. The worker now
persists a fixed error category (the exception class), not arbitrary exception
text. The one internal missing-handler error is a fixed allowlisted message.

Failed deliveries are deferred with exponential backoff: 30 seconds on the
first failure, doubling by attempt and capped at one hour. This reduces retry
storms when an external dependency is unavailable. The existing per-item
attempt caps still apply; terminal jobs enter the failed state and outbox
events reach their dead-letter threshold.

These safeguards apply to the enterprise worker entry points. Direct callers
of the lower-level enterprise_store failure methods must sanitize their own
error arguments. The current SQLite deployment remains single-instance;
these changes do not enable shared-service multi-tenancy or distributed
exactly-once processing.

## Tenant-scoped claims and acknowledgement fencing

Queue consumers now select one explicit tenant (`tenant_id`, default `default`).
Claim selection and conditional updates check tenant ownership, and the worker
passes the claim's monotonically increasing `attempts` as a fencing value to
completion/failure methods. A stale claim cannot acknowledge a newer claim,
even when a worker identifier is reused. Queue acknowledgement functions now
require `expected_attempts`; update direct callers when upgrading. Cross-tenant
reuse of an existing global deduplication key fails closed instead of returning
another tenant's row ID. Tenant IDs must be canonical, nonempty strings of at
most 120 characters. This is queue-level isolation only: it does **not** make
the application or its database a fully multi-tenant deployment. The existing
SQLite queue still requires one deployment instance; downstream publishers
must be idempotent because a worker can crash after sending but before ack.
