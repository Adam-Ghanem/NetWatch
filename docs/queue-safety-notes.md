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
