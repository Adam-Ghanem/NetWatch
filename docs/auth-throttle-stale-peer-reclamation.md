# Pre-auth throttle: stale peer reclamation

The in-process failure limiter stores a bounded number of transport-peer buckets. When all slots are occupied, failures for additional peers share an overflow bucket. `retry_after()` now reclaims expired peer buckets before consulting that shared overflow for an *unknown* peer. Otherwise, an expired peer could occupy the last slot and cause an unrelated fresh peer to receive HTTP 429 until another failure triggered cleanup.

Existing peers still use their own rolling-window history. If every peer slot remains active, unknown peers still share overflow throttling. This change does **not** clear overflow, bypass active limits, trust `X-Forwarded-For`, store credentials, or widen network authorization.

Regression: `tests/test_auth_throttle.py::test_fresh_peer_does_not_inherit_overflow_after_stale_slot_expires` uses a deterministic monotonic clock to prove that a fresh peer is unblocked after stale-slot expiry while active overflow remains blocked. Run `pytest -q tests/test_auth_throttle.py` and the normal Python/Security CI before merging.

The limiter is process-local, not a distributed edge defense. Multi-worker deployments still need trusted upstream controls. No production traffic, active probing, or credential material is needed to validate this fix.
