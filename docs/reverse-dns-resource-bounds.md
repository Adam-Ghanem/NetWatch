# Reverse DNS resource bounds

NetWatch optionally enriches authorized local-scan results with reverse DNS names. The operating-system resolver call may continue after the caller's configured lookup timeout; Python cannot safely cancel a blocked system resolver call.

To prevent repeated slow or stuck lookups from creating an unbounded number of daemon threads:

- A process-wide semaphore permits at most 16 in-flight reverse-DNS resolver workers, across concurrent scans.
- Each caller still waits only for NETWATCH_HOSTNAME_LOOKUP_TIMEOUT_SECONDS (clamped to 1–3 seconds).
- A caller that times out returns the existing "-" hostname value. Its worker retains the slot until the underlying resolver actually returns.
- If all 16 slots are occupied, additional hostname enrichment is skipped immediately. The authorized scan result itself is not discarded and no extra resolver thread is created.
- A failed thread start releases its slot; a completed resolver releases its slot in a finally block.

This is a resource bound, not resolver cancellation. If system resolver calls remain permanently stuck, up to 16 daemon workers can remain until process restart; hostname enrichment then fails soft while scan results continue. Operators should investigate the host's resolver configuration rather than increasing the worker cap.

Regression coverage uses a synthetic blocking resolver and a one-slot semaphore. It proves that a timed-out worker prevents a second thread from being created, and that the slot becomes reusable when the resolver exits. No live DNS queries, network scans, or external destinations are used by the test.
