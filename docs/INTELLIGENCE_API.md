# Asset Intelligence API contract

`intelligence_api.asset_intelligence()` combines two local, deterministic signals into one serializable snapshot:

- `fingerprint`: platform/family/confidence/score/evidence from `os_fingerprint`.
- `behavior`: finding counts grouped by severity and kind, plus a bounded summary risk score.

The helper does not perform network I/O, vulnerability lookups, or speculative classification. Sparse or ambiguous evidence stays `Unknown`/low confidence.

This contract is deliberately small so the backend can expose it later without coupling the HTTP layer to the fingerprint implementation.
