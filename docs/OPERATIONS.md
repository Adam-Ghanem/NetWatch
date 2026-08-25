# Intelligence Operations

## Confidence
Use `asset_confidence` as a bounded secondary indicator. It must never override explicit evidence or authorization state.

## Change windows
Use `changes_in_window` for deterministic event filtering. Timestamps are expected to be integer epoch values and the requested window is inclusive.

## Safety
Intelligence helpers are analysis primitives only. They do not initiate scans, connect to hosts, or infer vulnerabilities. Unknown and malformed evidence should remain non-actionable until validated by the scanner's existing authorization and evidence pipeline.
