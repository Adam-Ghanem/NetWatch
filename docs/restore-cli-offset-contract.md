# Restore timing CLI offset contract

The offline `scripts/measure_restore_drill.py` CLI requires a known timezone offset for **each** of `--last-durable`, `--failure`, and `--ready`. RFC 3339 `-00:00` signals an unknown offset and must fail closed (exit status 2, no JSON stdout). Explicit `+00:00` is known UTC and remains accepted.

`tests/test_restore_drill_cli_all_offsets.py` checks all three command-line arguments independently and the successful known-UTC case. These tests only validate input handling and arithmetic; they do **not** demonstrate backup restoration, authenticated service readiness, audit integrity, or production RTO/RPO compliance. Collect those separately in an isolated staging drill using synthetic data.
