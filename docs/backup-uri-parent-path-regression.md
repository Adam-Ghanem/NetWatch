# Offline backup parent directory URI regression

Run `pytest -q tests/test_backup_uri_parent_paths.py` to exercise the real schema-11 SQLite backup verifier against standalone snapshots inside parent directories containing `#`, `?`, literal `%23`, whitespace, or non-ASCII characters. The read-only SQLite URI must preserve **all path components**, not just the snapshot filename. The regression asserts the resolved report path matches the requested snapshot and the file bytes are unchanged.

This is an isolated temporary-filesystem test; it does not authenticate to the running application, restore application services, validate audit signing keys, or establish RTO/RPO. Stop recovery when the offline verifier fails. Review this stacked PR only after its parent #213 and earlier dependencies.
