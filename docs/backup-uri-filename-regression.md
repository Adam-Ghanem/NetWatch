# Offline backup filenames containing URI metacharacters

Run `pytest -q tests/test_backup_uri_filenames.py` to exercise the real SQLite backup verifier with standalone snapshots named using `#`, `?`, and literal percent-encoded-looking sequences (`%23`, `%3F`). These characters must be percent-encoded before constructing SQLite's read-only `file:` URI; otherwise SQLite can interpret part of the filename as a fragment or query string. The regression creates a real initialized schema-11 snapshot, checks successful offline verification, and asserts the resolved path identifies the exact requested snapshot and the snapshot bytes are unchanged. The literal percent sequences must not be decoded into `#` or `?` and accidentally select another file.

This test uses temporary local files only. It does not restore the application, validate audit signing keys, exercise authenticated endpoints, or establish production RTO/RPO. Treat a failed verification as a hard stop before recovery.
