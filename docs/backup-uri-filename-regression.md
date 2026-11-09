# Offline backup filenames containing URI metacharacters

Run `pytest -q tests/test_backup_uri_filenames.py` to exercise the real SQLite backup verifier with standalone snapshots named using `#` and `?`. These characters must be percent-encoded before constructing SQLite's read-only `file:` URI; otherwise SQLite can interpret part of the filename as a fragment or query string. The regression creates a real initialized schema-11 snapshot, checks successful offline verification, and asserts the snapshot bytes are unchanged.

This test uses temporary local files only. It does not restore the application, validate audit signing keys, exercise authenticated endpoints, or establish production RTO/RPO. Treat a failed verification as a hard stop before recovery.
