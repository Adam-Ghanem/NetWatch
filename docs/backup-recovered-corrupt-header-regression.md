# Corrupted recovered SQLite header regression

Run `python -m pytest -q tests/test_backup_recovered_corrupt_header.py` from the repository root.

The test creates a real-schema synthetic inventory, seals a standalone SQLite backup, confirms it verifies, then simulates loss of the source directory. It corrupts the recovered file's SQLite header while preserving file length and supplies the SHA-256 of those *corrupt* bytes. The offline verifier must still reject the file: a matching digest alone does not establish that the backup is a usable SQLite database. It also checks that verification does not alter the damaged snapshot or create SQLite sidecars.

**Recovery boundary:** For authenticity, preserve the expected digest independently of the recovered file. This test checks neither authenticated application login nor audit-HMAC key recovery, off-host storage, RTO/RPO, or adversarial filesystem races. No live networks or paid provider APIs are used.
