# Final backup path recheck

The offline SQLite backup verifier now rejects a pathname that becomes a symbolic link during its final SHA-256 read, even if the bytes match the first digest. A synthetic regression swaps the pathname after the second digest has read the original file, and checks that verification fails closed without modifying the replacement.

This is defense in depth, **not** a race-free file identity guarantee: a malicious writer may still replace the path after the final check, or swap a regular file with identical content. Verify only immutable, offline snapshots on a trusted filesystem; do not treat the verifier as a production restore drill. No network activity or provider API calls are required.
