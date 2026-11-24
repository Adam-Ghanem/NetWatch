# Audit readiness cache freshness

NetWatch briefly caches the public audit-readiness result to avoid re-hashing the
retained audit chain on every health probe. The cache identity now includes the
database path and filesystem signatures for the SQLite database, WAL, and
rollback-journal files (device, inode, size, modification time, and change
time). Ordinary external writes and same-path database replacement therefore
force a fresh integrity check instead of reusing a positive result for the
remainder of the five-second cache window.

Explicit integrity verification and uncached readiness checks invalidate the
cached result so the next public readiness probe must re-evaluate the chain.

This is cache-coherency protection, not a substitute for filesystem access
controls or cryptographic verification. A local actor able to modify the
database should not be able to modify the NetWatch data directory or audit key;
the HMAC chain remains the integrity authority.
