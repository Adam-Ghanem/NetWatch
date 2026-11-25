# Backup verifier snapshot consistency

The offline verifier copies an input regular file through one open file
descriptor into a private temporary directory. It computes SHA-256 while
copying, then runs SQLite integrity, schema, table, and foreign-key checks
against that exact copy. This avoids hashing one path target and inspecting a
different target after a path replacement.

The original file is not modified. Symlinks and non-regular files are rejected.
The verifier compares device, inode, size, modification time, and change time
before and after SQLite inspection; use a stopped, stable snapshot and do not
write to it concurrently. Temporary storage must have free space at least
equal to the backup size. The private temporary copy is removed on exit.

This is still structural/integrity screening, not proof of a restorable
application database, encryption, signature verification, audit-HMAC recovery,
off-host disaster recovery, or measured RTO/RPO.
