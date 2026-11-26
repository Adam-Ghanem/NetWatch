# Encrypt offline NetWatch backups with age

This is an **operator-side encryption step**, not an automated backup service.
It does not upload, schedule, rotate, retain, or restore backups. It never
receives a private identity key and does not add `age` to the NetWatch image.

## Trust and prerequisites

- Install the `age` command-line tool from its official release channel.
  Verify the release signature/checksum and record the exact version and
  independently trusted SHA-256 in the deployment change record. NetWatch does
  not download or update the binary.
- Create one or more age X25519 recipient identities using the organization's
  approved key-management procedure. Keep each private identity outside the
  application host, repository, container image, `.env`, and backup destination.
- Keep a second independently controlled recovery recipient where policy
  permits. The command accepts up to eight recipients; any matching private
  identity can decrypt the result.
- Protect the plaintext snapshot and its independently authenticated SHA-256
  until encryption completes. The digest is not a signature; its trusted
  provenance must be maintained separately.

## Prepare and encrypt

Create a consistent SQLite snapshot through NetWatch's Admin backup operation.
Do not copy a live database file or its WAL/SHM files with a normal filesystem
copy. Stop and access-control the source before offline verification.

First verify the snapshot with the offline verifier tracked in
[PR #199](https://github.com/Adam-Ghanem/NetWatch/pull/199). That verifier
checks SQLite integrity, required tables, schema version, foreign keys, and
SHA-256. Supply the digest from a separately authenticated recovery record to
the encryption step below; this helper independently recomputes the digest
while streaming the exact bytes to `age`.

```bash
python scripts/encrypt_backup_age.py \
  --expected-sha256 "$TRUSTED_BACKUP_SHA256" \
  --age-binary-sha256 "$TRUSTED_AGE_BINARY_SHA256" \
  --recipient age1REPLACE_WITH_RECOVERY_RECIPIENT \
  --recipient age1REPLACE_WITH_INDEPENDENT_RECIPIENT \
  backup.sqlite3 backup.sqlite3.age
```

The example recipient values are placeholders, not valid keys. Replace them
with actual public recipients. Do not put private identity material in the
command. The helper:

- accepts only age X25519 public-recipient syntax and one to eight recipients;
- opens a regular, non-symlink source file and streams it without loading the
  whole backup into memory or creating a plaintext temporary copy;
- checks the source descriptor/path identity before and after streaming;
- requires the streamed bytes to match the separately trusted SHA-256;
- resolves the selected `age` executable to its real path and requires
  a regular executable owned by root or the current user; rejects group/world-
  writable binaries and untrusted writable parent directories (sticky shared
  directories such as `/tmp` are allowed);
- when `--age-binary-sha256` is supplied, hashes the executable through a
  no-follow file descriptor immediately before launch, verifies its file
  identity remained stable while hashing, and fails closed on a mismatch;
- invokes the resolved executable without a shell, passes only a minimal
  environment, and suppresses child stderr to avoid accidental path or
  environment disclosure;
- enforces a 30-second no-progress deadline while streaming and a 30-second
  completion deadline after closing stdin; timeout cleanup kills the dedicated
  POSIX process group, including descendants that keep inherited pipes open;
- does not sandbox a deliberately hostile executable that detaches into a new
  session, so install only a verified age release from the approved channel;
- drains child output through a bounded pipe and caps ciphertext at the input
  size plus the larger of 1 MiB or 6.25% of the input size; an over-producing
  child is killed and its partial ciphertext is removed;
- writes ciphertext to a mode-`0600` temporary file in the destination
  directory, fsyncs the file, and publishes it atomically without overwriting
  an existing destination; it then attempts to fsync the destination directory.
  The JSON report records `directory_fsync` as `confirmed`, `unsupported`, or
  `failed`, plus `durability_confirmed`. If directory fsync is not confirmed,
  the ciphertext is still valid and published, but crash durability of the
  directory entry is not guaranteed; do not record the backup as crash-durable.

A nonzero exit means no final output was published. Run the helper on a POSIX
host. The destination filesystem must support same-directory hard links for
atomic no-overwrite publication. Windows ACL semantics are not implemented
by this helper.
The JSON success report contains only input/output basenames, byte count,
backup SHA-256, recipient count, output mode, and directory-durability status;
when a binary pin is supplied, it also reports the verified age executable
SHA-256. It never prints recipient values or private material.

## Transfer and restore

After successful encryption, transfer the `.age` file to an approved off-host
object store using the organization's separately managed uploader. Enforce
access control, immutable/versioned retention, monitoring, and deletion policy
there. This helper does not perform any network transfer.

For an isolated restore, use the operator-side helper. It requires a private
identity file outside NetWatch and the plaintext digest from the independently
authenticated recovery record:

```bash
umask 077
python scripts/restore_backup_age.py \
  --identity /secure/recovery/identity.txt \
  --expected-sha256 "$TRUSTED_BACKUP_SHA256" \
  --age-binary-sha256 "$TRUSTED_AGE_BINARY_SHA256" \
  backup.sqlite3.age /secure/staging/backup.sqlite3
```

The restore helper:
- accepts only a regular, non-symlink identity file owned by root or the current
  user, readable by its owner only, with trusted parent-directory ownership and
  write permissions;
- opens the identity once and passes only an inherited file-descriptor path to
  `age`; private identity contents are never loaded into Python or placed in
  the child command line;
- opens the encrypted input as a regular non-symlink file and supplies it
  directly as the child's stdin;
- uses the same trusted-binary ownership/permission checks as the encryption
  helper, and supports the optional independently trusted executable SHA-256;
- suppresses child stderr and uses a minimal environment;
- enforces a 30-second no-output deadline and a 30-second process-exit deadline;
  failure cleanup terminates the dedicated POSIX process group;
- caps plaintext output at the encrypted input size, writes to a mode-`0600`
  temporary file, and verifies the complete plaintext SHA-256 before publication;
- opens every destination directory component from the filesystem root
  with directory descriptors and `O_NOFOLLOW`, requiring root/current-user
  ownership and rejecting group/world-writable directories unless the sticky
  bit protects shared-directory entry ownership (for example `/tmp`);
- creates the private temporary file, checks for an existing destination,
  publishes with a same-directory no-overwrite hard link, removes temporary
  entries, and fsyncs the directory through the same open descriptor; it
  reopens and compares the directory identity before process launch and
  publication so a path rename or symlink swap cannot redirect writes to a
  replacement directory.

A nonzero exit, timeout, output-limit violation, identity/input mutation, or
digest mismatch leaves no final restored file. If directory fsync is unsupported
or fails, the restored file is valid and atomically published but its crash
durability is not confirmed. The JSON report contains only basenames, byte
count, plaintext SHA-256, output mode, and durability status; it never includes
the identity path or private material.

Then run the offline SQLite verifier against the restored file using the trusted
schema version and original plaintext SHA-256. Boot a fresh staging instance
with the separately recovered audit HMAC key, verify readiness, authenticated
inventory/operational records and the audit chain, and record the observed
restore time and backup age.

Never place the private identity beside the encrypted backup. Do not reset or
re-sign the audit chain to make a restore appear successful.

## Limits

The encryption and restore helpers provide local recipient-based encryption,
digest verification, and safe plaintext publication. The age executable pin is
optional for backward compatibility; when enabled, its expected digest must
come from an independently trusted release record. The pin is not a signature
verifier or a kernel-enforced immutable executable handle, so protected
ownership/permissions and a trusted host remain required. The restore helper
checks POSIX mode bits for the identity file and destination directory but does
not independently inspect extended filesystem ACLs; administrators must verify
both effective access policies. Directory-descriptor anchoring prevents a
pathname swap from redirecting publication, but it does not defend against
root or hostile same-UID processes, malicious mount changes, or filesystem
implementations with weaker-than-expected descriptor semantics.

These helpers do **not** provide key escrow, key rotation, off-host upload,
retention automation, a production restore drill, audit-HMAC validation, or
RTO/RPO guarantees. Synthetic tests do not prove interoperability with a real
age release. A successful encryption or restore command is not proof that the
application can recover. Complete an independently reviewed staging drill
with the actual approved age release and separately recovered audit HMAC key
before making disaster-recovery claims.
