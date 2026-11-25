# Encrypt offline NetWatch backups with age

This is an **operator-side encryption step**, not an automated backup service.
It does not upload, schedule, rotate, retain, or restore backups. It never
receives a private identity key and does not add `age` to the NetWatch image.

## Trust and prerequisites

- Install the `age` command-line tool from its official release channel.
  Verify the release signature/checksum and record the exact version in the
  deployment change record. NetWatch does not download or update the binary.
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
- invokes `age` without a shell, passes only a minimal environment, and
  suppresses child stderr to avoid accidental path or environment disclosure;
- writes ciphertext to a mode-`0600` temporary file in the destination
  directory, fsyncs it, and publishes it atomically without overwriting an
  existing destination.

A nonzero exit means no final output was published. Run the helper on a POSIX
host. The destination filesystem must support same-directory hard links for
atomic no-overwrite publication. Windows ACL semantics are not implemented
by this helper.
The JSON success report contains only input/output basenames, byte count,
SHA-256, recipient count, and the output mode; it never prints the recipient
values or private material.

## Transfer and restore

After successful encryption, transfer the `.age` file to an approved off-host
object store using the organization's separately managed uploader. Enforce
access control, immutable/versioned retention, monitoring, and deletion policy
there. This helper does not perform any network transfer.

For an isolated restore, use a private staging directory and an independently
retrieved identity:

```bash
umask 077
age -d -i /secure/recovery/identity.txt \
  -o /secure/staging/backup.sqlite3 \
  backup.sqlite3.age
```

Then run the offline SQLite verifier against the decrypted file using the
trusted schema version and original plaintext SHA-256. Boot a fresh staging
instance with the separately recovered audit HMAC key, verify readiness,
authenticated inventory/operational records and the audit chain, and record
the observed restore time and backup age.

Never place the private identity beside the encrypted backup. Do not reset or
re-sign the audit chain to make a restore appear successful.

## Limits

This helper provides local recipient-based encryption and a digest match. It
does **not** provide key escrow, key rotation, off-host upload, retention
automation, a production restore drill, audit-HMAC validation, or RTO/RPO
guarantees. A successful encryption command is not proof that a private key is
recoverable or that the application can restore. Complete an independently
reviewed staging drill before making disaster-recovery claims.
