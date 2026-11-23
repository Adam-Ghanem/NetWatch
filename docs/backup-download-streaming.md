# Admin SQLite backup download lifecycle

The Admin-only `GET /api/backups/database` endpoint creates a consistent
snapshot with SQLite's online backup API. It no longer calls
`Path.read_bytes()` or builds a second full-size Python `bytes` copy.

## Response behavior

- Snapshot creation completes before the HTTP response is returned, so SQLite
  and filesystem errors can still fail the request before response headers.
- The snapshot is stored in a private `TemporaryDirectory`.
- Starlette `FileResponse` sends the file in bounded 64 KiB chunks.
- The response keeps the SQLite media type and timestamped attachment filename
  and adds `Cache-Control: no-store`.
- A response background task removes the temporary directory after the
  response lifecycle completes. If the process is terminated abruptly, normal
  operating-system/container temporary-file cleanup is still required.

## Operational limits

Streaming avoids materializing the entire snapshot in application memory; it
does **not** cap the snapshot's total disk size or make temporary storage
durable. Ensure the configured temporary filesystem has adequate free space,
restricted permissions, and appropriate disk encryption for the sensitivity
of the database. Temporary-file cleanup is not secure erasure, and backups
must still be copied to approved encrypted off-host storage through a separate
operator-controlled process.

The endpoint remains Admin-only and audit-gated. The audit event records
successful snapshot generation, not proof that the client received every byte.
An interrupted download must be retried and verified independently before the
artifact is treated as a recovery copy.

This is not an automated restore, a production recovery drill, or a change to
the single-instance SQLite deployment boundary.
