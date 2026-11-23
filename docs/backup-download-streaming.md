# Admin SQLite backup download lifecycle

The Admin-only `GET /api/backups/database` endpoint creates a consistent
snapshot with SQLite's online backup API. It no longer calls
`Path.read_bytes()` or builds a second full-size Python `bytes` copy.

## Response behavior

- Snapshot creation completes before the HTTP response is returned, so SQLite
  and filesystem errors can still fail the request before response headers.
- The snapshot is stored in a private `TemporaryDirectory`.
- Starlette `FileResponse` uses its built-in bounded 64 KiB file-read chunks (the installed Starlette API does not accept a per-response `chunk_size` argument).
- The response keeps the SQLite media type and timestamped attachment filename
  and adds `Cache-Control: no-store`.
- A dedicated `FileResponse` subclass removes the temporary directory in a
  `finally` block around the ASGI response call. Cleanup therefore also runs
  when sending raises (for example, a client disconnect), the response is
  cancelled, or Starlette returns early for a malformed/unsatisfiable Range
  header. The installed Starlette 1.3.1 implementation invokes a background
  task only after its normal send path; its early Range returns and send errors
  bypass that call ([upstream source](https://github.com/Kludex/starlette/blob/1.3.1/starlette/responses.py)).
  If the process is terminated abruptly, operating-system/container temporary-file
  cleanup is still required.

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
