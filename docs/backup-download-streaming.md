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
- A process-local semaphore provides a fast per-worker guard. An OS advisory
  lock file named `.netwatch-backup-download.lock` beside the SQLite database
  coordinates other workers/processes that share the same data directory.
  Additional Admin requests receive HTTP 503 with `Retry-After: 30` before
  creating a snapshot. The lock remains held through response cleanup and is
  released if snapshot creation fails or the process exits.
- The coordination file is persistent, contains no credentials or backup data,
  and is created with owner-only permissions on POSIX systems. It must be a
  regular, single-link file; hard-linked aliases are rejected before acquiring
  the OS lock so the lock cannot operate on the SQLite database or another
  aliased file. Symlink paths are rejected on platforms that expose
  `O_NOFOLLOW`. Keep the database directory writable only by the NetWatch
  service account. Do not remove the lock file while NetWatch processes are
  running; the operating system releases the advisory lock when a process
  closes its descriptor or exits.
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
durable. The advisory lock coordinates processes only when they share the same
resolved database directory and the filesystem honors the platform's file-lock
semantics. It is not a distributed multi-host lock or a global disk quota;
for network filesystems with uncertain locking behavior, use one application
worker or a separately reviewed distributed coordinator. Ensure the configured
temporary filesystem has adequate free space, restricted permissions, and
appropriate disk encryption for the sensitivity of the database.
Temporary-file cleanup is not secure erasure, and backups must still be copied
to approved encrypted off-host storage through a separate operator-controlled
process.

The endpoint remains Admin-only and audit-gated. The audit event records
successful snapshot generation, not proof that the client received every byte.
An interrupted download must be retried and verified independently before the
artifact is treated as a recovery copy.

This is not an automated restore, a production recovery drill, or a change to
the single-instance SQLite deployment boundary.
