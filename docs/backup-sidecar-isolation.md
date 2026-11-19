# Offline SQLite sidecar safety

The verifier hashes only the supplied SQLite database file. SQLite may also read
`-wal`, `-shm`, or hot rollback `-journal` files adjacent to it. Without a
guard, a read-only integrity check could inspect bytes outside the hashed
artifact, making the reported digest incomplete as evidence of the inspected
database state.

The verifier therefore fails closed when any of these adjacent sidecars exist,
both before and after opening the database. Never delete sidecars from a live
database to satisfy this check: doing so can lose committed data or corrupt
recovery. Instead, use SQLite's supported backup API on an authorized, local
source to create a separate, consistent snapshot, close the destination, and
verify that standalone file. Keep the snapshot offline and immutable while
verifying it. Supply a digest from a separately trusted channel when comparing
transferred copies.

This guard does not prove absence of concurrent file replacement, verify audit
HMAC keys, perform an application restore, or establish RTO/RPO. It does not
modify the source database or invoke network scans or provider APIs.
