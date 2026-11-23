# Offline capture CLI input safety

The `netwatch-capture` command accepts a regular file as input and enforces the
32 MiB PCAP/PCAPNG byte ceiling while reading, not only before reading.

## Read boundary

- Open the input once and inspect the opened file descriptor with `fstat`.
- Reject directories, FIFOs, devices, and other non-regular inputs.
- Reject a file whose opened-descriptor size already exceeds the configured
  byte ceiling.
- Read at most `MAX_PCAP_BYTES + 1` bytes and reject if the extra byte exists.
  This second check prevents a file that grows after its initial size check
  from causing an unbounded `read_bytes()` allocation.
- Use non-blocking open where the platform supports it so a FIFO cannot hold
  the CLI indefinitely while waiting for a writer.

The parser retains its independent byte and packet limits and continues to
discard packet payloads after metadata extraction. This guard bounds the
input buffer; it does not make untrusted capture contents trustworthy.

Regression tests cover a normal bounded file, an oversized file, stale size
metadata followed by an over-limit read, and non-regular input. The tests use
temporary local files and a synthetic stale metadata result; they do not open
network sockets or inspect live traffic.
