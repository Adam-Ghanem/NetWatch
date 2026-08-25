# NetWatch Intelligence

NetWatch intelligence is intentionally evidence-first and deterministic.

## Behavioral analysis

Behavior findings describe meaningful changes such as new or removed ports/services, identity changes, and exposure shifts. `behavior_report.summarize_behavior()` produces a stable severity breakdown and bounded summary risk score.

## OS/platform fingerprinting

`os_fingerprint.fingerprint_os()` classifies a device only from supplied local evidence. Supported platforms include Android, iOS/iPadOS, Windows, Linux, macOS, ChromeOS, FreeBSD, and embedded/network Linux. The result contains platform, family, confidence, score, and evidence.

Unknown devices remain `Unknown` when evidence is insufficient. Hostnames and service metadata are signals, not proof; stronger evidence should be added incrementally through explicit rules.

## Extensibility

`fingerprint_registry.py` provides a small deterministic rule registry for future platform/device signatures without coupling the scanner to a vendor-specific implementation.
