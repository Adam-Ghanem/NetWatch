# NetWatch network feature backlog

This backlog is maintained from repository inspection plus upstream documentation research. Items are prioritized for authorized defensive/network-administration use and should be implemented incrementally with explicit bounds, tests, and evidence-quality controls.

## Priority order

| Priority | Capability | Current repository evidence | Next safe increment |
| --- | --- | --- | --- |
| P0 | Service/version evidence | `port_scanner.py` has bounded SSH, FTP, SMTP, HTTP, and TLS evidence; service history persists normalized product/version confidence. | Persist/display TLS protocol, cipher, ALPN, and certificate SHA-256 as first-class service-history fields without retaining certificate bodies. |
| P1 | Service reachability change intelligence | Retained service findings now produce evidence-safe transitions when a previously unconfirmed service becomes `Open`, or when a previously confirmed `Open` service is no longer confirmed open. Filtered/timeouts are never mislabeled as proof of downtime, and the events flow into the existing asset timeline. | Add configurable alert-policy hooks for high-risk newly reachable services while preserving debounce and authorization boundaries. |
| P1 | Conservative UDP service checks | `udp_service_scanner.py` now adds opt-in DNS/NTP checks with one datagram per profile, no retries, a 512-byte receive cap, strict timeouts, and explicit `Open|Filtered` silence semantics. | Surface the bounded UDP profiles through authenticated API/CLI workflows and persist results in normalized service history. |
| P1 | IPv6 feature parity | IPv6 TCP scanning, capture parsing, extension-header handling, inventory parity, host address-family metadata, and UDP socket targeting are present. | Audit remaining UI/API/export paths for address-family assumptions and add regression tests before widening probes. |
| P1 | TLS observability | Offline traffic metadata and protocol analysis exist; active HTTPS checks collect negotiated TLS protocol/cipher, bounded ALPN (`h2`/`http/1.1`) evidence, and a SHA-256 certificate fingerprint with strict timeout/certificate-size bounds. | Add expiry/issuer/subject summaries only after a privacy-preserving parser and persistence schema are defined. |
| P2 | Flow/session fidelity | Flow analysis, correlation, topology, timeline, display filters, Community ID, and anomaly modules exist. | Add TCP state/retransmission/termination-quality summaries from offline captures, inspired by Zeek connection semantics. |
| P2 | Capture/filter UX | PCAP/PCAPNG import and flow display filters exist. | Improve saved filter presets, validation errors, and investigator-oriented protocol/endpoint/time-range pivots. |
| P2 | Structured interoperability | JSON/CSV/report/export modules exist. | Add documented stable schemas for service and flow evidence, including address family, evidence source, confidence, and timestamps. |
| P3 | Plugin/scripting boundary | Intelligence and AI tool registries exist; a general network-analysis plugin contract is not yet established. | Define a signed/allowlisted read-only analyzer plugin interface before permitting third-party extensions. |
| P3 | Performance characterization | Concurrency controls and API benchmark tooling exist. | Add reproducible local benchmarks for scanner concurrency, large PCAP parsing, and flow aggregation; publish measured baselines only. |

## Research anchors

- Nmap UDP scanning and `open|filtered` semantics: https://nmap.org/book/scan-methods-udp-scan.html
- Nmap service/version detection: https://nmap.org/book/vscan.html
- Nmap IPv6 scanning: https://nmap.org/book/port-scanning-ipv6.html
- Wireshark display filters: https://www.wireshark.org/docs/man-pages/wireshark-filter.html
- Wireshark TLS display fields: https://www.wireshark.org/docs/dfref/t/tls.html
- Wireshark packet/conversation analysis: https://www.wireshark.org/docs/man-pages/wireshark.html
- Zeek TLS logging (`version`, `cipher`, `next_protocol`/ALPN): https://docs.zeek.org/en/current/reference/logs/ssl.html
- Zeek connection-oriented traffic logs: https://docs.zeek.org/en/master/quickstart.html
- Suricata EVE JSON schema: https://docs.suricata.io/en/latest/appendix/eve-schema.html

## Selection rule

Prefer the highest-priority item that can be implemented and verified without broadening authorization scope, requiring privileged attack techniques, or introducing unbounded network activity. Every completed item should include focused tests plus regression/CI verification before merge.
