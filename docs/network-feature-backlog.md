# NetWatch network feature backlog

This backlog is maintained from repository inspection plus upstream documentation research. Items are prioritized for authorized defensive/network-administration use and should be implemented incrementally with explicit bounds, tests, and evidence-quality controls.

## Priority order

| Priority | Capability | Current repository evidence | Next safe increment |
| --- | --- | --- | --- |
| P0 | Service/version evidence | `port_scanner.py` has bounded SSH, FTP, SMTP, HTTP, and TLS evidence; service history persists normalized product/version confidence. A bounded `tls_service_history` store retains TLS protocol, cipher, ALPN, SHA-256 certificate fingerprint, and certificate validity metadata across scans without certificate bodies or identity fields. Evidence-safe TLS change analysis derives certificate rotation, known protocol downgrade, ALPN application-protocol drift, expiry-risk transitions, and a deliberately narrow modern-AEAD to known-legacy cipher regression signal from consecutive observations without adding network probes. High-confidence downgrade/cipher-regression/invalid-certificate and configurable expiry-window events carry deterministic alert recommendations, while neutral rotation/unknown-cipher/ALPN changes never alert by name alone. A bounded TLS investigator snapshot packages filtered change evidence with recomputed change-type/severity facets, service counts, alert-recommended counts, explicit privacy scope, and a date-bucketed timeline derived only from the same filtered evidence. The snapshot is exposed through the existing authenticated read-only API/RBAC path with hard query bounds and Viewer access. | Add dashboard timeline/facet pivots that consume the same filtered API evidence, then route only recommended TLS alerts through durable notification receipts. |
| P1 | Service reachability change intelligence | Retained service findings produce evidence-safe reachability transitions, configurable evidence-gated alert recommendations, and bounded duplicate suppression for repeated high-risk reachability alerts while preserving every underlying state-change event. Filtered/timeouts never generate downtime or reachability alerts. | Add authenticated delivery hooks with durable delivery receipts so alert routing can be retried safely without duplicate notifications. |
| P1 | Conservative UDP service checks | `udp_service_scanner.py` adds opt-in DNS/NTP checks with one datagram per profile, no retries, a 512-byte receive cap, strict timeouts, and explicit `Open|Filtered` silence semantics. `netwatch_udp.py` exposes the same two-profile boundary through an explicit-authorization CLI with bounded 0.05..1.0 second timeouts plus JSON/CSV output; it does not add generic UDP port sweeping. | Add an authenticated API workflow that reuses the same two-profile boundary, then persist normalized UDP service evidence without collapsing `Open|Filtered` into `Open` or `Closed`. |
| P1 | IPv6 feature parity | IPv6 TCP scanning, capture parsing, extension-header handling, inventory parity, host address-family metadata, and UDP socket targeting are present. | Audit remaining UI/API/export paths for address-family assumptions and add regression tests before widening probes. |
| P1 | TLS observability | Offline traffic metadata and protocol analysis exist; active HTTPS checks collect negotiated TLS protocol/cipher, bounded ALPN (`h2`/`http/1.1`) evidence, SHA-256 certificate fingerprints, and privacy-preserving certificate validity/status metadata with strict timeout/certificate-size bounds. Normalized TLS history plus evidence-safe change analysis is retained separately from raw certificate material. The investigator snapshot has an authenticated read-only endpoint with bounded history/change limits, filtered timeline points, and the same no-extra-probes/privacy boundary. | Add dashboard pivots for TLS rotation/downgrade/cipher-regression/ALPN-drift/expiry evidence without collecting certificate bodies or subject/issuer strings by default. |
| P2 | Flow/session fidelity | Flow analysis, correlation, topology, timeline, display filters, Community ID, anomaly modules, bounded direction-aware TCP control history, and conservative handshake/termination-quality evidence exist. Shared flow queries, capture controls, and the offline capture CLI support exact, allowlisted `tcp_termination` pivots (`graceful_close`, `partial_close`, `reset`, `not_observed`) so reset/partial-close investigations rebuild scoped conversations and topology instead of exposing stale unfiltered pivots. Classic PCAP import now extracts bounded TCP sequence/ACK, segment-length, and sequence-advance metadata for non-fragmented TCP and derives capped `sequence_gap` / `sequence_overlap` observations by direction. Labels are capture-evidence only and explicitly avoid claiming packet loss or retransmission. | Extend the same bounded metadata/evidence path to PCAPNG and live capture, then add exact investigator pivots. Keep causal language conservative because capture loss, reordering, retransmission, and mid-stream collection can produce similar observations. |
| P2 | Capture/filter UX | PCAP/PCAPNG import and flow display filters exist. | Improve saved filter presets, validation errors, and investigator-oriented protocol/endpoint/time-range pivots. |
| P2 | Structured interoperability | JSON/CSV/report/export modules exist. | Add documented stable schemas for service and flow evidence, including address family, evidence source, confidence, and timestamps. |
| P3 | Plugin/scripting boundary | Intelligence and AI tool registries exist; a general network-analysis plugin contract is not yet established. | Define a signed/allowlisted read-only analyzer plugin interface before permitting third-party extensions. |
| P3 | Performance characterization | Concurrency controls and API benchmark tooling exist. | Add reproducible local benchmarks for scanner concurrency, large PCAP parsing, and flow aggregation; publish measured baselines only. |

## Research anchors

- Nmap UDP scanning and `open|filtered` semantics: https://nmap.org/book/scan-methods-udp-scan.html
- Nmap service/version detection: https://nmap.org/book/vscan.html
- Nmap IPv6 scanning: https://nmap.org/book/port-scanning-ipv6.html
- Nmap TLS certificate helpers: https://nmap.org/nsedoc/lib/sslcert.html
- Nmap `ssl-cert` validity/fingerprint output: https://nmap.org/nsedoc/scripts/ssl-cert.html
- Nmap `ssl-enum-ciphers` grading and legacy-cipher warnings: https://nmap.org/nsedoc/scripts/ssl-enum-ciphers.html
- Wireshark display filters: https://www.wireshark.org/docs/man-pages/wireshark-filter.html
- Wireshark TLS display fields: https://www.wireshark.org/docs/dfref/t/tls.html
- Wireshark packet/conversation analysis: https://www.wireshark.org/docs/man-pages/wireshark.html
- Wireshark conversation timelines: https://www.wireshark.org/docs/wsug_html_chunked/ChStatConversations.html
- Wireshark TCP sequence analysis: https://www.wireshark.org/docs/wsug_html_chunked/ChAdvTCPAnalysis.html
- Zeek TLS logging (`version`, `cipher`, `next_protocol`/ALPN): https://docs.zeek.org/en/current/reference/logs/ssl.html
- Zeek connection-oriented traffic logs: https://docs.zeek.org/en/master/quickstart.html
- Suricata EVE TLS fields and selective/custom logging: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
- Suricata EVE JSON schema and TCP gap fields: https://docs.suricata.io/en/latest/appendix/eve-schema.html
- Elastic Observability TLS certificate expiration rules: https://www.elastic.co/docs/solutions/observability/incident-management/create-tls-certificate-rule

## Selection rule

Prefer the highest-priority item that can be implemented and verified without broadening authorization scope, requiring privileged attack techniques, or introducing unbounded network activity. Every completed item should include focused tests plus regression/CI verification before merge.
