# NetWatch network feature backlog

This backlog is maintained from repository inspection plus upstream documentation research. Items are prioritized for authorized defensive/network-administration use and should be implemented incrementally with explicit bounds, tests, and evidence-quality controls.

## Priority order

| Priority | Capability | Current repository evidence | Next safe increment |
| --- | --- | --- | --- |
| P0 | Service/version evidence | `port_scanner.py` has bounded SSH, FTP, SMTP, HTTP, and TLS evidence; service history persists normalized product/version confidence. A bounded `tls_service_history` store retains TLS protocol, cipher, ALPN, SHA-256 certificate fingerprint, and certificate validity metadata across scans without certificate bodies or identity fields. Evidence-safe TLS change analysis derives certificate rotation, known protocol downgrade, cipher-change, and expiry-risk transitions from consecutive observations without adding network probes. High-confidence downgrade/invalid-certificate and configurable expiry-window events now carry deterministic alert recommendations, while neutral rotation/cipher changes never alert by name alone. | Surface bounded TLS history/change pivots through authenticated service-history APIs and the dashboard, then route only recommended TLS alerts through durable notification receipts. |
| P1 | Service reachability change intelligence | Retained service findings produce evidence-safe reachability transitions, configurable evidence-gated alert recommendations, and bounded duplicate suppression for repeated high-risk reachability alerts while preserving every underlying state-change event. Filtered/timeouts never generate downtime or reachability alerts. | Add authenticated delivery hooks with durable delivery receipts so alert routing can be retried safely without duplicate notifications. |
| P1 | Conservative UDP service checks | `udp_service_scanner.py` now adds opt-in DNS/NTP checks with one datagram per profile, no retries, a 512-byte receive cap, strict timeouts, and explicit `Open|Filtered` silence semantics. | Surface the bounded UDP profiles through authenticated API/CLI workflows and persist results in normalized service history. |
| P1 | IPv6 feature parity | IPv6 TCP scanning, capture parsing, extension-header handling, inventory parity, host address-family metadata, and UDP socket targeting are present. | Audit remaining UI/API/export paths for address-family assumptions and add regression tests before widening probes. |
| P1 | TLS observability | Offline traffic metadata and protocol analysis exist; active HTTPS checks collect negotiated TLS protocol/cipher, bounded ALPN (`h2`/`http/1.1`) evidence, SHA-256 certificate fingerprints, and privacy-preserving certificate validity/status metadata with strict timeout/certificate-size bounds. Normalized TLS history plus evidence-safe change analysis is retained separately from raw certificate material. | Add authenticated investigator pivots and dashboard timelines for TLS rotation/downgrade/expiry evidence without collecting certificate bodies or subject/issuer strings by default. |
| P2 | Flow/session fidelity | Flow analysis, correlation, topology, timeline, display filters, Community ID, and anomaly modules exist. | Add TCP state/retransmission/termination-quality summaries from offline captures, inspired by Zeek connection semantics. |
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
- Wireshark display filters: https://www.wireshark.org/docs/man-pages/wireshark-filter.html
- Wireshark TLS display fields: https://www.wireshark.org/docs/dfref/t/tls.html
- Wireshark packet/conversation analysis: https://www.wireshark.org/docs/man-pages/wireshark.html
- Zeek TLS logging (`version`, `cipher`, `next_protocol`/ALPN): https://docs.zeek.org/en/current/reference/logs/ssl.html
- Zeek connection-oriented traffic logs: https://docs.zeek.org/en/master/quickstart.html
- Suricata EVE TLS fields and selective/custom logging: https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
- Suricata EVE JSON schema: https://docs.suricata.io/en/latest/appendix/eve-schema.html
- Elastic Observability TLS certificate expiration rules: https://www.elastic.co/docs/solutions/observability/incident-management/create-tls-certificate-rule

## Selection rule

Prefer the highest-priority item that can be implemented and verified without broadening authorization scope, requiring privileged attack techniques, or introducing unbounded network activity. Every completed item should include focused tests plus regression/CI verification before merge.