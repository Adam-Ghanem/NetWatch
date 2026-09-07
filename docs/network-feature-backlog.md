# NetWatch network feature backlog

This backlog is maintained from repository inspection plus upstream documentation research. Items are prioritized for authorized defensive/network-administration use and should be implemented incrementally with explicit bounds, tests, and evidence-quality controls.

## Priority order

| Priority | Capability | Current repository evidence | Next safe increment |
| --- | --- | --- | --- |
| P0 | Service/version evidence | `port_scanner.py` has bounded SSH, FTP, and SMTP evidence; PR #102 adds bounded HTTP `Server` evidence. | Finish HTTP verification, then add TLS certificate/protocol evidence without storing certificate bodies. |
| P1 | Conservative UDP service checks | TCP scanning is mature; UDP service/version detection is not yet exposed by `port_scanner.py`. | Add an opt-in, tightly allowlisted UDP profile (for example DNS/NTP) with low packet budgets and explicit `open|filtered` semantics. |
| P1 | IPv6 feature parity | IPv6 TCP scanning, capture parsing, extension-header handling, inventory parity, and host address-family metadata are present. | Audit remaining UI/API/export paths for address-family assumptions and add regression tests before widening probes. |
| P1 | TLS observability | Offline traffic metadata and protocol analysis exist, but active service checks do not yet surface bounded TLS handshake/certificate metadata. | Add opt-in TLS handshake metadata: negotiated protocol/cipher and certificate subject/issuer fingerprints, with strict time/byte limits. |
| P2 | Flow/session fidelity | Flow analysis, correlation, topology, timeline, display filters, Community ID, and anomaly modules exist. | Add TCP state/retransmission/termination-quality summaries from offline captures, inspired by Zeek connection semantics. |
| P2 | Capture/filter UX | PCAP/PCAPNG import and flow display filters exist. | Improve saved filter presets, validation errors, and investigator-oriented protocol/endpoint/time-range pivots. |
| P2 | Structured interoperability | JSON/CSV/report/export modules exist. | Add documented stable schemas for service and flow evidence, including address family, evidence source, confidence, and timestamps. |
| P3 | Plugin/scripting boundary | Intelligence and AI tool registries exist; a general network-analysis plugin contract is not yet established. | Define a signed/allowlisted read-only analyzer plugin interface before permitting third-party extensions. |
| P3 | Performance characterization | Concurrency controls and API benchmark tooling exist. | Add reproducible local benchmarks for scanner concurrency, large PCAP parsing, and flow aggregation; publish measured baselines only. |

## Research anchors

- Nmap service/version detection: https://nmap.org/book/vscan.html
- Nmap IPv6 scanning: https://nmap.org/book/port-scanning-ipv6.html
- Wireshark display filters: https://www.wireshark.org/docs/man-pages/wireshark-filter.html
- Wireshark packet/conversation analysis: https://www.wireshark.org/docs/man-pages/wireshark.html
- Zeek connection-oriented traffic logs: https://docs.zeek.org/en/master/quickstart.html
- Suricata EVE JSON schema: https://docs.suricata.io/en/latest/appendix/eve-schema.html

## Selection rule

Prefer the highest-priority item that can be implemented and verified without broadening authorization scope, requiring privileged attack techniques, or introducing unbounded network activity. Every completed item should include focused tests plus regression/CI verification before merge.
