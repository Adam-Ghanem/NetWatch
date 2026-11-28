# TLS Investigator evidence export

The TLS Investigator exports only the filtered, bounded retained-evidence response from the same-origin authenticated API. The API key is sent in the request header and is never added to the export URL.

The browser creates a temporary object URL for the downloaded Blob. NetWatch removes the temporary anchor after the click, then schedules object-URL revocation **60 seconds later**. Immediate revocation in the same JavaScript task can race the browser's download handoff in some browser implementations; the bounded delay gives the browser time to consume the Blob URL while still ensuring automatic cleanup.

Exports can include device IP addresses and certificate SHA-256 fingerprints. Share them only with the authorized team and store them according to the organization's evidence-handling policy.

The export path does not initiate TLS handshakes, scans, or provider calls. It reads retained TLS metadata only.
