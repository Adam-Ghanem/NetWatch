# Security Policy

## Intended Use

NetWatch is intended for authorized local-network monitoring, cybersecurity education, and defensive administration.

## Built-in Safeguards

- Private/local IP target validation
- Broad public scanning blocked by default
- Conservative common-port scanning only
- Maximum CIDR scan size
- Explicit authorization checkbox before scan actions
- Explicit authorization field for API scan actions
- Local API Host and CORS allowlists
- Bounded API input and one active API scan at a time
- Activity logging
- Defensive recommendations only
- Local Risk Advisor with no external service calls
- Dynamic UI text cleaned before entering custom HTML cards
- CSV exports sanitized to reduce spreadsheet formula-injection risk
- HTML report tables escaped before export
- Generated local data ignored by Git

## Local Data

NetWatch may generate these local files while running:

```text
data/netwatch.db
data/scan_history.csv
logs/netwatch.log
```

These files can contain internal IP information and should not be committed or shared publicly.

## Security Limits

NetWatch is not a replacement for a full professional security audit. It does not include vulnerability exploitation, credential testing, stealth scanning, or brute-force logic.

## Reporting Issues

If private vulnerability reporting is available in the repository Security tab,
use **Report a vulnerability**. Otherwise, open a minimal GitHub issue without
private network data or working exploit details and ask for a private contact.

Include:

- A clear description
- Steps to reproduce
- Expected and actual behavior
- Suggested fix if available

Do not include secrets, passwords, private IP maps, or sensitive screenshots in public issues.
