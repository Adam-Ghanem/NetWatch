# Security Policy

## Intended Use

NetWatch is intended for authorized local-network monitoring, cybersecurity education, and defensive administration.

## Built-in Safeguards

- Private/local IP target validation
- Broad public scanning blocked by default
- Conservative common-port scanning only
- Maximum CIDR scan size
- Explicit authorization checkbox before scan actions
- Activity logging
- Defensive recommendations only
- Local AI Advisor with no external API calls
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

If you find a security issue in this project, open a GitHub issue with:

- A clear description
- Steps to reproduce
- Expected and actual behavior
- Suggested fix if available

Do not include secrets, passwords, private IP maps, or sensitive screenshots in public issues.
