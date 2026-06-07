# Security Review Notes

NetWatch is designed as a defensive local-network visibility tool. These notes summarize the safety choices used in the project.

## Target restrictions

The app validates targets before scanning:

- Private IP addresses
- Loopback addresses
- Link-local addresses

Public Internet targets are blocked by default.

## Scan limits

The app keeps scanning conservative:

- A maximum number of hosts per CIDR scan
- A short predefined list of common TCP ports
- No stealth behavior
- No exploitation logic
- No credential collection
- No brute-force features

## User confirmation

The UI asks for explicit confirmation before scan actions. This is not a legal control by itself, but it helps keep the app focused on authorized use.

## Generated data

NetWatch creates local data files:

```text
data/netwatch.db
data/scan_history.csv
logs/netwatch.log
```

These files can contain internal IPs and should not be committed or shared publicly. They are ignored in `.gitignore`.

## Recommended company controls

If this app is used inside an organization, add:

- Organization authentication
- Role-based access control
- Approved scan ranges
- Centralized logging
- Retention policy for scan history
- Review process for exported reports
