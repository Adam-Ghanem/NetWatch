# NetWatch Demo Script

Use this script when presenting NetWatch to a teacher, internship supervisor, or company contact.

## 1. Opening

NetWatch is a small local network monitoring dashboard. I built it to practice Python, networking, Streamlit, local asset tracking, and defensive security reporting.

The app is intentionally limited to private/local networks and does not include exploitation features.

## 2. Show the dashboard

Open NetWatch and show the **Overview** page.

Mention:

- Online hosts from the latest scan
- Saved inventory count
- Open ports from the latest audit
- Exposure level and score

## 3. Explain safety controls

Go to **Safety** and mention:

- Local/private IP validation
- Maximum scan size
- Short common-port list
- Permission checkbox before scans
- No brute force or exploitation

## 4. Run Network Tools

Go to **Network Tools** and enter a CIDR such as:

```text
192.168.1.0/24
```

Explain:

- Network address
- Netmask
- Broadcast address
- Usable hosts
- Gateway guess

## 5. Run Host Check

Go to **Host Check** and test the router or lab machine:

```text
192.168.1.1
```

Explain that some devices block ping, so offline does not always mean the device is down.

## 6. Run Network Scan

Go to **Network Scan** and use a small authorized local range first.

Example:

```text
192.168.1.0/24
```

Confirm permission and start the scan.

## 7. Run Port Audit

Go to **Port Audit** and audit one internal IP. Explain that the app checks common services and gives defensive recommendations.

## 8. Show Inventory

Go to **Inventory** and show saved devices, last seen time, open ports, and exposure score.

## 9. Export report

Go to **Reports** and export:

- Markdown report
- HTML report

## 10. Closing

NetWatch is currently a lab/portfolio project, but it can be extended with authentication, scheduled scans, PDF reports, and more detailed asset management.
