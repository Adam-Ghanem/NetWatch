from __future__ import annotations

SERVICE_DETAILS = {
    20: {
        "protocol": "TCP",
        "description": "FTP data channel",
        "common_role": "File transfer",
        "check": "Avoid plain FTP on production networks.",
    },
    21: {
        "protocol": "TCP",
        "description": "FTP control service",
        "common_role": "File transfer",
        "check": "Prefer SFTP/SSH and disable anonymous access.",
    },
    22: {
        "protocol": "TCP",
        "description": "Secure Shell remote administration",
        "common_role": "Linux/Network admin",
        "check": "Use keys, strong passwords, and restrict admin access.",
    },
    23: {
        "protocol": "TCP",
        "description": "Telnet remote administration",
        "common_role": "Legacy network admin",
        "check": "Disable Telnet and replace it with SSH.",
    },
    25: {
        "protocol": "TCP",
        "description": "SMTP mail transfer",
        "common_role": "Mail server",
        "check": "Verify relay restrictions and mail-server hardening.",
    },
    53: {
        "protocol": "TCP",
        "description": "DNS service",
        "common_role": "DNS resolver/server",
        "check": "Restrict recursion to trusted clients.",
    },
    80: {
        "protocol": "TCP",
        "description": "Unencrypted web service",
        "common_role": "Web/admin panel",
        "check": "Redirect to HTTPS where possible.",
    },
    110: {
        "protocol": "TCP",
        "description": "POP3 mail access",
        "common_role": "Mail access",
        "check": "Prefer encrypted mail access.",
    },
    143: {
        "protocol": "TCP",
        "description": "IMAP mail access",
        "common_role": "Mail access",
        "check": "Prefer encrypted mail access.",
    },
    443: {
        "protocol": "TCP",
        "description": "Encrypted web service",
        "common_role": "Web/admin panel",
        "check": "Check certificate and access control.",
    },
    445: {
        "protocol": "TCP",
        "description": "SMB file sharing",
        "common_role": "Windows file sharing",
        "check": "Keep SMB internal and patched.",
    },
    3306: {
        "protocol": "TCP",
        "description": "MySQL database",
        "common_role": "Database server",
        "check": "Bind to trusted networks only.",
    },
    3389: {
        "protocol": "TCP",
        "description": "Remote Desktop Protocol",
        "common_role": "Windows remote admin",
        "check": "Restrict with VPN/firewall and strong authentication.",
    },
    5432: {
        "protocol": "TCP",
        "description": "PostgreSQL database",
        "common_role": "Database server",
        "check": "Bind to trusted networks only.",
    },
    8080: {
        "protocol": "TCP",
        "description": "Alternative HTTP service",
        "common_role": "Web/admin panel",
        "check": "Protect admin panels with authentication and firewall rules.",
    },
}


def service_info(port: int) -> dict[str, str]:
    return SERVICE_DETAILS.get(
        port,
        {
            "protocol": "TCP",
            "description": "Unknown service in the configured scan list",
            "common_role": "Unknown",
            "check": "Confirm that this service is expected.",
        },
    )


def guess_device_role(open_ports: list[int]) -> str:
    ports = set(open_ports)
    if {3306, 5432} & ports:
        return "Database host"
    if 3389 in ports:
        return "Windows workstation/server"
    if 445 in ports:
        return "Windows or file-sharing host"
    if 22 in ports and ({80, 443, 8080} & ports):
        return "Linux/web server or network appliance"
    if 53 in ports and ({80, 443} & ports):
        return "Router, DNS service, or network appliance"
    if {80, 443, 8080} & ports:
        return "Web service or admin panel"
    if 22 in ports:
        return "Linux/network device"
    if not ports:
        return "No open service detected in checked list"
    return "General network host"
