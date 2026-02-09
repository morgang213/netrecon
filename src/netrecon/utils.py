"""Shared utility functions for NetRecon tools."""

import ipaddress
import socket

# Common port-to-service mapping for inline annotations
COMMON_SERVICES: dict[int, tuple[str, str]] = {
    20: ("FTP-DATA", "File transfer (data channel)"),
    21: ("FTP", "File transfer (control channel)"),
    22: ("SSH", "Secure remote login"),
    23: ("Telnet", "Unencrypted remote login (insecure)"),
    25: ("SMTP", "Email sending"),
    53: ("DNS", "Domain name resolution"),
    67: ("DHCP", "Dynamic IP address assignment"),
    68: ("DHCP", "Dynamic IP address assignment (client)"),
    80: ("HTTP", "Web server (unencrypted)"),
    110: ("POP3", "Email retrieval"),
    119: ("NNTP", "News/Usenet"),
    123: ("NTP", "Time synchronization"),
    135: ("MSRPC", "Microsoft RPC"),
    137: ("NetBIOS", "Windows name service"),
    138: ("NetBIOS", "Windows datagram service"),
    139: ("NetBIOS", "Windows session service"),
    143: ("IMAP", "Email retrieval (with folders)"),
    161: ("SNMP", "Network device management"),
    162: ("SNMP-TRAP", "Network device alerts"),
    389: ("LDAP", "Directory service"),
    443: ("HTTPS", "Web server (encrypted with TLS)"),
    445: ("SMB", "Windows file sharing"),
    465: ("SMTPS", "Email sending (encrypted)"),
    514: ("Syslog", "System logging"),
    587: ("SMTP", "Email submission (encrypted)"),
    636: ("LDAPS", "Directory service (encrypted)"),
    993: ("IMAPS", "Email retrieval (encrypted)"),
    995: ("POP3S", "Email retrieval (encrypted)"),
    1433: ("MSSQL", "Microsoft SQL Server"),
    1521: ("Oracle", "Oracle database"),
    3306: ("MySQL", "MySQL database"),
    3389: ("RDP", "Remote desktop (Windows)"),
    5432: ("PostgreSQL", "PostgreSQL database"),
    5900: ("VNC", "Virtual Network Computing (remote desktop)"),
    6379: ("Redis", "Redis in-memory data store"),
    8080: ("HTTP-ALT", "Alternative web server"),
    8443: ("HTTPS-ALT", "Alternative HTTPS"),
    27017: ("MongoDB", "MongoDB database"),
}


def get_service_info(port: int) -> tuple[str, str]:
    """Get service name and description for a port number."""
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]
    return ("Unknown", "")


def validate_host(target: str) -> str:
    """Validate and resolve a hostname or IP address. Returns the IP address."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass

    try:
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        raise SystemExit(f"[!] Could not resolve hostname: {target}") from None


def parse_port_range(port_str: str) -> list[int]:
    """Parse a port specification string into a list of port numbers.

    Supports:
        - Single port: "80"
        - Comma-separated: "80,443,8080"
        - Range: "1-1024"
        - Mixed: "22,80,443,8000-8100"
    """
    ports: list[int] = []
    for part in port_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            start_port = int(start.strip())
            end_port = int(end.strip())
            if not (0 <= start_port <= 65535 and 0 <= end_port <= 65535):
                raise ValueError(f"Port numbers must be 0-65535, got {part}")
            if start_port > end_port:
                raise ValueError(f"Invalid range: {part}")
            ports.extend(range(start_port, end_port + 1))
        else:
            port = int(part)
            if not 0 <= port <= 65535:
                raise ValueError(f"Port number must be 0-65535, got {port}")
            ports.append(port)
    return sorted(set(ports))


# Common port presets
PORT_PRESETS: dict[str, str] = {
    "top-20": (
        "21,22,23,25,53,80,110,111,135,139,"
        "143,443,445,993,995,1723,3306,3389,5900,8080"
    ),
    "web": "80,443,8080,8443",
    "database": "1433,1521,3306,5432,6379,27017",
    "mail": "25,110,143,465,587,993,995",
}
