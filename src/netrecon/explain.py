"""Education system for beginner-friendly explanations."""

from rich.console import Console
from rich.panel import Panel

console = Console()

EXPLANATIONS: dict[str, dict[str, str]] = {
    "port_scanner": {
        "title": "What is Port Scanning?",
        "body": (
            "A port is like a numbered door on a computer. Services (like websites "
            "on port 80 or email on port 25) listen behind specific doors. A port "
            "scan knocks on these doors to see which ones are open.\n\n"
            "Open ports tell you what services are running on a machine. Security "
            "professionals use port scans to find unexpected services that could be "
            "entry points for attackers."
        ),
        "learn_more": "https://en.wikipedia.org/wiki/Port_scanner",
    },
    "ping_sweep": {
        "title": "What is a Ping Sweep?",
        "body": (
            "A ping sweep is like shouting 'Is anyone there?' to every address on "
            "a network. Each computer that responds is 'alive' -- meaning it's "
            "powered on and connected.\n\n"
            "This helps you map out what devices exist on a network. It uses ICMP "
            "(Internet Control Message Protocol) echo requests, the same thing "
            "that happens when you run 'ping' in your terminal."
        ),
        "learn_more": "https://en.wikipedia.org/wiki/Ping_sweep",
    },
    "dns_lookup": {
        "title": "What is DNS?",
        "body": (
            "DNS (Domain Name System) is the internet's phone book. When you type "
            "'google.com', DNS translates that human-readable name into an IP "
            "address like 142.250.80.46 that computers actually use.\n\n"
            "A DNS lookup lets you see these translations, including:\n"
            "  - A records: IPv4 addresses\n"
            "  - AAAA records: IPv6 addresses\n"
            "  - MX records: Mail servers\n"
            "  - NS records: Name servers\n"
            "  - TXT records: Text data (often used for email security)\n"
            "  - CNAME records: Aliases pointing to other domains"
        ),
        "learn_more": "https://en.wikipedia.org/wiki/Domain_Name_System",
    },
    "traceroute": {
        "title": "What is Traceroute?",
        "body": (
            "When you visit a website, your data doesn't go directly there -- it "
            "bounces through multiple routers, like passing a note through a chain "
            "of people.\n\n"
            "Traceroute reveals each 'hop' in that chain, showing you the path your "
            "data takes and how long each step takes. High latency at a particular "
            "hop can reveal network bottlenecks or routing problems."
        ),
        "learn_more": "https://en.wikipedia.org/wiki/Traceroute",
    },
    "banner_grab": {
        "title": "What is Banner Grabbing?",
        "body": (
            "When you connect to a network service, it often introduces itself -- "
            "like a receptionist saying 'Welcome to Apache 2.4.52'. This greeting "
            "is called a 'banner'.\n\n"
            "Banners reveal what software and version is running on a port. Security "
            "professionals check banners to find outdated software with known "
            "vulnerabilities that need patching."
        ),
        "learn_more": "https://en.wikipedia.org/wiki/Banner_grabbing",
    },
    "ssl_checker": {
        "title": "What is SSL/TLS?",
        "body": (
            "SSL/TLS is the encryption that puts the padlock icon in your browser. "
            "It does two things:\n"
            "  1. Encrypts data so nobody can eavesdrop\n"
            "  2. Verifies identity via certificates (digital ID cards)\n\n"
            "An SSL certificate proves a website is who it claims to be. This tool "
            "checks whether that certificate is valid, expired, or issued by a "
            "trusted authority, and which encryption protocols are supported."
        ),
        "learn_more": "https://en.wikipedia.org/wiki/Transport_Layer_Security",
    },
    "whois_lookup": {
        "title": "What is WHOIS?",
        "body": (
            "WHOIS is like looking up who owns a house using public property "
            "records. For websites, WHOIS tells you who registered the domain, "
            "when it was created, and when it expires.\n\n"
            "This is publicly available information. Security analysts use WHOIS "
            "to investigate suspicious domains, check registration dates (newly "
            "created domains are often suspicious), and find contact information."
        ),
        "learn_more": "https://en.wikipedia.org/wiki/WHOIS",
    },
    "header_inspector": {
        "title": "What are HTTP Security Headers?",
        "body": (
            "HTTP headers are invisible metadata sent with every web page -- like "
            "the return address and handling instructions on a package.\n\n"
            "Security headers tell browsers how to protect users:\n"
            "  - Strict-Transport-Security: 'Only connect over HTTPS'\n"
            "  - Content-Security-Policy: 'Only load scripts from these sources'\n"
            "  - X-Frame-Options: 'Don't embed this page in a frame'\n"
            "  - X-Content-Type-Options: 'Don't guess the file type'\n\n"
            "Missing security headers can leave users vulnerable to attacks like "
            "clickjacking and cross-site scripting (XSS)."
        ),
        "learn_more": "https://owasp.org/www-project-secure-headers/",
    },
    "pcap_viewer": {
        "title": "What is a PCAP File?",
        "body": (
            "A PCAP (Packet Capture) file is a recording of network traffic -- "
            "like a security camera for data. Each 'packet' is a small chunk of "
            "data traveling between computers.\n\n"
            "Network analysts examine PCAP files to:\n"
            "  - Troubleshoot connectivity issues\n"
            "  - Detect malicious traffic patterns\n"
            "  - Understand how applications communicate\n"
            "  - Investigate security incidents\n\n"
            "Tools like Wireshark and tcpdump create PCAP files."
        ),
        "learn_more": "https://en.wikipedia.org/wiki/Pcap",
    },
    "log_parser": {
        "title": "What are Security Logs?",
        "body": (
            "Log files are a diary kept by your computer and its services, "
            "recording who connected, what they did, and what went wrong.\n\n"
            "Security analysts read logs to spot attacks. For example:\n"
            "  - 100 failed logins from one IP = brute-force attack\n"
            "  - Login at 3 AM from unusual country = account compromise\n"
            "  - Repeated 404 errors on admin paths = reconnaissance\n\n"
            "This tool parses common log formats and surfaces suspicious patterns "
            "automatically."
        ),
        "learn_more": "https://en.wikipedia.org/wiki/Log_file",
    },
    "subnet_calc": {
        "title": "What is a Subnet?",
        "body": (
            "A subnet divides a big network into smaller sections -- like splitting "
            "a building into floors. The subnet mask determines which part of an IP "
            "address identifies the network and which part identifies a specific "
            "device.\n\n"
            "For example, in 192.168.1.0/24:\n"
            "  - /24 means the first 24 bits are the network part\n"
            "  - The remaining 8 bits are for host addresses\n"
            "  - This gives 254 usable addresses (192.168.1.1 - 192.168.1.254)\n\n"
            "Understanding subnets is fundamental to networking and security."
        ),
        "learn_more": "https://en.wikipedia.org/wiki/Subnetwork",
    },
}

GLOSSARY: dict[str, str] = {
    "port": (
        "A numbered endpoint (0-65535) on a computer where network services "
        "listen for connections. Think of it as a door number. Well-known ports "
        "include 22 (SSH), 80 (HTTP), 443 (HTTPS), and 25 (SMTP)."
    ),
    "tcp": (
        "Transmission Control Protocol. A reliable, connection-based protocol "
        "that ensures data arrives in order and without errors. Used for web "
        "browsing, email, and file transfers. Think of it like a phone call -- "
        "you establish a connection before talking."
    ),
    "udp": (
        "User Datagram Protocol. A fast, connectionless protocol that sends "
        "data without guaranteeing delivery or order. Used for streaming, "
        "gaming, and DNS. Think of it like sending postcards -- fast but no "
        "delivery confirmation."
    ),
    "ip address": (
        "A unique numerical label assigned to every device on a network. IPv4 "
        "addresses look like 192.168.1.1 (four numbers 0-255). IPv6 addresses "
        "are longer, like 2001:db8::1. It's the computer equivalent of a "
        "street address."
    ),
    "dns": (
        "Domain Name System. The internet's phone book that translates "
        "human-readable domain names (like google.com) into IP addresses "
        "(like 142.250.80.46) that computers use to find each other."
    ),
    "icmp": (
        "Internet Control Message Protocol. Used by network devices to send "
        "error messages and operational information. The 'ping' command uses "
        "ICMP to check if a host is reachable."
    ),
    "subnet": (
        "A subdivision of an IP network. Subnets let you split a large network "
        "into smaller, manageable pieces. The subnet mask (like /24 or "
        "255.255.255.0) defines the boundary between the network and host "
        "portions of an address."
    ),
    "cidr": (
        "Classless Inter-Domain Routing. A notation for IP addresses and their "
        "subnet masks, written as IP/prefix (e.g., 192.168.1.0/24). The number "
        "after the slash tells you how many bits are used for the network part."
    ),
    "firewall": (
        "A security system that monitors and controls incoming and outgoing "
        "network traffic based on rules. Firewalls can block specific ports, "
        "IP addresses, or types of traffic. They're your network's bouncer."
    ),
    "ssl": (
        "Secure Sockets Layer (now replaced by TLS). The encryption protocol "
        "that secures HTTPS connections. When you see a padlock in your browser, "
        "SSL/TLS is encrypting data between you and the website."
    ),
    "tls": (
        "Transport Layer Security. The modern successor to SSL that encrypts "
        "network communications. TLS 1.2 and 1.3 are current standards. "
        "Despite the name change, people still often say 'SSL' to mean TLS."
    ),
    "http": (
        "Hypertext Transfer Protocol. The foundation of web communication. "
        "HTTP defines how web browsers request pages and how servers respond. "
        "Plain HTTP is unencrypted -- anyone on the network can read the data."
    ),
    "https": (
        "HTTP Secure. HTTP with encryption provided by TLS. All sensitive web "
        "traffic should use HTTPS. You can tell a site uses it by the 'https://' "
        "in the URL and the padlock icon."
    ),
    "packet": (
        "A small unit of data transmitted over a network. When you send a file "
        "or load a web page, the data is broken into packets, sent individually, "
        "and reassembled at the destination. Each packet contains headers "
        "(addressing info) and a payload (the actual data)."
    ),
    "banner": (
        "The initial response a network service sends when you connect to it. "
        "Banners often reveal the software name and version (e.g., 'Apache/2.4.52'). "
        "Attackers use banners to identify vulnerable software versions."
    ),
    "whois": (
        "A query protocol for looking up registration info about domains and "
        "IP addresses. WHOIS records include the registrant, creation date, "
        "expiration date, and name servers. This is public information."
    ),
    "brute force": (
        "An attack method that tries every possible combination to guess "
        "passwords or encryption keys. In logs, brute force appears as "
        "many rapid failed login attempts from the same source."
    ),
    "vulnerability": (
        "A weakness in software, hardware, or configuration that can be "
        "exploited by an attacker. Vulnerabilities are cataloged as CVEs "
        "(Common Vulnerabilities and Exposures) and rated by severity."
    ),
    "reconnaissance": (
        "The first phase of a security assessment (or attack) where information "
        "is gathered about the target. Port scanning, DNS lookups, and WHOIS "
        "queries are all reconnaissance techniques."
    ),
    "pcap": (
        "Packet Capture. A file format (.pcap) for storing recorded network "
        "traffic. Created by tools like tcpdump and Wireshark. Used for "
        "network troubleshooting, security analysis, and forensics."
    ),
}


def show_explanation(tool_name: str) -> None:
    """Display a beginner-friendly explanation panel for a tool."""
    info = EXPLANATIONS.get(tool_name)
    if not info:
        return

    body = info["body"]
    if info.get("learn_more"):
        body += f"\n\n[dim]Learn more: {info['learn_more']}[/dim]"

    console.print()
    console.print(
        Panel(
            body,
            title=f"[bold cyan]{info['title']}[/bold cyan]",
            border_style="cyan",
            padding=(1, 2),
        )
    )
    console.print()
