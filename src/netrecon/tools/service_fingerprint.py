"""Service Fingerprinting - Identify OS and service versions on targets."""

import re
import socket
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from netrecon.explain import show_explanation
from netrecon.utils import parse_port_range, validate_host
from netrecon.warnings import confirm_active_use

console = Console()
TOOL_NAME = "service_fingerprint"

# Service-specific probes and patterns
SERVICE_SIGNATURES = {
    21: {  # FTP
        "probe": b"",
        "patterns": [
            (r"220.*vsFTPd (\S+)", "vsFTPd"),
            (r"220.*ProFTPD (\S+)", "ProFTPD"),
            (r"220.*FileZilla Server (\S+)", "FileZilla"),
            (r"220.*Pure-FTPd", "Pure-FTPd"),
        ],
    },
    22: {  # SSH
        "probe": b"",
        "patterns": [
            (r"SSH-2.0-OpenSSH_(\S+)", "OpenSSH"),
            (r"SSH-.*Dropbear_(\S+)", "Dropbear"),
            (r"SSH-.*libssh", "libssh"),
        ],
    },
    25: {  # SMTP
        "probe": b"EHLO test\r\n",
        "patterns": [
            (r"220.*Postfix", "Postfix"),
            (r"220.*Exim (\S+)", "Exim"),
            (r"220.*Sendmail (\S+)", "Sendmail"),
            (r"220.*Microsoft ESMTP", "Microsoft Exchange"),
        ],
    },
    80: {  # HTTP
        "probe": b"HEAD / HTTP/1.0\r\n\r\n",
        "patterns": [
            (r"Server: Apache/(\S+)", "Apache"),
            (r"Server: nginx/(\S+)", "nginx"),
            (r"Server: Microsoft-IIS/(\S+)", "IIS"),
            (r"Server: LiteSpeed", "LiteSpeed"),
        ],
    },
    443: {  # HTTPS
        "probe": b"",
        "patterns": [],  # HTTPS requires SSL/TLS handshake
    },
    3306: {  # MySQL
        "probe": b"",
        "patterns": [
            (r"(\d+\.\d+\.\d+)-MariaDB", "MariaDB"),
            (r"(\d+\.\d+\.\d+).*MySQL", "MySQL"),
        ],
    },
    5432: {  # PostgreSQL
        "probe": b"",
        "patterns": [],
    },
}


def fingerprint_service(
    host: str, port: int, timeout: float
) -> tuple[str, Optional[str]]:
    """
    Fingerprint a service on a specific port.
    Returns (service_type, version_info).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Get service signature config
            sig_config = SERVICE_SIGNATURES.get(port, {"probe": b"", "patterns": []})
            probe = sig_config["probe"]

            # Send probe if defined
            if probe:
                sock.send(probe)

            # Receive banner
            banner = sock.recv(4096).decode("utf-8", errors="replace")

            # Match against patterns
            for pattern, service_name in sig_config["patterns"]:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else "unknown"
                    return (service_name, version)

            # If no specific pattern matched, return generic info
            if banner:
                # Extract first line for display
                first_line = banner.split("\n")[0].strip()[:60]
                return ("Unknown", first_line)

            return ("Unknown", None)

    except socket.timeout:
        return ("Timeout", None)
    except ConnectionRefusedError:
        return ("Closed", None)
    except OSError as e:
        return ("Error", str(e)[:40])


def fingerprint_ports(
    host: str, ports: list[int], timeout: float
) -> dict[int, tuple[str, Optional[str]]]:
    """Fingerprint multiple ports. Returns {port: (service, version)}."""
    results: dict[int, tuple[str, Optional[str]]] = {}

    for port in ports:
        service, version = fingerprint_service(host, port, timeout)
        results[port] = (service, version)

    return results


def display_results(
    target: str, host: str, results: dict[int, tuple[str, Optional[str]]]
) -> None:
    """Display fingerprinting results."""
    addr_info = f"{target} ({host})" if target != host else host

    table = Table(title=f"Service Fingerprinting: {addr_info}", border_style="cyan")
    table.add_column("Port", style="bold", min_width=10)
    table.add_column("Service", min_width=15)
    table.add_column("Version/Info", min_width=30)

    found_services = False
    for port in sorted(results.keys()):
        service, version = results[port]

        # Skip closed/timeout ports
        if service in ["Closed", "Timeout", "Error"]:
            continue

        found_services = True
        version_display = version if version else "[dim]No version info[/dim]"

        # Colorize known services
        if service == "Unknown":
            service_display = f"[yellow]{service}[/yellow]"
        else:
            service_display = f"[green]{service}[/green]"

        table.add_row(f"{port}/tcp", service_display, version_display)

    if not found_services:
        console.print(
            f"\n[yellow]No accessible services found on {addr_info}.[/yellow]\n"
        )
        return

    console.print()
    console.print(table)
    console.print(
        "\n[dim]Note: Fingerprinting relies on banner information. "
        "Some services may not reveal version details.[/dim]\n"
    )


def run(
    target: str = typer.Argument(..., help="Target host (IP address or hostname)"),
    ports: str = typer.Option(
        "21,22,25,80,443,3306,5432,8080",
        "--ports",
        "-p",
        help="Ports to fingerprint (e.g., 22,80,443)",
    ),
    timeout: float = typer.Option(
        3.0, "--timeout", "-t", help="Connection timeout in seconds"
    ),
    explain: bool = typer.Option(
        False, "--explain", "-e", help="Show beginner-friendly explanation"
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip authorization confirmation"
    ),
) -> None:
    """Identify operating systems and service versions on network targets."""
    if explain:
        show_explanation(TOOL_NAME)

    if not yes:
        confirm_active_use()

    host = validate_host(target)
    port_list = parse_port_range(ports)

    addr_info = f"{target} ({host})" if target != host else host
    console.print(
        f"\n[bold]Fingerprinting services on {addr_info}...[/bold] "
        f"({len(port_list)} ports)\n"
    )

    results = fingerprint_ports(host, port_list, timeout)
    display_results(target, host, results)
