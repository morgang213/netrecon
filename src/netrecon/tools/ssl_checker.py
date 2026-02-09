"""SSL/TLS Checker - Check SSL/TLS certificates and configuration."""

import datetime
import socket
import ssl

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from netrecon.explain import show_explanation
from netrecon.warnings import confirm_active_use

console = Console()
TOOL_NAME = "ssl_checker"


def check_ssl(host: str, port: int, timeout: float) -> dict:
    """Check SSL/TLS certificate and configuration. Returns info dict."""
    context = ssl.create_default_context()

    try:
        with (
            socket.create_connection((host, port), timeout=timeout) as sock,
            context.wrap_socket(sock, server_hostname=host) as ssock,
        ):
            cert = ssock.getpeercert()
            cipher = ssock.cipher()
            version = ssock.version()

            # Parse certificate fields
            subject = dict(x[0] for x in cert.get("subject", ()))
            issuer = dict(x[0] for x in cert.get("issuer", ()))
            not_before = cert.get("notBefore", "")
            not_after = cert.get("notAfter", "")

            # Parse dates
            date_format = "%b %d %H:%M:%S %Y %Z"
            try:
                expire_date = datetime.datetime.strptime(not_after, date_format)
                days_left = (expire_date - datetime.datetime.utcnow()).days
            except ValueError:
                expire_date = None
                days_left = None

            # Subject Alternative Names
            san_list = []
            for san_type, san_value in cert.get("subjectAltName", ()):
                san_list.append(f"{san_type}: {san_value}")

            return {
                "host": host,
                "port": port,
                "subject_cn": subject.get("commonName", "N/A"),
                "issuer_cn": issuer.get("commonName", "N/A"),
                "issuer_org": issuer.get("organizationName", "N/A"),
                "serial": cert.get("serialNumber", "N/A"),
                "not_before": not_before,
                "not_after": not_after,
                "days_left": days_left,
                "version": version,
                "cipher_name": cipher[0] if cipher else "N/A",
                "cipher_bits": cipher[2] if cipher else 0,
                "san": san_list,
            }
    except ssl.SSLCertVerificationError as e:
        return {"error": f"Certificate verification failed: {e}"}
    except ssl.SSLError as e:
        return {"error": f"SSL error: {e}"}
    except socket.timeout:
        return {"error": f"Connection timed out to {host}:{port}"}
    except ConnectionRefusedError:
        return {"error": f"Connection refused to {host}:{port}"}
    except OSError as e:
        return {"error": f"Connection error: {e}"}


def display_results(info: dict) -> None:
    """Display SSL check results."""
    if "error" in info:
        console.print(f"\n[red][!] {info['error']}[/red]\n")
        return

    table = Table(border_style="cyan", show_header=False, padding=(0, 2))
    table.add_column("Field", style="bold cyan", min_width=22)
    table.add_column("Value", style="white")

    table.add_row("Host", f"{info['host']}:{info['port']}")
    table.add_row("Subject (CN)", info["subject_cn"])
    table.add_row("Issuer", f"{info['issuer_cn']} ({info['issuer_org']})")
    table.add_row("Serial Number", info["serial"][:40])
    table.add_row("Valid From", info["not_before"])
    table.add_row("Valid Until", info["not_after"])

    if info["days_left"] is not None:
        if info["days_left"] < 0:
            expiry_str = f"[red]EXPIRED ({abs(info['days_left'])} days ago)[/red]"
        elif info["days_left"] < 30:
            expiry_str = f"[yellow]{info['days_left']} days (expiring soon!)[/yellow]"
        else:
            expiry_str = f"[green]{info['days_left']} days[/green]"
        table.add_row("Days Until Expiry", expiry_str)

    table.add_row("TLS Version", info["version"])
    table.add_row("Cipher", f"{info['cipher_name']} ({info['cipher_bits']}-bit)")

    if info["san"]:
        san_display = "\n".join(info["san"][:10])
        if len(info["san"]) > 10:
            san_display += f"\n... and {len(info['san']) - 10} more"
        table.add_row("Alt Names (SAN)", san_display)

    console.print()
    console.print(
        Panel(table, title="[bold]SSL/TLS Certificate[/bold]", border_style="cyan")
    )
    console.print()


def run(
    host: str = typer.Argument(..., help="Hostname to check (e.g., example.com)"),
    port: int = typer.Option(443, "--port", "-p", help="Port to connect to"),
    timeout: float = typer.Option(
        5.0, "--timeout", "-t", help="Connection timeout in seconds"
    ),
    explain: bool = typer.Option(
        False, "--explain", "-e", help="Show beginner-friendly explanation"
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip authorization confirmation"
    ),
) -> None:
    """Check SSL/TLS certificate and configuration for a host."""
    if explain:
        show_explanation(TOOL_NAME)

    if not yes:
        confirm_active_use()

    console.print(f"\n[bold]Checking SSL/TLS on {host}:{port}...[/bold]")

    info = check_ssl(host, port, timeout)
    display_results(info)
