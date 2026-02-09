"""Banner Grab - Read service banners from open ports."""

import socket

import typer
from rich.console import Console
from rich.table import Table

from netrecon.explain import show_explanation
from netrecon.utils import get_service_info, parse_port_range, validate_host
from netrecon.warnings import confirm_active_use

console = Console()
TOOL_NAME = "banner_grab"

# Probes to send for services that don't send banners automatically
SERVICE_PROBES: dict[int, bytes] = {
    80: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    443: b"",  # SSL/TLS handled differently
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
}


def grab_banner(host: str, port: int, timeout: float) -> tuple[int, str]:
    """Grab the banner from a single port. Returns (port, banner_text)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Some services need a probe to trigger a response
            probe = SERVICE_PROBES.get(port, b"")
            if probe:
                probe = probe.replace(b"target", host.encode())
                sock.send(probe)

            banner = sock.recv(1024)
            return (port, banner.decode("utf-8", errors="replace").strip())
    except (socket.timeout, ConnectionRefusedError):
        return (port, "")
    except OSError:
        return (port, "")


def grab_banners(host: str, ports: list[int], timeout: float) -> dict[int, str]:
    """Grab banners from multiple ports. Returns {port: banner}."""
    results: dict[int, str] = {}
    for port in ports:
        port_num, banner = grab_banner(host, port, timeout)
        results[port_num] = banner
    return results


def display_results(target: str, host: str, results: dict[int, str]) -> None:
    """Display banner grab results."""
    addr_info = f"{target} ({host})" if target != host else host

    table = Table(title=f"Banner Grab: {addr_info}", border_style="cyan")
    table.add_column("Port", style="bold", min_width=10)
    table.add_column("Service", min_width=12)
    table.add_column("Banner", min_width=40)

    found = False
    for port in sorted(results.keys()):
        banner = results[port]
        service_name, _ = get_service_info(port)

        if banner:
            found = True
            # Truncate long banners for display
            display_banner = banner[:200]
            if len(banner) > 200:
                display_banner += "..."
            table.add_row(f"{port}/tcp", service_name, display_banner)
        else:
            table.add_row(f"{port}/tcp", service_name, "[dim]No banner received[/dim]")

    console.print()
    console.print(table)

    if not found:
        console.print(
            "\n[yellow]No banners received. The ports may be closed, filtered, "
            "or the services don't send banners.[/yellow]"
        )
    console.print()


def run(
    target: str = typer.Argument(..., help="Target host (IP address or hostname)"),
    ports: str = typer.Option(
        "21,22,25,80,110,143,443,3306,5432,8080",
        "--ports",
        "-p",
        help="Ports to grab banners from (e.g., 22,80,443)",
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
    """Grab service banners from open ports to identify running software."""
    if explain:
        show_explanation(TOOL_NAME)

    if not yes:
        confirm_active_use()

    host = validate_host(target)
    port_list = parse_port_range(ports)

    addr_info = f"{target} ({host})" if target != host else host
    console.print(
        f"\n[bold]Grabbing banners from {addr_info}...[/bold] ({len(port_list)} ports)"
    )

    results = grab_banners(host, port_list, timeout)
    display_results(target, host, results)
