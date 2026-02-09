"""Port Scanner - Discover open ports on a target host."""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import typer
from rich.console import Console
from rich.table import Table

from netrecon.explain import show_explanation
from netrecon.utils import get_service_info, parse_port_range, validate_host
from netrecon.warnings import confirm_active_use

console = Console()
TOOL_NAME = "port_scanner"


def scan_port(host: str, port: int, timeout: float) -> tuple[int, str]:
    """Scan a single port. Returns (port, state)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            if result == 0:
                return (port, "open")
            return (port, "closed")
    except socket.timeout:
        return (port, "filtered")
    except OSError:
        return (port, "filtered")


def scan_ports(
    host: str, ports: list[int], timeout: float, threads: int
) -> dict[int, str]:
    """Scan multiple ports concurrently. Returns {port: state} dict."""
    results: dict[int, str] = {}

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, host, port, timeout): port for port in ports
        }
        for future in as_completed(futures):
            port, state = future.result()
            results[port] = state

    return results


def display_results(target: str, host: str, results: dict[int, str]) -> None:
    """Format and display scan results."""
    open_count = sum(1 for s in results.values() if s == "open")
    closed_count = sum(1 for s in results.values() if s == "closed")
    filtered_count = sum(1 for s in results.values() if s == "filtered")

    addr_info = f"{target} ({host})" if target != host else host

    table = Table(title=f"Scan Results for {addr_info}", border_style="cyan")
    table.add_column("Port", style="bold", min_width=10)
    table.add_column("State", min_width=10)
    table.add_column("Service", min_width=12)
    table.add_column("Description", style="dim")

    for port in sorted(results.keys()):
        state = results[port]
        if state == "closed":
            continue

        service_name, service_desc = get_service_info(port)

        state_display = {
            "open": "[green]open[/green]",
            "closed": "[red]closed[/red]",
            "filtered": "[yellow]filtered[/yellow]",
        }.get(state, state)

        table.add_row(f"{port}/tcp", state_display, service_name, service_desc)

    if table.row_count == 0:
        console.print(
            f"\n[yellow]No open or filtered ports found on {addr_info}.[/yellow]"
        )
    else:
        console.print()
        console.print(table)

    console.print(
        f"\nScan complete: [green]{open_count} open[/green], "
        f"[red]{closed_count} closed[/red], "
        f"[yellow]{filtered_count} filtered[/yellow] "
        f"({len(results)} ports scanned)"
    )
    console.print()


def run(
    target: str = typer.Argument(..., help="Target host (IP address or hostname)"),
    ports: str = typer.Option(
        "1-1024", "--ports", "-p", help="Port range (e.g., 80,443 or 1-1024)"
    ),
    timeout: float = typer.Option(
        1.0, "--timeout", "-t", help="Connection timeout in seconds"
    ),
    threads: int = typer.Option(
        100, "--threads", help="Number of concurrent scan threads"
    ),
    explain: bool = typer.Option(
        False, "--explain", "-e", help="Show beginner-friendly explanation"
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip authorization confirmation"
    ),
) -> None:
    """Scan ports on a target host to find open services."""
    if explain:
        show_explanation(TOOL_NAME)

    if not yes:
        confirm_active_use()

    host = validate_host(target)
    port_list = parse_port_range(ports)

    addr_info = f"{target} ({host})" if target != host else host
    console.print(f"\n[bold]Scanning {addr_info}...[/bold] ({len(port_list)} ports)")

    results = scan_ports(host, port_list, timeout, threads)
    display_results(target, host, results)
