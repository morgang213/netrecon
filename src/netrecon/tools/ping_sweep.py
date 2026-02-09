"""Ping Sweep - Discover live hosts on a network."""

import ipaddress
import platform
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

import typer
from rich.console import Console
from rich.table import Table

from netrecon.explain import show_explanation
from netrecon.warnings import confirm_active_use

console = Console()
TOOL_NAME = "ping_sweep"


def ping_host(ip: str, timeout: int = 1) -> tuple[str, bool]:
    """Ping a single host. Returns (ip, is_alive)."""
    param = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_param = "-w" if platform.system().lower() == "windows" else "-W"

    try:
        result = subprocess.run(
            ["ping", param, "1", timeout_param, str(timeout), ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 2,
        )
        return (ip, result.returncode == 0)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return (ip, False)


def sweep_network(network: str, timeout: int, threads: int) -> list[tuple[str, bool]]:
    """Ping all hosts in a network range. Returns [(ip, is_alive)]."""
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        console.print(f"[red][!] Invalid network: {e}[/red]")
        raise typer.Exit(code=1) from None

    hosts = [str(ip) for ip in net.hosts()]
    if not hosts:
        hosts = [str(net.network_address)]

    results: list[tuple[str, bool]] = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(ping_host, ip, timeout): ip for ip in hosts}
        for future in as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda x: ipaddress.ip_address(x[0]))


def display_results(network: str, results: list[tuple[str, bool]]) -> None:
    """Display ping sweep results."""
    alive = [(ip, status) for ip, status in results if status]
    total = len(results)

    table = Table(title=f"Ping Sweep: {network}", border_style="cyan")
    table.add_column("IP Address", style="bold", min_width=18)
    table.add_column("Status", min_width=10)

    for ip, is_alive in results:
        if is_alive:
            table.add_row(ip, "[green]alive[/green]")

    console.print()
    console.print(table)
    console.print(
        f"\n[bold]{len(alive)}[/bold] hosts alive out of [bold]{total}[/bold] scanned"
    )
    console.print()


def run(
    network: str = typer.Argument(
        ..., help="Network range in CIDR notation (e.g., 192.168.1.0/24)"
    ),
    timeout: int = typer.Option(1, "--timeout", "-t", help="Ping timeout in seconds"),
    threads: int = typer.Option(50, "--threads", help="Number of concurrent pings"),
    explain: bool = typer.Option(
        False, "--explain", "-e", help="Show beginner-friendly explanation"
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip authorization confirmation"
    ),
) -> None:
    """Sweep a network range to discover live hosts."""
    if explain:
        show_explanation(TOOL_NAME)

    if not yes:
        confirm_active_use()

    try:
        net = ipaddress.ip_network(network, strict=False)
        host_count = max(net.num_addresses - 2, 1)
    except ValueError as e:
        console.print(f"[red][!] Invalid network: {e}[/red]")
        raise typer.Exit(code=1) from None

    console.print(f"\n[bold]Sweeping {network}...[/bold] ({host_count} hosts)")

    results = sweep_network(network, timeout, threads)
    display_results(network, results)
