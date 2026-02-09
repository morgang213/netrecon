"""Subnet Calculator - Calculate network ranges and host counts."""

import ipaddress

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from netrecon.explain import show_explanation

console = Console()
TOOL_NAME = "subnet_calc"


def calculate_subnet(network_str: str) -> dict:
    """Calculate subnet information for a given CIDR or IP/mask."""
    network = ipaddress.ip_network(network_str, strict=False)

    num_addresses = network.num_addresses
    if network.version == 4:
        usable_hosts = (
            max(0, num_addresses - 2) if network.prefixlen < 31 else num_addresses
        )
    else:
        usable_hosts = num_addresses

    result = {
        "network": str(network.network_address),
        "broadcast": str(network.broadcast_address),
        "netmask": str(network.netmask),
        "prefix_length": network.prefixlen,
        "total_addresses": num_addresses,
        "usable_hosts": usable_hosts,
        "first_host": str(network.network_address + 1) if usable_hosts > 0 else "N/A",
        "last_host": str(network.broadcast_address - 1)
        if usable_hosts > 0 and network.prefixlen < 31
        else str(network.broadcast_address),
        "version": network.version,
        "is_private": network.is_private,
        "wildcard": str(network.hostmask),
    }
    return result


def display_results(info: dict) -> None:
    """Display subnet calculation results."""
    table = Table(border_style="cyan", show_header=False, padding=(0, 2))
    table.add_column("Property", style="bold cyan", min_width=20)
    table.add_column("Value", style="white")

    table.add_row("Network Address", info["network"])
    table.add_row("Broadcast Address", info["broadcast"])
    table.add_row("Subnet Mask", info["netmask"])
    table.add_row("Wildcard Mask", info["wildcard"])
    table.add_row("Prefix Length", f"/{info['prefix_length']}")
    table.add_row("Total Addresses", f"{info['total_addresses']:,}")
    table.add_row("Usable Hosts", f"{info['usable_hosts']:,}")
    table.add_row("First Usable Host", info["first_host"])
    table.add_row("Last Usable Host", info["last_host"])
    table.add_row("IP Version", f"IPv{info['version']}")
    table.add_row(
        "Address Type",
        "[green]Private[/green]" if info["is_private"] else "[yellow]Public[/yellow]",
    )

    console.print()
    console.print(
        Panel(table, title="[bold]Subnet Calculation[/bold]", border_style="cyan")
    )

    # Binary visualization for /16 and larger
    if info["version"] == 4:
        _show_binary_breakdown(info["network"], info["prefix_length"])

    console.print()


def _show_binary_breakdown(network_addr: str, prefix: int) -> None:
    """Show a visual binary breakdown of the network/host split."""
    octets = network_addr.split(".")
    bits = "".join(f"{int(o):08b}" for o in octets)
    network_bits = bits[:prefix]
    host_bits = bits[prefix:]

    console.print()
    console.print("[dim]Binary breakdown (network | host):[/dim]")
    console.print(f"  [cyan]{network_bits}[/cyan][yellow]{host_bits}[/yellow]")
    console.print(
        f"  [cyan]{'N' * prefix}[/cyan][yellow]{'H' * (32 - prefix)}[/yellow]"
    )


def run(
    network: str = typer.Argument(
        ..., help="Network in CIDR notation (e.g., 192.168.1.0/24)"
    ),
    explain: bool = typer.Option(
        False, "--explain", "-e", help="Show beginner-friendly explanation"
    ),
) -> None:
    """Calculate subnet ranges, host counts, and network details."""
    if explain:
        show_explanation(TOOL_NAME)

    try:
        info = calculate_subnet(network)
    except ValueError as e:
        console.print(f"[red][!] Invalid network: {e}[/red]")
        raise typer.Exit(code=1) from None

    display_results(info)
