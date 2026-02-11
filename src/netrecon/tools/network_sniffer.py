"""Network Sniffer - Capture and analyze live network traffic."""

import signal
from collections import Counter
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from scapy.all import IP, TCP, UDP, sniff
from scapy.packet import Packet

from netrecon.explain import show_explanation
from netrecon.warnings import confirm_active_use

console = Console()
TOOL_NAME = "network_sniffer"

# Global state for packet capture
packets_captured = []
capture_running = True


def signal_handler(sig, frame) -> None:
    """Handle Ctrl+C gracefully."""
    global capture_running
    capture_running = False
    console.print("\n[yellow]Stopping capture...[/yellow]")


def packet_callback(packet: Packet) -> None:
    """Callback function for each captured packet."""
    global packets_captured
    packets_captured.append(packet)

    # Show live counter every 10 packets
    if len(packets_captured) % 10 == 0:
        console.print(
            f"\r[dim]Packets captured: {len(packets_captured)}[/dim]", end=""
        )


def analyze_packets(packets: list[Packet]) -> dict:
    """Analyze captured packets and extract statistics."""
    stats = {
        "total": len(packets),
        "protocols": Counter(),
        "src_ips": Counter(),
        "dst_ips": Counter(),
        "src_ports": Counter(),
        "dst_ports": Counter(),
        "conversations": Counter(),
    }

    for pkt in packets:
        # Protocol analysis
        if TCP in pkt:
            stats["protocols"]["TCP"] += 1
        elif UDP in pkt:
            stats["protocols"]["UDP"] += 1
        elif IP in pkt:
            stats["protocols"]["IP"] += 1
        else:
            stats["protocols"]["Other"] += 1

        # IP analysis
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            stats["src_ips"][src_ip] += 1
            stats["dst_ips"][dst_ip] += 1

            # Conversation tracking
            conversation = f"{src_ip} → {dst_ip}"
            stats["conversations"][conversation] += 1

        # Port analysis (TCP/UDP)
        if TCP in pkt:
            stats["src_ports"][pkt[TCP].sport] += 1
            stats["dst_ports"][pkt[TCP].dport] += 1
        elif UDP in pkt:
            stats["src_ports"][pkt[UDP].sport] += 1
            stats["dst_ports"][pkt[UDP].dport] += 1

    return stats


def display_results(stats: dict, save_file: Optional[str]) -> None:
    """Display packet capture analysis."""
    console.print("\n\n[bold]Capture Summary[/bold]\n")
    console.print(f"Total packets captured: [cyan]{stats['total']}[/cyan]\n")

    # Protocol distribution
    if stats["protocols"]:
        proto_table = Table(title="Protocol Distribution", border_style="cyan")
        proto_table.add_column("Protocol", style="bold")
        proto_table.add_column("Count", justify="right")
        proto_table.add_column("Percentage", justify="right")

        for proto, count in stats["protocols"].most_common():
            pct = (count / stats["total"]) * 100
            proto_table.add_row(proto, str(count), f"{pct:.1f}%")

        console.print(proto_table)
        console.print()

    # Top source IPs
    if stats["src_ips"]:
        src_table = Table(title="Top Source IPs", border_style="cyan")
        src_table.add_column("IP Address", style="bold")
        src_table.add_column("Packets", justify="right")

        for ip, count in stats["src_ips"].most_common(10):
            src_table.add_row(ip, str(count))

        console.print(src_table)
        console.print()

    # Top destination IPs
    if stats["dst_ips"]:
        dst_table = Table(title="Top Destination IPs", border_style="cyan")
        dst_table.add_column("IP Address", style="bold")
        dst_table.add_column("Packets", justify="right")

        for ip, count in stats["dst_ips"].most_common(10):
            dst_table.add_row(ip, str(count))

        console.print(dst_table)
        console.print()

    # Top destination ports
    if stats["dst_ports"]:
        port_table = Table(title="Top Destination Ports", border_style="cyan")
        port_table.add_column("Port", style="bold")
        port_table.add_column("Packets", justify="right")
        port_table.add_column("Common Service", style="dim")

        common_ports = {
            80: "HTTP",
            443: "HTTPS",
            22: "SSH",
            21: "FTP",
            25: "SMTP",
            53: "DNS",
            3306: "MySQL",
            5432: "PostgreSQL",
            8080: "HTTP Alt",
        }

        for port, count in stats["dst_ports"].most_common(10):
            service = common_ports.get(port, "")
            port_table.add_row(str(port), str(count), service)

        console.print(port_table)
        console.print()

    # Top conversations
    if stats["conversations"]:
        conv_table = Table(title="Top Conversations", border_style="cyan")
        conv_table.add_column("Source → Destination", style="bold")
        conv_table.add_column("Packets", justify="right")

        for conv, count in stats["conversations"].most_common(10):
            conv_table.add_row(conv, str(count))

        console.print(conv_table)
        console.print()

    if save_file:
        console.print(f"[green]Packets saved to: {save_file}[/green]\n")


def run(
    interface: str = typer.Option(
        None,
        "--interface",
        "-i",
        help="Network interface to capture on (e.g., eth0, en0)",
    ),
    count: int = typer.Option(
        100, "--count", "-c", help="Number of packets to capture (0 for unlimited)"
    ),
    filter_expr: str = typer.Option(
        "", "--filter", "-f", help="BPF filter expression (e.g., 'tcp port 80')"
    ),
    save: str = typer.Option(
        None, "--save", "-s", help="Save captured packets to PCAP file"
    ),
    timeout: int = typer.Option(
        30, "--timeout", "-t", help="Capture timeout in seconds (0 for no timeout)"
    ),
    explain: bool = typer.Option(
        False, "--explain", "-e", help="Show beginner-friendly explanation"
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip authorization confirmation"
    ),
) -> None:
    """Capture and analyze live network traffic (requires root/admin privileges)."""
    if explain:
        show_explanation(TOOL_NAME)

    if not yes:
        confirm_active_use()

    # Register signal handler for graceful shutdown
    signal.signal(signal.SIGINT, signal_handler)

    # Build capture parameters
    capture_params = {"prn": packet_callback, "store": True}

    if interface:
        capture_params["iface"] = interface

    if count > 0:
        capture_params["count"] = count

    if filter_expr:
        capture_params["filter"] = filter_expr

    if timeout > 0:
        capture_params["timeout"] = timeout

    # Display capture info
    console.print("\n[bold]Starting network capture...[/bold]")
    if interface:
        console.print(f"Interface: [cyan]{interface}[/cyan]")
    if filter_expr:
        console.print(f"Filter: [cyan]{filter_expr}[/cyan]")
    if count > 0:
        console.print(f"Count: [cyan]{count} packets[/cyan]")
    if timeout > 0:
        console.print(f"Timeout: [cyan]{timeout} seconds[/cyan]")

    console.print("\n[yellow]Press Ctrl+C to stop capture[/yellow]\n")

    # Start capture
    try:
        global packets_captured
        packets_captured = []

        captured = sniff(**capture_params)

        # Use captured packets if available
        if captured:
            packets_captured = list(captured)

    except PermissionError:
        console.print(
            "\n[red]Error: Packet capture requires root/administrator privileges.[/red]"
        )
        console.print("[dim]Try running with sudo on Linux/macOS[/dim]\n")
        raise typer.Exit(1) from None
    except OSError as e:
        console.print(f"\n[red]Error: {e}[/red]")
        if interface:
            console.print(
                f"[dim]Interface '{interface}' may not exist. "
                "Try without --interface to use default.[/dim]\n"
            )
        raise typer.Exit(1) from None
    except Exception as e:
        console.print(f"\n[red]Capture error: {e}[/red]\n")
        raise typer.Exit(1) from None

    # Save packets if requested
    if save and packets_captured:
        try:
            from scapy.all import wrpcap

            wrpcap(save, packets_captured)
        except Exception as e:
            console.print(f"[red]Error saving packets: {e}[/red]")

    # Analyze and display results
    if packets_captured:
        stats = analyze_packets(packets_captured)
        display_results(stats, save)
    else:
        console.print("\n[yellow]No packets captured.[/yellow]\n")
