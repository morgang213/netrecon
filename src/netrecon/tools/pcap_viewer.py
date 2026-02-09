"""PCAP Viewer - Read and summarize packet capture files."""

from collections import Counter
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from netrecon.explain import show_explanation

console = Console()
TOOL_NAME = "pcap_viewer"


def read_pcap(filepath: str) -> dict:
    """Read a PCAP file and return summary statistics."""
    from scapy.all import IP, TCP, UDP, rdpcap

    path = Path(filepath)
    if not path.exists():
        console.print(f"[red][!] File not found: {filepath}[/red]")
        raise typer.Exit(code=1) from None

    try:
        packets = rdpcap(str(path))
    except Exception as e:
        console.print(f"[red][!] Failed to read PCAP file: {e}[/red]")
        raise typer.Exit(code=1) from None

    total = len(packets)
    protocols = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    conversations = Counter()
    src_ports = Counter()
    dst_ports = Counter()

    for pkt in packets:
        # Count protocols
        if pkt.haslayer(TCP):
            protocols["TCP"] += 1
        elif pkt.haslayer(UDP):
            protocols["UDP"] += 1
        else:
            proto_name = pkt.lastlayer().__class__.__name__
            protocols[proto_name] += 1

        # Count IPs and conversations
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            src_ips[src] += 1
            dst_ips[dst] += 1
            conversations[(src, dst)] += 1

        # Count ports
        if pkt.haslayer(TCP):
            src_ports[pkt[TCP].sport] += 1
            dst_ports[pkt[TCP].dport] += 1
        elif pkt.haslayer(UDP):
            src_ports[pkt[UDP].sport] += 1
            dst_ports[pkt[UDP].dport] += 1

    return {
        "filename": path.name,
        "total_packets": total,
        "protocols": protocols,
        "top_src_ips": src_ips.most_common(10),
        "top_dst_ips": dst_ips.most_common(10),
        "top_conversations": conversations.most_common(10),
        "top_dst_ports": dst_ports.most_common(10),
    }


def display_results(info: dict) -> None:
    """Display PCAP summary."""
    console.print(
        f"\n[bold]File:[/bold] {info['filename']}  |  "
        f"[bold]Packets:[/bold] {info['total_packets']:,}"
    )

    # Protocol distribution
    proto_table = Table(title="Protocol Distribution", border_style="cyan")
    proto_table.add_column("Protocol", style="bold cyan", min_width=12)
    proto_table.add_column("Packets", min_width=10, justify="right")
    proto_table.add_column("Percentage", min_width=10, justify="right")

    total = info["total_packets"]
    for proto, count in info["protocols"].most_common():
        pct = (count / total * 100) if total > 0 else 0
        proto_table.add_row(proto, f"{count:,}", f"{pct:.1f}%")

    console.print()
    console.print(proto_table)

    # Top source IPs
    if info["top_src_ips"]:
        src_table = Table(title="Top Source IPs (Talkers)", border_style="cyan")
        src_table.add_column("IP Address", style="bold", min_width=18)
        src_table.add_column("Packets", min_width=10, justify="right")

        for ip, count in info["top_src_ips"][:5]:
            src_table.add_row(ip, f"{count:,}")

        console.print()
        console.print(src_table)

    # Top destination ports
    if info["top_dst_ports"]:
        port_table = Table(title="Top Destination Ports", border_style="cyan")
        port_table.add_column("Port", style="bold", min_width=10)
        port_table.add_column("Packets", min_width=10, justify="right")

        from netrecon.utils import get_service_info

        for port, count in info["top_dst_ports"][:10]:
            service_name, _ = get_service_info(port)
            port_label = (
                f"{port} ({service_name})" if service_name != "Unknown" else str(port)
            )
            port_table.add_row(port_label, f"{count:,}")

        console.print()
        console.print(port_table)

    # Top conversations
    if info["top_conversations"]:
        conv_table = Table(title="Top Conversations", border_style="cyan")
        conv_table.add_column("Source", style="bold", min_width=18)
        conv_table.add_column("Destination", min_width=18)
        conv_table.add_column("Packets", min_width=10, justify="right")

        for (src, dst), count in info["top_conversations"][:5]:
            conv_table.add_row(src, dst, f"{count:,}")

        console.print()
        console.print(conv_table)

    console.print()


def run(
    filepath: str = typer.Argument(..., help="Path to .pcap file"),
    explain: bool = typer.Option(
        False, "--explain", "-e", help="Show beginner-friendly explanation"
    ),
) -> None:
    """Read and summarize a packet capture (PCAP) file."""
    if explain:
        show_explanation(TOOL_NAME)

    console.print(f"\n[bold]Reading PCAP file: {filepath}...[/bold]")

    info = read_pcap(filepath)
    display_results(info)
