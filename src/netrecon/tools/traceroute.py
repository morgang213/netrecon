"""Traceroute - Trace the network path to a destination."""

import platform
import re
import subprocess

import typer
from rich.console import Console
from rich.table import Table

from netrecon.explain import show_explanation
from netrecon.warnings import confirm_active_use

console = Console()
TOOL_NAME = "traceroute"


def run_traceroute(target: str, max_hops: int, timeout: int) -> list[dict]:
    """Run system traceroute and parse output. Returns list of hop dicts."""
    system = platform.system().lower()

    if system == "windows":
        cmd = ["tracert", "-h", str(max_hops), "-w", str(timeout * 1000), target]
    else:
        cmd = ["traceroute", "-m", str(max_hops), "-w", str(timeout), target]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max_hops * timeout + 10,
        )
        output = result.stdout
    except FileNotFoundError:
        console.print(
            "[red][!] traceroute command not found. "
            "Install it with your package manager.[/red]"
        )
        raise typer.Exit(code=1) from None
    except subprocess.TimeoutExpired:
        console.print("[yellow][!] Traceroute timed out.[/yellow]")
        return []

    return parse_traceroute_output(output, system)


def parse_traceroute_output(output: str, system: str) -> list[dict]:
    """Parse traceroute output into structured hop data."""
    hops = []

    for line in output.strip().splitlines():
        line = line.strip()

        # Skip header lines
        if not line or line.startswith("traceroute") or line.startswith("Tracing"):
            continue
        if line.startswith("over a maximum") or line.startswith("Trace complete"):
            continue

        # Try to parse hop number at start of line
        match = re.match(r"^\s*(\d+)\s+(.+)$", line)
        if not match:
            continue

        hop_num = int(match.group(1))
        rest = match.group(2)

        # Check for timeout
        if rest.strip() == "* * *":
            hops.append(
                {
                    "hop": hop_num,
                    "host": "*",
                    "ip": "*",
                    "rtts": [],
                }
            )
            continue

        # Extract IP address
        ip_match = re.search(r"\(?([\d.]+)\)?", rest)
        ip_addr = ip_match.group(1) if ip_match else "*"

        # Extract hostname (before the IP)
        host_match = re.match(r"^([\w\-.]+)\s", rest)
        hostname = host_match.group(1) if host_match else ip_addr

        # Extract RTT values (numbers followed by "ms")
        rtt_matches = re.findall(r"([\d.]+)\s*ms", rest)
        rtts = [float(r) for r in rtt_matches]

        hops.append(
            {
                "hop": hop_num,
                "host": hostname,
                "ip": ip_addr,
                "rtts": rtts,
            }
        )

    return hops


def display_results(target: str, hops: list[dict]) -> None:
    """Display traceroute results."""
    table = Table(title=f"Traceroute to {target}", border_style="cyan")
    table.add_column("Hop", style="bold", min_width=5, justify="right")
    table.add_column("Host", min_width=25)
    table.add_column("IP Address", min_width=16)
    table.add_column("RTT", min_width=20)

    for hop in hops:
        if hop["host"] == "*":
            table.add_row(
                str(hop["hop"]), "[dim]* * *[/dim]", "", "[dim]Request timed out[/dim]"
            )
        else:
            rtt_str = (
                "  ".join(f"{r:.1f} ms" for r in hop["rtts"]) if hop["rtts"] else "N/A"
            )
            table.add_row(str(hop["hop"]), hop["host"], hop["ip"], rtt_str)

    console.print()
    console.print(table)
    console.print(f"\nTrace complete: {len(hops)} hops")
    console.print()


def run(
    target: str = typer.Argument(..., help="Destination host (IP address or hostname)"),
    max_hops: int = typer.Option(30, "--max-hops", "-m", help="Maximum number of hops"),
    timeout: int = typer.Option(
        3, "--timeout", "-t", help="Timeout per hop in seconds"
    ),
    explain: bool = typer.Option(
        False, "--explain", "-e", help="Show beginner-friendly explanation"
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip authorization confirmation"
    ),
) -> None:
    """Trace the network path (hops) to a destination."""
    if explain:
        show_explanation(TOOL_NAME)

    if not yes:
        confirm_active_use()

    console.print(f"\n[bold]Tracing route to {target}...[/bold] (max {max_hops} hops)")

    hops = run_traceroute(target, max_hops, timeout)
    display_results(target, hops)
