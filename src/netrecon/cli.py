"""Main CLI application for NetRecon."""

import typer
from rich.console import Console
from rich.table import Table

from netrecon.explain import GLOSSARY

app = typer.Typer(
    name="netrecon",
    help="NetRecon - A beginner-friendly network security tools suite.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()


@app.command()
def glossary(
    term: str = typer.Argument(
        None, help="Term to look up (e.g., 'port', 'tcp', 'dns')"
    ),
) -> None:
    """Look up networking and security terms in the built-in glossary."""
    if term is None:
        table = Table(title="NetRecon Glossary", border_style="cyan")
        table.add_column("Term", style="bold cyan", min_width=15)
        table.add_column("Definition")
        for key in sorted(GLOSSARY.keys()):
            table.add_row(key.upper(), GLOSSARY[key])
        console.print()
        console.print(table)
        return

    term_lower = term.lower()
    matches = {k: v for k, v in GLOSSARY.items() if term_lower in k}

    if not matches:
        console.print(f"[yellow]No glossary entry found for '{term}'.[/yellow]")
        console.print("[dim]Available terms:[/dim]", ", ".join(sorted(GLOSSARY.keys())))
        return

    for key, definition in matches.items():
        console.print(f"\n[bold cyan]{key.upper()}[/bold cyan]")
        console.print(definition)
    console.print()


# Import and register tool commands
from netrecon.tools.banner_grab import run as banner_grab_run  # noqa: E402
from netrecon.tools.dns_lookup import run as dns_lookup_run  # noqa: E402
from netrecon.tools.header_inspector import run as header_inspector_run  # noqa: E402
from netrecon.tools.log_parser import run as log_parser_run  # noqa: E402
from netrecon.tools.pcap_viewer import run as pcap_viewer_run  # noqa: E402
from netrecon.tools.ping_sweep import run as ping_sweep_run  # noqa: E402
from netrecon.tools.port_scanner import run as port_scanner_run  # noqa: E402
from netrecon.tools.ssl_checker import run as ssl_checker_run  # noqa: E402
from netrecon.tools.subnet_calc import run as subnet_calc_run  # noqa: E402
from netrecon.tools.traceroute import run as traceroute_run  # noqa: E402
from netrecon.tools.whois_lookup import run as whois_lookup_run  # noqa: E402

app.command(name="scan", help="Scan ports on a target host to find open services.")(
    port_scanner_run
)
app.command(name="ping", help="Sweep a network range to discover live hosts.")(
    ping_sweep_run
)
app.command(name="dns", help="Look up DNS records for a domain.")(dns_lookup_run)
app.command(name="trace", help="Trace the network path to a destination.")(
    traceroute_run
)
app.command(name="banner", help="Grab service banners from open ports.")(
    banner_grab_run
)
app.command(name="ssl", help="Check SSL/TLS certificates and configuration.")(
    ssl_checker_run
)
app.command(name="whois", help="Look up domain or IP registration info.")(
    whois_lookup_run
)
app.command(name="headers", help="Inspect HTTP security headers on a URL.")(
    header_inspector_run
)
app.command(name="pcap", help="Read and summarize packet capture files.")(
    pcap_viewer_run
)
app.command(name="logs", help="Parse security logs for suspicious activity.")(
    log_parser_run
)
app.command(name="subnet", help="Calculate subnet ranges and host counts.")(
    subnet_calc_run
)
