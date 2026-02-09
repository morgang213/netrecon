"""DNS Lookup - Query DNS records for a domain."""

from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from netrecon.explain import show_explanation
from netrecon.warnings import confirm_active_use

console = Console()
TOOL_NAME = "dns_lookup"

RECORD_DESCRIPTIONS: dict[str, str] = {
    "A": "IPv4 address - where the domain points",
    "AAAA": "IPv6 address - modern IP addressing",
    "MX": "Mail server - handles email for this domain",
    "NS": "Name server - authoritative DNS server for this domain",
    "TXT": "Text record - often used for email security (SPF, DKIM)",
    "CNAME": "Alias - this domain is an alias for another domain",
    "SOA": "Start of Authority - primary DNS info for the zone",
    "SRV": "Service record - locates servers for specific services",
    "PTR": "Pointer - maps IP address back to a domain (reverse DNS)",
}


def query_dns(
    domain: str, record_types: list[str], server: Optional[str] = None
) -> dict[str, list[str]]:
    """Query DNS records for a domain. Returns {record_type: [values]}."""
    import dns.resolver

    results: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver()

    if server:
        resolver.nameservers = [server]

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            values = []
            for rdata in answers:
                if rtype == "MX":
                    values.append(f"{rdata.preference} {rdata.exchange}")
                elif rtype == "SOA":
                    values.append(
                        f"Primary NS: {rdata.mname}, "
                        f"Contact: {rdata.rname}, "
                        f"Serial: {rdata.serial}"
                    )
                else:
                    values.append(str(rdata))
            results[rtype] = values
        except dns.resolver.NoAnswer:
            results[rtype] = []
        except dns.resolver.NXDOMAIN:
            console.print(f"[red][!] Domain not found: {domain}[/red]")
            raise typer.Exit(code=1) from None
        except dns.resolver.NoNameservers:
            console.print(f"[red][!] No name servers available for {domain}[/red]")
            raise typer.Exit(code=1) from None
        except Exception as e:
            results[rtype] = [f"Error: {e}"]

    return results


def display_results(domain: str, results: dict[str, list[str]]) -> None:
    """Display DNS query results."""
    table = Table(title=f"DNS Records for {domain}", border_style="cyan")
    table.add_column("Type", style="bold cyan", min_width=8)
    table.add_column("Value", min_width=30)
    table.add_column("Description", style="dim")

    for rtype, values in results.items():
        desc = RECORD_DESCRIPTIONS.get(rtype, "")
        if not values:
            table.add_row(rtype, "[dim]No records found[/dim]", desc)
        else:
            for i, value in enumerate(values):
                table.add_row(rtype if i == 0 else "", value, desc if i == 0 else "")

    console.print()
    console.print(table)
    console.print()


def run(
    domain: str = typer.Argument(
        ..., help="Domain name to look up (e.g., example.com)"
    ),
    record_type: str = typer.Option(
        "A,AAAA,MX,NS,TXT",
        "--type",
        "-r",
        help="Record types to query (comma-separated: A,AAAA,MX,NS,TXT,CNAME,SOA)",
    ),
    server: Optional[str] = typer.Option(
        None, "--server", "-s", help="DNS server to query (e.g., 8.8.8.8)"
    ),
    explain: bool = typer.Option(
        False, "--explain", "-e", help="Show beginner-friendly explanation"
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip authorization confirmation"
    ),
) -> None:
    """Look up DNS records for a domain."""
    if explain:
        show_explanation(TOOL_NAME)

    if not yes:
        confirm_active_use()

    record_types = [r.strip().upper() for r in record_type.split(",")]

    console.print(
        f"\n[bold]Querying DNS records for {domain}...[/bold] "
        f"(types: {', '.join(record_types)})"
    )

    results = query_dns(domain, record_types, server)
    display_results(domain, results)
