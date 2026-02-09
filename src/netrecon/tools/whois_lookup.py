"""WHOIS Lookup - Look up domain or IP registration information."""


import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from netrecon.explain import show_explanation

console = Console()
TOOL_NAME = "whois_lookup"


def query_whois(target: str) -> dict:
    """Query WHOIS information for a domain or IP. Returns parsed dict."""
    import whois

    try:
        w = whois.whois(target)
    except Exception as e:
        console.print(f"[red][!] WHOIS lookup failed: {e}[/red]")
        raise typer.Exit(code=1) from None

    result = {}

    def _first(val):
        if isinstance(val, list):
            return val[0] if val else None
        return val

    result["domain"] = _first(w.domain_name) or target
    result["registrar"] = w.registrar or "N/A"
    result["creation_date"] = str(_first(w.creation_date) or "N/A")
    result["expiration_date"] = str(_first(w.expiration_date) or "N/A")
    result["updated_date"] = str(_first(w.updated_date) or "N/A")
    result["name_servers"] = w.name_servers or []
    result["status"] = (
        w.status if isinstance(w.status, list) else ([w.status] if w.status else [])
    )
    result["org"] = w.org or "N/A"
    result["country"] = w.country or "N/A"
    result["emails"] = (
        w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else [])
    )

    return result


def display_results(info: dict) -> None:
    """Display WHOIS results."""
    table = Table(border_style="cyan", show_header=False, padding=(0, 2))
    table.add_column("Field", style="bold cyan", min_width=20)
    table.add_column("Value", style="white")

    table.add_row("Domain", str(info["domain"]))
    table.add_row("Registrar", info["registrar"])
    table.add_row("Organization", info["org"])
    table.add_row("Country", info["country"])
    table.add_row("Created", info["creation_date"])
    table.add_row("Expires", info["expiration_date"])
    table.add_row("Last Updated", info["updated_date"])

    if info["name_servers"]:
        ns_list = "\n".join(str(ns) for ns in info["name_servers"][:5])
        table.add_row("Name Servers", ns_list)

    if info["emails"]:
        table.add_row("Contact Emails", "\n".join(str(e) for e in info["emails"]))

    if info["status"]:
        statuses = "\n".join(str(s).split(" ")[0] for s in info["status"][:5])
        table.add_row("Status", statuses)

    console.print()
    console.print(
        Panel(table, title="[bold]WHOIS Information[/bold]", border_style="cyan")
    )
    console.print()


def run(
    target: str = typer.Argument(..., help="Domain name or IP address to look up"),
    explain: bool = typer.Option(
        False, "--explain", "-e", help="Show beginner-friendly explanation"
    ),
) -> None:
    """Look up domain or IP registration information via WHOIS."""
    if explain:
        show_explanation(TOOL_NAME)

    console.print(f"\n[bold]Looking up WHOIS info for {target}...[/bold]")

    info = query_whois(target)
    display_results(info)
