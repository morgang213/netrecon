"""Authorization warnings for active network tools."""

import typer
from rich.console import Console
from rich.panel import Panel

console = Console()

ACTIVE_WARNING = (
    "[bold red]AUTHORIZATION WARNING[/bold red]\n\n"
    "This tool sends network traffic to the target system.\n"
    "Only use against systems you [bold]own[/bold] or have "
    "[bold]explicit written permission[/bold] to test.\n\n"
    "Unauthorized scanning may violate laws in your jurisdiction."
)


def confirm_active_use() -> None:
    """Display warning and require confirmation for active tools."""
    console.print()
    console.print(Panel(ACTIVE_WARNING, border_style="red", title="[red]Warning[/red]"))
    if not typer.confirm("Do you have authorization to proceed?"):
        console.print("[yellow]Scan cancelled.[/yellow]")
        raise typer.Exit(code=0)
