"""HTTP Fuzzer - Discover hidden directories and files on web servers."""

import httpx
import typer
from rich.console import Console
from rich.progress import Progress
from rich.table import Table

from netrecon.explain import show_explanation
from netrecon.warnings import confirm_active_use

console = Console()
TOOL_NAME = "http_fuzzer"

# Common directory/file names for fuzzing
DEFAULT_WORDLIST = [
    "admin",
    "administrator",
    "api",
    "backup",
    "config",
    "data",
    "debug",
    "dev",
    "login",
    "old",
    "test",
    "tmp",
    "upload",
    "uploads",
    ".git",
    ".env",
    ".htaccess",
    "robots.txt",
    "sitemap.xml",
    "phpmyadmin",
    "wp-admin",
    "wp-content",
    "index.php",
    "admin.php",
    "config.php",
]


def fuzz_url(
    base_url: str, wordlist: list[str], timeout: float, show_404: bool
) -> dict[str, tuple[int, int]]:
    """
    Fuzz a URL with a wordlist.
    Returns {path: (status_code, content_length)}.
    """
    results: dict[str, tuple[int, int]] = {}

    # Ensure base_url starts with http:// or https://
    if not base_url.startswith(("http://", "https://")):
        base_url = f"http://{base_url}"

    # Remove trailing slash
    base_url = base_url.rstrip("/")

    with Progress(console=console) as progress:
        task = progress.add_task("[cyan]Fuzzing...", total=len(wordlist))

        for path in wordlist:
            url = f"{base_url}/{path}"
            try:
                with httpx.Client(verify=False, follow_redirects=False) as client:
                    response = client.get(url, timeout=timeout)
                    status = response.status_code
                    length = len(response.content)

                    # Store results for non-404 or if show_404 is True
                    if show_404 or status != 404:
                        results[path] = (status, length)

            except httpx.TimeoutException:
                results[path] = (0, 0)  # Timeout
            except httpx.ConnectError:
                results[path] = (-1, 0)  # Connection error
            except Exception:
                pass  # Silently skip other errors

            progress.update(task, advance=1)

    return results


def display_results(base_url: str, results: dict[str, tuple[int, int]]) -> None:
    """Display fuzzing results."""
    if not results:
        console.print(
            f"\n[yellow]No accessible paths found on {base_url}.[/yellow]\n"
        )
        return

    table = Table(title=f"HTTP Fuzzing Results: {base_url}", border_style="cyan")
    table.add_column("Path", style="bold", min_width=20)
    table.add_column("Status", min_width=10)
    table.add_column("Size", min_width=10)
    table.add_column("Notes", style="dim")

    # Sort by status code (interesting ones first)
    sorted_results = sorted(
        results.items(), key=lambda x: (x[1][0] == 404, x[1][0], x[0])
    )

    for path, (status, length) in sorted_results:
        # Colorize status codes
        if status == 200:
            status_display = "[green]200 OK[/green]"
            notes = "Found!"
        elif status == 301:
            status_display = "[yellow]301 Redirect[/yellow]"
            notes = "Moved"
        elif status == 302:
            status_display = "[yellow]302 Redirect[/yellow]"
            notes = "Redirect"
        elif status == 403:
            status_display = "[red]403 Forbidden[/red]"
            notes = "Exists but forbidden"
        elif status == 401:
            status_display = "[yellow]401 Unauthorized[/yellow]"
            notes = "Requires auth"
        elif status == 404:
            status_display = "[dim]404 Not Found[/dim]"
            notes = "Not found"
        elif status == 0:
            status_display = "[red]Timeout[/red]"
            notes = "Request timed out"
        elif status == -1:
            status_display = "[red]Error[/red]"
            notes = "Connection failed"
        else:
            status_display = f"[blue]{status}[/blue]"
            notes = ""

        size_display = f"{length} bytes" if length > 0 else "-"
        table.add_row(f"/{path}", status_display, size_display, notes)

    console.print()
    console.print(table)

    # Summary
    found = sum(1 for s, _ in results.values() if 200 <= s < 400)
    forbidden = sum(1 for s, _ in results.values() if s == 403)
    console.print(
        f"\n[bold]Summary:[/bold] {found} accessible, "
        f"{forbidden} forbidden out of {len(results)} paths checked\n"
    )


def run(
    target: str = typer.Argument(..., help="Target URL (e.g., example.com or http://example.com)"),
    wordlist_file: str = typer.Option(
        None,
        "--wordlist",
        "-w",
        help="Path to custom wordlist file (one path per line)",
    ),
    timeout: float = typer.Option(
        5.0, "--timeout", "-t", help="Request timeout in seconds"
    ),
    show_404: bool = typer.Option(
        False, "--show-404", help="Show 404 Not Found results"
    ),
    explain: bool = typer.Option(
        False, "--explain", "-e", help="Show beginner-friendly explanation"
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip authorization confirmation"
    ),
) -> None:
    """Discover hidden directories and files on web servers using fuzzing."""
    if explain:
        show_explanation(TOOL_NAME)

    if not yes:
        confirm_active_use()

    # Load wordlist
    if wordlist_file:
        try:
            with open(wordlist_file) as f:
                wordlist = [line.strip() for line in f if line.strip()]
            console.print(
                f"[dim]Loaded {len(wordlist)} paths from {wordlist_file}[/dim]"
            )
        except FileNotFoundError:
            console.print(
                f"[red]Error: Wordlist file '{wordlist_file}' not found.[/red]"
            )
            raise typer.Exit(1) from None
    else:
        wordlist = DEFAULT_WORDLIST
        console.print(f"[dim]Using built-in wordlist ({len(wordlist)} paths)[/dim]")

    console.print(f"\n[bold]Fuzzing {target}...[/bold]\n")

    results = fuzz_url(target, wordlist, timeout, show_404)
    display_results(target, results)
