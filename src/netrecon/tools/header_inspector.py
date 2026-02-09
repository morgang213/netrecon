"""HTTP Header Inspector - Analyze HTTP security headers."""

import typer
from rich.console import Console
from rich.table import Table

from netrecon.explain import show_explanation

console = Console()
TOOL_NAME = "header_inspector"

# Security headers to check and their descriptions
SECURITY_HEADERS: dict[str, dict[str, str]] = {
    "strict-transport-security": {
        "name": "Strict-Transport-Security (HSTS)",
        "desc": "Forces browsers to use HTTPS only",
        "severity": "high",
    },
    "content-security-policy": {
        "name": "Content-Security-Policy (CSP)",
        "desc": "Controls which resources the browser can load",
        "severity": "high",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "desc": (
            "Prevents the page from being embedded in frames"
            " (clickjacking protection)"
        ),
        "severity": "medium",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "desc": "Prevents browsers from guessing (MIME-sniffing) content types",
        "severity": "medium",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "desc": "Controls how much referrer info is sent with requests",
        "severity": "low",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "desc": "Controls which browser features the page can use (camera, mic, etc.)",
        "severity": "low",
    },
    "x-xss-protection": {
        "name": "X-XSS-Protection",
        "desc": "Legacy XSS filter (mostly replaced by CSP)",
        "severity": "low",
    },
}


def fetch_headers(url: str, follow_redirects: bool = True) -> dict:
    """Fetch HTTP headers from a URL. Returns {header: value} dict."""
    import httpx

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    try:
        with httpx.Client(follow_redirects=follow_redirects, timeout=10) as client:
            response = client.head(url)
            return {
                "status_code": response.status_code,
                "url": str(response.url),
                "headers": dict(response.headers),
            }
    except httpx.ConnectError:
        console.print(f"[red][!] Could not connect to {url}[/red]")
        raise typer.Exit(code=1) from None
    except httpx.TimeoutException:
        console.print(f"[red][!] Connection timed out: {url}[/red]")
        raise typer.Exit(code=1) from None
    except Exception as e:
        console.print(f"[red][!] Error fetching headers: {e}[/red]")
        raise typer.Exit(code=1) from None


def analyze_security_headers(headers: dict[str, str]) -> list[dict]:
    """Analyze response headers for security. Returns list of findings."""
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    for header_key, info in SECURITY_HEADERS.items():
        value = headers_lower.get(header_key)
        findings.append(
            {
                "header": info["name"],
                "present": value is not None,
                "value": value or "",
                "desc": info["desc"],
                "severity": info["severity"],
            }
        )

    return findings


def display_results(
    url: str, status_code: int, findings: list[dict], headers: dict[str, str]
) -> None:
    """Display header inspection results."""
    # All headers table
    all_table = Table(title=f"HTTP Headers: {url} ({status_code})", border_style="cyan")
    all_table.add_column("Header", style="bold", min_width=25)
    all_table.add_column("Value", max_width=60)

    for key, value in sorted(headers.items()):
        all_table.add_row(key, value[:120])

    console.print()
    console.print(all_table)

    # Security analysis table
    sec_table = Table(title="Security Header Analysis", border_style="cyan")
    sec_table.add_column("Header", style="bold", min_width=35)
    sec_table.add_column("Status", min_width=10)
    sec_table.add_column("Description", style="dim")

    present_count = 0
    for finding in findings:
        if finding["present"]:
            present_count += 1
            status = "[green]Present[/green]"
        else:
            severity_color = {
                "high": "red",
                "medium": "yellow",
                "low": "dim",
            }.get(finding["severity"], "white")
            status = f"[{severity_color}]Missing[/{severity_color}]"

        sec_table.add_row(finding["header"], status, finding["desc"])

    console.print()
    console.print(sec_table)

    total = len(findings)
    score = f"{present_count}/{total}"
    console.print(f"\nSecurity headers score: [bold]{score}[/bold]")

    if present_count == total:
        console.print("[green]All recommended security headers are present.[/green]")
    elif present_count >= total - 2:
        console.print(
            "[yellow]Most security headers present."
            " Consider adding the missing ones.[/yellow]"
        )
    else:
        console.print(
            "[red]Several security headers are missing."
            " This may leave users vulnerable.[/red]"
        )
    console.print()


def run(
    url: str = typer.Argument(..., help="URL to inspect (e.g., example.com)"),
    explain: bool = typer.Option(
        False, "--explain", "-e", help="Show beginner-friendly explanation"
    ),
) -> None:
    """Inspect HTTP security headers on a website."""
    if explain:
        show_explanation(TOOL_NAME)

    console.print(f"\n[bold]Inspecting headers for {url}...[/bold]")

    result = fetch_headers(url)
    findings = analyze_security_headers(result["headers"])
    display_results(result["url"], result["status_code"], findings, result["headers"])
