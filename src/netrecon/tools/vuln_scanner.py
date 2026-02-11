"""Vulnerability Scanner - Check for common security vulnerabilities."""

import re
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from netrecon.explain import show_explanation
from netrecon.warnings import confirm_active_use

console = Console()
TOOL_NAME = "vuln_scanner"


class VulnerabilityCheck:
    """Represents a single vulnerability check."""

    def __init__(
        self,
        name: str,
        severity: str,
        description: str,
        check_func: callable,
    ):
        self.name = name
        self.severity = severity
        self.description = description
        self.check_func = check_func


def check_http_methods(url: str, timeout: float) -> Optional[str]:
    """Check for dangerous HTTP methods enabled."""
    try:
        with httpx.Client(verify=False) as client:
            response = client.options(url, timeout=timeout)
            allowed = response.headers.get("Allow", "")

            dangerous = []
            if "PUT" in allowed:
                dangerous.append("PUT")
            if "DELETE" in allowed:
                dangerous.append("DELETE")
            if "TRACE" in allowed:
                dangerous.append("TRACE")

            if dangerous:
                return f"Dangerous methods enabled: {', '.join(dangerous)}"
    except Exception:
        pass
    return None


def check_server_header(url: str, timeout: float) -> Optional[str]:
    """Check for information disclosure in Server header."""
    try:
        with httpx.Client(verify=False) as client:
            response = client.get(url, timeout=timeout)
            server = response.headers.get("Server", "")

            # Check if version info is disclosed
            if server and re.search(r"\d+\.\d+", server):
                return f"Server version disclosed: {server}"
    except Exception:
        pass
    return None


def check_security_headers(url: str, timeout: float) -> Optional[str]:
    """Check for missing security headers."""
    try:
        with httpx.Client(verify=False) as client:
            response = client.get(url, timeout=timeout)
            headers = response.headers

            missing = []
            if "Strict-Transport-Security" not in headers:
                missing.append("HSTS")
            if "X-Frame-Options" not in headers:
                missing.append("X-Frame-Options")
            if "X-Content-Type-Options" not in headers:
                missing.append("X-Content-Type-Options")
            if "Content-Security-Policy" not in headers:
                missing.append("CSP")

            if len(missing) >= 3:
                return f"Missing critical headers: {', '.join(missing)}"
    except Exception:
        pass
    return None


def check_directory_listing(url: str, timeout: float) -> Optional[str]:
    """Check for directory listing enabled."""
    try:
        with httpx.Client(verify=False) as client:
            # Check root
            response = client.get(url, timeout=timeout)
            content = response.text.lower()

            # Common indicators of directory listing
            indicators = [
                "index of /",
                "parent directory",
                "[dir]",
                "<title>directory listing",
            ]

            for indicator in indicators:
                if indicator in content:
                    return "Directory listing may be enabled"
    except Exception:
        pass
    return None


def check_default_credentials(url: str, timeout: float) -> Optional[str]:
    """Check for common default admin paths (indicator only)."""
    try:
        admin_paths = ["/admin", "/administrator", "/phpmyadmin", "/wp-admin"]
        found_paths = []

        with httpx.Client(verify=False, follow_redirects=False) as client:
            for path in admin_paths:
                try:
                    response = client.get(f"{url}{path}", timeout=timeout)
                    if response.status_code in [200, 401, 403]:
                        found_paths.append(path)
                except Exception:
                    continue

        if found_paths:
            return (
                f"Admin panels accessible: {', '.join(found_paths)} "
                "(check default creds)"
            )
    except Exception:
        pass
    return None


def check_robots_txt(url: str, timeout: float) -> Optional[str]:
    """Check robots.txt for sensitive paths."""
    try:
        with httpx.Client(verify=False) as client:
            response = client.get(f"{url}/robots.txt", timeout=timeout)
            if response.status_code == 200:
                content = response.text.lower()
                sensitive = []

                patterns = [
                    (r"admin", "admin"),
                    (r"backup", "backup"),
                    (r"config", "config"),
                    (r"db", "database"),
                    (r"\.git", ".git"),
                ]

                for pattern, name in patterns:
                    if re.search(pattern, content):
                        sensitive.append(name)

                if sensitive:
                    return f"robots.txt reveals sensitive paths: {', '.join(sensitive)}"
    except Exception:
        pass
    return None


def check_ssl_tls(url: str, timeout: float) -> Optional[str]:
    """Check for insecure HTTP (not HTTPS)."""
    if url.startswith("http://") and not url.startswith("http://localhost"):
        return "Site uses insecure HTTP instead of HTTPS"
    return None


# Define vulnerability checks
VULNERABILITY_CHECKS = [
    VulnerabilityCheck(
        "Insecure Transport",
        "HIGH",
        "Site does not use HTTPS encryption",
        check_ssl_tls,
    ),
    VulnerabilityCheck(
        "Missing Security Headers",
        "MEDIUM",
        "Critical security headers not configured",
        check_security_headers,
    ),
    VulnerabilityCheck(
        "Dangerous HTTP Methods",
        "MEDIUM",
        "Potentially dangerous HTTP methods enabled",
        check_http_methods,
    ),
    VulnerabilityCheck(
        "Information Disclosure",
        "LOW",
        "Server version information disclosed",
        check_server_header,
    ),
    VulnerabilityCheck(
        "Directory Listing",
        "MEDIUM",
        "Directory listing may be enabled",
        check_directory_listing,
    ),
    VulnerabilityCheck(
        "Exposed Admin Panels",
        "MEDIUM",
        "Admin panels accessible without protection",
        check_default_credentials,
    ),
    VulnerabilityCheck(
        "robots.txt Disclosure",
        "LOW",
        "Sensitive paths revealed in robots.txt",
        check_robots_txt,
    ),
]


def scan_vulnerabilities(
    url: str, timeout: float
) -> list[tuple[VulnerabilityCheck, str]]:
    """Run all vulnerability checks. Returns list of (check, finding)."""
    findings = []

    # Ensure URL has scheme
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"

    with console.status("[bold cyan]Scanning for vulnerabilities...[/bold cyan]"):
        for check in VULNERABILITY_CHECKS:
            try:
                result = check.check_func(url, timeout)
                if result:
                    findings.append((check, result))
            except Exception:
                pass  # Silently skip failed checks

    return findings


def display_results(url: str, findings: list[tuple[VulnerabilityCheck, str]]) -> None:
    """Display vulnerability scan results."""
    if not findings:
        console.print()
        console.print(
            Panel(
                f"[green]No common vulnerabilities detected on {url}[/green]\n\n"
                "[dim]Note: This is a basic scan. Professional tools like Nessus, "
                "OpenVAS, or Burp Suite provide more comprehensive testing.[/dim]",
                title="[bold green]Scan Complete[/bold green]",
                border_style="green",
            )
        )
        console.print()
        return

    table = Table(title=f"Vulnerability Scan Results: {url}", border_style="red")
    table.add_column("Severity", style="bold", min_width=10)
    table.add_column("Issue", min_width=25)
    table.add_column("Finding", min_width=40)

    # Sort by severity
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_findings = sorted(
        findings, key=lambda x: severity_order.get(x[0].severity, 3)
    )

    high_count = 0
    medium_count = 0
    low_count = 0

    for check, finding in sorted_findings:
        severity = check.severity
        if severity == "HIGH":
            severity_display = "[red bold]HIGH[/red bold]"
            high_count += 1
        elif severity == "MEDIUM":
            severity_display = "[yellow bold]MEDIUM[/yellow bold]"
            medium_count += 1
        else:
            severity_display = "[blue]LOW[/blue]"
            low_count += 1

        table.add_row(severity_display, check.name, finding)

    console.print()
    console.print(table)

    # Summary
    console.print(
        f"\n[bold]Summary:[/bold] "
        f"[red]{high_count} high[/red], "
        f"[yellow]{medium_count} medium[/yellow], "
        f"[blue]{low_count} low[/blue] severity issues found\n"
    )

    console.print(
        "[dim]Recommendation: Address high-severity issues immediately. "
        "Use professional tools for comprehensive assessment.[/dim]\n"
    )


def run(
    target: str = typer.Argument(..., help="Target URL (e.g., example.com or https://example.com)"),
    timeout: float = typer.Option(
        5.0, "--timeout", "-t", help="Request timeout in seconds"
    ),
    explain: bool = typer.Option(
        False, "--explain", "-e", help="Show beginner-friendly explanation"
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip authorization confirmation"
    ),
) -> None:
    """Check web applications for common security vulnerabilities."""
    if explain:
        show_explanation(TOOL_NAME)

    if not yes:
        confirm_active_use()

    console.print(f"\n[bold]Scanning {target} for vulnerabilities...[/bold]\n")

    findings = scan_vulnerabilities(target, timeout)
    display_results(target, findings)
