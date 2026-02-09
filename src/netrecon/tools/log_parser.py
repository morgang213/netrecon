"""Log Parser - Parse security logs for suspicious activity."""

import re
from collections import Counter
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from netrecon.explain import show_explanation

console = Console()
TOOL_NAME = "log_parser"

# Patterns for detecting suspicious activity
FAILED_LOGIN_PATTERNS = [
    re.compile(
        r"Failed password for (?:invalid user )?(\S+) from (\S+)", re.IGNORECASE
    ),
    re.compile(r"authentication failure.*rhost=(\S+).*user=(\S+)", re.IGNORECASE),
    re.compile(r"Invalid user (\S+) from (\S+)", re.IGNORECASE),
]

AUTH_SUCCESS_PATTERNS = [
    re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+)", re.IGNORECASE),
    re.compile(r"session opened for user (\S+)", re.IGNORECASE),
]

HTTP_LOG_PATTERN = re.compile(
    r'(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+|-)'
)

SUSPICIOUS_PATHS = [
    "/admin",
    "/wp-admin",
    "/wp-login",
    "/phpmyadmin",
    "/manager",
    "/.env",
    "/config",
    "/backup",
    "/shell",
    "/cmd",
    "/exec",
    "/../",
]


def parse_auth_log(filepath: str) -> dict:
    """Parse an authentication log file. Returns analysis results."""
    path = Path(filepath)
    if not path.exists():
        console.print(f"[red][!] File not found: {filepath}[/red]")
        raise typer.Exit(code=1)

    failed_logins: list[tuple[str, str]] = []  # (user, ip)
    successful_logins: list[tuple[str, str]] = []
    failed_ips = Counter()
    failed_users = Counter()
    total_lines = 0

    with open(path) as f:
        for line in f:
            total_lines += 1

            for pattern in FAILED_LOGIN_PATTERNS:
                match = pattern.search(line)
                if match:
                    groups = match.groups()
                    # Pattern order varies: some have (user, ip), some have (ip, user)
                    if re.match(r"\d+\.\d+\.\d+\.\d+", groups[0]):
                        ip, user = (
                            groups[0],
                            groups[1] if len(groups) > 1 else "unknown",
                        )
                    else:
                        user, ip = (
                            groups[0],
                            groups[1] if len(groups) > 1 else "unknown",
                        )

                    failed_logins.append((user, ip))
                    failed_ips[ip] += 1
                    failed_users[user] += 1
                    break

            for pattern in AUTH_SUCCESS_PATTERNS:
                match = pattern.search(line)
                if match:
                    groups = match.groups()
                    user = groups[0]
                    ip = groups[1] if len(groups) > 1 else "local"
                    successful_logins.append((user, ip))
                    break

    # Detect brute force: IPs with >= 10 failed attempts
    brute_force_ips = {ip: count for ip, count in failed_ips.items() if count >= 10}

    return {
        "log_type": "auth",
        "total_lines": total_lines,
        "failed_logins": len(failed_logins),
        "successful_logins": len(successful_logins),
        "top_failed_ips": failed_ips.most_common(10),
        "top_failed_users": failed_users.most_common(10),
        "brute_force_ips": brute_force_ips,
    }


def parse_http_log(filepath: str) -> dict:
    """Parse an HTTP access log file. Returns analysis results."""
    path = Path(filepath)
    if not path.exists():
        console.print(f"[red][!] File not found: {filepath}[/red]")
        raise typer.Exit(code=1)

    total_lines = 0
    ips = Counter()
    status_codes = Counter()
    paths_accessed = Counter()
    suspicious_requests: list[tuple[str, str, int]] = []  # (ip, path, status)

    with open(path) as f:
        for line in f:
            total_lines += 1
            match = HTTP_LOG_PATTERN.match(line)
            if not match:
                continue

            ip, _date, method, req_path, status, _size = match.groups()
            status_code = int(status)

            ips[ip] += 1
            status_codes[status_code] += 1
            paths_accessed[req_path] += 1

            # Check for suspicious paths
            path_lower = req_path.lower()
            for sus_path in SUSPICIOUS_PATHS:
                if sus_path in path_lower:
                    suspicious_requests.append((ip, req_path, status_code))
                    break

    return {
        "log_type": "http",
        "total_lines": total_lines,
        "total_requests": sum(ips.values()),
        "unique_ips": len(ips),
        "top_ips": ips.most_common(10),
        "status_codes": status_codes.most_common(),
        "top_paths": paths_accessed.most_common(10),
        "suspicious_requests": suspicious_requests[:20],
    }


def detect_log_type(filepath: str) -> str:
    """Detect log type by examining content."""
    path = Path(filepath)
    with open(path) as f:
        sample = f.read(4096)

    if any(
        kw in sample.lower()
        for kw in ["sshd", "failed password", "pam_unix", "session opened"]
    ):
        return "auth"
    if HTTP_LOG_PATTERN.search(sample):
        return "http"
    return "unknown"


def display_auth_results(info: dict) -> None:
    """Display auth log analysis."""
    console.print(f"\n[bold]Lines parsed:[/bold] {info['total_lines']:,}")
    console.print(f"[bold]Failed logins:[/bold] [red]{info['failed_logins']:,}[/red]")
    console.print(
        f"[bold]Successful logins:[/bold] [green]{info['successful_logins']:,}[/green]"
    )

    # Brute force alerts
    if info["brute_force_ips"]:
        console.print(
            f"\n[bold red]Potential brute-force detected from "
            f"{len(info['brute_force_ips'])} IP(s):[/bold red]"
        )
        for ip, count in sorted(info["brute_force_ips"].items(), key=lambda x: -x[1]):
            console.print(f"  [red]{ip}[/red] - {count} failed attempts")

    # Top failed IPs
    if info["top_failed_ips"]:
        table = Table(title="Top Sources of Failed Logins", border_style="cyan")
        table.add_column("IP Address", style="bold", min_width=18)
        table.add_column("Failed Attempts", min_width=15, justify="right")
        table.add_column("Risk", min_width=10)

        for ip, count in info["top_failed_ips"]:
            risk = (
                "[red]HIGH[/red]"
                if count >= 10
                else "[yellow]MEDIUM[/yellow]"
                if count >= 5
                else "[green]LOW[/green]"
            )
            table.add_row(ip, str(count), risk)

        console.print()
        console.print(table)

    # Top targeted users
    if info["top_failed_users"]:
        table = Table(title="Most Targeted Usernames", border_style="cyan")
        table.add_column("Username", style="bold", min_width=15)
        table.add_column("Failed Attempts", min_width=15, justify="right")

        for user, count in info["top_failed_users"]:
            table.add_row(user, str(count))

        console.print()
        console.print(table)

    console.print()


def display_http_results(info: dict) -> None:
    """Display HTTP log analysis."""
    console.print(f"\n[bold]Total requests:[/bold] {info['total_requests']:,}")
    console.print(f"[bold]Unique IPs:[/bold] {info['unique_ips']:,}")

    # Status code breakdown
    if info["status_codes"]:
        table = Table(title="HTTP Status Codes", border_style="cyan")
        table.add_column("Status", style="bold", min_width=10)
        table.add_column("Count", min_width=10, justify="right")
        table.add_column("Meaning", style="dim")

        status_meanings = {
            200: "OK",
            301: "Moved Permanently",
            302: "Found (Redirect)",
            304: "Not Modified",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            500: "Internal Server Error",
            502: "Bad Gateway",
            503: "Service Unavailable",
        }

        for code, count in info["status_codes"]:
            meaning = status_meanings.get(code, "")
            color = "green" if code < 400 else "yellow" if code < 500 else "red"
            table.add_row(f"[{color}]{code}[/{color}]", f"{count:,}", meaning)

        console.print()
        console.print(table)

    # Suspicious requests
    if info["suspicious_requests"]:
        console.print(
            f"\n[bold yellow]Suspicious requests detected: "
            f"{len(info['suspicious_requests'])}[/bold yellow]"
        )
        table = Table(
            title="Suspicious Requests (Reconnaissance)", border_style="yellow"
        )
        table.add_column("IP", style="bold", min_width=18)
        table.add_column("Path", min_width=30)
        table.add_column("Status", min_width=8)

        for ip, path, status in info["suspicious_requests"][:10]:
            table.add_row(ip, path, str(status))

        console.print()
        console.print(table)

    # Top IPs
    if info["top_ips"]:
        table = Table(title="Top Requesting IPs", border_style="cyan")
        table.add_column("IP Address", style="bold", min_width=18)
        table.add_column("Requests", min_width=10, justify="right")

        for ip, count in info["top_ips"][:5]:
            table.add_row(ip, f"{count:,}")

        console.print()
        console.print(table)

    console.print()


def run(
    filepath: str = typer.Argument(..., help="Path to log file"),
    log_type: str = typer.Option(
        "auto",
        "--type",
        "-r",
        help="Log type: auto, auth, or http",
    ),
    explain: bool = typer.Option(
        False, "--explain", "-e", help="Show beginner-friendly explanation"
    ),
) -> None:
    """Parse security logs for suspicious activity."""
    if explain:
        show_explanation(TOOL_NAME)

    path = Path(filepath)
    if not path.exists():
        console.print(f"[red][!] File not found: {filepath}[/red]")
        raise typer.Exit(code=1)

    if log_type == "auto":
        log_type = detect_log_type(filepath)
        if log_type == "unknown":
            console.print(
                "[yellow][!] Could not auto-detect log type. "
                "Use --type auth or --type http.[/yellow]"
            )
            raise typer.Exit(code=1)
        console.print(f"[dim]Auto-detected log type: {log_type}[/dim]")

    console.print(f"\n[bold]Parsing {path.name}...[/bold]")

    if log_type == "auth":
        info = parse_auth_log(filepath)
        display_auth_results(info)
    elif log_type == "http":
        info = parse_http_log(filepath)
        display_http_results(info)
    else:
        console.print(f"[red][!] Unknown log type: {log_type}[/red]")
        raise typer.Exit(code=1)
