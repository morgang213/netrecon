"""Tests for HTTP Fuzzer tool."""

from typer.testing import CliRunner

from netrecon.cli import app

runner = CliRunner()


def test_http_fuzzer_help():
    """Test that fuzzer help works."""
    result = runner.invoke(app, ["fuzz", "--help"])
    assert result.exit_code == 0
    assert "Discover hidden directories" in result.stdout


def test_http_fuzzer_explain():
    """Test fuzzer explanation."""
    result = runner.invoke(app, ["fuzz", "example.com", "--explain", "--yes"])
    assert result.exit_code == 0
    assert "fuzzing" in result.stdout.lower() or "Fuzzing" in result.stdout


def test_http_fuzzer_requires_target():
    """Test that fuzzer requires target argument."""
    result = runner.invoke(app, ["fuzz"])
    assert result.exit_code != 0


def test_http_fuzzer_wordlist_not_found():
    """Test error handling for missing wordlist file."""
    result = runner.invoke(
        app,
        ["fuzz", "example.com", "--wordlist", "/nonexistent/wordlist.txt", "--yes"],
    )
    assert result.exit_code == 1
    assert (
        "not found" in result.stdout.lower() or "error" in result.stdout.lower()
    )
