"""Tests for Vulnerability Scanner tool."""

from typer.testing import CliRunner

from netrecon.cli import app

runner = CliRunner()


def test_vuln_scanner_help():
    """Test that vulnerability scanner help works."""
    result = runner.invoke(app, ["vulnscan", "--help"])
    assert result.exit_code == 0
    assert "vulnerabilit" in result.stdout.lower()


def test_vuln_scanner_explain():
    """Test vulnerability scanner explanation."""
    result = runner.invoke(app, ["vulnscan", "example.com", "--explain", "--yes"])
    assert result.exit_code == 0
    assert (
        "vulnerabilit" in result.stdout.lower()
        or "scanning" in result.stdout.lower()
    )


def test_vuln_scanner_requires_target():
    """Test that vulnerability scanner requires target argument."""
    result = runner.invoke(app, ["vulnscan"])
    assert result.exit_code != 0
