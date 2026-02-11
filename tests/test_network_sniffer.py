"""Tests for Network Sniffer tool."""

from typer.testing import CliRunner

from netrecon.cli import app

runner = CliRunner()


def test_network_sniffer_help():
    """Test that network sniffer help works."""
    result = runner.invoke(app, ["sniff", "--help"])
    assert result.exit_code == 0
    assert "network" in result.stdout.lower() or "traffic" in result.stdout.lower()


def test_network_sniffer_explain():
    """Test network sniffer explanation."""
    result = runner.invoke(app, ["sniff", "--explain", "--count", "0", "--yes"])
    # Should show explanation and exit
    assert "sniff" in result.stdout.lower() or "packet" in result.stdout.lower()
