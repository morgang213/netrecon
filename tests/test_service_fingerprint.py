"""Tests for Service Fingerprinting tool."""

from typer.testing import CliRunner

from netrecon.cli import app

runner = CliRunner()


def test_service_fingerprint_help():
    """Test that fingerprinting help works."""
    result = runner.invoke(app, ["fingerprint", "--help"])
    assert result.exit_code == 0
    assert "service" in result.stdout.lower()


def test_service_fingerprint_explain():
    """Test fingerprinting explanation."""
    result = runner.invoke(app, ["fingerprint", "localhost", "--explain", "--yes"])
    assert result.exit_code == 0
    assert "fingerprint" in result.stdout.lower()


def test_service_fingerprint_requires_target():
    """Test that fingerprinting requires target argument."""
    result = runner.invoke(app, ["fingerprint"])
    assert result.exit_code != 0


def test_service_fingerprint_localhost():
    """Test fingerprinting localhost (should complete without error)."""
    result = runner.invoke(
        app, ["fingerprint", "localhost", "--ports", "80", "--timeout", "1", "--yes"]
    )
    assert result.exit_code == 0
