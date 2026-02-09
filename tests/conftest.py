"""Shared test fixtures for NetRecon."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from netrecon.cli import app


@pytest.fixture
def runner():
    """Typer CLI test runner."""
    return CliRunner()


@pytest.fixture
def cli_app():
    """The main Typer app."""
    return app


@pytest.fixture
def sample_auth_log():
    """Path to sample auth log."""
    return str(Path(__file__).parent.parent / "examples" / "sample_auth.log")


@pytest.fixture
def sample_access_log():
    """Path to sample HTTP access log."""
    return str(Path(__file__).parent.parent / "examples" / "sample_access.log")
