"""Tests for ping sweep."""

from unittest.mock import patch

from netrecon.tools.ping_sweep import ping_host


class TestPingHost:
    @patch("netrecon.tools.ping_sweep.subprocess.run")
    def test_alive_host(self, mock_run):
        mock_run.return_value.returncode = 0
        ip, alive = ping_host("192.168.1.1", timeout=1)
        assert ip == "192.168.1.1"
        assert alive is True

    @patch("netrecon.tools.ping_sweep.subprocess.run")
    def test_dead_host(self, mock_run):
        mock_run.return_value.returncode = 1
        ip, alive = ping_host("192.168.1.1", timeout=1)
        assert ip == "192.168.1.1"
        assert alive is False


class TestPingSweepCLI:
    def test_help(self, runner, cli_app):
        result = runner.invoke(cli_app, ["ping", "--help"])
        assert result.exit_code == 0
        assert "CIDR" in result.output

    def test_authorization_prompt_decline(self, runner, cli_app):
        result = runner.invoke(cli_app, ["ping", "192.168.1.0/24"], input="n\n")
        assert "AUTHORIZATION WARNING" in result.output
