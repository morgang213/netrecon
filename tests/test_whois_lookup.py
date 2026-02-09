"""Tests for WHOIS lookup."""

from unittest.mock import MagicMock, patch


class TestWhoisLookupCLI:
    def test_help(self, runner, cli_app):
        result = runner.invoke(cli_app, ["whois", "--help"])
        assert result.exit_code == 0
        assert "Domain" in result.output or "domain" in result.output

    @patch("whois.whois")
    def test_basic_lookup(self, mock_whois, runner, cli_app):
        mock_result = MagicMock()
        mock_result.domain_name = "EXAMPLE.COM"
        mock_result.registrar = "Test Registrar"
        mock_result.creation_date = "2000-01-01"
        mock_result.expiration_date = "2030-01-01"
        mock_result.updated_date = "2023-01-01"
        mock_result.name_servers = ["ns1.example.com", "ns2.example.com"]
        mock_result.status = "active"
        mock_result.org = "Example Inc"
        mock_result.country = "US"
        mock_result.emails = "admin@example.com"
        mock_whois.return_value = mock_result

        result = runner.invoke(cli_app, ["whois", "example.com"])
        assert result.exit_code == 0
        assert "EXAMPLE.COM" in result.output
