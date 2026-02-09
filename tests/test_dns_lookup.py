"""Tests for DNS lookup."""

from unittest.mock import MagicMock, patch

from netrecon.tools.dns_lookup import query_dns


class TestQueryDns:
    @patch("dns.resolver.Resolver")
    def test_a_record(self, mock_resolver_cls):
        mock_resolver = MagicMock()
        mock_answer = MagicMock()
        mock_answer.__iter__ = lambda self: iter(
            [MagicMock(__str__=lambda s: "93.184.216.34")]
        )
        mock_resolver.resolve.return_value = mock_answer
        mock_resolver_cls.return_value = mock_resolver

        results = query_dns("example.com", ["A"])
        assert "A" in results
        assert len(results["A"]) == 1
        assert "93.184.216.34" in results["A"][0]


class TestDnsLookupCLI:
    def test_help(self, runner, cli_app):
        result = runner.invoke(cli_app, ["dns", "--help"])
        assert result.exit_code == 0
        assert "Domain name" in result.output

    def test_authorization_prompt_decline(self, runner, cli_app):
        result = runner.invoke(cli_app, ["dns", "example.com"], input="n\n")
        assert "AUTHORIZATION WARNING" in result.output
