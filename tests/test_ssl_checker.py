"""Tests for SSL/TLS checker."""

from unittest.mock import MagicMock, patch

from netrecon.tools.ssl_checker import check_ssl


class TestCheckSsl:
    @patch("netrecon.tools.ssl_checker.ssl.create_default_context")
    @patch("netrecon.tools.ssl_checker.socket.create_connection")
    def test_valid_cert(self, mock_conn, mock_ctx):
        mock_ssock = MagicMock()
        mock_ssock.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": (
                (("commonName", "Test CA"),),
                (("organizationName", "Test Org"),),
            ),
            "notBefore": "Jan  1 00:00:00 2024 GMT",
            "notAfter": "Dec 31 23:59:59 2030 GMT",
            "serialNumber": "ABCDEF1234567890",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "*.example.com")),
        }
        mock_ssock.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_ssock.version.return_value = "TLSv1.3"

        mock_ctx_instance = MagicMock()
        mock_ctx.return_value = mock_ctx_instance
        mock_ctx_instance.wrap_socket.return_value.__enter__ = lambda s: mock_ssock
        mock_ctx_instance.wrap_socket.return_value.__exit__ = MagicMock(
            return_value=False
        )

        mock_sock = MagicMock()
        mock_conn.return_value.__enter__ = lambda s: mock_sock
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        info = check_ssl("example.com", 443, 5.0)
        assert info["subject_cn"] == "example.com"
        assert info["version"] == "TLSv1.3"
        assert "error" not in info

    @patch("netrecon.tools.ssl_checker.ssl.create_default_context")
    @patch("netrecon.tools.ssl_checker.socket.create_connection")
    def test_connection_refused(self, mock_conn, mock_ctx):
        mock_conn.side_effect = ConnectionRefusedError()
        info = check_ssl("example.com", 443, 5.0)
        assert "error" in info


class TestSslCheckerCLI:
    def test_help(self, runner, cli_app):
        result = runner.invoke(cli_app, ["ssl", "--help"])
        assert result.exit_code == 0
        assert "Hostname" in result.output or "hostname" in result.output
