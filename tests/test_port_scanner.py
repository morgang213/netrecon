"""Tests for port scanner."""

from unittest.mock import MagicMock, patch

from netrecon.tools.port_scanner import scan_port, scan_ports


class TestScanPort:
    @patch("netrecon.tools.port_scanner.socket.socket")
    def test_open_port(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_class.return_value.__enter__ = lambda s: mock_sock
        mock_socket_class.return_value.__exit__ = MagicMock(return_value=False)

        port, state = scan_port("127.0.0.1", 80, 1.0)
        assert port == 80
        assert state == "open"

    @patch("netrecon.tools.port_scanner.socket.socket")
    def test_closed_port(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 111
        mock_socket_class.return_value.__enter__ = lambda s: mock_sock
        mock_socket_class.return_value.__exit__ = MagicMock(return_value=False)

        port, state = scan_port("127.0.0.1", 80, 1.0)
        assert port == 80
        assert state == "closed"


class TestScanPorts:
    @patch("netrecon.tools.port_scanner.scan_port")
    def test_multiple_ports(self, mock_scan_port):
        mock_scan_port.side_effect = [
            (22, "open"),
            (80, "open"),
            (443, "closed"),
        ]
        results = scan_ports("127.0.0.1", [22, 80, 443], 1.0, 3)
        assert results[22] == "open"
        assert results[80] == "open"
        assert results[443] == "closed"


class TestPortScannerCLI:
    def test_help(self, runner, cli_app):
        result = runner.invoke(cli_app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "Target host" in result.output

    @patch("netrecon.tools.port_scanner.scan_ports")
    @patch("netrecon.tools.port_scanner.validate_host", return_value="127.0.0.1")
    def test_scan_with_yes(self, mock_validate, mock_scan, runner, cli_app):
        mock_scan.return_value = {80: "open", 443: "closed"}
        result = runner.invoke(cli_app, ["scan", "127.0.0.1", "-p", "80,443", "--yes"])
        assert result.exit_code == 0

    def test_authorization_prompt_decline(self, runner, cli_app):
        result = runner.invoke(cli_app, ["scan", "127.0.0.1"], input="n\n")
        assert "AUTHORIZATION WARNING" in result.output
