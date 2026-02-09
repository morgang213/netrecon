"""Tests for banner grabber."""

from unittest.mock import MagicMock, patch

from netrecon.tools.banner_grab import grab_banner


class TestGrabBanner:
    @patch("netrecon.tools.banner_grab.socket.socket")
    def test_banner_received(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.9\r\n"
        mock_socket_class.return_value.__enter__ = lambda s: mock_sock
        mock_socket_class.return_value.__exit__ = MagicMock(return_value=False)

        port, banner = grab_banner("127.0.0.1", 22, 3.0)
        assert port == 22
        assert "SSH" in banner

    @patch("netrecon.tools.banner_grab.socket.socket")
    def test_no_banner(self, mock_socket_class):

        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError()
        mock_socket_class.return_value.__enter__ = lambda s: mock_sock
        mock_socket_class.return_value.__exit__ = MagicMock(return_value=False)

        port, banner = grab_banner("127.0.0.1", 9999, 3.0)
        assert port == 9999
        assert banner == ""


class TestBannerGrabCLI:
    def test_help(self, runner, cli_app):
        result = runner.invoke(cli_app, ["banner", "--help"])
        assert result.exit_code == 0
        assert "Target host" in result.output
