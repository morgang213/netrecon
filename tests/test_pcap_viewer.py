"""Tests for PCAP viewer."""



class TestPcapViewerCLI:
    def test_help(self, runner, cli_app):
        result = runner.invoke(cli_app, ["pcap", "--help"])
        assert result.exit_code == 0
        assert "pcap" in result.output.lower()

    def test_missing_file(self, runner, cli_app):
        result = runner.invoke(cli_app, ["pcap", "/nonexistent/file.pcap"])
        assert result.exit_code == 1
        assert "not found" in result.output.lower()
