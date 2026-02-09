"""Tests for traceroute."""

from netrecon.tools.traceroute import parse_traceroute_output


class TestParseTracerouteOutput:
    def test_unix_output(self):
        output = (
            "traceroute to example.com (93.184.216.34),"
            " 30 hops max, 60 byte packets\n"
            " 1  gateway (192.168.1.1)  1.234 ms  1.456 ms  1.789 ms\n"
            " 2  10.0.0.1 (10.0.0.1)  5.123 ms  5.456 ms  5.789 ms\n"
            " 3  * * *\n"
            " 4  93.184.216.34 (93.184.216.34)"
            "  20.123 ms  20.456 ms  20.789 ms"
        )

        hops = parse_traceroute_output(output, "linux")
        assert len(hops) == 4
        assert hops[0]["hop"] == 1
        assert hops[0]["ip"] == "192.168.1.1"
        assert len(hops[0]["rtts"]) == 3
        assert hops[2]["host"] == "*"  # timeout hop

    def test_empty_output(self):
        hops = parse_traceroute_output("", "linux")
        assert hops == []


class TestTracerouteCLI:
    def test_help(self, runner, cli_app):
        result = runner.invoke(cli_app, ["trace", "--help"])
        assert result.exit_code == 0
        assert "Destination" in result.output or "destination" in result.output
