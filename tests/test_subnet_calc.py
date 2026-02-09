"""Tests for subnet calculator."""

import pytest

from netrecon.tools.subnet_calc import calculate_subnet


class TestCalculateSubnet:
    def test_class_c_network(self):
        info = calculate_subnet("192.168.1.0/24")
        assert info["network"] == "192.168.1.0"
        assert info["broadcast"] == "192.168.1.255"
        assert info["netmask"] == "255.255.255.0"
        assert info["prefix_length"] == 24
        assert info["total_addresses"] == 256
        assert info["usable_hosts"] == 254
        assert info["first_host"] == "192.168.1.1"
        assert info["last_host"] == "192.168.1.254"
        assert info["is_private"] is True

    def test_class_b_network(self):
        info = calculate_subnet("172.16.0.0/16")
        assert info["total_addresses"] == 65536
        assert info["usable_hosts"] == 65534

    def test_single_host(self):
        info = calculate_subnet("10.0.0.1/32")
        assert info["total_addresses"] == 1
        assert info["network"] == "10.0.0.1"

    def test_slash_31(self):
        info = calculate_subnet("192.168.1.0/31")
        assert info["total_addresses"] == 2
        assert info["usable_hosts"] == 2

    def test_public_network(self):
        info = calculate_subnet("8.8.8.0/24")
        assert info["is_private"] is False

    def test_invalid_network(self):
        with pytest.raises(ValueError):
            calculate_subnet("not-a-network")

    def test_wildcard_mask(self):
        info = calculate_subnet("192.168.1.0/24")
        assert info["wildcard"] == "0.0.0.255"


class TestSubnetCLI:
    def test_help(self, runner, cli_app):
        result = runner.invoke(cli_app, ["subnet", "--help"])
        assert result.exit_code == 0
        assert "CIDR" in result.output

    def test_basic_calculation(self, runner, cli_app):
        result = runner.invoke(cli_app, ["subnet", "10.0.0.0/8"])
        assert result.exit_code == 0
        assert "10.0.0.0" in result.output
        assert "255.0.0.0" in result.output

    def test_explain_flag(self, runner, cli_app):
        result = runner.invoke(cli_app, ["subnet", "192.168.1.0/24", "--explain"])
        assert result.exit_code == 0
        assert "subnet" in result.output.lower()

    def test_invalid_input(self, runner, cli_app):
        result = runner.invoke(cli_app, ["subnet", "garbage"])
        assert result.exit_code == 1
