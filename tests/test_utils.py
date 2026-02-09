"""Tests for utility functions."""

import pytest

from netrecon.utils import get_service_info, parse_port_range


class TestParsePortRange:
    def test_single_port(self):
        assert parse_port_range("80") == [80]

    def test_comma_separated(self):
        assert parse_port_range("22,80,443") == [22, 80, 443]

    def test_range(self):
        assert parse_port_range("20-25") == [20, 21, 22, 23, 24, 25]

    def test_mixed(self):
        result = parse_port_range("22,80,100-102,443")
        assert result == [22, 80, 100, 101, 102, 443]

    def test_deduplication(self):
        result = parse_port_range("80,80,80")
        assert result == [80]

    def test_sorted(self):
        result = parse_port_range("443,80,22")
        assert result == [22, 80, 443]

    def test_invalid_port_too_high(self):
        with pytest.raises(ValueError):
            parse_port_range("70000")

    def test_invalid_range(self):
        with pytest.raises(ValueError):
            parse_port_range("100-50")


class TestGetServiceInfo:
    def test_known_port(self):
        name, desc = get_service_info(80)
        assert name == "HTTP"
        assert "Web server" in desc

    def test_unknown_port(self):
        name, desc = get_service_info(9999)
        assert name == "Unknown"
        assert desc == ""

    def test_ssh_port(self):
        name, desc = get_service_info(22)
        assert name == "SSH"
