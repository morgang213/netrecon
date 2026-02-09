"""Tests for log parser."""

from netrecon.tools.log_parser import detect_log_type, parse_auth_log, parse_http_log


class TestDetectLogType:
    def test_detect_auth_log(self, sample_auth_log):
        assert detect_log_type(sample_auth_log) == "auth"

    def test_detect_http_log(self, sample_access_log):
        assert detect_log_type(sample_access_log) == "http"


class TestParseAuthLog:
    def test_basic_parsing(self, sample_auth_log):
        info = parse_auth_log(sample_auth_log)
        assert info["log_type"] == "auth"
        assert info["failed_logins"] > 0
        assert info["successful_logins"] > 0
        assert info["total_lines"] > 0

    def test_brute_force_detection(self, sample_auth_log):
        info = parse_auth_log(sample_auth_log)
        assert len(info["brute_force_ips"]) >= 1
        assert "192.168.1.100" in info["brute_force_ips"]

    def test_top_failed_ips(self, sample_auth_log):
        info = parse_auth_log(sample_auth_log)
        top_ips = dict(info["top_failed_ips"])
        assert "192.168.1.100" in top_ips


class TestParseHttpLog:
    def test_basic_parsing(self, sample_access_log):
        info = parse_http_log(sample_access_log)
        assert info["log_type"] == "http"
        assert info["total_requests"] > 0
        assert info["unique_ips"] > 0

    def test_suspicious_requests(self, sample_access_log):
        info = parse_http_log(sample_access_log)
        assert len(info["suspicious_requests"]) > 0
        suspicious_paths = [r[1] for r in info["suspicious_requests"]]
        assert any("/wp-admin" in p for p in suspicious_paths)

    def test_status_codes(self, sample_access_log):
        info = parse_http_log(sample_access_log)
        status_dict = dict(info["status_codes"])
        assert 200 in status_dict
        assert 404 in status_dict


class TestLogParserCLI:
    def test_help(self, runner, cli_app):
        result = runner.invoke(cli_app, ["logs", "--help"])
        assert result.exit_code == 0

    def test_auth_log(self, runner, cli_app, sample_auth_log):
        result = runner.invoke(cli_app, ["logs", sample_auth_log])
        assert result.exit_code == 0
        assert "Failed" in result.output or "failed" in result.output

    def test_http_log(self, runner, cli_app, sample_access_log):
        result = runner.invoke(cli_app, ["logs", sample_access_log])
        assert result.exit_code == 0

    def test_missing_file(self, runner, cli_app):
        result = runner.invoke(cli_app, ["logs", "/nonexistent/file.log"])
        assert result.exit_code == 1
