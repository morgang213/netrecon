"""Tests for HTTP header inspector."""

from netrecon.tools.header_inspector import analyze_security_headers


class TestAnalyzeSecurityHeaders:
    def test_all_headers_present(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
            "X-XSS-Protection": "1; mode=block",
        }
        findings = analyze_security_headers(headers)
        assert all(f["present"] for f in findings)

    def test_no_headers_present(self):
        findings = analyze_security_headers({})
        assert not any(f["present"] for f in findings)

    def test_partial_headers(self):
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
        }
        findings = analyze_security_headers(headers)
        present = [f for f in findings if f["present"]]
        missing = [f for f in findings if not f["present"]]
        assert len(present) == 2
        assert len(missing) == 5


class TestHeaderInspectorCLI:
    def test_help(self, runner, cli_app):
        result = runner.invoke(cli_app, ["headers", "--help"])
        assert result.exit_code == 0
        assert "URL" in result.output or "url" in result.output
