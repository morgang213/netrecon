"""Tests for the explanation/education system."""

from netrecon.explain import EXPLANATIONS, GLOSSARY


class TestExplanations:
    def test_all_tools_have_explanations(self):
        expected_tools = [
            "port_scanner",
            "ping_sweep",
            "dns_lookup",
            "traceroute",
            "banner_grab",
            "ssl_checker",
            "whois_lookup",
            "header_inspector",
            "pcap_viewer",
            "log_parser",
            "subnet_calc",
        ]
        for tool in expected_tools:
            assert tool in EXPLANATIONS, f"Missing explanation for {tool}"

    def test_explanations_have_required_fields(self):
        for tool_name, info in EXPLANATIONS.items():
            assert "title" in info, f"{tool_name} missing title"
            assert "body" in info, f"{tool_name} missing body"
            assert len(info["body"]) > 50, f"{tool_name} body too short"

    def test_explanations_have_learn_more(self):
        for tool_name, info in EXPLANATIONS.items():
            assert "learn_more" in info, f"{tool_name} missing learn_more"
            assert info["learn_more"].startswith("http"), (
                f"{tool_name} invalid learn_more URL"
            )


class TestGlossary:
    def test_glossary_not_empty(self):
        assert len(GLOSSARY) >= 10

    def test_core_terms_present(self):
        core_terms = ["port", "tcp", "udp", "dns", "ip address", "firewall"]
        for term in core_terms:
            assert term in GLOSSARY, f"Missing glossary term: {term}"

    def test_definitions_are_substantive(self):
        for term, definition in GLOSSARY.items():
            assert len(definition) > 30, f"Definition for '{term}' is too short"
