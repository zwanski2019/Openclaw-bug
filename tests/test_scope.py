"""Tests for scope enforcement. The most critical safety subsystem."""
import pytest
from openclaw.safety.scope import (
    Scope, _host_matches, extract_host,
    load_all_scopes, find_scope_for_host,
    assert_allowed, ScopeViolation,
)


class TestHostMatching:
    def test_wildcard_subdomain(self):
        assert _host_matches("api.example.com", "*.example.com")
        assert _host_matches("deep.api.example.com", "*.example.com")

    def test_wildcard_matches_bare(self):
        # Our rule: *.example.com covers example.com itself
        assert _host_matches("example.com", "*.example.com")

    def test_wildcard_rejects_different_domain(self):
        assert not _host_matches("evil.com", "*.example.com")
        assert not _host_matches("notexample.com", "*.example.com")

    def test_exact_match(self):
        assert _host_matches("api.example.com", "api.example.com")
        assert not _host_matches("api.example.com", "web.example.com")

    def test_cidr_ipv4(self):
        assert _host_matches("192.168.1.5", "192.168.1.0/24")
        assert _host_matches("192.168.1.255", "192.168.1.0/24")
        assert not _host_matches("192.168.2.1", "192.168.1.0/24")
        assert not _host_matches("10.0.0.1", "192.168.1.0/24")

    def test_case_insensitive(self):
        assert _host_matches("API.EXAMPLE.COM", "*.example.com")

    def test_fnmatch_pattern(self):
        assert _host_matches("api-v1.example.com", "api-*.example.com")


class TestExtractHost:
    def test_plain_host(self):
        assert extract_host("example.com") == "example.com"

    def test_url(self):
        assert extract_host("https://api.example.com/v1/users") == "api.example.com"
        assert extract_host("http://target.tld:8080/path") == "target.tld"

    def test_strips_port(self):
        assert extract_host("example.com:443") == "example.com"

    def test_empty(self):
        assert extract_host("") == ""


class TestScopeFile:
    def test_loads_example(self, sample_scope):
        scopes = load_all_scopes()
        assert "test-prog" in scopes
        s = scopes["test-prog"]
        assert s.platform == "hackerone"
        assert "*.example.com" in s.in_scope

    def test_find_for_host(self, sample_scope):
        s = find_scope_for_host("api.example.com")
        assert s is not None and s.name == "test-prog"

    def test_find_for_unknown_host(self, sample_scope):
        assert find_scope_for_host("totally-unknown.org") is None

    def test_out_of_scope_overrides_in(self, sample_scope):
        s = find_scope_for_host("blog.example.com")
        # Matching in_scope wildcard but also out_of_scope → blocked
        assert s is None or not s.is_host_allowed("blog.example.com")

    def test_cidr_scope(self, sample_scope):
        s = find_scope_for_host("192.168.1.42")
        assert s is not None

    def test_tool_allowlist(self, sample_scope):
        s = find_scope_for_host("api.example.com")
        assert s.is_tool_allowed("subfinder") is True
        assert s.is_tool_allowed("sqlmap") is False  # not in allowlist


class TestAssertAllowed:
    def test_blocks_unknown_host(self, sample_scope):
        with pytest.raises(ScopeViolation):
            assert_allowed("evil.com", "subfinder")

    def test_blocks_unlisted_tool(self, sample_scope):
        with pytest.raises(ScopeViolation):
            assert_allowed("api.example.com", "metasploit")

    def test_allows_valid(self, sample_scope):
        scope = assert_allowed("api.example.com", "subfinder")
        assert scope.name == "test-prog"

    def test_blocks_out_of_scope(self, sample_scope):
        with pytest.raises(ScopeViolation):
            assert_allowed("blog.example.com", "subfinder")

    def test_no_scope_file_blocks(self, scope_dir):
        # scope_dir is empty
        with pytest.raises(ScopeViolation):
            assert_allowed("anything.com", "subfinder")
