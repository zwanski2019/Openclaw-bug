"""Tests for candidate dedup — SHA256 fingerprinting."""
from openclaw.safety.dedup import (
    fingerprint, _normalize_url, _stable_evidence_summary,
    is_duplicate, remember, check_and_remember,
)


class TestNormalizeUrl:
    def test_strips_query(self):
        a = _normalize_url("https://api.example.com/users/1?foo=1")
        b = _normalize_url("https://api.example.com/users/1")
        assert a == b

    def test_collapses_numeric_ids(self):
        # /users/123 and /users/456 should map to same normalized form
        a = _normalize_url("https://api.example.com/users/123")
        b = _normalize_url("https://api.example.com/users/456")
        assert a == b
        assert "{id}" in a

    def test_collapses_uuids(self):
        a = _normalize_url("https://a.com/obj/12345678-1234-1234-1234-123456789abc/view")
        b = _normalize_url("https://a.com/obj/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee/view")
        assert a == b
        assert "{uuid}" in a

    def test_case_insensitive_host(self):
        a = _normalize_url("https://API.Example.COM/path")
        b = _normalize_url("https://api.example.com/path")
        assert a == b

    def test_trailing_slash(self):
        a = _normalize_url("https://a.com/path/")
        b = _normalize_url("https://a.com/path")
        assert a == b


class TestFingerprint:
    def test_same_inputs_same_fp(self):
        fp1 = fingerprint("IDOR", "https://a.com/u/1", {"param": "id"})
        fp2 = fingerprint("IDOR", "https://a.com/u/2", {"param": "id"})
        assert fp1 == fp2  # numeric IDs collapsed

    def test_different_vuln_class_different_fp(self):
        fp1 = fingerprint("IDOR", "https://a.com/path", {})
        fp2 = fingerprint("XSS", "https://a.com/path", {})
        assert fp1 != fp2

    def test_different_evidence_signatures_differ(self):
        fp1 = fingerprint("SSRF", "https://a.com/", {"template_id": "aws-metadata"})
        fp2 = fingerprint("SSRF", "https://a.com/", {"template_id": "gcp-metadata"})
        assert fp1 != fp2

    def test_unstable_evidence_ignored(self):
        """Volatile fields like timestamps shouldn't change the fingerprint."""
        fp1 = fingerprint("IDOR", "https://a.com/", {"timestamp": "2026-01-01"})
        fp2 = fingerprint("IDOR", "https://a.com/", {"timestamp": "2026-04-20"})
        assert fp1 == fp2


class TestStableEvidence:
    def test_picks_known_keys(self):
        evidence = {"template_id": "xss-payload", "random": "ignore me"}
        summary = _stable_evidence_summary(evidence)
        assert "template_id=xss-payload" in summary
        assert "ignore me" not in summary

    def test_handles_json_string(self):
        summary = _stable_evidence_summary('{"name": "alert", "other": "x"}')
        assert "name=alert" in summary

    def test_handles_malformed(self):
        # Non-JSON string falls through safely
        summary = _stable_evidence_summary("not json")
        assert isinstance(summary, str)


class TestDedupIntegration:
    def test_first_time_not_duplicate(self):
        was_dup, fp = check_and_remember(
            "scope-a", "IDOR", "https://a.com/u/1", {}
        )
        assert was_dup is False
        assert len(fp) == 32

    def test_second_time_is_duplicate(self):
        check_and_remember("scope-a", "IDOR", "https://a.com/u/1", {})
        was_dup, _ = check_and_remember(
            "scope-a", "IDOR", "https://a.com/u/2", {}  # different numeric id
        )
        assert was_dup is True

    def test_different_scope_independent(self):
        check_and_remember("scope-a", "IDOR", "https://a.com/u/1", {})
        was_dup, _ = check_and_remember("scope-b", "IDOR", "https://a.com/u/1", {})
        # scope-b has its own dedup space — but global memories are shared
        # This test asserts current behavior (scope 'a' and 'b' can both have the same fp)
        # since dedup keys are scoped. Adjust if global dedup becomes default.
        assert was_dup is False
