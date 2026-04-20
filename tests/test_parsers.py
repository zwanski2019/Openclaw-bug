"""Parser + planner output parsing tests."""
import json
from openclaw.tools.parser import (
    parse_subfinder, parse_httpx, parse_nuclei, extract_insights,
)
from openclaw.agent.planner import _parse_plan


class TestParsers:
    def test_subfinder_deduplicates(self):
        raw = "api.example.com\nwww.example.com\napi.example.com\n\n"
        subs = parse_subfinder(raw)
        assert subs == ["api.example.com", "www.example.com"]

    def test_subfinder_strips_whitespace(self):
        assert parse_subfinder("  sub.example.com  \n") == ["sub.example.com"]

    def test_httpx_parses_jsonl(self):
        raw = "\n".join([
            json.dumps({"url": "https://a.com", "status_code": 200}),
            json.dumps({"url": "https://b.com", "status_code": 403}),
            "",
            "malformed line",
            json.dumps({"url": "https://c.com", "status_code": 404}),
        ])
        results = parse_httpx(raw)
        assert len(results) == 3
        assert results[0]["url"] == "https://a.com"

    def test_nuclei_parses_jsonl(self):
        raw = json.dumps({"info": {"severity": "high"}, "host": "a.com"})
        findings = parse_nuclei(raw)
        assert findings[0]["info"]["severity"] == "high"

    def test_parsers_handle_empty(self):
        assert parse_subfinder("") == []
        assert parse_httpx("") == []
        assert parse_nuclei("") == []


class TestInsights:
    def test_counts_subdomains(self):
        insights = extract_insights({
            "subfinder": ["a.example.com", "b.example.com", "c.example.com"],
        })
        assert insights["subdomains_count"] == 3

    def test_counts_live_hosts_and_tech(self):
        insights = extract_insights({
            "httpx": [
                {"url": "https://a.com", "status_code": 200, "tech": ["nginx", "node.js"]},
                {"url": "https://b.com", "status_code": 200, "tech": ["apache"]},
            ],
        })
        assert insights["live_hosts_count"] == 2
        assert "nginx" in insights["interesting_tech"]
        assert "apache" in insights["interesting_tech"]

    def test_flags_interesting_statuses(self):
        insights = extract_insights({
            "httpx": [
                {"url": "https://a.com/admin", "status_code": 403, "title": "Forbidden"},
                {"url": "https://a.com/debug", "status_code": 200, "title": "Debug"},
            ],
        })
        urls = [e["url"] for e in insights["interesting_endpoints"]]
        assert "https://a.com/admin" in urls
        assert "https://a.com/debug" in urls

    def test_aggregates_nuclei_severity(self):
        insights = extract_insights({
            "nuclei": [
                {"info": {"severity": "high"}},
                {"info": {"severity": "high"}},
                {"info": {"severity": "medium"}},
            ],
        })
        assert insights["findings_by_severity"]["high"] == 2
        assert insights["findings_by_severity"]["medium"] == 1


class TestPlanParsing:
    def test_clean_json(self):
        raw = json.dumps({
            "reasoning": "enum first",
            "steps": [{"tool": "subfinder", "target": "example.com",
                       "args": {}, "rationale": "pasv"}],
            "stop_when": "have subs",
        })
        plan = _parse_plan(raw)
        assert len(plan.steps) == 1
        assert plan.steps[0].tool == "subfinder"

    def test_markdown_fenced(self):
        """LLMs often wrap JSON in ```json fences."""
        raw = """Sure, here is the plan:

```json
{"reasoning": "test", "steps": [{"tool": "httpx", "target": "https://a.com", "args": {}, "rationale": "probe"}]}
```

Let me know if you want changes."""
        plan = _parse_plan(raw)
        assert len(plan.steps) == 1
        assert plan.steps[0].tool == "httpx"

    def test_malformed_returns_empty(self):
        plan = _parse_plan("no json here at all")
        assert plan.steps == []

    def test_missing_tool_field_skipped(self):
        raw = json.dumps({
            "reasoning": "bad plan",
            "steps": [
                {"target": "example.com", "args": {}},  # no tool
                {"tool": "subfinder", "target": "example.com", "args": {}},
            ],
        })
        plan = _parse_plan(raw)
        assert len(plan.steps) == 1
        assert plan.steps[0].tool == "subfinder"
