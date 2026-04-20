"""GitHub recon tool. Wraps gitleaks for secret scanning.

Two modes:
  - repo: scan a single repo (clone + scan)
  - org:  scan all public repos for an org (clone each, scan)

Finds: API keys, tokens, private keys, .env leaks, hardcoded creds.
Low duplicate rate in bug bounty because most programs don't include
GitHub recon in their program scope — but findings that lead to prod
access are paid as critical.
"""
from __future__ import annotations
from openclaw.tools.registry import Tool, register_tool


@register_tool
class GitLeaks(Tool):
    name = "gitleaks"
    binary = "gitleaks"
    description = "Scan a git repo or directory for leaked secrets"

    def build_args(self, target: str, **kwargs) -> list[str]:
        # target = local path to repo or directory
        args = ["detect", "--source", target, "-f", "json", "--no-banner"]
        if kwargs.get("redact"):
            args.append("--redact")
        return args


@register_tool
class GHDork(Tool):
    """Shallow GitHub dork via search. Relies on `gh` CLI if present,
    otherwise unauthenticated web search (rate-limited)."""
    name = "gh_dork"
    binary = "gh"
    description = "GitHub code search for target-specific secrets/paths"
    default_timeout = 120

    def build_args(self, target: str, **kwargs) -> list[str]:
        # target can be a domain, org, or search query
        query = kwargs.get("query") or target
        return [
            "search", "code", query,
            "--limit", str(kwargs.get("limit", 50)),
            "--json", "repository,path,url,textMatches",
        ]
