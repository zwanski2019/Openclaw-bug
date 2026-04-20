"""Scope enforcement. EVERY tool execution goes through is_allowed().

Design: explicit allow-list per target via YAML file. No wildcard-all.
Supports DNS-style wildcards (`*.example.com`) and exact matches.
Out-of-scope overrides in-scope.
"""
from __future__ import annotations
import fnmatch
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse
import yaml
from openclaw.config import settings


@dataclass
class Scope:
    name: str
    platform: str = ""
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    rate_limit_rps: int = 5
    allowed_tools: list[str] = field(default_factory=list)
    notes: str = ""

    @classmethod
    def from_file(cls, path: Path) -> "Scope":
        data = yaml.safe_load(path.read_text())
        return cls(
            name=data.get("name", path.stem),
            platform=data.get("platform", ""),
            in_scope=data.get("in_scope", []),
            out_of_scope=data.get("out_of_scope", []),
            rate_limit_rps=data.get("rate_limit_rps", 5),
            allowed_tools=data.get("allowed_tools", []),
            notes=data.get("notes", ""),
        )

    def matches_in(self, host: str) -> bool:
        return any(_host_matches(host, p) for p in self.in_scope)

    def matches_out(self, host: str) -> bool:
        return any(_host_matches(host, p) for p in self.out_of_scope)

    def is_host_allowed(self, host: str) -> bool:
        if self.matches_out(host):
            return False
        return self.matches_in(host)

    def is_tool_allowed(self, tool: str) -> bool:
        # Empty allowed_tools = default safe set (recon only, no active exploit)
        if not self.allowed_tools:
            return tool in {"subfinder", "amass", "httpx", "assetfinder",
                            "waybackurls", "katana", "nuclei", "naabu"}
        return tool in self.allowed_tools


def _host_matches(host: str, pattern: str) -> bool:
    """Match host against a pattern. Supports:
    - `*.example.com`  → subdomains only (not bare)
    - `example.com`    → exact
    - CIDR             → IP ranges
    """
    host = host.lower().strip()
    pattern = pattern.lower().strip()

    # CIDR
    if "/" in pattern:
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            ip = ipaddress.ip_address(host)
            return ip in net
        except ValueError:
            return False

    # Wildcard subdomain
    if pattern.startswith("*."):
        base = pattern[2:]
        return host == base or host.endswith("." + base)

    # fnmatch fallback for patterns like `api-*.example.com`
    return fnmatch.fnmatch(host, pattern) or host == pattern


def extract_host(target: str) -> str:
    """Pull a bare host from a URL or host string."""
    if "://" in target:
        return urlparse(target).hostname or ""
    # Strip port if present
    return target.split(":")[0].strip().lower()


def load_all_scopes() -> dict[str, Scope]:
    scopes = {}
    for f in settings.scopes_dir.glob("*.yaml"):
        try:
            s = Scope.from_file(f)
            scopes[s.name] = s
        except Exception as e:
            print(f"[scope] failed to parse {f}: {e}")
    return scopes


def find_scope_for_host(host: str) -> Scope | None:
    """Return the first scope whose in_scope matches this host."""
    for scope in load_all_scopes().values():
        if scope.is_host_allowed(host):
            return scope
    return None


def assert_allowed(target: str, tool: str) -> Scope:
    """Raise ScopeViolation if target or tool not permitted. Returns the matching scope."""
    host = extract_host(target)
    if not host:
        raise ScopeViolation(f"Cannot extract host from target: {target}")

    scope = find_scope_for_host(host)
    if scope is None:
        raise ScopeViolation(
            f"Host '{host}' has no matching scope file in {settings.scopes_dir}. "
            f"Create scopes/<name>.yaml with in_scope list before running tools."
        )

    if not scope.is_tool_allowed(tool):
        raise ScopeViolation(
            f"Tool '{tool}' not allowed for scope '{scope.name}'. "
            f"Allowed: {scope.allowed_tools or 'default recon set'}"
        )

    return scope


class ScopeViolation(Exception):
    """Raised when a tool execution is blocked by scope rules."""
    pass
