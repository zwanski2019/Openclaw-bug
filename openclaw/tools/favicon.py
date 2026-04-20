"""Favicon hash infrastructure pivot.

Computes mmh3 hash of favicon.ico the same way Shodan/Censys index it.
The resulting hash lets you pivot from one asset to others in the same
infrastructure (same favicon = same codebase/tenant = likely related infra,
even behind different CDNs or DNS names).

Unauthenticated workflow: compute hash locally, print Shodan search URL.
Authenticated: if SHODAN_API_KEY set, perform the search.
"""
from __future__ import annotations
import base64
import codecs
import hashlib
import json
import os
import time
from urllib.parse import urljoin
import httpx
import mmh3
from openclaw.tools.registry import ToolResult, Tool, register_tool
from openclaw.safety.scope import assert_allowed
from openclaw.safety.rate_limit import get_registry as rl_registry
from openclaw.config import settings


@register_tool
class Favicon(Tool):
    name = "favicon"
    binary = "__native__"
    description = "Fetch favicon, compute mmh3/md5 hash for Shodan/Censys pivot"


def compute_favicon_hash(favicon_bytes: bytes) -> int:
    """mmh3 hash using Shodan's convention: base64-encode with newlines every 76 chars, then mmh3."""
    b64 = codecs.encode(favicon_bytes, "base64").decode()
    return mmh3.hash(b64)


def md5_favicon(favicon_bytes: bytes) -> str:
    """Censys uses MD5 for favicon fingerprinting."""
    return hashlib.md5(favicon_bytes).hexdigest()


async def execute_favicon_pivot(
    target: str,
    run_id: int,
    step_num: int,
    **kwargs,
) -> ToolResult:
    """Target = base URL. Fetches /favicon.ico, computes hashes, optionally queries Shodan."""
    try:
        scope = assert_allowed(target, "favicon")
    except Exception as e:
        return ToolResult(
            tool="favicon", target=target, args=[],
            exit_code=-1, stdout="", stderr=str(e),
            duration_ms=0, scope_verdict="blocked", error=str(e),
        )

    bucket = await rl_registry().get(scope.name, scope.rate_limit_rps)
    await bucket.acquire(1.0)

    favicon_url = urljoin(target, "/favicon.ico")
    t0 = time.perf_counter()

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as c:
            r = await c.get(favicon_url)
            r.raise_for_status()
            favicon_bytes = r.content
    except Exception as e:
        return ToolResult(
            tool="favicon", target=target, args=[favicon_url],
            exit_code=-1, stdout="", stderr=str(e),
            duration_ms=int((time.perf_counter() - t0) * 1000),
            scope_verdict="allowed", error="fetch_failed",
        )

    mmh = compute_favicon_hash(favicon_bytes)
    md5 = md5_favicon(favicon_bytes)
    payload = {
        "favicon_url": favicon_url,
        "bytes": len(favicon_bytes),
        "mmh3_hash": mmh,
        "md5_hash": md5,
        "shodan_search": f"http.favicon.hash:{mmh}",
        "shodan_url": f"https://www.shodan.io/search?query=http.favicon.hash%3A{mmh}",
        "censys_url": f"https://search.censys.io/search?q=services.http.response.favicons.md5_hash%3A{md5}",
    }

    # Optional authenticated Shodan lookup
    shodan_key = os.getenv("SHODAN_API_KEY", "").strip()
    if shodan_key:
        try:
            async with httpx.AsyncClient(timeout=15.0) as c:
                sr = await c.get(
                    "https://api.shodan.io/shodan/host/search",
                    params={"key": shodan_key, "query": f"http.favicon.hash:{mmh}"},
                )
                if sr.status_code == 200:
                    data = sr.json()
                    payload["shodan_matches"] = data.get("total", 0)
                    payload["shodan_sample"] = [
                        {"ip": m.get("ip_str"), "port": m.get("port"),
                         "hostnames": m.get("hostnames", [])}
                        for m in (data.get("matches") or [])[:10]
                    ]
        except Exception:
            payload["shodan_error"] = "lookup failed"

    duration = int((time.perf_counter() - t0) * 1000)
    run_dir = settings.runs_dir / str(run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = run_dir / f"{step_num:03d}_favicon.stdout"
    stdout_path.write_text(json.dumps(payload, indent=2))

    return ToolResult(
        tool="favicon", target=target, args=["favicon", target],
        exit_code=0,
        stdout=json.dumps(payload, indent=2),
        stderr="",
        duration_ms=duration,
        stdout_path=str(stdout_path),
        stderr_path="",
        scope_verdict="allowed",
    )
