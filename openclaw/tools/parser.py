"""Parse tool outputs into structured records."""
from __future__ import annotations
import json
from typing import Any


def parse_subfinder(stdout: str) -> list[str]:
    """Newline-separated subdomains."""
    return sorted(set(line.strip() for line in stdout.splitlines() if line.strip()))


def parse_assetfinder(stdout: str) -> list[str]:
    return parse_subfinder(stdout)


def parse_httpx(stdout: str) -> list[dict]:
    """JSONL — one probe result per line."""
    results = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return results


def parse_nuclei(stdout: str) -> list[dict]:
    """JSONL findings."""
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings


def parse_naabu(stdout: str) -> list[dict]:
    """JSONL: {ip, host, port}."""
    return parse_httpx(stdout)


def parse_waybackurls(stdout: str) -> list[str]:
    return sorted(set(line.strip() for line in stdout.splitlines() if line.strip()))


def extract_insights(parsed: dict[str, Any]) -> dict:
    """High-level summary from parsed results for the analyzer LLM."""
    insights: dict[str, Any] = {
        "subdomains_count": 0,
        "live_hosts_count": 0,
        "interesting_tech": [],
        "findings_by_severity": {},
        "interesting_endpoints": [],
        "open_ports": [],
    }

    for tool, data in parsed.items():
        if tool in ("subfinder", "assetfinder") and isinstance(data, list):
            insights["subdomains_count"] += len(data)

        elif tool in ("httpx", "httpx_list") and isinstance(data, list):
            insights["live_hosts_count"] = len(data)
            for probe in data:
                tech = probe.get("tech", [])
                if isinstance(tech, list):
                    insights["interesting_tech"].extend(tech)
                # Flag interesting status + path combos
                status = probe.get("status_code") or probe.get("status-code")
                url = probe.get("url", "")
                if status in (401, 403) or "admin" in url.lower() or "debug" in url.lower():
                    insights["interesting_endpoints"].append({
                        "url": url, "status": status,
                        "title": probe.get("title", ""),
                    })

        elif tool == "nuclei" and isinstance(data, list):
            for f in data:
                sev = (f.get("info", {}).get("severity") or "unknown").lower()
                insights["findings_by_severity"][sev] = \
                    insights["findings_by_severity"].get(sev, 0) + 1

        elif tool == "naabu" and isinstance(data, list):
            for p in data:
                insights["open_ports"].append({
                    "host": p.get("host"), "port": p.get("port"),
                })

    # Dedupe tech list
    insights["interesting_tech"] = sorted(set(insights["interesting_tech"]))
    return insights
