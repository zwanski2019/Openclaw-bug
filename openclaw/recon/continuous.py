"""Continuous recon. Diff-based monitoring of subdomains & live hosts.

Per your 2026 reference doc: "New assets = new bugs. Being first on a newly
exposed subdomain is the single highest-ROI recon play."

Workflow:
  1. Run subfinder + httpx on target (scoped)
  2. Compare against previous snapshot
  3. New subs / newly-live hosts → write 'new_asset' memory entries
  4. Optional: write a candidate for each (since agent will auto-triage new assets
     as high-priority recon targets)
  5. Schedule via cron: `python -m openclaw continuous --scope example-program`
"""
from __future__ import annotations
import json
import time
from dataclasses import dataclass
from pathlib import Path
from openclaw.config import settings
from openclaw.db import client as db
from openclaw.safety.scope import load_all_scopes
from openclaw.tools import registry
from openclaw.tools.parser import parse_subfinder, parse_httpx


@dataclass
class ContinuousDiff:
    scope: str
    domain: str
    new_subs: list[str]
    removed_subs: list[str]
    newly_live: list[str]
    snapshot_at: int


def _snapshot_dir(scope_name: str) -> Path:
    d = settings.data_dir / "continuous" / scope_name
    d.mkdir(parents=True, exist_ok=True)
    return d


def _latest_snapshot(scope_name: str, domain: str) -> dict | None:
    sdir = _snapshot_dir(scope_name)
    snaps = sorted(sdir.glob(f"{domain}_*.json"))
    if not snaps:
        return None
    try:
        return json.loads(snaps[-1].read_text())
    except json.JSONDecodeError:
        return None


def _write_snapshot(scope_name: str, domain: str, data: dict) -> Path:
    sdir = _snapshot_dir(scope_name)
    path = sdir / f"{domain}_{int(time.time())}.json"
    path.write_text(json.dumps(data, indent=2))
    return path


async def run_continuous(scope_name: str, domain: str) -> ContinuousDiff:
    """Run recon against a scope, diff, log new assets.

    domain = a domain within the scope (e.g. example.com). The tool enforces scope
    on every sub-query via the executor.
    """
    scopes = load_all_scopes()
    if scope_name not in scopes:
        raise ValueError(f"Unknown scope '{scope_name}'. Known: {list(scopes)}")

    run_id = db.create_run(
        target_id=None,
        goal=f"continuous recon: {scope_name}/{domain}",
    )

    # ── Subfinder ─────────────────────────────────────────────
    sub_result = await registry.execute(
        tool_name="subfinder",
        target=domain,
        run_id=run_id,
        step_num=1,
    )
    current_subs = set(parse_subfinder(sub_result.stdout)) if sub_result.exit_code == 0 else set()

    # ── Write all subs to a temp file for httpx_list ─────────
    subs_file = settings.runs_dir / str(run_id) / "subs.txt"
    subs_file.write_text("\n".join(sorted(current_subs)))

    # ── httpx probe ───────────────────────────────────────────
    live_result = await registry.execute(
        tool_name="httpx_list",
        target=str(subs_file),
        run_id=run_id,
        step_num=2,
    )
    current_live = {
        entry.get("url") or entry.get("input") or ""
        for entry in parse_httpx(live_result.stdout)
        if entry.get("status_code") or entry.get("status-code")
    }
    current_live.discard("")

    # ── Diff against last snapshot ────────────────────────────
    prev = _latest_snapshot(scope_name, domain) or {"subs": [], "live": []}
    prev_subs = set(prev.get("subs", []))
    prev_live = set(prev.get("live", []))

    diff = ContinuousDiff(
        scope=scope_name,
        domain=domain,
        new_subs=sorted(current_subs - prev_subs),
        removed_subs=sorted(prev_subs - current_subs),
        newly_live=sorted(current_live - prev_live),
        snapshot_at=int(time.time()),
    )

    # ── Write snapshot ────────────────────────────────────────
    _write_snapshot(scope_name, domain, {
        "subs": sorted(current_subs),
        "live": sorted(current_live),
        "snapshot_at": diff.snapshot_at,
    })

    # ── Memory: log new assets ────────────────────────────────
    for sub in diff.new_subs:
        db.add_memory(
            scope=scope_name,
            kind="new_asset",
            content=f"{diff.snapshot_at}::subdomain::{sub}",
        )
    for url in diff.newly_live:
        db.add_memory(
            scope=scope_name,
            kind="new_asset",
            content=f"{diff.snapshot_at}::live_host::{url}",
        )

    db.update_run_status(run_id, "complete")
    return diff
