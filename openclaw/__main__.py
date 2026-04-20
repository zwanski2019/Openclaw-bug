"""CLI for OpenClaw. Alternative to Streamlit UI for headless / CI use.

Usage:
    python -m openclaw run --target api.example.com --goal "enumerate subs and flag OAuth endpoints"
    python -m openclaw candidates
    python -m openclaw report promote --id 5
    python -m openclaw sync
"""
from __future__ import annotations
import asyncio
import json
import typer
from rich.console import Console
from rich.table import Table
from openclaw.agent.loop import AgentLoop
from openclaw.reports.generator import ReportGenerator
from openclaw.db import client as db
from openclaw.safety.scope import load_all_scopes
from openclaw.tools.registry import list_tools

app = typer.Typer(help="OpenClaw — autonomous bug bounty research agent.")
console = Console()


@app.command()
def run(
    target: str = typer.Option(..., help="Target host or URL"),
    goal: str = typer.Option(..., help="Plain-English research goal"),
    max_steps: int = typer.Option(20, help="Max agent iterations"),
):
    """Run the agent against a target."""
    async def drive():
        loop = AgentLoop()
        async for event in loop.run(
            goal=goal, target_host=target, max_steps=max_steps,
        ):
            console.print(f"[dim]{event.kind}[/dim]", event.payload)

    asyncio.run(drive())


@app.command()
def candidates(status: str = typer.Option("pending", help="Filter by status")):
    """List candidates in the queue."""
    rows = db.list_candidates(status=None if status == "all" else status)
    t = Table(title=f"Candidates ({status})")
    for col in ("id", "title", "vuln_class", "severity", "url", "status"):
        t.add_column(col)
    for c in rows:
        t.add_row(
            str(c["id"]), c["title"][:50], c["vuln_class"] or "",
            c["severity_guess"] or "", (c["affected_url"] or "")[:60],
            c["status"],
        )
    console.print(t)


report_app = typer.Typer(help="Report management")
app.add_typer(report_app, name="report")


@report_app.command("promote")
def report_promote(id: int = typer.Option(..., help="Candidate ID")):
    """Promote candidate to report (LLM generates markdown)."""
    gen = ReportGenerator()
    rid = asyncio.run(gen.generate_and_save(id))
    console.print(f"[green]✓[/green] Report {rid} saved.")


@report_app.command("list")
def report_list():
    rows = db.list_reports()
    t = Table(title="Reports")
    for col in ("id", "title", "cvss", "status"):
        t.add_column(col)
    for r in rows:
        t.add_row(
            str(r["id"]), r["title"][:60],
            f"{r['cvss_score']:.1f}" if r["cvss_score"] else "-",
            r["status"],
        )
    console.print(t)


@report_app.command("show")
def report_show(id: int):
    rows = [r for r in db.list_reports() if r["id"] == id]
    if not rows:
        console.print(f"[red]Report {id} not found[/red]")
        raise typer.Exit(1)
    console.print(rows[0]["markdown"])


@app.command()
def tools():
    """List registered tools and availability."""
    t = Table(title="Tools")
    for col in ("name", "binary", "available", "description"):
        t.add_column(col)
    for tool in list_tools():
        t.add_row(
            tool["name"], tool["binary"],
            "✅" if tool["available"] else "❌",
            tool["description"],
        )
    console.print(t)


@app.command()
def scopes():
    """List configured scope files."""
    s = load_all_scopes()
    if not s:
        console.print("[yellow]No scope files loaded.[/yellow]")
        return
    t = Table(title="Scopes")
    for col in ("name", "platform", "in_scope", "out_of_scope"):
        t.add_column(col)
    for name, scope in s.items():
        t.add_row(
            name, scope.platform or "-",
            ", ".join(scope.in_scope[:3]),
            ", ".join(scope.out_of_scope[:3]),
        )
    console.print(t)


@app.command()
def sync():
    """Sync local SQLite to Supabase (if configured)."""
    result = db.sync_to_supabase()
    console.print(json.dumps(result, indent=2))


@app.command()
def continuous(
    scope: str = typer.Option(..., help="Scope name from scopes/<n>.yaml"),
    domain: str = typer.Option(..., help="Domain to monitor (e.g. example.com)"),
):
    """Diff-based recon. Run on cron for continuous new-asset monitoring."""
    import asyncio as _asyncio
    from openclaw.recon.continuous import run_continuous

    diff = _asyncio.run(run_continuous(scope, domain))
    t = Table(title=f"Continuous recon: {scope}/{domain}")
    for col in ("metric", "count", "sample"):
        t.add_column(col)
    t.add_row("New subdomains", str(len(diff.new_subs)), ", ".join(diff.new_subs[:5]))
    t.add_row("Newly live hosts", str(len(diff.newly_live)), ", ".join(diff.newly_live[:5]))
    t.add_row("Removed subs", str(len(diff.removed_subs)), ", ".join(diff.removed_subs[:5]))
    console.print(t)


if __name__ == "__main__":
    app()
