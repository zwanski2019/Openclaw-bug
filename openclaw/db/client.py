"""DB client. SQLite primary. Supabase sync adapter optional.

The agent only ever writes to SQLite synchronously. Supabase sync runs
out-of-band via `sync_to_supabase()` when configured.
"""
from __future__ import annotations
import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator
from openclaw.config import settings


SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def _init_db(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA_PATH.read_text())
    conn.commit()


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    db_path = Path(settings.db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    first_run = not db_path.exists()
    conn = sqlite3.connect(db_path, isolation_level=None)  # autocommit off for txns
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        if first_run:
            _init_db(conn)
        yield conn
    finally:
        conn.close()


# ── Target ops ─────────────────────────────────────────────────
def upsert_target(name: str, platform: str, scope_file: str, notes: str = "") -> int:
    with get_conn() as c:
        c.execute(
            """INSERT INTO targets (name, platform, scope_file, notes)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(name) DO UPDATE SET
                 platform=excluded.platform,
                 scope_file=excluded.scope_file,
                 notes=excluded.notes""",
            (name, platform, scope_file, notes),
        )
        row = c.execute("SELECT id FROM targets WHERE name = ?", (name,)).fetchone()
        return row["id"]


def list_targets() -> list[dict]:
    with get_conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM targets ORDER BY id DESC")]


# ── Run ops ────────────────────────────────────────────────────
def create_run(target_id: int | None, goal: str) -> int:
    with get_conn() as c:
        cur = c.execute(
            "INSERT INTO runs (target_id, goal) VALUES (?, ?)", (target_id, goal)
        )
        return cur.lastrowid


def update_run_status(run_id: int, status: str) -> None:
    with get_conn() as c:
        c.execute(
            "UPDATE runs SET status = ?, finished_at = datetime('now') WHERE id = ?",
            (status, run_id),
        )


def get_run_steps(run_id: int) -> list[dict]:
    with get_conn() as c:
        rows = c.execute(
            "SELECT * FROM agent_steps WHERE run_id = ? ORDER BY step_num ASC",
            (run_id,),
        ).fetchall()
        return [dict(r) for r in rows]


# ── Agent step ops ─────────────────────────────────────────────
def log_step(run_id: int, step_num: int, kind: str, content: dict | str) -> int:
    payload = content if isinstance(content, str) else json.dumps(content)
    with get_conn() as c:
        cur = c.execute(
            "INSERT INTO agent_steps (run_id, step_num, kind, content) VALUES (?, ?, ?, ?)",
            (run_id, step_num, kind, payload),
        )
        return cur.lastrowid


# ── Tool execution ops ─────────────────────────────────────────
def log_tool_execution(
    run_id: int,
    tool_name: str,
    target: str,
    args: list[str],
    stdout_path: str,
    stderr_path: str,
    exit_code: int,
    duration_ms: int,
    scope_verdict: str,
) -> int:
    with get_conn() as c:
        cur = c.execute(
            """INSERT INTO tool_executions
               (run_id, tool_name, target, args_json, stdout_path, stderr_path,
                exit_code, duration_ms, scope_verdict)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (run_id, tool_name, target, json.dumps(args), stdout_path,
             stderr_path, exit_code, duration_ms, scope_verdict),
        )
        return cur.lastrowid


# ── Candidates ─────────────────────────────────────────────────
def add_candidate(
    run_id: int | None,
    target_id: int | None,
    title: str,
    vuln_class: str,
    affected_url: str,
    severity_guess: str,
    evidence: dict,
    reasoning: str,
) -> int:
    with get_conn() as c:
        cur = c.execute(
            """INSERT INTO candidates
               (run_id, target_id, title, vuln_class, affected_url,
                severity_guess, evidence_json, agent_reasoning)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (run_id, target_id, title, vuln_class, affected_url,
             severity_guess, json.dumps(evidence), reasoning),
        )
        return cur.lastrowid


def list_candidates(status: str | None = None) -> list[dict]:
    with get_conn() as c:
        if status:
            rows = c.execute(
                "SELECT * FROM candidates WHERE status = ? ORDER BY id DESC", (status,)
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM candidates ORDER BY id DESC"
            ).fetchall()
        return [dict(r) for r in rows]


def update_candidate_status(candidate_id: int, status: str) -> None:
    with get_conn() as c:
        c.execute(
            "UPDATE candidates SET status = ?, reviewed_at = datetime('now') WHERE id = ?",
            (status, candidate_id),
        )


# ── Memory ─────────────────────────────────────────────────────
def add_memory(scope: str, kind: str, content: str) -> int:
    with get_conn() as c:
        cur = c.execute(
            "INSERT INTO memory (scope, kind, content) VALUES (?, ?, ?)",
            (scope, kind, content),
        )
        return cur.lastrowid


def recall_memory(scope: str, kind: str | None = None, limit: int = 50) -> list[dict]:
    with get_conn() as c:
        if kind:
            rows = c.execute(
                "SELECT * FROM memory WHERE scope IN (?, 'global') AND kind = ? ORDER BY id DESC LIMIT ?",
                (scope, kind, limit),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM memory WHERE scope IN (?, 'global') ORDER BY id DESC LIMIT ?",
                (scope, limit),
            ).fetchall()
        return [dict(r) for r in rows]


# ── Reports ────────────────────────────────────────────────────
def save_report(
    candidate_id: int,
    target_id: int | None,
    title: str,
    markdown: str,
    cvss_vector: str = "",
    cvss_score: float = 0.0,
    platform: str = "",
) -> int:
    with get_conn() as c:
        cur = c.execute(
            """INSERT INTO reports
               (candidate_id, target_id, title, markdown, cvss_vector, cvss_score, platform)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (candidate_id, target_id, title, markdown, cvss_vector, cvss_score, platform),
        )
        return cur.lastrowid


def list_reports() -> list[dict]:
    with get_conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM reports ORDER BY id DESC")]


# ── Supabase sync (optional) ───────────────────────────────────
def sync_to_supabase() -> dict:
    """Push local tables to Supabase. No-op if not configured."""
    if not settings.has_supabase():
        return {"synced": False, "reason": "not_configured"}
    try:
        from supabase import create_client
        sb = create_client(settings.supabase_url, settings.supabase_key)
        synced = {}
        with get_conn() as c:
            for table in ("targets", "runs", "candidates", "reports"):
                rows = [dict(r) for r in c.execute(f"SELECT * FROM {table}")]
                if rows:
                    sb.table(table).upsert(rows).execute()
                synced[table] = len(rows)
        return {"synced": True, "counts": synced}
    except Exception as e:
        return {"synced": False, "reason": str(e)}
