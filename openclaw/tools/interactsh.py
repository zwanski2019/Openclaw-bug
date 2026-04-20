"""Interactsh OOB callback bridge.

Interactsh is PD's out-of-band interaction server. Essential for:
- Blind SSRF detection (force the target to hit your callback)
- Blind SSTI / command injection
- Request smuggling confirmation
- XXE / log4shell style attacks

This module:
  1. Registers a session with an interactsh server (self-hosted or oast.site)
  2. Returns a correlation ID to embed in payloads (`<id>.oast.site`)
  3. Polls for callbacks and returns any interactions received

Docs: https://github.com/projectdiscovery/interactsh
"""
from __future__ import annotations
import base64
import json
import os
import secrets
import string
import time
import uuid
from pathlib import Path
import httpx

from openclaw.tools.registry import ToolResult, Tool, register_tool
from openclaw.config import settings


@register_tool
class InteractshPoll(Tool):
    name = "interactsh_poll"
    binary = "__native__"
    skip_scope = True  # talks to OOB server, not the target
    description = "Poll Interactsh server for OOB callbacks on a registered correlation ID"


SESSIONS_FILE = Path("/app/data/interactsh_sessions.json")


def _load_sessions() -> dict:
    if SESSIONS_FILE.exists():
        try:
            return json.loads(SESSIONS_FILE.read_text())
        except json.JSONDecodeError:
            return {}
    return {}


def _save_sessions(sessions: dict) -> None:
    SESSIONS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SESSIONS_FILE.write_text(json.dumps(sessions, indent=2))


async def register_session(server: str = "oast.site") -> dict:
    """Register a new Interactsh session. Returns correlation_id + full hostname to embed.

    Uses the public projectdiscovery oast servers by default. For serious hunting
    run your own: `interactsh-server -domain yours.com`.
    """
    # Simple correlation IDs: 20 chars [a-z0-9]
    correlation_id = "".join(
        secrets.choice(string.ascii_lowercase + string.digits) for _ in range(20)
    )
    secret_key = str(uuid.uuid4())

    payload = {
        "public-key": "",  # we're not using E2EE — keep simple
        "secret-key": secret_key,
        "correlation-id": correlation_id,
    }

    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.post(
            f"https://{server}/register",
            json=payload,
            headers={"Content-Type": "application/json"},
        )
        r.raise_for_status()

    session = {
        "correlation_id": correlation_id,
        "secret_key": secret_key,
        "server": server,
        "hostname": f"{correlation_id}.{server}",
        "created_at": int(time.time()),
    }
    sessions = _load_sessions()
    sessions[correlation_id] = session
    _save_sessions(sessions)
    return session


async def poll_session(correlation_id: str) -> list[dict]:
    """Fetch interactions received for a correlation ID."""
    sessions = _load_sessions()
    if correlation_id not in sessions:
        raise ValueError(f"No local session for {correlation_id}. Register first.")
    sess = sessions[correlation_id]

    async with httpx.AsyncClient(timeout=15.0) as c:
        r = await c.get(
            f"https://{sess['server']}/poll",
            params={"id": correlation_id, "secret": sess["secret_key"]},
        )
        if r.status_code != 200:
            return []
        data = r.json()

    interactions = []
    for raw in data.get("data", []) or []:
        try:
            # Each entry is base64-encoded JSON when E2EE not used; otherwise plain dict
            if isinstance(raw, str):
                decoded = json.loads(base64.b64decode(raw))
            else:
                decoded = raw
            interactions.append({
                "protocol": decoded.get("protocol"),
                "remote_address": decoded.get("remote-address"),
                "timestamp": decoded.get("timestamp"),
                "raw_request": decoded.get("raw-request", "")[:2000],
                "full_id": decoded.get("full-id"),
            })
        except Exception:
            continue

    return interactions


async def execute_interactsh_poll(
    target: str,
    run_id: int,
    step_num: int,
    action: str = "poll",
    server: str = "oast.site",
    **kwargs,
) -> ToolResult:
    """Dispatch entry point. target = correlation_id (for poll) or ignored (for register).

    Action: 'register' | 'poll'
    Register doesn't need scope check (no traffic to target). Poll doesn't either.
    """
    t0 = time.perf_counter()
    try:
        if action == "register":
            sess = await register_session(server=server)
            payload = {"action": "register", "session": sess,
                       "usage": f"Embed `{sess['hostname']}` in your payloads, then poll."}
        elif action == "poll":
            correlation_id = target.split(".")[0] if "." in target else target
            interactions = await poll_session(correlation_id)
            payload = {
                "action": "poll",
                "correlation_id": correlation_id,
                "interactions_count": len(interactions),
                "interactions": interactions,
            }
        else:
            return ToolResult(
                tool="interactsh_poll", target=target, args=[action],
                exit_code=-1, stdout="",
                stderr=f"Unknown action '{action}'. Use 'register' or 'poll'.",
                duration_ms=0, scope_verdict="allowed", error="bad_action",
            )
    except Exception as e:
        return ToolResult(
            tool="interactsh_poll", target=target, args=[action],
            exit_code=-1, stdout="", stderr=str(e),
            duration_ms=int((time.perf_counter() - t0) * 1000),
            scope_verdict="allowed", error="exec_failed",
        )

    duration = int((time.perf_counter() - t0) * 1000)
    run_dir = settings.runs_dir / str(run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = run_dir / f"{step_num:03d}_interactsh.stdout"
    stdout_path.write_text(json.dumps(payload, indent=2))

    return ToolResult(
        tool="interactsh_poll", target=target, args=["interactsh_poll", action],
        exit_code=0,
        stdout=json.dumps(payload, indent=2),
        stderr="",
        duration_ms=duration,
        stdout_path=str(stdout_path),
        stderr_path="",
        scope_verdict="allowed",
    )
