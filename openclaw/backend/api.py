"""Backend API for split deployment (Railway backend + Streamlit frontend)."""
from __future__ import annotations

import asyncio
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from openclaw.agent.loop import AgentLoop
from openclaw.api.openrouter import get_llm
from openclaw.db import client as db
from openclaw.safety.scope import load_all_scopes
from openclaw.tools.registry import list_tools
from openclaw.reports.generator import ReportGenerator


app = FastAPI(title="OpenClaw Backend", version="1.0.0")


class RunRequest(BaseModel):
    scope_name: str
    target: str
    goal: str
    max_steps: int = 20


class StatusUpdateRequest(BaseModel):
    status: str


class PromoteRequest(BaseModel):
    candidate_id: int


class ChatRequest(BaseModel):
    messages: list[dict[str, str]]
    task: str = "planner"
    temperature: float = 0.4


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/dashboard")
def dashboard() -> dict[str, Any]:
    targets = db.list_targets()
    candidates = db.list_candidates()
    reports = db.list_reports()
    pending = [c for c in candidates if c["status"] == "pending"]
    return {
        "targets_count": len(targets),
        "pending_count": len(pending),
        "candidates_count": len(candidates),
        "reports_count": len(reports),
        "recent_candidates": candidates[:10],
    }


@app.get("/tools")
def tools() -> list[dict[str, Any]]:
    return list_tools()


@app.get("/scopes")
def scopes() -> dict[str, dict[str, Any]]:
    scopes_map = load_all_scopes()
    return {
        name: {
            "name": scope.name,
            "platform": scope.platform,
            "in_scope": scope.in_scope,
            "out_of_scope": scope.out_of_scope,
            "rate_limit_rps": scope.rate_limit_rps,
            "allowed_tools": scope.allowed_tools,
            "notes": scope.notes,
        }
        for name, scope in scopes_map.items()
    }


@app.get("/candidates")
def candidates(status: str | None = None) -> list[dict[str, Any]]:
    return db.list_candidates(status=status)


@app.post("/candidates/{candidate_id}/status")
def update_candidate_status(candidate_id: int, req: StatusUpdateRequest) -> dict[str, bool]:
    valid = {"pending", "promoted", "rejected", "dup_self"}
    if req.status not in valid:
        raise HTTPException(status_code=400, detail=f"status must be one of {sorted(valid)}")
    db.update_candidate_status(candidate_id, req.status)
    return {"ok": True}


@app.get("/reports")
def reports() -> list[dict[str, Any]]:
    return db.list_reports()


@app.post("/reports/promote")
def promote_report(req: PromoteRequest) -> dict[str, int]:
    report_id = asyncio.run(ReportGenerator().generate_and_save(req.candidate_id))
    return {"report_id": report_id}


@app.post("/runs")
def run_agent(req: RunRequest) -> dict[str, Any]:
    scopes = load_all_scopes()
    scope = scopes.get(req.scope_name)
    if scope is None:
        raise HTTPException(status_code=404, detail=f"scope '{req.scope_name}' not found")

    target_id = db.upsert_target(
        name=scope.name,
        platform=scope.platform,
        scope_file=f"scopes/{scope.name}.yaml",
        notes=scope.notes,
    )

    async def drive() -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        loop = AgentLoop()
        async for event in loop.run(
            goal=req.goal,
            target_host=req.target,
            target_id=target_id,
            max_steps=req.max_steps,
        ):
            events.append(event.to_dict())
        return events

    events = asyncio.run(drive())
    return {"events": events}


@app.post("/chat")
def chat(req: ChatRequest) -> dict[str, str]:
    async def complete() -> str:
        llm = get_llm()
        output = []
        async for chunk in llm.stream(
            messages=req.messages,
            task=req.task,  # type: ignore[arg-type]
            temperature=req.temperature,
        ):
            output.append(chunk)
        return "".join(output)

    content = asyncio.run(complete())
    return {"content": content}
