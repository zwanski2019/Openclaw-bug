"""Main agent loop. ReAct style: plan → execute → analyze → reflect → replan.

Emits step events via async generator so the UI can render in real time.
Enforces max_agent_steps to prevent runaway loops.
"""
from __future__ import annotations
import json
from dataclasses import dataclass, field
from typing import AsyncIterator
from openclaw.config import settings
from openclaw.agent.planner import Planner, Plan
from openclaw.agent.executor import Executor
from openclaw.agent.analyzer import Analyzer, Analysis
from openclaw.agent.memory import ShortTermMemory, LongTermMemory
from openclaw.safety.scope import load_all_scopes, find_scope_for_host, extract_host
from openclaw.db import client as db


@dataclass
class AgentEvent:
    """Emitted to UI / logs during loop execution."""
    kind: str  # plan | tool_start | tool_done | analysis | reflection | done | error
    payload: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "payload": self.payload}


class AgentLoop:
    def __init__(self) -> None:
        self.planner = Planner()
        self.executor = Executor()
        self.analyzer = Analyzer()

    async def run(
        self,
        goal: str,
        target_host: str,
        target_id: int | None = None,
        max_steps: int | None = None,
    ) -> AsyncIterator[AgentEvent]:
        """Yield AgentEvents as the loop progresses."""
        max_steps = max_steps or settings.max_agent_steps

        # ── Resolve scope ────────────────────────────────────────
        host = extract_host(target_host)
        scope = find_scope_for_host(host) if host else None
        if scope is None:
            yield AgentEvent("error", {
                "message": f"No scope file matches host '{host}'. "
                           f"Create scopes/<n>.yaml with this host in in_scope.",
            })
            return

        scope_name = scope.name
        scope_context = json.dumps({
            "name": scope.name,
            "platform": scope.platform,
            "in_scope": scope.in_scope,
            "out_of_scope": scope.out_of_scope,
            "allowed_tools": scope.allowed_tools or "[default recon set]",
            "rate_limit_rps": scope.rate_limit_rps,
            "notes": scope.notes,
        }, indent=2)

        # ── Initialize run + memory ──────────────────────────────
        run_id = db.create_run(target_id=target_id, goal=goal)
        short_mem = ShortTermMemory(max_size=50)
        long_mem = LongTermMemory(scope=scope_name)
        observation_history: list[dict] = []

        yield AgentEvent("started", {"run_id": run_id, "scope": scope_name, "goal": goal})

        step_counter = 0
        try:
            while step_counter < max_steps:
                # ── PLAN ────────────────────────────────────────
                memory_ctx = "\n".join(long_mem.lessons()[:10])
                obs_ctx = short_mem.to_context()

                plan = await self.planner.plan(
                    goal=goal,
                    scope_context=scope_context,
                    memory_context=memory_ctx,
                    observation_context=obs_ctx,
                )

                db.log_step(run_id, step_counter, "plan", {
                    "reasoning": plan.reasoning,
                    "steps": [{"tool": s.tool, "target": s.target, "args": s.args,
                               "rationale": s.rationale} for s in plan.steps],
                    "stop_when": plan.stop_when,
                })
                yield AgentEvent("plan", {
                    "step": step_counter,
                    "reasoning": plan.reasoning,
                    "actions": [f"{s.tool}({s.target})" for s in plan.steps],
                    "stop_when": plan.stop_when,
                })

                if not plan.steps:
                    yield AgentEvent("done", {
                        "reason": "planner returned no further steps",
                        "run_id": run_id,
                    })
                    db.update_run_status(run_id, "complete")
                    return

                # ── EXECUTE each step in plan ───────────────────
                step_observations: list[dict] = []
                for plan_step in plan.steps:
                    step_counter += 1
                    if step_counter > max_steps:
                        break

                    yield AgentEvent("tool_start", {
                        "step": step_counter,
                        "tool": plan_step.tool,
                        "target": plan_step.target,
                        "args": plan_step.args,
                        "rationale": plan_step.rationale,
                    })

                    obs = await self.executor.execute_step(
                        step=plan_step,
                        run_id=run_id,
                        step_num=step_counter,
                    )
                    step_observations.append(obs)
                    observation_history.append(obs)

                    db.log_step(run_id, step_counter, "tool_call", obs)

                    summary = _summarize_observation(obs)
                    short_mem.remember({
                        "kind": "tool_result",
                        "summary": summary,
                    })

                    yield AgentEvent("tool_done", {
                        "step": step_counter,
                        "tool": plan_step.tool,
                        "target": plan_step.target,
                        "exit_code": obs["exit_code"],
                        "scope_verdict": obs["scope_verdict"],
                        "duration_ms": obs["duration_ms"],
                        "summary": summary,
                        "stdout_path": obs.get("stdout_path", ""),
                    })

                # ── ANALYZE the batch ───────────────────────────
                analysis = await self.analyzer.analyze(
                    run_id=run_id,
                    target_id=target_id,
                    observations=step_observations,
                    scope_name=scope_name,
                )

                db.log_step(run_id, step_counter, "observation", {
                    "summary": analysis.summary,
                    "candidates_count": len(analysis.candidates),
                    "next_steps": analysis.next_steps,
                })

                yield AgentEvent("analysis", {
                    "summary": analysis.summary,
                    "candidates_count": len(analysis.candidates),
                    "candidates_new": len(analysis.candidates_created),
                    "candidates_filtered_as_dup": analysis.candidates_filtered,
                    "candidates_preview": [
                        {"title": c.get("title"),
                         "vuln_class": c.get("vuln_class"),
                         "severity": c.get("severity_guess")}
                        for c in analysis.candidates
                    ],
                    "next_steps": analysis.next_steps,
                })

                short_mem.remember({
                    "kind": "analysis",
                    "summary": analysis.summary,
                })

                # ── REFLECT: stop condition? ────────────────────
                if _should_stop(plan, analysis, step_counter, max_steps):
                    db.log_step(run_id, step_counter, "reflect", {
                        "decision": "stop", "reason": "goal satisfied or no useful next step",
                    })
                    yield AgentEvent("done", {
                        "reason": "stop condition met",
                        "run_id": run_id,
                        "total_steps": step_counter,
                        "candidates_written": sum(1 for _ in db.list_candidates())
                            if False else None,  # UI queries fresh
                    })
                    db.update_run_status(run_id, "complete")
                    return

            # Max steps hit
            yield AgentEvent("done", {
                "reason": f"max_agent_steps ({max_steps}) reached",
                "run_id": run_id,
                "total_steps": step_counter,
            })
            db.update_run_status(run_id, "complete")

        except Exception as e:
            db.update_run_status(run_id, "error")
            yield AgentEvent("error", {"message": str(e), "run_id": run_id})
            raise


def _summarize_observation(obs: dict) -> str:
    """Pack an observation into a single-line summary for short-term memory."""
    tool = obs["tool"]
    if obs["scope_verdict"] == "blocked":
        return f"{tool}({obs['target']}) BLOCKED by scope"
    if obs["exit_code"] != 0:
        err = obs.get("error") or obs.get("stderr_truncated", "")[:100]
        return f"{tool}({obs['target']}) failed exit={obs['exit_code']}: {err}"

    parsed = obs.get("parsed")
    if isinstance(parsed, list):
        return f"{tool}({obs['target']}) → {len(parsed)} results"
    if isinstance(parsed, dict):
        return f"{tool}({obs['target']}) → dict with {len(parsed)} keys"
    return f"{tool}({obs['target']}) → exit 0"


def _should_stop(plan: Plan, analysis: Analysis, step: int, max_steps: int) -> bool:
    if step >= max_steps:
        return True
    if not analysis.next_steps:
        return True
    # If planner provided an explicit stop condition, check it naively
    if plan.stop_when and any(
        kw in analysis.summary.lower()
        for kw in ("no further", "exhausted", "complete", "satisfied")
    ):
        return True
    return False
