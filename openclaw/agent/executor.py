"""Executor. Runs planner steps and persists results."""
from __future__ import annotations
from openclaw.agent.planner import PlanStep
from openclaw.tools import registry, parser
from openclaw.db import client as db


PARSERS = {
    "subfinder": parser.parse_subfinder,
    "assetfinder": parser.parse_assetfinder,
    "httpx": parser.parse_httpx,
    "httpx_list": parser.parse_httpx,
    "nuclei": parser.parse_nuclei,
    "naabu": parser.parse_naabu,
    "waybackurls": parser.parse_waybackurls,
}


class Executor:
    async def execute_step(
        self,
        step: PlanStep,
        run_id: int,
        step_num: int,
    ) -> dict:
        """Run one step. Returns dict with result + parsed + metadata."""
        result = await registry.execute(
            tool_name=step.tool,
            target=step.target,
            run_id=run_id,
            step_num=step_num,
            **step.args,
        )

        db.log_tool_execution(
            run_id=run_id,
            tool_name=result.tool,
            target=result.target,
            args=result.args,
            stdout_path=result.stdout_path,
            stderr_path=result.stderr_path,
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            scope_verdict=result.scope_verdict,
        )

        parsed = None
        if result.exit_code == 0 and step.tool in PARSERS:
            try:
                parsed = PARSERS[step.tool](result.stdout)
            except Exception as e:
                parsed = {"_parse_error": str(e)}

        return {
            "tool": step.tool,
            "target": step.target,
            "args": step.args,
            "exit_code": result.exit_code,
            "duration_ms": result.duration_ms,
            "scope_verdict": result.scope_verdict,
            "stdout_truncated": result.stdout[:4000],
            "stderr_truncated": result.stderr[:1000],
            "stdout_path": result.stdout_path,
            "parsed": parsed,
            "error": result.error,
        }
