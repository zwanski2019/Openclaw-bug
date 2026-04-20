"""Tool registry. Decorator-based plugin system.

Every tool:
  - Declares its binary name and arg builder
  - Cannot do shell interpolation — args are list[str] subprocess.run style
  - Output is captured, truncated, persisted to data/runs/<run_id>/
"""
from __future__ import annotations
import asyncio
import shutil
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, ClassVar

from openclaw.config import settings
from openclaw.safety.scope import assert_allowed, extract_host
from openclaw.safety.rate_limit import get_registry as rl_registry


@dataclass
class ToolResult:
    tool: str
    target: str
    args: list[str]
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: int
    stdout_path: str = ""
    stderr_path: str = ""
    scope_verdict: str = "allowed"
    error: str = ""


class Tool:
    """Base class. Subclass and register with @register_tool."""
    name: ClassVar[str] = ""
    binary: ClassVar[str] = ""
    description: ClassVar[str] = ""
    default_timeout: ClassVar[int] = 0  # 0 = use settings

    def build_args(self, target: str, **kwargs) -> list[str]:
        raise NotImplementedError


_REGISTRY: dict[str, type[Tool]] = {}


def register_tool(cls: type[Tool]) -> type[Tool]:
    if not cls.name:
        raise ValueError(f"{cls.__name__} must set .name")
    _REGISTRY[cls.name] = cls
    return cls


def get_tool(name: str) -> Tool:
    if name not in _REGISTRY:
        raise KeyError(f"Tool '{name}' not registered. Available: {list(_REGISTRY)}")
    return _REGISTRY[name]()


def list_tools() -> list[dict]:
    return [
        {"name": c.name, "binary": c.binary, "description": c.description,
         "available": shutil.which(c.binary) is not None}
        for c in _REGISTRY.values()
    ]


async def execute(
    tool_name: str,
    target: str,
    run_id: int,
    step_num: int,
    **kwargs,
) -> ToolResult:
    """Primary entry point. Enforces scope, runs binary, captures output."""
    tool = get_tool(tool_name)

    # ── Scope gate (tools can opt out with skip_scope=True class attr) ──
    skip_scope = getattr(tool, "skip_scope", False)
    scope = None
    if not skip_scope:
        try:
            scope = assert_allowed(target, tool_name)
        except Exception as e:
            return ToolResult(
                tool=tool_name, target=target, args=[],
                exit_code=-1, stdout="", stderr=str(e),
                duration_ms=0, scope_verdict="blocked", error=str(e),
            )

    # ── Rate limit (per-scope; skip if no scope) ────────────────
    if scope is not None:
        bucket = await rl_registry().get(scope.name, scope.rate_limit_rps)
        await bucket.acquire(cost=1.0)

    # ── Native (non-binary) tool dispatch ───────────────────────
    if tool.binary == "__native__":
        return await _dispatch_native(tool_name, target, run_id, step_num, **kwargs)

    if not shutil.which(tool.binary):
        return ToolResult(
            tool=tool_name, target=target, args=[],
            exit_code=-1, stdout="",
            stderr=f"Binary '{tool.binary}' not found in PATH",
            duration_ms=0, scope_verdict="allowed",
            error="binary_missing",
        )

    args = [tool.binary] + tool.build_args(target, **kwargs)
    timeout = tool.default_timeout or settings.tool_timeout_seconds

    # Per-run output dir
    run_dir = settings.runs_dir / str(run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = run_dir / f"{step_num:03d}_{tool_name}.stdout"
    stderr_path = run_dir / f"{step_num:03d}_{tool_name}.stderr"

    t0 = time.perf_counter()
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return ToolResult(
                tool=tool_name, target=target, args=args,
                exit_code=-1, stdout="",
                stderr=f"Timeout after {timeout}s",
                duration_ms=int((time.perf_counter() - t0) * 1000),
                scope_verdict="allowed", error="timeout",
            )
    except FileNotFoundError as e:
        return ToolResult(
            tool=tool_name, target=target, args=args,
            exit_code=-1, stdout="", stderr=str(e),
            duration_ms=0, scope_verdict="allowed", error="exec_failed",
        )

    duration_ms = int((time.perf_counter() - t0) * 1000)

    # Cap output size
    max_b = settings.tool_output_max_bytes
    stdout_b = stdout[:max_b]
    stderr_b = stderr[:max_b]

    stdout_path.write_bytes(stdout_b)
    stderr_path.write_bytes(stderr_b)

    return ToolResult(
        tool=tool_name, target=target, args=args,
        exit_code=proc.returncode or 0,
        stdout=stdout_b.decode("utf-8", errors="replace"),
        stderr=stderr_b.decode("utf-8", errors="replace"),
        duration_ms=duration_ms,
        stdout_path=str(stdout_path),
        stderr_path=str(stderr_path),
        scope_verdict="allowed",
    )


async def _dispatch_native(tool_name: str, target: str, run_id: int, step_num: int, **kwargs) -> ToolResult:
    """Route native (non-binary) tools to their async handler."""
    if tool_name == "ai_probe":
        from openclaw.tools.ai_probe import execute_ai_probe
        return await execute_ai_probe(target, run_id, step_num, **kwargs)
    if tool_name == "favicon":
        from openclaw.tools.favicon import execute_favicon_pivot
        return await execute_favicon_pivot(target, run_id, step_num, **kwargs)
    if tool_name == "interactsh_poll":
        from openclaw.tools.interactsh import execute_interactsh_poll
        return await execute_interactsh_poll(target, run_id, step_num, **kwargs)
    return ToolResult(
        tool=tool_name, target=target, args=[],
        exit_code=-1, stdout="",
        stderr=f"Native tool '{tool_name}' has no dispatcher",
        duration_ms=0, scope_verdict="allowed", error="no_dispatcher",
    )


# Import plugins so they self-register
from openclaw.tools import recon as _recon  # noqa: F401,E402
from openclaw.tools import github_recon as _gh  # noqa: F401,E402
from openclaw.tools import ai_probe as _ai  # noqa: F401,E402
from openclaw.tools import favicon as _fav  # noqa: F401,E402
from openclaw.tools import interactsh as _int  # noqa: F401,E402
