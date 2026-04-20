"""Planner. Decomposes a goal into tool calls.

Returns a `Plan` with ordered steps. The executor runs them.
The analyzer's output feeds back into the planner for next-step replanning.
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from openclaw.api.openrouter import get_llm


SYSTEM_PROMPT = """You are OpenClaw, an elite bug bounty research agent.
You plan multi-step reconnaissance and analysis against AUTHORIZED targets only.

You MUST return a JSON plan with this exact schema:
{
  "reasoning": "brief rationale for this plan",
  "steps": [
    {"tool": "<tool_name>", "target": "<host_or_url>", "args": {...}, "rationale": "why"}
  ],
  "stop_when": "condition to declare done"
}

Available tools:
- subfinder(target=domain)  passive sub enum
- assetfinder(target=domain)  quick sub enum
- httpx(target=url)  single host probe
- httpx_list(target=file_path)  probe a file of hosts
- katana(target=url, depth=3)  JS-aware crawl
- nuclei(target=url, severity="medium,high,critical", tags=optional)  template scan
- naabu(target=host, ports="top-1000")  port scan
- nmap(target=host, scripts=optional)  service version scan
- ffuf(target=url_with_FUZZ, wordlist=path)  content fuzz
- waybackurls(target=domain)  historical URLs

Rules:
1. Chain tools sensibly: subs → probe → crawl → fuzz → nuclei
2. Don't run nuclei blindly against massive lists — scope first
3. If the target is already a specific URL, skip sub enum
4. Prefer low-duplicate vuln classes: OAuth chains, desync, prompt injection,
   business logic, SSRF via PDF/webhooks, mass assignment
5. Respect out_of_scope — if a host looks out of scope, don't include it
6. Keep each plan to 1-5 steps. The agent will replan after observing output.
"""


@dataclass
class PlanStep:
    tool: str
    target: str
    args: dict
    rationale: str = ""


@dataclass
class Plan:
    reasoning: str
    steps: list[PlanStep]
    stop_when: str = ""


class Planner:
    def __init__(self) -> None:
        self.llm = get_llm()

    async def plan(
        self,
        goal: str,
        scope_context: str,
        memory_context: str,
        observation_context: str = "",
    ) -> Plan:
        user = f"""GOAL: {goal}

SCOPE CONTEXT:
{scope_context}

MEMORY (prior lessons):
{memory_context or '(none)'}

OBSERVATIONS SO FAR:
{observation_context or '(none — this is step 0)'}

Produce the next plan. Return ONLY the JSON object, no prose before or after."""

        raw = await self.llm.complete(
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user},
            ],
            task="planner",
            temperature=0.3,
        )
        return _parse_plan(raw)


def _parse_plan(raw: str) -> Plan:
    # Strip markdown fences if model wrapped them
    s = raw.strip()
    m = re.search(r"\{.*\}", s, re.DOTALL)
    if not m:
        return Plan(reasoning="(no valid plan returned)", steps=[], stop_when="")
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return Plan(reasoning="(malformed JSON)", steps=[], stop_when="")

    steps = [
        PlanStep(
            tool=s.get("tool", ""),
            target=s.get("target", ""),
            args=s.get("args", {}) or {},
            rationale=s.get("rationale", ""),
        )
        for s in data.get("steps", [])
        if s.get("tool") and s.get("target")
    ]
    return Plan(
        reasoning=data.get("reasoning", ""),
        steps=steps,
        stop_when=data.get("stop_when", ""),
    )
