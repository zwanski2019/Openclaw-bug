"""Analyzer. Consumes parsed tool output, produces:
  - natural-language observation summary (fed back to planner)
  - candidate vulnerabilities (written to candidates table for human review)

Candidates are NEVER auto-promoted to reports. They live in a queue until
the hunter manually reviews and promotes. This is the adversarial self-review
gate.
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from openclaw.api.openrouter import get_llm
from openclaw.tools.parser import extract_insights
from openclaw.db import client as db
from openclaw.safety import dedup


ANALYZER_SYSTEM = """You are a senior bug bounty analyst reviewing recon output.

Your job:
1. Summarize what the tools found (2-4 sentences, concrete facts only).
2. Flag CANDIDATE vulnerabilities — things worth a hunter's manual follow-up.
3. Suggest next investigation steps.

STRICT RULES:
- Never invent findings. Only flag things supported by the actual output.
- Be conservative on severity — default 'medium' unless evidence is strong.
- Prefer LOW-DUPLICATE vuln classes: OAuth chains, HTTP desync, prompt injection,
  business logic, SSRF via PDF/webhook, mass assignment, race conditions,
  JWT algo confusion, prototype pollution, cache deception, GraphQL batching.
- Skip informational noise (missing headers, version banners alone).
- Each candidate MUST include: title, vuln_class, affected_url, severity_guess,
  evidence (concrete data from output), reasoning (why it's worth pursuing).

Return JSON ONLY:
{
  "summary": "short plain-English summary of what was found",
  "candidates": [
    {
      "title": "...",
      "vuln_class": "IDOR|SSRF|OAuth|Desync|LLM_PI|BusinessLogic|XSS|SQLi|RCE|...",
      "affected_url": "...",
      "severity_guess": "informational|low|medium|high|critical",
      "evidence": {"key": "value from actual output"},
      "reasoning": "why this deserves manual follow-up, and what the attacker gains"
    }
  ],
  "next_steps": ["concrete next action 1", "..."]
}
"""


@dataclass
class Analysis:
    summary: str
    candidates: list[dict]
    next_steps: list[str]
    candidates_created: list[int] = None
    candidates_filtered: int = 0

    def __post_init__(self):
        if self.candidates_created is None:
            self.candidates_created = []


class Analyzer:
    def __init__(self) -> None:
        self.llm = get_llm()

    async def analyze(
        self,
        run_id: int,
        target_id: int | None,
        observations: list[dict],
        scope_name: str = "global",
        use_local: bool = False,
    ) -> Analysis:
        """Runs LLM over observations, writes candidates to DB, returns Analysis."""
        insights = extract_insights({
            obs["tool"]: obs.get("parsed")
            for obs in observations
            if obs.get("parsed") is not None
        })

        # Cap observation payload sent to LLM — full files stay on disk
        obs_slim = []
        for obs in observations:
            parsed = obs.get("parsed")
            # Truncate parsed lists / dicts to keep prompt small
            if isinstance(parsed, list):
                parsed_sample = parsed[:50]
                parsed_note = f"... ({len(parsed)} total, showing 50)" if len(parsed) > 50 else ""
            else:
                parsed_sample = parsed
                parsed_note = ""

            obs_slim.append({
                "tool": obs["tool"],
                "target": obs["target"],
                "exit_code": obs["exit_code"],
                "parsed_sample": parsed_sample,
                "parsed_note": parsed_note,
                "stderr": obs.get("stderr_truncated", "")[:300],
            })

        user = f"""INSIGHTS:
{json.dumps(insights, indent=2)}

OBSERVATIONS:
{json.dumps(obs_slim, indent=2, default=str)}

Analyze and return JSON per schema."""

        raw = await self.llm.complete(
            messages=[
                {"role": "system", "content": ANALYZER_SYSTEM},
                {"role": "user", "content": user},
            ],
            task="local" if use_local else "analyzer",
            temperature=0.2,
            max_tokens=3000,
        )

        analysis = _parse_analysis(raw)

        # Persist candidates — with dedup check against prior runs
        fresh, duplicates = [], 0
        for c in analysis.candidates:
            was_dup, fp = dedup.check_and_remember(
                scope=scope_name,
                vuln_class=c.get("vuln_class", "unknown"),
                affected_url=c.get("affected_url", ""),
                evidence=c.get("evidence", {}),
            )
            if was_dup:
                duplicates += 1
                continue
            cid = db.add_candidate(
                run_id=run_id,
                target_id=target_id,
                title=c.get("title", "(untitled)"),
                vuln_class=c.get("vuln_class", "unknown"),
                affected_url=c.get("affected_url", ""),
                severity_guess=c.get("severity_guess", "medium"),
                evidence={**c.get("evidence", {}), "_fp": fp},
                reasoning=c.get("reasoning", ""),
            )
            fresh.append(cid)

        # Stash dedup stats onto the analysis for UI display
        analysis.candidates_filtered = duplicates
        analysis.candidates_created = fresh
        return analysis


def _parse_analysis(raw: str) -> Analysis:
    s = raw.strip()
    m = re.search(r"\{.*\}", s, re.DOTALL)
    if not m:
        return Analysis(summary="(no analysis parsed)", candidates=[], next_steps=[])
    try:
        data = json.loads(m.group(0))
    except json.JSONDecodeError:
        return Analysis(summary="(malformed analysis JSON)", candidates=[], next_steps=[])

    return Analysis(
        summary=data.get("summary", ""),
        candidates=data.get("candidates", []) or [],
        next_steps=data.get("next_steps", []) or [],
    )
