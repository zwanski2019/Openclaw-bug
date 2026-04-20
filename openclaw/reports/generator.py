"""Report generation. Candidate → markdown report.

Uses LLM to structure the narrative, enforces canonical HackerOne/Bugcrowd
template, suggests CVSS 3.1 vector. Hunter reviews and edits before submission.
"""
from __future__ import annotations
import json
import re
from dataclasses import dataclass
from openclaw.api.openrouter import get_llm
from openclaw.config import settings
from openclaw.db import client as db


REPORT_SYSTEM = """You write bug bounty reports for a senior hunter.

Match this tone: direct, technical, no corporate filler, attacker POV.
No disclaimers. No "responsible disclosure" preamble — the hunter already
operates in that space.

Template:
# [Title: Vuln Type + Location + Impact]

## Summary
One tight paragraph: what's broken, attack flow, what the attacker gains.

## Impact
Concrete business impact. User/data exposure scope. Attacker prerequisites
(authenticated? what privilege level?). Regulatory implications if relevant
(GDPR, HIPAA, PCI).

## Steps to Reproduce
Numbered. Each step reproducible from a clean incognito session.
Include exact URLs, HTTP methods, headers, two-account PoC if authz issue.
Show request/response blocks as code fences.

## Proof of Concept
Describe the PoC. Reference screenshots/video by name (e.g. `[poc-1.png]`).
Include standalone curl or Python script that reliably triggers.

## Suggested Fix
Specific, not generic. "Enforce server-side authorization check on user_id
against session owner" NOT "fix authorization."

## CVSS 3.1
Vector string + score. Justify any debatable metric.

## References
CWE, OWASP, similar disclosed reports if relevant.

---

Return JSON:
{
  "title": "...",
  "markdown": "the full report body in markdown",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
  "cvss_score": 7.5
}
"""


@dataclass
class GeneratedReport:
    title: str
    markdown: str
    cvss_vector: str
    cvss_score: float


class ReportGenerator:
    def __init__(self) -> None:
        self.llm = get_llm()

    async def generate(self, candidate_id: int) -> GeneratedReport:
        candidates = [c for c in db.list_candidates() if c["id"] == candidate_id]
        if not candidates:
            raise ValueError(f"candidate {candidate_id} not found")
        cand = candidates[0]

        try:
            evidence = json.loads(cand.get("evidence_json") or "{}")
        except json.JSONDecodeError:
            evidence = {}

        user = f"""CANDIDATE:
Title: {cand['title']}
Vuln class: {cand['vuln_class']}
Affected URL: {cand['affected_url']}
Severity guess: {cand['severity_guess']}
Agent reasoning: {cand['agent_reasoning']}
Evidence: {json.dumps(evidence, indent=2)}

Hunter handle: {settings.hunter_handle}
Hunter email: {settings.hunter_email}

Produce the report JSON per schema."""

        raw = await self.llm.complete(
            messages=[
                {"role": "system", "content": REPORT_SYSTEM},
                {"role": "user", "content": user},
            ],
            task="report",
            temperature=0.3,
            max_tokens=4000,
        )
        return _parse_report(raw)

    async def generate_and_save(self, candidate_id: int, platform: str = "") -> int:
        """Generate + persist. Returns report id."""
        report = await self.generate(candidate_id)
        candidates = [c for c in db.list_candidates() if c["id"] == candidate_id]
        target_id = candidates[0].get("target_id") if candidates else None

        report_id = db.save_report(
            candidate_id=candidate_id,
            target_id=target_id,
            title=report.title,
            markdown=report.markdown,
            cvss_vector=report.cvss_vector,
            cvss_score=report.cvss_score,
            platform=platform,
        )
        db.update_candidate_status(candidate_id, "promoted")
        return report_id


def _parse_report(raw: str) -> GeneratedReport:
    s = raw.strip()
    m = re.search(r"\{.*\}", s, re.DOTALL)
    if m:
        try:
            data = json.loads(m.group(0))
            return GeneratedReport(
                title=data.get("title", "Untitled"),
                markdown=data.get("markdown", raw),
                cvss_vector=data.get("cvss_vector", ""),
                cvss_score=float(data.get("cvss_score") or 0.0),
            )
        except (json.JSONDecodeError, ValueError):
            pass
    # Fallback: treat entire response as markdown
    return GeneratedReport(
        title="Generated Report (review)",
        markdown=raw,
        cvss_vector="",
        cvss_score=0.0,
    )
