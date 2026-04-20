"""Streamlit UI for OpenClaw.

Pages:
  - Dashboard       (targets, scopes, tools availability)
  - Run Agent       (goal + target → live streaming agent steps)
  - Candidates      (findings queue, review & promote)
  - Reports         (generated markdown reports, copy/export)
  - Chat            (free-form conversation, agent can plan/execute from chat)
"""
from __future__ import annotations
import asyncio
import json
import streamlit as st

from openclaw.config import settings
from openclaw.db import client as db
from openclaw.tools.registry import list_tools
from openclaw.safety.scope import load_all_scopes
from openclaw.agent.loop import AgentLoop
from openclaw.reports.generator import ReportGenerator


st.set_page_config(
    page_title="OpenClaw",
    page_icon="🦅",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Light styling ─────────────────────────────────────────────
st.markdown("""
<style>
.stAlert { border-radius: 4px; }
code { font-size: 13px; }
.step-plan { border-left: 3px solid #3b82f6; padding: 8px 12px; background: #1e293b22; margin: 6px 0; }
.step-tool { border-left: 3px solid #10b981; padding: 8px 12px; background: #064e3b22; margin: 6px 0; }
.step-analysis { border-left: 3px solid #f59e0b; padding: 8px 12px; background: #78350f22; margin: 6px 0; }
.step-error { border-left: 3px solid #ef4444; padding: 8px 12px; background: #7f1d1d22; margin: 6px 0; }
</style>
""", unsafe_allow_html=True)


# ── Sidebar ───────────────────────────────────────────────────
with st.sidebar:
    st.title("🦅 OpenClaw")
    st.caption(f"Hunter: `{settings.hunter_handle}`")
    page = st.radio(
        "Navigate",
        ["Dashboard", "Run Agent", "Candidates", "Reports", "Chat", "Tools & Scopes"],
        label_visibility="collapsed",
    )

    st.divider()
    st.caption("Backend")
    if settings.has_openrouter():
        st.success("OpenRouter: connected", icon="✓")
    else:
        st.warning("OpenRouter: no key (Ollama only)")
    if settings.has_supabase():
        st.success("Supabase: sync enabled", icon="✓")

    st.caption(f"DB: `{settings.db_path}`")


# ═══════════════════════════════════════════════════════════════
# Dashboard
# ═══════════════════════════════════════════════════════════════
if page == "Dashboard":
    st.header("Dashboard")

    col1, col2, col3, col4 = st.columns(4)
    targets = db.list_targets()
    candidates = db.list_candidates()
    pending = [c for c in candidates if c["status"] == "pending"]
    reports = db.list_reports()

    col1.metric("Targets", len(targets))
    col2.metric("Pending candidates", len(pending))
    col3.metric("Total candidates", len(candidates))
    col4.metric("Reports", len(reports))

    st.divider()

    st.subheader("Recent candidates (top 10)")
    if candidates:
        for c in candidates[:10]:
            with st.container(border=True):
                cols = st.columns([3, 1, 1, 1])
                cols[0].markdown(f"**{c['title']}**")
                cols[0].caption(f"{c['vuln_class']} · `{c['affected_url']}`")
                cols[1].write(c["severity_guess"])
                cols[2].code(c["status"], language=None)
                cols[3].caption(c["created_at"])
    else:
        st.info("No candidates yet. Run the agent first.")


# ═══════════════════════════════════════════════════════════════
# Run Agent (goal mode)
# ═══════════════════════════════════════════════════════════════
elif page == "Run Agent":
    st.header("Run agent on target")

    scopes = load_all_scopes()
    if not scopes:
        st.error("No scope files found. Create `scopes/<target>.yaml` first.")
        with st.expander("Example scope file"):
            st.code("""name: example-program
platform: hackerone
in_scope:
  - "*.example.com"
  - "api.example.net"
out_of_scope:
  - "blog.example.com"
rate_limit_rps: 5
allowed_tools:
  - subfinder
  - httpx
  - nuclei
notes: |
  Program notes here.
""", language="yaml")
        st.stop()

    col1, col2 = st.columns([2, 1])
    with col1:
        scope_name = st.selectbox(
            "Scope",
            options=list(scopes.keys()),
            help="Agent is hard-blocked from touching anything outside this scope.",
        )
    scope = scopes[scope_name]
    with col2:
        max_steps = st.number_input(
            "Max agent steps", min_value=1, max_value=100,
            value=settings.max_agent_steps,
        )

    with st.expander("Scope details", expanded=False):
        st.json({
            "in_scope": scope.in_scope,
            "out_of_scope": scope.out_of_scope,
            "allowed_tools": scope.allowed_tools or "(default recon set)",
        })

    target = st.text_input(
        "Target host or URL",
        placeholder="api.example.com or https://api.example.com/v1/",
    )

    goal = st.text_area(
        "Goal",
        placeholder="e.g. Enumerate subdomains, identify exposed admin panels, "
                    "and flag candidates for OAuth / IDOR / SSRF testing.",
        height=100,
    )

    run_btn = st.button("Run agent", type="primary", disabled=not (target and goal))

    if run_btn:
        # Ensure target registered
        target_id = db.upsert_target(
            name=scope.name,
            platform=scope.platform,
            scope_file=f"scopes/{scope.name}.yaml",
            notes=scope.notes,
        )

        placeholder = st.container()
        placeholder.info(f"Starting agent against `{target}` (scope: {scope.name})")
        step_log = placeholder.empty()
        all_events: list[dict] = []

        async def drive():
            loop = AgentLoop()
            async for event in loop.run(
                goal=goal,
                target_host=target,
                target_id=target_id,
                max_steps=int(max_steps),
            ):
                all_events.append(event.to_dict())
                render_events(step_log, all_events)

        try:
            asyncio.run(drive())
            st.success("Agent run complete.")
            st.balloons()
        except Exception as e:
            st.error(f"Agent errored: {e}")


def render_events(container, events: list[dict]):
    lines = []
    for e in events:
        kind = e["kind"]
        p = e["payload"]
        if kind == "started":
            lines.append(f"<div class='step-plan'>🚀 <b>Run started</b> · scope=<code>{p.get('scope')}</code> · run_id=<code>{p.get('run_id')}</code></div>")
        elif kind == "plan":
            actions = " → ".join(p.get("actions", []))
            lines.append(
                f"<div class='step-plan'>🧠 <b>Plan step {p.get('step')}</b><br>"
                f"<i>{p.get('reasoning', '')}</i><br>"
                f"<code>{actions}</code></div>"
            )
        elif kind == "tool_start":
            lines.append(
                f"<div class='step-tool'>⚙️ <b>[{p.get('step')}] {p.get('tool')}</b>"
                f"(<code>{p.get('target')}</code>) — {p.get('rationale', '')}</div>"
            )
        elif kind == "tool_done":
            color = "step-tool" if p.get("exit_code") == 0 else "step-error"
            lines.append(
                f"<div class='{color}'>✅ [{p.get('step')}] {p.get('tool')} "
                f"exit={p.get('exit_code')} "
                f"({p.get('duration_ms')}ms) — {p.get('summary', '')}</div>"
            )
        elif kind == "analysis":
            preview = p.get("candidates_preview", [])
            preview_lines = "<br>".join(
                f"&nbsp;&nbsp;• [{c.get('severity')}] {c.get('title')} ({c.get('vuln_class')})"
                for c in preview[:5]
            )
            lines.append(
                f"<div class='step-analysis'>🔎 <b>Analysis</b><br>"
                f"{p.get('summary', '')}<br>"
                f"Candidates: {p.get('candidates_count', 0)}<br>{preview_lines}</div>"
            )
        elif kind == "done":
            lines.append(f"<div class='step-plan'>🏁 <b>Done</b>: {p.get('reason', '')}</div>")
        elif kind == "error":
            lines.append(f"<div class='step-error'>❌ <b>Error</b>: {p.get('message', '')}</div>")
    container.markdown("\n".join(lines), unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════
# Candidates
# ═══════════════════════════════════════════════════════════════
if page == "Candidates":
    st.header("Candidates queue")
    st.caption("Agent-surfaced findings. Promote to report after manual review.")

    filter_status = st.selectbox(
        "Filter",
        ["pending", "promoted", "rejected", "dup_self", "all"],
        index=0,
    )
    candidates = db.list_candidates(
        status=None if filter_status == "all" else filter_status
    )

    if not candidates:
        st.info("No candidates match this filter.")
    else:
        for c in candidates:
            with st.container(border=True):
                header = f"**{c['title']}**  ·  `{c['vuln_class']}`  ·  `{c['severity_guess']}`"
                st.markdown(header)
                st.caption(f"URL: `{c['affected_url']}`  ·  status: `{c['status']}`")

                with st.expander("Evidence & reasoning"):
                    try:
                        st.json(json.loads(c.get("evidence_json") or "{}"))
                    except json.JSONDecodeError:
                        st.text(c.get("evidence_json") or "")
                    st.markdown("**Agent reasoning:**")
                    st.write(c.get("agent_reasoning", ""))

                if c["status"] == "pending":
                    cols = st.columns(4)
                    if cols[0].button("Promote → report", key=f"p{c['id']}", type="primary"):
                        with st.spinner("Generating report..."):
                            try:
                                gen = ReportGenerator()
                                report_id = asyncio.run(
                                    gen.generate_and_save(c["id"])
                                )
                                st.success(f"Report #{report_id} generated. See Reports page.")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Generation failed: {e}")
                    if cols[1].button("Reject", key=f"r{c['id']}"):
                        db.update_candidate_status(c["id"], "rejected")
                        st.rerun()
                    if cols[2].button("Mark duplicate", key=f"d{c['id']}"):
                        db.update_candidate_status(c["id"], "dup_self")
                        st.rerun()


# ═══════════════════════════════════════════════════════════════
# Reports
# ═══════════════════════════════════════════════════════════════
if page == "Reports":
    st.header("Reports")
    reports = db.list_reports()
    if not reports:
        st.info("No reports yet. Promote a candidate first.")
    else:
        for r in reports:
            with st.container(border=True):
                cols = st.columns([4, 1, 1])
                cols[0].markdown(f"**{r['title']}**")
                cols[1].metric("CVSS", f"{r['cvss_score']:.1f}" if r['cvss_score'] else "—")
                cols[2].code(r["status"], language=None)

                with st.expander("Report markdown"):
                    st.code(r["markdown"], language="markdown")
                    if r["cvss_vector"]:
                        st.caption(f"Vector: `{r['cvss_vector']}`")
                    st.download_button(
                        "Download .md",
                        r["markdown"],
                        file_name=f"report-{r['id']}.md",
                        mime="text/markdown",
                        key=f"dl{r['id']}",
                    )


# ═══════════════════════════════════════════════════════════════
# Chat
# ═══════════════════════════════════════════════════════════════
if page == "Chat":
    st.header("Chat with OpenClaw")
    st.caption("Free-form conversation. For agent execution, use 'Run Agent' page.")

    if "chat_history" not in st.session_state:
        st.session_state.chat_history = [
            {"role": "system",
             "content": "You are OpenClaw's conversational assistant. "
                        "You help a senior bug bounty hunter plan, analyze, and "
                        "debug their hunts. Direct, technical, attacker POV, no filler."}
        ]

    for msg in st.session_state.chat_history[1:]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    if prompt := st.chat_input("Ask anything..."):
        st.session_state.chat_history.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        with st.chat_message("assistant"):
            from openclaw.api.openrouter import get_llm
            placeholder = st.empty()
            full = ""

            async def stream():
                global full
                async for chunk in get_llm().stream(
                    messages=st.session_state.chat_history,
                    task="planner",
                    temperature=0.4,
                ):
                    full += chunk
                    placeholder.markdown(full + "▌")

            asyncio.run(stream())
            placeholder.markdown(full)
            st.session_state.chat_history.append({"role": "assistant", "content": full})


# ═══════════════════════════════════════════════════════════════
# Tools & Scopes
# ═══════════════════════════════════════════════════════════════
if page == "Tools & Scopes":
    st.header("Tools & Scopes")

    tab1, tab2 = st.tabs(["Tools available", "Scope files"])

    with tab1:
        st.subheader("Registered tools")
        tools = list_tools()
        for t in tools:
            icon = "✅" if t["available"] else "❌"
            st.markdown(f"{icon}  **{t['name']}** (`{t['binary']}`) — {t['description']}")

    with tab2:
        st.subheader("Scope files")
        scopes = load_all_scopes()
        if not scopes:
            st.warning(f"No scope files in `{settings.scopes_dir}`.")
        for name, scope in scopes.items():
            with st.expander(f"{name} ({scope.platform or 'unspecified'})"):
                st.json({
                    "in_scope": scope.in_scope,
                    "out_of_scope": scope.out_of_scope,
                    "allowed_tools": scope.allowed_tools,
                    "rate_limit_rps": scope.rate_limit_rps,
                    "notes": scope.notes,
                })
