"""Streamlit frontend for OpenClaw using remote backend API."""
from __future__ import annotations
import json
import os
import httpx
import streamlit as st

from openclaw.config import settings


BACKEND_URL = (
    os.getenv("BACKEND_BASE_URL")
    or getattr(settings, "backend_base_url", "http://localhost:8000")
).rstrip("/")


def api_get(path: str, **params):
    with httpx.Client(timeout=120.0) as client:
        r = client.get(f"{BACKEND_URL}{path}", params=params or None)
        r.raise_for_status()
        return r.json()


def api_post(path: str, payload: dict):
    with httpx.Client(timeout=300.0) as client:
        r = client.post(f"{BACKEND_URL}{path}", json=payload)
        r.raise_for_status()
        return r.json()


st.set_page_config(
    page_title="OpenClaw",
    page_icon="O",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
.stAlert { border-radius: 4px; }
code { font-size: 13px; }
.step-plan { border-left: 3px solid #3b82f6; padding: 8px 12px; background: #1e293b22; margin: 6px 0; }
.step-tool { border-left: 3px solid #10b981; padding: 8px 12px; background: #064e3b22; margin: 6px 0; }
.step-analysis { border-left: 3px solid #f59e0b; padding: 8px 12px; background: #78350f22; margin: 6px 0; }
.step-error { border-left: 3px solid #ef4444; padding: 8px 12px; background: #7f1d1d22; margin: 6px 0; }
</style>
""",
    unsafe_allow_html=True,
)


def render_events(container, events: list[dict]):
    lines = []
    for e in events:
        kind = e["kind"]
        p = e["payload"]
        if kind == "started":
            lines.append(
                f"<div class='step-plan'>Run started, scope=<code>{p.get('scope')}</code>, "
                f"run_id=<code>{p.get('run_id')}</code></div>"
            )
        elif kind == "plan":
            actions = " -> ".join(p.get("actions", []))
            lines.append(
                f"<div class='step-plan'><b>Plan step {p.get('step')}</b><br>"
                f"<i>{p.get('reasoning', '')}</i><br><code>{actions}</code></div>"
            )
        elif kind == "tool_start":
            lines.append(
                f"<div class='step-tool'><b>[{p.get('step')}] {p.get('tool')}</b> "
                f"(<code>{p.get('target')}</code>) - {p.get('rationale', '')}</div>"
            )
        elif kind == "tool_done":
            color = "step-tool" if p.get("exit_code") == 0 else "step-error"
            lines.append(
                f"<div class='{color}'>[{p.get('step')}] {p.get('tool')} "
                f"exit={p.get('exit_code')} ({p.get('duration_ms')}ms) - {p.get('summary', '')}</div>"
            )
        elif kind == "analysis":
            preview = p.get("candidates_preview", [])
            preview_lines = "<br>".join(
                f"&nbsp;&nbsp;* [{c.get('severity')}] {c.get('title')} ({c.get('vuln_class')})"
                for c in preview[:5]
            )
            lines.append(
                f"<div class='step-analysis'><b>Analysis</b><br>{p.get('summary', '')}<br>"
                f"Candidates: {p.get('candidates_count', 0)}<br>{preview_lines}</div>"
            )
        elif kind == "done":
            lines.append(f"<div class='step-plan'><b>Done</b>: {p.get('reason', '')}</div>")
        elif kind == "error":
            lines.append(f"<div class='step-error'><b>Error</b>: {p.get('message', '')}</div>")
    container.markdown("\n".join(lines), unsafe_allow_html=True)


with st.sidebar:
    st.title("OpenClaw")
    st.caption(f"Hunter: `{settings.hunter_handle}`")
    st.caption(f"Backend: `{BACKEND_URL}`")
    page = st.radio(
        "Navigate",
        ["Dashboard", "Run Agent", "Candidates", "Reports", "Chat", "Tools & Scopes"],
        label_visibility="collapsed",
    )
    st.divider()
    try:
        health = api_get("/health")
        st.success(f"Backend: {health.get('status', 'ok')}")
    except Exception as e:
        st.error(f"Backend unreachable: {e}")


if page == "Dashboard":
    st.header("Dashboard")
    data = api_get("/dashboard")
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Targets", data["targets_count"])
    col2.metric("Pending candidates", data["pending_count"])
    col3.metric("Total candidates", data["candidates_count"])
    col4.metric("Reports", data["reports_count"])

    st.divider()
    st.subheader("Recent candidates (top 10)")
    if data["recent_candidates"]:
        for c in data["recent_candidates"]:
            with st.container(border=True):
                cols = st.columns([3, 1, 1, 1])
                cols[0].markdown(f"**{c['title']}**")
                cols[0].caption(f"{c['vuln_class']} · `{c['affected_url']}`")
                cols[1].write(c["severity_guess"])
                cols[2].code(c["status"], language=None)
                cols[3].caption(c["created_at"])
    else:
        st.info("No candidates yet. Run the agent first.")

elif page == "Run Agent":
    st.header("Run agent on target")
    scopes = api_get("/scopes")
    if not scopes:
        st.error("No scope files found. Create `scopes/<target>.yaml` first.")
        st.stop()

    col1, col2 = st.columns([2, 1])
    with col1:
        scope_name = st.selectbox("Scope", options=list(scopes.keys()))
    with col2:
        max_steps = st.number_input("Max agent steps", min_value=1, max_value=100, value=settings.max_agent_steps)

    with st.expander("Scope details", expanded=False):
        st.json(scopes[scope_name])

    target = st.text_input("Target host or URL", placeholder="api.example.com or https://api.example.com/v1/")
    goal = st.text_area("Goal", placeholder="Describe recon objective", height=100)
    run_btn = st.button("Run agent", type="primary", disabled=not (target and goal))

    if run_btn:
        with st.spinner("Running agent via backend..."):
            result = api_post(
                "/runs",
                {"scope_name": scope_name, "target": target, "goal": goal, "max_steps": int(max_steps)},
            )
        st.success("Agent run complete.")
        render_events(st.container(), result["events"])

if page == "Candidates":
    st.header("Candidates queue")
    filter_status = st.selectbox("Filter", ["pending", "promoted", "rejected", "dup_self", "all"], index=0)
    status = None if filter_status == "all" else filter_status
    candidates = api_get("/candidates", status=status)

    if not candidates:
        st.info("No candidates match this filter.")
    else:
        for c in candidates:
            with st.container(border=True):
                st.markdown(f"**{c['title']}**  ·  `{c['vuln_class']}`  ·  `{c['severity_guess']}`")
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
                    if cols[0].button("Promote -> report", key=f"p{c['id']}", type="primary"):
                        with st.spinner("Generating report..."):
                            report_resp = api_post("/reports/promote", {"candidate_id": c["id"]})
                            st.success(f"Report #{report_resp['report_id']} generated.")
                            st.rerun()
                    if cols[1].button("Reject", key=f"r{c['id']}"):
                        api_post(f"/candidates/{c['id']}/status", {"status": "rejected"})
                        st.rerun()
                    if cols[2].button("Mark duplicate", key=f"d{c['id']}"):
                        api_post(f"/candidates/{c['id']}/status", {"status": "dup_self"})
                        st.rerun()

if page == "Reports":
    st.header("Reports")
    reports = api_get("/reports")
    if not reports:
        st.info("No reports yet. Promote a candidate first.")
    else:
        for r in reports:
            with st.container(border=True):
                cols = st.columns([4, 1, 1])
                cols[0].markdown(f"**{r['title']}**")
                cols[1].metric("CVSS", f"{r['cvss_score']:.1f}" if r["cvss_score"] else "-")
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

if page == "Chat":
    st.header("Chat with OpenClaw")
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = [
            {
                "role": "system",
                "content": (
                    "You are OpenClaw's conversational assistant. "
                    "You help a senior bug bounty hunter plan and analyze hunts."
                ),
            }
        ]

    for msg in st.session_state.chat_history[1:]:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])

    if prompt := st.chat_input("Ask anything..."):
        st.session_state.chat_history.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        with st.chat_message("assistant"):
            try:
                with st.spinner("Thinking..."):
                    resp = api_post(
                        "/chat",
                        {"messages": st.session_state.chat_history, "task": "planner", "temperature": 0.4},
                    )
                st.markdown(resp["content"])
                st.session_state.chat_history.append({"role": "assistant", "content": resp["content"]})
            except Exception as e:
                st.error(f"Chat failed: {e}")

if page == "Tools & Scopes":
    st.header("Tools & Scopes")
    tab1, tab2 = st.tabs(["Tools available", "Scope files"])
    with tab1:
        for t in api_get("/tools"):
            icon = "OK" if t["available"] else "NO"
            st.markdown(f"{icon}  **{t['name']}** (`{t['binary']}`) — {t['description']}")
    with tab2:
        scopes = api_get("/scopes")
        if not scopes:
            st.warning("No scope files configured.")
        for name, scope in scopes.items():
            with st.expander(f"{name} ({scope.get('platform') or 'unspecified'})"):
                st.json(scope)
