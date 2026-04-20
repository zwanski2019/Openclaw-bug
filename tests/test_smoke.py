"""Smoke tests — verify the whole system assembles correctly."""


def test_all_modules_import():
    import openclaw.config
    import openclaw.api.openrouter
    import openclaw.db.client
    import openclaw.safety.scope
    import openclaw.safety.rate_limit
    import openclaw.safety.dedup
    import openclaw.tools.registry
    import openclaw.tools.recon
    import openclaw.tools.parser
    import openclaw.tools.ai_probe
    import openclaw.tools.favicon
    import openclaw.tools.github_recon
    import openclaw.tools.interactsh
    import openclaw.agent.memory
    import openclaw.agent.planner
    import openclaw.agent.executor
    import openclaw.agent.analyzer
    import openclaw.agent.loop
    import openclaw.reports.generator
    import openclaw.recon.continuous


def test_all_tools_registered():
    from openclaw.tools.registry import list_tools
    names = {t["name"] for t in list_tools()}
    expected = {
        # Binary tools
        "subfinder", "assetfinder", "httpx", "httpx_list",
        "nuclei", "katana", "naabu", "nmap", "ffuf", "waybackurls",
        "gitleaks", "gh_dork",
        # Native tools
        "ai_probe", "favicon", "interactsh_poll",
    }
    assert expected <= names, f"Missing: {expected - names}"


def test_native_tools_dispatch():
    """Native tools should have binary='__native__'."""
    from openclaw.tools.registry import list_tools
    tools_by_name = {t["name"]: t for t in list_tools()}
    for native_name in ("ai_probe", "favicon", "interactsh_poll"):
        assert tools_by_name[native_name]["binary"] == "__native__"
