# OpenClaw v2

Autonomous bug bounty research assistant. Local-first, Dockerized, OpenRouter-backed, scope-aware.

**Built for real hunters, not slop factories.** Scope gate on every tool call. Rate-limited. Dedup'd. Human-gated promotion from candidate → report.

---

## What's new in v2

- **Rate limiter** — per-scope async token bucket, enforced at executor level (no advisory BS)
- **Candidate dedup** — SHA256 fingerprints with URL normalization (`/users/123` == `/users/456`)
- **AI/LLM probe tool** — prompt injection + output-handling testing (Tier S, +540% YoY in 2026)
- **GitHub secrets recon** — gitleaks + `gh` CLI wrappers
- **Favicon hash pivot** — mmh3 + MD5 → Shodan/Censys infra discovery
- **Interactsh OOB bridge** — register + poll for blind SSRF/SSTI/desync callbacks
- **Continuous recon mode** — diff-based subdomain monitoring, logs `new_asset` memory
- **Multi-stage Dockerfile** — Go build cached separately, 10x faster rebuilds
- **pytest suite** — 57 tests covering scope, dedup, rate limit, parsers, smoke
- **Scope-exempt tools** — `skip_scope=True` for tools that only talk to your own infra
- **Nuclei custom templates** — mount `./nuclei-custom/` into the container

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      Streamlit UI (8501)                     │
│        Chat · Agent steps · Candidates · Reports · Tools     │
└────────────────────────┬─────────────────────────────────────┘
                         │
┌────────────────────────▼─────────────────────────────────────┐
│                  Agent Loop (ReAct)                          │
│   Planner → Executor → Analyzer → Dedup → Memory → Reflect   │
└──┬──────────────┬──────────────┬──────────────┬──────────────┘
   │              │              │              │
┌──▼───┐  ┌───────▼────────┐ ┌───▼──────┐  ┌────▼──────┐
│ LLM  │  │   Tools        │ │  Safety  │  │  Memory   │
│OR/Oll│  │ ──────────────│ │ ─────────│  │ ──────────│
│      │  │ Binary (nuclei│ │ Scope    │  │ SQLite    │
│      │  │ subfinder,    │ │ Rate lim │  │ (+Supa)   │
│      │  │ httpx, gitleaks│ │ Dedup    │  │           │
│      │  │ ...)          │ │          │  │           │
│      │  │ Native (AI    │ │          │  │           │
│      │  │ probe, favicon│ │          │  │           │
│      │  │ interactsh)   │ │          │  │           │
└──────┘  └───────────────┘ └──────────┘  └───────────┘
```

**Key design choices (unchanged from v1):**

- Scope gate on every tool execution — no request leaves without match
- Human-in-the-loop — candidates queue, manual promote to report
- SQLite primary, Supabase sync optional
- OpenRouter primary, Ollama fallback for scope-sensitive analysis
- Pluggable tools via `@register_tool` decorator

---

## Quick start

```bash
git clone <repo> openclaw && cd openclaw
cp .env.example .env
# edit .env — set OPENROUTER_API_KEY at minimum

docker compose up --build
# → http://localhost:8501
```

This now starts two services:

- Frontend (Streamlit): `http://localhost:8501`
- Backend API (FastAPI): `http://localhost:8000`

First run initializes SQLite at `./data/openclaw.db` and writes recon output to `./data/runs/<run_id>/`.

---

## Split deployment (Railway backend + Streamlit frontend)

Deploy backend to Railway using `Dockerfile.backend`:

- Start command: `uvicorn openclaw.backend.api:app --host 0.0.0.0 --port $PORT`
- Health check path: `/health`

Deploy frontend separately using `Dockerfile.frontend` and set:

- `BACKEND_BASE_URL=https://<your-railway-backend-domain>`

---

## Scope file (mandatory)

```bash
cat > scopes/example.yaml <<'EOF'
name: example-program
platform: hackerone
in_scope:
  - "*.example.com"
  - "api.example.net"
  - "10.0.0.0/24"
out_of_scope:
  - "blog.example.com"
  - "*.corp.example.com"
rate_limit_rps: 5
allowed_tools:
  - subfinder
  - httpx
  - httpx_list
  - nuclei
  - katana
  - gitleaks
  - ai_probe
  - favicon
notes: |
  HackerOne program. No DoS, no brute force. Include @zwanski in reports.
EOF
```

If you skip this file, every tool call returns `scope_verdict=blocked`.

---

## Usage modes

### Goal mode (Streamlit UI)

Pick scope → enter target URL → describe goal → watch live agent steps.

### Headless CLI

```bash
# Run the agent
docker compose exec openclaw python -m openclaw run \
    --target api.example.com \
    --goal "enum subs, flag OAuth endpoints and admin panels, prioritize low-dup classes" \
    --max-steps 15

# List candidates
docker compose exec openclaw python -m openclaw candidates --status pending

# Promote candidate → report (LLM generates markdown)
docker compose exec openclaw python -m openclaw report promote --id 5

# Show a report
docker compose exec openclaw python -m openclaw report show 3

# Show registered tools
docker compose exec openclaw python -m openclaw tools

# Continuous recon (run on cron for new-asset alerts)
docker compose exec openclaw python -m openclaw continuous \
    --scope example-program --domain example.com

# Sync to Supabase (if configured)
docker compose exec openclaw python -m openclaw sync
```

---

## Continuous recon (cron recipe)

Per the 2026 reference: "new assets = new bugs."

```bash
# /etc/cron.d/openclaw-recon
0 6 * * * root cd /srv/openclaw && docker compose exec -T openclaw \
    python -m openclaw continuous --scope example-program --domain example.com \
    >> /var/log/openclaw-recon.log 2>&1
```

Diffs against the previous snapshot, writes new subs + newly-live hosts as `new_asset` entries in the agent's long-term memory. Next time you run the agent, planner context includes them automatically.

---

## Tools in v2

### Binary (subprocess)

| Tool | Binary | What it does |
|---|---|---|
| `subfinder` | subfinder | Passive subdomain enum (PD) |
| `assetfinder` | assetfinder | Quick sub enum (tomnomnom) |
| `httpx` | httpx | HTTP probe + tech detect |
| `httpx_list` | httpx | Probe against a file of hosts |
| `katana` | katana | JS-aware crawler |
| `nuclei` | nuclei | Template scanner |
| `naabu` | naabu | Fast port scan |
| `nmap` | nmap | Service/version detection |
| `ffuf` | ffuf | Content/param fuzzer |
| `waybackurls` | waybackurls | Historical URLs |
| `gitleaks` | gitleaks | Repo secrets scan |
| `gh_dork` | gh | GitHub code search |

### Native (async Python)

| Tool | What it does |
|---|---|
| `ai_probe` | LLM endpoint probing (6 prompt injection + output-handling probes) |
| `favicon` | Fetch favicon, compute mmh3/md5 hash, generate Shodan/Censys URLs (optional authenticated Shodan lookup if `SHODAN_API_KEY` set) |
| `interactsh_poll` | OOB bridge — register session / poll callbacks (scope-exempt) |

### Custom Nuclei templates

Drop your own templates in `./nuclei-custom/` — they're mounted at `/app/nuclei-custom` in the container. Use via:

```bash
docker compose exec openclaw nuclei \
    -t /app/nuclei-custom/my-templates/ \
    -u https://target.example.com
```

---

## Adding a new tool

```python
# openclaw/tools/plugins/my_tool.py
from openclaw.tools.registry import register_tool, Tool

@register_tool
class MyTool(Tool):
    name = "my_tool"
    binary = "my_binary"         # or "__native__" for async Python
    description = "what it does"
    default_timeout = 600         # optional, seconds
    # skip_scope = True           # optional, for tools that don't touch target

    def build_args(self, target: str, **kwargs) -> list[str]:
        return ["-u", target, "-fmt", "json"]
```

Then import it in `openclaw/tools/registry.py`:

```python
from openclaw.tools import my_tool as _my  # noqa
```

For native tools, add a case in `_dispatch_native()`.

---

## Safety architecture

1. **Scope gate** (`safety/scope.py`) — YAML-driven allowlist. CIDR and wildcard support. Out-of-scope overrides in-scope. Tool allowlist per scope.
2. **Rate limiter** (`safety/rate_limit.py`) — async token bucket per scope. Every tool acquires 1 token before executing.
3. **Dedup** (`safety/dedup.py`) — SHA256 fingerprint over (vuln_class, normalized_url, stable_evidence_keys). Numeric IDs and UUIDs collapsed so `/users/123` doesn't create a new finding per ID.
4. **Human-in-the-loop** — candidates → manual review → promote → report. No auto-submit to HackerOne/Bugcrowd.
5. **Local LLM fallback** — task type `"local"` routes to Ollama. Use for scope-sensitive analysis.

---

## Running tests

```bash
docker compose exec openclaw python -m pytest tests/ -v

# From host
pip install pytest pytest-asyncio mmh3 pydantic pydantic-settings pyyaml httpx
cd openclaw && python -m pytest tests/ -v
```

Current suite: 57 tests covering scope enforcement, dedup normalization + fingerprinting, rate limiting, parsers, planner output handling, all tool registrations.

---

## Legal

Only run against targets you're authorized to test. Scope files are enforcement, not decoration.

OpenClaw refuses execution on any target without a valid scope file in `scopes/`. The rate limiter prevents you from accidentally DoSing a target. The dedup system prevents flooding triage queues with the same finding across runs.

None of this is a substitute for you reading the program's scope policy.

---

## Roadmap (beyond v2)

- Vector embeddings on candidates for semantic dedup (v2 is hash-based; misses paraphrased findings)
- HTTP desync detection helper (wraps HTTP Request Smuggler v3 invocations)
- Scope auto-import from HackerOne/Bugcrowd program JSON exports
- Self-hosted Interactsh bridge config (current default is public `oast.site`)
- Report platform integration (submit-draft-only, not auto-submit)
- Caido/Burp export ingestion for analyzing captured traffic offline
