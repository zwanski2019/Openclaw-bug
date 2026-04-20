-- OpenClaw schema. SQLite compatible; adapted dialect works on Postgres/Supabase.

CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    platform TEXT,                -- hackerone | bugcrowd | bbs | private
    scope_file TEXT NOT NULL,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER REFERENCES targets(id),
    goal TEXT,
    status TEXT DEFAULT 'running',  -- running | complete | aborted | error
    started_at TEXT DEFAULT (datetime('now')),
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS agent_steps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES runs(id) ON DELETE CASCADE,
    step_num INTEGER NOT NULL,
    kind TEXT NOT NULL,             -- plan | tool_call | observation | reflect
    content TEXT NOT NULL,          -- JSON payload
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS tool_executions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES runs(id) ON DELETE CASCADE,
    tool_name TEXT NOT NULL,
    target TEXT NOT NULL,
    args_json TEXT,
    stdout_path TEXT,               -- written to data/runs/<run_id>/<n>.stdout
    stderr_path TEXT,
    exit_code INTEGER,
    duration_ms INTEGER,
    scope_verdict TEXT NOT NULL,    -- allowed | blocked
    created_at TEXT DEFAULT (datetime('now'))
);

-- Candidates: agent-surfaced findings awaiting human review.
-- Promotion to 'report' status requires manual action.
CREATE TABLE IF NOT EXISTS candidates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER REFERENCES runs(id) ON DELETE SET NULL,
    target_id INTEGER REFERENCES targets(id),
    title TEXT NOT NULL,
    vuln_class TEXT,                -- IDOR | SSRF | OAuth | Desync | LLM_PI | ...
    affected_url TEXT,
    severity_guess TEXT,            -- informational | low | medium | high | critical
    evidence_json TEXT,
    agent_reasoning TEXT,
    status TEXT DEFAULT 'pending',  -- pending | promoted | rejected | dup_self | dup_known
    created_at TEXT DEFAULT (datetime('now')),
    reviewed_at TEXT
);

CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    candidate_id INTEGER REFERENCES candidates(id),
    target_id INTEGER REFERENCES targets(id),
    title TEXT NOT NULL,
    markdown TEXT NOT NULL,
    cvss_vector TEXT,
    cvss_score REAL,
    status TEXT DEFAULT 'draft',    -- draft | submitted | paid | rejected
    platform TEXT,
    external_id TEXT,               -- HackerOne report id etc.
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);

-- Long-term agent memory (lessons, patterns, user corrections).
CREATE TABLE IF NOT EXISTS memory (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL,            -- 'global' | target name
    kind TEXT NOT NULL,             -- lesson | pattern | correction | dedup_key
    content TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target_id);
CREATE INDEX IF NOT EXISTS idx_steps_run ON agent_steps(run_id, step_num);
CREATE INDEX IF NOT EXISTS idx_candidates_status ON candidates(status);
CREATE INDEX IF NOT EXISTS idx_memory_scope ON memory(scope, kind);
