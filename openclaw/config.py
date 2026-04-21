"""Central config. All env vars loaded and validated here."""
from __future__ import annotations
from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # LLM
    openrouter_api_key: str = ""
    openrouter_model_planner: str = "anthropic/claude-3.5-sonnet"
    openrouter_model_analyzer: str = "meta-llama/llama-3.3-70b-instruct:free"
    openrouter_model_report: str = "anthropic/claude-3.5-sonnet"

    ollama_base_url: str = "http://host.docker.internal:11434"
    ollama_model: str = "qwen2.5-coder:7b"

    # DB
    db_path: str = "/app/data/openclaw.db"
    supabase_url: str = ""
    supabase_key: str = ""

    # Agent
    max_agent_steps: int = 20
    tool_timeout_seconds: int = 600
    tool_output_max_bytes: int = 2_000_000

    # UI
    streamlit_server_port: int = 8501
    backend_base_url: str = "http://localhost:8000"

    # Hunter identity
    hunter_handle: str = "zwanski"
    hunter_email: str = ""

    # Paths (derived)
    @property
    def data_dir(self) -> Path:
        p = Path(self.db_path).parent
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def runs_dir(self) -> Path:
        p = self.data_dir / "runs"
        p.mkdir(parents=True, exist_ok=True)
        return p

    @property
    def scopes_dir(self) -> Path:
        # Resolve relative to project root when running outside container
        for candidate in (Path("/app/scopes"), Path("scopes"), Path(__file__).parent.parent / "scopes"):
            if candidate.exists():
                return candidate
        fallback = Path("scopes")
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback

    def has_openrouter(self) -> bool:
        return bool(self.openrouter_api_key.strip())

    def has_supabase(self) -> bool:
        return bool(self.supabase_url.strip() and self.supabase_key.strip())


settings = Settings()
