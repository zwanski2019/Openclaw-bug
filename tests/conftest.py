"""Shared pytest fixtures."""
import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    """Every test gets a fresh SQLite file so they don't pollute each other."""
    db_file = tmp_path / "test.db"
    monkeypatch.setenv("DB_PATH", str(db_file))

    # Rebuild settings from env
    from openclaw import config as _cfg
    new_settings = _cfg.Settings()
    monkeypatch.setattr(_cfg, "settings", new_settings)

    # Patch the bound `settings` reference in every module that imported it
    # at module load time (these won't see updates to _cfg.settings otherwise).
    from openclaw.db import client as _dbc
    monkeypatch.setattr(_dbc, "settings", new_settings)

    from openclaw.safety import scope as _scope
    monkeypatch.setattr(_scope, "settings", new_settings)

    yield db_file


@pytest.fixture
def scope_dir(tmp_path, monkeypatch):
    """Provide a clean scopes dir and patch settings to use it."""
    sdir = tmp_path / "scopes"
    sdir.mkdir()
    from openclaw import config as _cfg
    # Temporarily override scopes_dir resolution
    monkeypatch.setattr(_cfg.Settings, "scopes_dir", property(lambda self: sdir))
    _cfg.settings = _cfg.Settings()
    return sdir


@pytest.fixture
def sample_scope(scope_dir):
    """Write a canonical scope YAML for tests."""
    (scope_dir / "test-prog.yaml").write_text(
        """name: test-prog
platform: hackerone
in_scope:
  - "*.example.com"
  - "192.168.1.0/24"
out_of_scope:
  - "blog.example.com"
rate_limit_rps: 10
allowed_tools:
  - subfinder
  - httpx
  - nuclei
"""
    )
    return scope_dir / "test-prog.yaml"
