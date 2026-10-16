"""Shared fixtures: isolate MCPGuard's data dir and expose the bundled test servers."""

from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
TEST_SERVERS = ROOT / "test_servers"


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Every test gets its own DB/home and no AI endpoints (deterministic, offline)."""
    import mcpguard.config as config
    import mcpguard.db as db

    monkeypatch.setenv("MCPGUARD_HOME", str(tmp_path))
    monkeypatch.setenv("OPENAI_API_KEY", "")
    monkeypatch.delenv("MCPGUARD_LLM_API_KEY", raising=False)
    monkeypatch.delenv("MCPGUARD_PROMPTGUARD_URL", raising=False)
    monkeypatch.setattr(config, "_settings", None)
    monkeypatch.setattr(db, "_db", None)
    from mcpguard.desc_analyzer import llm_judge, prompt_guard

    monkeypatch.setattr(llm_judge, "_status_cache", None)
    monkeypatch.setattr(prompt_guard, "_status_cache", None)
    yield tmp_path


@pytest.fixture
def servers() -> Path:
    return TEST_SERVERS
