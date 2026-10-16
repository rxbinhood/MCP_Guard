"""Runtime configuration, read from environment variables.

Everything has a sensible default so MCPGuard runs with zero configuration;
missing optional engines (LLM, Docker, Semgrep...) degrade gracefully.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default).strip() or default


@dataclass
class Settings:
    # Where the SQLite DB, cloned repos and reports live.
    home: Path = field(default_factory=lambda: Path(_env("MCPGUARD_HOME", str(PROJECT_ROOT / "data"))))

    # LLM judge: any OpenAI-compatible Chat Completions endpoint.
    # Default is the OpenAI API; point MCPGUARD_LLM_BASE_URL at e.g. http://localhost:11434/v1 for a local model.
    llm_base_url: str = field(default_factory=lambda: _env("MCPGUARD_LLM_BASE_URL", "https://api.openai.com/v1"))
    llm_model: str = field(default_factory=lambda: _env("MCPGUARD_LLM_MODEL", "gpt-4.1-mini"))
    llm_api_key: str = field(
        default_factory=lambda: os.environ.get("MCPGUARD_LLM_API_KEY") or os.environ.get("OPENAI_API_KEY", "")
    )
    llm_timeout: float = field(default_factory=lambda: float(_env("MCPGUARD_LLM_TIMEOUT", "60")))

    # Optional Prompt Guard 2 classifier: an HTTP service URL or a local HF model id/path.
    promptguard_url: str = field(default_factory=lambda: os.environ.get("MCPGUARD_PROMPTGUARD_URL", ""))
    promptguard_model: str = field(
        default_factory=lambda: _env("MCPGUARD_PROMPTGUARD_MODEL", "meta-llama/Llama-Prompt-Guard-2-86M")
    )

    # Sandbox for running target servers: auto | docker | static | host.
    #   auto   -> docker if available, else static AST extraction (never runs code on the host)
    #   host   -> run directly on this machine; explicit opt-in for trusted code only
    sandbox: str = field(default_factory=lambda: _env("MCPGUARD_SANDBOX", "auto"))
    docker_timeout: float = field(default_factory=lambda: float(_env("MCPGUARD_DOCKER_TIMEOUT", "300")))

    @property
    def db_path(self) -> Path:
        return self.home / "mcpguard.db"

    @property
    def repos_dir(self) -> Path:
        return self.home / "repos"

    def ensure_dirs(self) -> None:
        self.home.mkdir(parents=True, exist_ok=True)
        self.repos_dir.mkdir(parents=True, exist_ok=True)


_settings: Settings | None = None


def get_settings() -> Settings:
    global _settings
    if _settings is None:
        _settings = Settings()
        _settings.ensure_dirs()
    return _settings


def update_settings(**changes: object) -> Settings:
    """Apply runtime changes (from the Settings page) to the live settings object."""
    s = get_settings()
    for key, value in changes.items():
        if hasattr(s, key) and value is not None:
            setattr(s, key, value)
    return s
