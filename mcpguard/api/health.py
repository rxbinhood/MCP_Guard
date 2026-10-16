"""Engine health: which optional components are available right now."""

from __future__ import annotations

from typing import Any

from mcpguard.config import get_settings
from mcpguard.desc_analyzer import llm_judge, prompt_guard
from mcpguard.ingest import sandbox
from mcpguard.static_scan.scanner import engine_status


def engine_health(refresh: bool = False) -> list[dict[str, Any]]:
    s = get_settings()
    llm_ok, llm_detail = llm_judge.status(refresh=refresh)
    pg_ok, pg_detail = prompt_guard.status()
    docker_ok, docker_detail = sandbox.docker_status(refresh=refresh)
    static = engine_status()
    engines = [
        {"id": "llm", "label": "LLM judge", "kind": "ai", "model": s.llm_model, "ok": llm_ok, "detail": llm_detail},
        {"id": "prompt_guard", "label": "Prompt Guard 2", "kind": "ai", "model": s.promptguard_model,
         "ok": pg_ok, "detail": pg_detail},
        {"id": "docker", "label": "Docker sandbox", "kind": "sandbox", "ok": docker_ok, "detail": docker_detail},
        {"id": "semgrep", "label": "Semgrep", "kind": "static", "ok": static["semgrep"][0],
         "detail": static["semgrep"][1]},
        {"id": "bandit", "label": "Bandit", "kind": "static", "ok": static["bandit"][0], "detail": static["bandit"][1]},
        {"id": "gitleaks", "label": "Gitleaks", "kind": "static", "ok": static["gitleaks"][0],
         "detail": static["gitleaks"][1]},
        {"id": "builtin", "label": "Built-in rules", "kind": "static", "ok": True, "detail": "always available"},
        {"id": "sqlite", "label": "SQLite", "kind": "storage", "ok": True, "detail": str(s.db_path)},
    ]
    for e in engines:
        e["status"] = "online" if e["ok"] else "offline"
    return engines
