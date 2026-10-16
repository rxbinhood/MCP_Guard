"""JSON report: the full ScanResult plus summary counts."""

from __future__ import annotations

import json

from mcpguard import __version__
from mcpguard.findings import ScanResult


def render_json(result: ScanResult) -> str:
    data = result.model_dump(mode="json")
    data["summary"] = {"verdict": result.verdict.value, "risk_score": result.risk_score,
                       "counts": result.counts(), "tools": len(result.manifest.tools) if result.manifest else 0}
    data["generator"] = {"name": "MCPGuard", "version": __version__}
    return json.dumps(data, indent=2, ensure_ascii=False)
