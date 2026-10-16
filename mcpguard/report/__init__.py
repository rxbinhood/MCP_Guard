"""Report renderers: Markdown (humans), JSON (machines) and SARIF 2.1.0 (CI / GitHub code scanning)."""

from __future__ import annotations

from mcpguard.findings import ScanResult
from mcpguard.report.json_report import render_json
from mcpguard.report.markdown import render_markdown
from mcpguard.report.sarif import render_sarif

FORMATS = {"md": render_markdown, "json": render_json, "sarif": render_sarif}
EXTENSIONS = {"md": "md", "json": "json", "sarif": "sarif.json"}
MEDIA_TYPES = {"md": "text/markdown", "json": "application/json", "sarif": "application/sarif+json"}


def render(result: ScanResult, fmt: str) -> str:
    try:
        return FORMATS[fmt](result)
    except KeyError as exc:
        raise ValueError(f"unknown report format {fmt!r}; choose from {', '.join(FORMATS)}") from exc
