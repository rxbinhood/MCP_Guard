"""SARIF 2.1.0 output for CI pipelines and GitHub code scanning."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from mcpguard import __version__
from mcpguard.findings import Finding, ScanResult, Severity

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
          Severity.LOW: "note", Severity.INFO: "none"}
# GitHub uses `security-severity` (0-10) to bucket results.
_SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
                      Severity.LOW: "3.0", Severity.INFO: "0.0"}


def _rule_id(f: Finding) -> str:
    return f.rule_id or f"{f.source.value}.{f.category.value}"


def _find_file_and_line(f: Finding, target: str | None = None) -> tuple[str, int]:
    # 1. If f.file is specified
    if f.file:
        if Path(f.file).is_file():
            return f.file, f.line or 1
        if target:
            candidate = Path(target) / f.file
            if candidate.is_file():
                return str(candidate), f.line or 1
        return f.file, f.line or 1

    # 2. Check if f.evidence contains file:line pattern (e.g. "server.py:35")
    if f.evidence:
        match = re.search(r"\b([a-zA-Z0-9_./-]+\.(?:py|js|ts|mjs|cjs|json|ya?ml|toml|txt|sh)):(\d+)\b", f.evidence)
        if match:
            ev_file, ev_line = match.group(1), int(match.group(2))
            if Path(ev_file).is_file():
                return ev_file, ev_line
            if target and (Path(target) / ev_file).is_file():
                return str(Path(target) / ev_file), ev_line
            return ev_file, ev_line

    # 3. Check target path for an entry file or tool definition
    if target:
        t_path = Path(target)
        if t_path.is_file():
            return str(t_path), f.line or 1
        if t_path.is_dir():
            for candidate in ("server.py", "main.py", "app.py", "index.ts", "index.js", "package.json"):
                cand_path = t_path / candidate
                if cand_path.is_file():
                    if f.tool:
                        try:
                            content = cand_path.read_text(encoding="utf-8", errors="ignore").splitlines()
                            for idx, line in enumerate(content, 1):
                                if f.tool in line:
                                    return str(cand_path), idx
                        except Exception:
                            pass
                    return str(cand_path), f.line or 1
            try:
                for item in t_path.iterdir():
                    if item.is_file() and not item.name.startswith("."):
                        return str(item), f.line or 1
            except Exception:
                pass

    return "README.md", f.line or 1


def _location(f: Finding, target: str | None = None) -> dict[str, Any]:
    file_path, line = _find_file_and_line(f, target)
    loc: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": line or 1, "startColumn": 1},
        }
    }
    if f.tool:
        loc["logicalLocations"] = [{
            "name": f.tool or "manifest",
            "kind": "function",
            "fullyQualifiedName": f"mcp-tool:{f.tool or 'manifest'}",
        }]
    return loc


def render_sarif(result: ScanResult) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []
    for f in result.findings:
        rid = _rule_id(f)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": rid.replace(".", "_"),
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.why or f.title},
                "help": {"text": f.fix or f.title, "markdown": f.fix or f.title},
                "properties": {
                    "tags": ["security", f.category.value, f.source.value] + ([f.owasp_llm_ref] if f.owasp_llm_ref else []),
                    "security-severity": _SECURITY_SEVERITY[f.severity],
                },
            }
        elif float(_SECURITY_SEVERITY[f.severity]) > float(rules[rid]["properties"]["security-severity"]):
            rules[rid]["properties"]["security-severity"] = _SECURITY_SEVERITY[f.severity]
        results.append({
            "ruleId": rid,
            "level": _LEVEL[f.severity],
            "message": {"text": f"{f.title}" + (f" (tool: {f.tool})" if f.tool else "") +
                                (f"\nEvidence: {f.evidence[:500]}" if f.evidence else "") +
                                (f"\nFix: {f.fix}" if f.fix else "")},
            "locations": [_location(f, result.target)],
            "partialFingerprints": {"mcpguard/v1": f"{rid}:{f.tool}:{f.file}:{f.line}"},
            "properties": {"mcpguardId": f.id, "severity": f.severity.value, "confidence": f.confidence,
                           "category": f.category.value, "source": f.source.value, "tool": f.tool},
        })
    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "MCPGuard", "version": __version__, "semanticVersion": __version__,
                                "informationUri": "https://github.com/rxbinhood/MCP_Guard", "rules": list(rules.values())}},
            "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "Root of the scanned repository"}}},
            "results": results,
            "properties": {"target": result.target, "verdict": result.verdict.value,
                           "riskScore": result.risk_score},
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
