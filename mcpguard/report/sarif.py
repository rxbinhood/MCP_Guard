"""SARIF 2.1.0 output for CI pipelines and GitHub code scanning."""

from __future__ import annotations

import json
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


def _location(f: Finding) -> dict[str, Any]:
    if f.file:
        region = {"startLine": f.line} if f.line else {}
        loc: dict[str, Any] = {"physicalLocation": {"artifactLocation": {"uri": f.file, "uriBaseId": "SRCROOT"}}}
        if region:
            loc["physicalLocation"]["region"] = region
        return loc
    # Manifest-level findings have no file; anchor them to the tool as a logical location.
    return {"logicalLocations": [{"name": f.tool or "manifest", "kind": "function",
                                  "fullyQualifiedName": f"mcp-tool:{f.tool or 'manifest'}"}]}


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
            "locations": [_location(f)],
            "partialFingerprints": {"mcpguard/v1": f"{rid}:{f.tool}:{f.file}:{f.line}"},
            "properties": {"mcpguardId": f.id, "severity": f.severity.value, "confidence": f.confidence,
                           "category": f.category.value, "source": f.source.value, "tool": f.tool},
        })
    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "MCPGuard", "version": __version__, "semanticVersion": __version__,
                                "informationUri": "https://github.com/Robinaditya1045/mcpguard", "rules": list(rules.values())}},
            "originalUriBaseIds": {"SRCROOT": {"description": {"text": "Root of the scanned MCP server"}}},
            "results": results,
            "properties": {"target": result.target, "verdict": result.verdict.value,
                           "riskScore": result.risk_score},
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
