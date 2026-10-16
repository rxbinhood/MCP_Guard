"""Pin & verify: rug-pull detection.

``pin``    stores the canonical manifest fingerprint (per-tool SHA-256 + whole-list hash).
``verify`` re-fetches the manifest, compares hashes and, if anything changed, diffs it and
re-runs the description analyzer on the changed tools. A changed tool whose new definition
is malicious raises a CRITICAL rug-pull finding.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

from pydantic import BaseModel, Field

from mcpguard.db import Database, get_db
from mcpguard.desc_analyzer.analyzer import analyze_tools
from mcpguard.findings import Category, Finding, Manifest, Severity, Source
from mcpguard.ingest.manifest import fetch_manifest
from mcpguard.ingest.source import resolve
from mcpguard.pin_diff.canonical import fingerprint
from mcpguard.pin_diff.diff import ManifestDiff, diff_manifests

Log = Callable[[str], None]


class PinRecord(BaseModel):
    server_key: str
    server_name: str
    server_version: str | None
    target: str
    manifest_hash: str
    tool_hashes: dict[str, str]
    manifest: Manifest
    pinned_at: float


class VerifyResult(BaseModel):
    server_key: str
    server_name: str
    status: str  # unchanged | changed | error
    diff: ManifestDiff | None = None
    findings: list[Finding] = Field(default_factory=list)
    rug_pull: bool = False
    error: str | None = None
    checked_at: float = Field(default_factory=time.time)
    engines: dict[str, Any] = Field(default_factory=dict)


def pin_manifest(target: str, server_key: str, manifest: Manifest, db: Database | None = None) -> PinRecord:
    db = db or get_db()
    whole, per_tool = fingerprint(manifest)
    record = PinRecord(server_key=server_key, server_name=manifest.server_name,
                       server_version=manifest.server_version, target=target, manifest_hash=whole,
                       tool_hashes=per_tool, manifest=manifest, pinned_at=time.time())
    db.upsert_pin({**record.model_dump(mode="json"), "last_status": "pinned"})
    return record


async def pin(target: str, mode: str | None = None, log: Log | None = None,
              db: Database | None = None) -> PinRecord:
    project = resolve(target)
    manifest = await fetch_manifest(project, mode, log)
    return pin_manifest(target, project.server_key, manifest, db)


async def rug_pull_findings(diff: ManifestDiff, new: Manifest, use_ai: bool = True,
                            log: Log | None = None) -> tuple[list[Finding], dict[str, Any]]:
    """Re-analyze changed/added tools and turn the diff into findings."""
    touched = [t for t in new.tools if t.name in set(diff.changed) | set(diff.added)]
    analysis = await analyze_tools(touched, use_ai=use_ai, log=log) if touched else None
    findings: list[Finding] = []
    for change in diff.tools:
        verdict = analysis.verdict_for(change.tool) if analysis else None
        changed_fields = ", ".join(f.path for f in change.fields) or change.status
        if change.status == "removed":
            findings.append(Finding(
                severity=Severity.INFO, category=Category.RUG_PULL, tool=change.tool,
                title=f"Tool `{change.tool}` was removed since it was pinned",
                evidence=f"Pinned hash {change.old_hash[:12]} no longer present.",
                fix="Confirm the removal is expected, then re-pin the server.",
                source=Source.PIN_DIFF, confidence=1.0, rule_id="pin_diff.tool_removed"))
            continue
        malicious = verdict is not None and verdict.verdict == "malicious"
        suspicious = verdict is not None and verdict.verdict == "suspicious"
        if malicious:
            severity, title = Severity.CRITICAL, f"Rug pull: `{change.tool}` now contains malicious instructions"
        elif suspicious:
            severity, title = Severity.HIGH, f"Rug pull suspected: `{change.tool}` changed to suspicious wording"
        elif change.status == "added":
            severity, title = Severity.LOW, f"New tool `{change.tool}` added since pin"
        else:
            severity, title = Severity.MEDIUM, f"Tool `{change.tool}` definition changed since pin"
        new_desc = next((f.new for f in change.fields if f.path == "description"), None)
        evidence = f"Changed: {changed_fields}"
        if isinstance(new_desc, str):
            evidence += f"\nNew description: {new_desc[:400]}"
        if verdict and verdict.highlights:
            evidence += "\nFlagged text: " + "; ".join(h["text"] for h in verdict.highlights[:4])
        findings.append(Finding(
            severity=severity, category=Category.RUG_PULL, tool=change.tool, title=title, evidence=evidence,
            fix=("Do NOT approve the new definition. Disconnect the server from your agents, pin a known-good "
                 "version (commit hash / package version) and report the change to the maintainer."
                 if malicious or suspicious else
                 "Review the change. If it is expected, re-pin the server to accept the new definition."),
            source=Source.PIN_DIFF, confidence=0.95 if malicious else 0.8 if suspicious else 1.0,
            rule_id="pin_diff." + ("malicious_change" if malicious else f"tool_{change.status}"),
            highlights=[h["text"] for h in (verdict.highlights if verdict else [])],
            detectors=["pin_diff"] + (verdict.layers_used if verdict else []),
            extra={"score": verdict.score if verdict else 0.0, "fields": changed_fields},
        ))
    return findings, (analysis.engines if analysis else {})


async def verify(target_or_key: str, mode: str | None = None, use_ai: bool = True, log: Log | None = None,
                 db: Database | None = None) -> VerifyResult:
    db = db or get_db()
    project = resolve(target_or_key)
    pinned = db.get_pin(project.server_key)
    if pinned is None:
        raise LookupError(f"{target_or_key} is not pinned; run `mcpguard pin {target_or_key}` first")
    old = Manifest.model_validate(pinned["manifest"])
    try:
        new = await fetch_manifest(project, mode, log)
    except Exception as exc:  # noqa: BLE001 - surfaced to the user as a failed verification
        db.record_check(project.server_key, "error", None, None, [])
        return VerifyResult(server_key=project.server_key, server_name=old.server_name, status="error",
                            error=str(exc))
    diff = diff_manifests(old, new)
    findings: list[Finding] = []
    engines: dict[str, Any] = {}
    if diff.status == "changed":
        findings, engines = await rug_pull_findings(diff, new, use_ai, log)
    for i, f in enumerate(findings, 1):
        f.id = f"MCPG-PIN-{i:03d}"
    result = VerifyResult(server_key=project.server_key, server_name=new.server_name, status=diff.status,
                          diff=diff, findings=findings, engines=engines,
                          rug_pull=any(f.severity == Severity.CRITICAL for f in findings))
    db.record_check(project.server_key, diff.status, diff.new_hash, diff.model_dump(mode="json"),
                    [f.model_dump(mode="json") for f in findings])
    return result
