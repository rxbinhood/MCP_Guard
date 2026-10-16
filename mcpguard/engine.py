"""Findings engine: merge, dedupe, correlate across modules, assign IDs, compute verdict and risk.

Verdict rule: any CRITICAL/HIGH -> FAIL, any MEDIUM -> WARN, otherwise PASS.
Risk score (0-100): noisy-OR of per-finding severity weight x confidence, so a single
critical finding dominates while many low findings only nudge the score.
"""

from __future__ import annotations

from mcpguard.findings import SOURCE_CODES, Category, Finding, Severity, Source, Verdict

SEVERITY_WEIGHT = {Severity.CRITICAL: 0.95, Severity.HIGH: 0.7, Severity.MEDIUM: 0.35,
                   Severity.LOW: 0.1, Severity.INFO: 0.0}

# Static categories that a dynamic observation can confirm (same tool or same underlying issue).
_CORROBORATES = {
    Category.COMMAND_INJECTION: {Category.COMMAND_INJECTION},
    Category.EXFILTRATION: {Category.EXFILTRATION, Category.TOOL_POISONING, Category.EXCESS_ACCESS},
    Category.EXCESS_ACCESS: {Category.EXCESS_ACCESS, Category.BEHAVIOR_MISMATCH},
    Category.BEHAVIOR_MISMATCH: {Category.EXCESS_ACCESS},
}


def _merge_into(base: Finding, other: Finding) -> None:
    base.detectors = sorted(set(base.detectors) | set(other.detectors))
    base.confidence = round(min(0.99, 1 - (1 - base.confidence) * (1 - other.confidence * 0.5)), 3)
    if other.severity.rank > base.severity.rank:
        base.severity = other.severity
    for h in other.highlights:
        if h not in base.highlights:
            base.highlights.append(h)
    if base.tool is None and other.tool:
        base.tool = other.tool
    if not base.fix and other.fix:
        base.fix = other.fix


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse findings describing the same issue (e.g. Semgrep + Bandit on the same line)."""
    by_key: dict[tuple, Finding] = {}
    for f in findings:
        key = f.dedupe_key
        if key in by_key:
            _merge_into(by_key[key], f)
        else:
            by_key[key] = f.model_copy(deep=True)
    return list(by_key.values())


def correlate(findings: list[Finding]) -> list[Finding]:
    """Boost confidence when static/description evidence is confirmed by dynamic probing."""
    dynamic = [f for f in findings if f.source == Source.DYNAMIC]
    boosted: set[int] = set()
    for d in dynamic:
        related_cats = _CORROBORATES.get(d.category, set())
        for s in findings:
            if s.source not in (Source.STATIC, Source.DESCRIPTION) or s.severity.rank < Severity.MEDIUM.rank:
                continue
            if s.tool and d.tool:
                match = s.tool == d.tool and s.category in related_cats
            else:  # file-level static finding: only an exact category match counts
                match = s.category == d.category
            if not match:
                continue
            s.extra["confirmed_by"] = sorted(set(s.extra.get("confirmed_by", [])) | {d.id or d.title})
            if "dynamic" not in s.detectors:
                s.detectors.append("dynamic")
            if id(s) not in boosted:  # boost each corroborated finding once
                boosted.add(id(s))
                s.confidence = round(min(0.99, s.confidence + 0.15), 3)
    return findings


def assign_ids(findings: list[Finding]) -> list[Finding]:
    counters: dict[Source, int] = {}
    for f in sorted(findings, key=lambda f: (-f.severity.rank, f.source.value, f.tool or "", f.title)):
        counters[f.source] = counters.get(f.source, 0) + 1
        f.id = f"MCPG-{SOURCE_CODES[f.source]}-{counters[f.source]:03d}"
    return sort_findings(findings)


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity.rank, -f.confidence, f.id))


def verdict_for(findings: list[Finding]) -> Verdict:
    worst = max((f.severity.rank for f in findings), default=-1)
    if worst >= Severity.HIGH.rank:
        return Verdict.FAIL
    if worst == Severity.MEDIUM.rank:
        return Verdict.WARN
    return Verdict.PASS


def risk_score(findings: list[Finding]) -> int:
    p = 1.0
    for f in findings:
        p *= 1 - SEVERITY_WEIGHT[f.severity] * f.confidence
    return round(100 * (1 - p))


def process(findings: list[Finding]) -> tuple[list[Finding], Verdict, int]:
    """Full engine pass. Returns (final findings, verdict, risk score)."""
    merged = dedupe(findings)
    merged = assign_ids(merged)  # IDs first so correlation can reference dynamic findings by ID
    merged = correlate(merged)
    return sort_findings(merged), verdict_for(merged), risk_score(merged)
