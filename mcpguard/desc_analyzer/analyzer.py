"""Description analyzer: rules -> Prompt Guard 2 -> LLM judge, cheapest first.

Produces one :class:`ToolVerdict` per tool (for the Tools Inspector) plus findings.
Layers that are offline are skipped and reported in ``engines`` so the UI can show
an "AI model offline" badge; rule checks always run.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

import httpx

from mcpguard.config import get_settings
from mcpguard.desc_analyzer import llm_judge, prompt_guard
from mcpguard.desc_analyzer.rules import RuleResult, check_fields, noisy_or
from mcpguard.findings import Category, Finding, Severity, Source, ToolDef, ToolVerdict

Log = Callable[[str], None]

PG_WEIGHT = 0.8  # Prompt Guard is tuned for jailbreaks; trust it slightly less than a direct rule hit.
LLM_CONCURRENCY = 4

# Keyword fallback for "claimed capabilities" when the LLM judge is offline.
_CAPABILITY_WORDS = {
    "network": r"\b(http|https|url|api|fetch|download|upload|web|request|weather|forecast|search|online|remote"
               r"|email|send|webhook|slack|github)\b",
    "filesystem": r"\b(file|files|folder|directory|path|note|notes|read|write|save|disk|document)\b",
    "exec": r"\b(command|shell|execute|run|ping|process|script|terminal)\b",
}


@dataclass
class AnalysisResult:
    findings: list[Finding] = field(default_factory=list)
    verdicts: list[ToolVerdict] = field(default_factory=list)
    engines: dict[str, Any] = field(default_factory=dict)

    def verdict_for(self, tool: str) -> ToolVerdict | None:
        return next((v for v in self.verdicts if v.tool == tool), None)


def keyword_capabilities(tool: ToolDef) -> list[str]:
    text = " ".join(t for _, t in tool.text_fields()).lower()
    caps = [cap for cap, pat in _CAPABILITY_WORDS.items() if re.search(pat, text)]
    return caps or ["none"]


def severity_for(score: float) -> Severity | None:
    if score >= 0.85:
        return Severity.CRITICAL
    if score >= 0.6:
        return Severity.HIGH
    if score >= 0.4:
        return Severity.MEDIUM
    if score > 0.15:
        return Severity.LOW
    return None


def _combine(rules: RuleResult, pg: float | None, judgement: llm_judge.Judgement | None) -> float:
    parts = [rules.score]
    if pg is not None:
        parts.append(PG_WEIGHT * pg)
    if judgement is not None and judgement.malicious:
        parts.append(judgement.confidence)
    score = noisy_or(parts)
    # A confident "benign" from the judge dampens weak rule-only signals (reduces false positives),
    # but never overrides strong rule evidence.
    if judgement is not None and not judgement.malicious and rules.score < 0.6:
        score *= 1.0 - 0.6 * judgement.confidence
    return round(score, 3)


def _build_finding(tool: ToolDef, verdict: ToolVerdict, rules: RuleResult,
                   judgement: llm_judge.Judgement | None) -> list[Finding]:
    sev = severity_for(verdict.score)
    if sev is None:
        return []
    ids = rules.rule_ids
    detectors = sorted({s["layer"] for s in verdict.signals})
    evidence_lines = [f"[{h['field']}] {h['text']}" for h in verdict.highlights[:6]]
    if judgement and judgement.malicious and judgement.reason:
        evidence_lines.append(f"LLM judge: {judgement.reason}")
    if ids & {"desc.conceal", "desc.ai_directed", "desc.instruction_override", "desc.hidden_unicode"}:
        title = "Hidden instructions addressed to the AI in tool definition"
    elif judgement and judgement.malicious:
        title = "LLM judge flags tool definition as manipulative"
    elif "desc.base64_blob" in ids:
        title = "Encoded content in tool definition"
    else:
        title = "Suspicious wording in tool definition"
    findings = [Finding(
        severity=sev, category=Category.TOOL_POISONING, tool=tool.name, title=title,
        evidence="\n".join(evidence_lines) or tool.description[:300],
        fix=(f"Remove any text addressed to the model from `{tool.name}` (description and parameter "
             "descriptions). A tool description should only explain what the tool does and what its "
             "parameters mean. Do not connect this server to an agent until the definition is fixed and re-pinned."),
        source=Source.DESCRIPTION, confidence=min(0.99, max(verdict.score, 0.3)),
        rule_id="description." + ("llm" if not ids else sorted(ids)[0].split(".", 1)[1]),
        highlights=[h["text"] for h in verdict.highlights], detectors=detectors,
    )]
    # Instructions that point the model at secrets are an exfiltration attempt in their own right.
    if "desc.sensitive_path" in ids and ids & {"desc.ai_directed", "desc.conceal", "desc.secret_request",
                                                "desc.instruction_override"}:
        paths = sorted({h.match for h in rules.hits if h.rule_id == "desc.sensitive_path"})
        findings.append(Finding(
            severity=Severity.HIGH if sev.rank < Severity.CRITICAL.rank else Severity.CRITICAL,
            category=Category.EXFILTRATION, tool=tool.name,
            title=f"Tool definition instructs the agent to access {', '.join(paths)}",
            evidence="\n".join(f"[{h.field}] {h.match}" for h in rules.hits
                               if h.rule_id in ("desc.sensitive_path", "desc.secret_request")),
            fix=("Treat any credentials on machines where this server ran as exposed and rotate them. "
                 "Block the server and report it to the registry/maintainer."),
            source=Source.DESCRIPTION, confidence=min(0.99, verdict.score),
            rule_id="description.sensitive_path", highlights=paths, detectors=detectors,
        ))
    return findings


async def analyze_tools(tools: list[ToolDef], use_ai: bool = True, log: Log | None = None) -> AnalysisResult:
    result = AnalysisResult()
    say = log or (lambda _m: None)

    # Layer 1: rules (always).
    rule_results = {t.name: check_fields(t.text_fields()) for t in tools}
    say(f"Rule checks: {sum(1 for r in rule_results.values() if r.hits)} of {len(tools)} tool(s) with hits")
    result.engines["rules"] = {"status": "online", "detail": f"{8} rule families"}

    # Layer 2: Prompt Guard 2 (optional).
    pg_scores: dict[str, float] = {}
    if use_ai:
        pg_ok, pg_detail = prompt_guard.status()
        scores = None
        if pg_ok:
            texts = ["\n".join(text for f, text in t.text_fields() if f != "name") for t in tools]
            scores = await asyncio.to_thread(prompt_guard.score_texts, texts)
        if scores is not None:
            pg_scores = {t.name: s for t, s in zip(tools, scores, strict=True)}
            result.engines["prompt_guard"] = {"status": "online", "detail": pg_detail}
            say(f"Prompt Guard 2 scored {len(scores)} tool(s)")
        else:
            result.engines["prompt_guard"] = {"status": "offline", "detail": pg_detail}
            say(f"Prompt Guard 2 offline ({pg_detail}); skipping")
    else:
        result.engines["prompt_guard"] = {"status": "disabled", "detail": "AI analysis disabled"}

    # Layer 3: LLM judge (optional), run concurrently.
    judgements: dict[str, llm_judge.Judgement] = {}
    if use_ai:
        ok, detail = llm_judge.status()
        if ok:
            sem = asyncio.Semaphore(LLM_CONCURRENCY)
            errors: list[str] = []
            async with httpx.AsyncClient(timeout=get_settings().llm_timeout) as client:
                async def one(tool: ToolDef) -> None:
                    async with sem:
                        try:
                            judgements[tool.name] = await llm_judge.judge(tool, client)
                            j = judgements[tool.name]
                            say(f"LLM judge: {tool.name} -> {'MALICIOUS' if j.malicious else 'benign'} "
                                f"({j.confidence:.2f})")
                        except llm_judge.JudgeUnavailable as exc:
                            errors.append(f"{tool.name}: {exc}")
                await asyncio.gather(*(one(t) for t in tools))
            status = "online" if not errors else ("degraded" if judgements else "offline")
            result.engines["llm"] = {"status": status, "detail": detail, "errors": errors[:5]}
            for e in errors[:3]:
                say(f"LLM judge error: {e}")
        else:
            result.engines["llm"] = {"status": "offline", "detail": detail}
            say(f"AI model offline ({detail}); using rule-based detection only")
    else:
        result.engines["llm"] = {"status": "disabled", "detail": "AI analysis disabled"}

    # Combine per tool.
    for tool in tools:
        rules = rule_results[tool.name]
        pg = pg_scores.get(tool.name)
        j = judgements.get(tool.name)
        verdict = ToolVerdict(tool=tool.name)
        verdict.layers_used = ["rules"] + (["prompt_guard"] if pg is not None else []) + (["llm"] if j else [])
        for h in rules.hits:
            verdict.signals.append({"layer": "rules", "rule": h.rule_id, "title": h.title, "field": h.field,
                                    "match": h.match, "weight": h.weight, "decoded": h.decoded})
            verdict.highlights.append({"field": h.field, "text": h.match})
        if pg is not None:
            verdict.signals.append({"layer": "prompt_guard", "score": round(pg, 3)})
        if j is not None:
            verdict.signals.append({"layer": "llm", "malicious": j.malicious, "confidence": j.confidence,
                                    "reason": j.reason, "suspicious_text": j.suspicious_text})
            if j.malicious and j.suspicious_text:
                field_name = next((f for f, text in tool.text_fields() if j.suspicious_text in text), "description")
                verdict.highlights.append({"field": field_name, "text": j.suspicious_text})
            verdict.claimed_behavior = j.claimed_behavior or None
            verdict.claimed_capabilities = [c for c in j.claimed_capabilities if c] or keyword_capabilities(tool)
        else:
            verdict.claimed_capabilities = keyword_capabilities(tool)
        verdict.score = _combine(rules, pg, j)
        verdict.verdict = "malicious" if verdict.score >= 0.6 else "suspicious" if verdict.score >= 0.3 else "clean"
        result.verdicts.append(verdict)
        result.findings += _build_finding(tool, verdict, rules, j)
    return result
