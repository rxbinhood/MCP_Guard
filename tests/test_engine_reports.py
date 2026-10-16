"""Findings engine (dedupe, verdict, risk) and report renderers."""

import json

from mcpguard import engine
from mcpguard.findings import Category, Finding, Manifest, ScanResult, Severity, Source, ToolDef, Verdict
from mcpguard.report import render


def _f(sev, cat=Category.COMMAND_INJECTION, src=Source.STATIC, file="s.py", line=1, conf=0.8, tool=None, det="x"):
    return Finding(severity=sev, category=cat, title="t", source=src, file=file, line=line, confidence=conf,
                   tool=tool, detectors=[det], evidence="os.system(cmd)", fix="fix it")


def test_dedupe_merges_same_line_and_keeps_worst_severity():
    a, b = _f(Severity.HIGH, det="bandit"), _f(Severity.CRITICAL, det="semgrep", tool="ping")
    merged = engine.dedupe([a, b])
    assert len(merged) == 1
    m = merged[0]
    assert m.severity == Severity.CRITICAL and m.tool == "ping"
    assert set(m.detectors) == {"bandit", "semgrep"} and m.confidence > 0.8


def test_verdict_rules():
    assert engine.verdict_for([]) == Verdict.PASS
    assert engine.verdict_for([_f(Severity.LOW)]) == Verdict.PASS
    assert engine.verdict_for([_f(Severity.MEDIUM)]) == Verdict.WARN
    assert engine.verdict_for([_f(Severity.HIGH)]) == Verdict.FAIL


def test_risk_score_monotonic():
    low = engine.risk_score([_f(Severity.LOW)])
    crit = engine.risk_score([_f(Severity.CRITICAL, conf=0.95)])
    assert 0 < low < crit <= 100 and engine.risk_score([]) == 0


def test_ids_and_dynamic_correlation():
    static = _f(Severity.HIGH, tool="ping_host")
    dyn = _f(Severity.CRITICAL, src=Source.DYNAMIC, file=None, line=None, tool="ping_host")
    out, verdict, _ = engine.process([static, dyn])
    ids = {f.id for f in out}
    assert {"MCPG-STAT-001", "MCPG-DYN-001"} == ids
    s = next(f for f in out if f.source == Source.STATIC)
    assert "dynamic" in s.detectors and s.extra["confirmed_by"] and verdict == Verdict.FAIL


def _result():
    findings, verdict, risk = engine.process([
        _f(Severity.HIGH, tool="ping_host"),
        Finding(severity=Severity.CRITICAL, category=Category.TOOL_POISONING, tool="get_weather", title="Hidden",
                source=Source.DESCRIPTION, evidence="[description] <IMPORTANT>", confidence=0.9),
    ])
    return ScanResult(id="s1", target="x", server_name="demo", started_at=0, finished_at=1, verdict=verdict,
                      risk_score=risk, findings=findings,
                      manifest=Manifest(server_name="demo", tools=[ToolDef(name="ping_host")]))


def test_sarif_is_valid_shape():
    sarif = json.loads(render(_result(), "sarif"))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert len(run["results"]) == 2
    for res in run["results"]:
        assert res["ruleId"] in rule_ids
        assert res["level"] in ("error", "warning", "note", "none")
        loc = res["locations"][0]
        assert "physicalLocation" in loc or "logicalLocations" in loc


def test_markdown_and_json_reports():
    md = render(_result(), "md")
    assert "FAIL" in md and "MCPG-DESC-001" in md and "**Fix:**" in md
    data = json.loads(render(_result(), "json"))
    assert data["summary"]["verdict"] == "FAIL" and data["summary"]["counts"]["CRITICAL"] == 1
