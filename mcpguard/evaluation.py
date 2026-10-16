"""Evaluation harness.

1. Description samples: a labeled JSON file of tool descriptions
   ``[{"id": "...", "text": "...", "label": "benign" | "malicious", "kind": "..."}]``.
   Reports detection rate (TPR) and false-positive rate per analyzer mode.
2. Test servers: scans every bundled server and checks the verdict matches the expected one.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from mcpguard.config import PROJECT_ROOT, get_settings
from mcpguard.desc_analyzer.analyzer import analyze_tools
from mcpguard.findings import Severity, ToolDef

Log = Callable[[str], None]

# Ground truth for the bundled test servers.
EXPECTED_SERVERS = [
    {"server": "clean_calc", "expected": "PASS", "planted": "None (safe AST-based calculator)"},
    {"server": "clean_notes", "expected": "PASS", "planted": "None (file access scoped to notes dir)"},
    {"server": "vuln_shell", "expected": "FAIL", "planted": "Command injection (shell=True), pickle.loads, hardcoded token"},
    {"server": "poisoned_weather", "expected": "FAIL",
     "planted": "Hidden instructions in description + parameter description; reads ~/.ssh/id_rsa and posts it"},
    {"server": "rugpull_todo", "expected": "PASS", "planted": "Clean at pin time; rug pull when toggle is armed"},
]

MALICIOUS_THRESHOLD = 0.4  # score at/above which a description counts as "detected" (MEDIUM or worse)


def results_path() -> Path:
    return get_settings().home / "eval_results.json"


def _rates(rows: list[tuple[str, float]]) -> dict[str, Any]:
    tp = sum(1 for label, s in rows if label == "malicious" and s >= MALICIOUS_THRESHOLD)
    fn = sum(1 for label, s in rows if label == "malicious" and s < MALICIOUS_THRESHOLD)
    fp = sum(1 for label, s in rows if label == "benign" and s >= MALICIOUS_THRESHOLD)
    tn = sum(1 for label, s in rows if label == "benign" and s < MALICIOUS_THRESHOLD)
    pos, neg = tp + fn, fp + tn
    return {"n": len(rows), "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "detection_rate": tp / pos if pos else 0.0, "false_positive_rate": fp / neg if neg else 0.0,
            "precision": tp / (tp + fp) if tp + fp else 0.0}


async def evaluate_descriptions(samples_file: Path, use_ai: bool = True, log: Log | None = None) -> dict[str, Any]:
    say = log or (lambda _m: None)
    if not samples_file.exists():
        return {"available": False, "reason": f"{samples_file} not found"}
    try:
        samples = json.loads(samples_file.read_text(encoding="utf-8"))
        tools = [ToolDef(name=s.get("id", f"sample_{i}"), description=s["text"]) for i, s in enumerate(samples)]
        labels = [s["label"] for s in samples]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        return {"available": False, "reason": f"invalid samples file: {exc}"}

    modes: dict[str, Any] = {}
    per_sample: list[dict[str, Any]] = [
        {"id": t.name, "label": lab, "kind": s.get("kind"), "text": s["text"][:300]}
        for t, lab, s in zip(tools, labels, samples, strict=True)
    ]
    runs = [("rules", False)] + ([("full", True)] if use_ai else [])
    for mode, ai in runs:
        say(f"Evaluating {len(tools)} samples in mode '{mode}'")
        res = await analyze_tools(tools, use_ai=ai)
        if mode == "full" and all(e.get("status") != "online" for k, e in res.engines.items() if k != "rules"):
            say("No AI layer online; skipping 'full' mode")
            break
        scores = [res.verdict_for(t.name).score for t in tools]
        modes[mode] = {**_rates(list(zip(labels, scores, strict=True))),
                       "layers": [k for k, e in res.engines.items() if e.get("status") == "online"]}
        for row, score in zip(per_sample, scores, strict=True):
            row[f"score_{mode}"] = score
    by_kind: dict[str, dict[str, int]] = {}
    best = "full" if "full" in modes else "rules"
    for row in per_sample:
        k = by_kind.setdefault(row.get("kind") or row["label"], {"total": 0, "flagged": 0})
        k["total"] += 1
        k["flagged"] += int(row.get(f"score_{best}", 0) >= MALICIOUS_THRESHOLD)
    return {"available": True, "file": str(samples_file), "threshold": MALICIOUS_THRESHOLD, "modes": modes,
            "by_kind": by_kind, "samples": per_sample}


async def evaluate_servers(use_ai: bool = True, log: Log | None = None) -> list[dict[str, Any]]:
    from mcpguard.pipeline import ScanOptions, run_scan

    out: list[dict[str, Any]] = []
    for spec in EXPECTED_SERVERS:
        target = str(PROJECT_ROOT / "test_servers" / spec["server"])
        if log:
            log(f"Scanning {spec['server']}")
        res = await run_scan(target, ScanOptions(ai=use_ai))
        serious = [f for f in res.findings if f.severity.rank >= Severity.MEDIUM.rank]
        out.append({**spec, "verdict": res.verdict.value, "risk_score": res.risk_score,
                    "passed": res.verdict.value == spec["expected"], "findings": len(res.findings),
                    "caught_by": sorted({f.source.value for f in serious}),
                    "top_finding": serious[0].title if serious else None, "scan_id": res.id})
    return out


async def run_evaluation(samples_file: Path | None = None, use_ai: bool = True, include_servers: bool = True,
                         log: Log | None = None) -> dict[str, Any]:
    samples_file = samples_file or PROJECT_ROOT / "tests" / "description_samples.json"
    if not samples_file.is_absolute():
        samples_file = (Path.cwd() / samples_file) if (Path.cwd() / samples_file).exists() else PROJECT_ROOT / samples_file
    result: dict[str, Any] = {"generated_at": time.time(),
                              "descriptions": await evaluate_descriptions(samples_file, use_ai, log)}
    if include_servers:
        result["servers"] = await evaluate_servers(use_ai, log)
    return result


def save_results(result: dict[str, Any], path: Path | None = None) -> Path:
    path = path or results_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return path


def load_results() -> dict[str, Any] | None:
    path = results_path()
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
