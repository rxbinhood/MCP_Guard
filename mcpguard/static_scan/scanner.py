"""Static scanner: built-in analyzer + Semgrep (custom MCP rules) + Bandit + Gitleaks.

External engines are optional. Each one that is missing is reported as offline and
skipped; the built-in analyzer always runs. All results are normalized into the
common findings schema.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcpguard.findings import Category, Finding, Severity, Source, ToolVerdict
from mcpguard.static_scan import builtin
from mcpguard.static_scan.builtin import Capabilities

Log = Callable[[str], None]
RULES_DIR = Path(__file__).parent / "rules"
TIMEOUT = 240

# Bandit test id -> (category, severity). Unlisted tests fall back to a severity-based mapping.
_BANDIT_MAP: dict[str, tuple[Category, Severity]] = {
    "B602": (Category.COMMAND_INJECTION, Severity.HIGH),  # subprocess shell=True
    "B605": (Category.COMMAND_INJECTION, Severity.HIGH),  # os.system
    "B604": (Category.COMMAND_INJECTION, Severity.MEDIUM),
    "B609": (Category.COMMAND_INJECTION, Severity.MEDIUM),
    "B301": (Category.UNSAFE_DESERIALIZATION, Severity.HIGH),  # pickle
    "B302": (Category.UNSAFE_DESERIALIZATION, Severity.HIGH),  # marshal
    "B506": (Category.UNSAFE_DESERIALIZATION, Severity.HIGH),  # yaml.load
    "B307": (Category.UNSAFE_DESERIALIZATION, Severity.HIGH),  # eval
    "B102": (Category.UNSAFE_DESERIALIZATION, Severity.HIGH),  # exec
    "B105": (Category.HARDCODED_SECRET, Severity.MEDIUM),
    "B106": (Category.HARDCODED_SECRET, Severity.MEDIUM),
    "B107": (Category.HARDCODED_SECRET, Severity.MEDIUM),
    "B501": (Category.EXCESS_ACCESS, Severity.MEDIUM),  # verify=False
    "B310": (Category.EXCESS_ACCESS, Severity.LOW),  # urlopen with arbitrary scheme
    "B108": (Category.EXCESS_ACCESS, Severity.LOW),  # hardcoded /tmp
}
_BANDIT_IGNORE = {"B101", "B404", "B403", "B603", "B607"}  # asserts / import notices / list-arg subprocess


@dataclass
class StaticResult:
    findings: list[Finding] = field(default_factory=list)
    capabilities: Capabilities = field(default_factory=Capabilities)
    engines: dict[str, dict[str, Any]] = field(default_factory=dict)


def engine_status() -> dict[str, tuple[bool, str]]:
    return {
        "semgrep": (shutil.which("semgrep") is not None, shutil.which("semgrep") or "not installed"),
        "bandit": (shutil.which("bandit") is not None, shutil.which("bandit") or "not installed"),
        "gitleaks": (shutil.which("gitleaks") is not None, shutil.which("gitleaks") or "not installed"),
    }


async def _exec(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd, cwd=str(cwd) if cwd else None, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        env={**os.environ, "SEMGREP_SEND_METRICS": "off"},
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(), TIMEOUT)
    except TimeoutError:
        proc.kill()
        return -1, "", "timeout"
    return proc.returncode or 0, out.decode(errors="replace"), err.decode(errors="replace")


def _line(root: Path, rel: str, line: int | None) -> str:
    if not line:
        return ""
    try:
        lines = (root / rel).read_text(errors="ignore").splitlines()
        return lines[line - 1].strip() if 0 < line <= len(lines) else ""
    except OSError:
        return ""


def _rel(root: Path, path: str) -> str:
    p = Path(path)
    try:
        return str(p.resolve().relative_to(root.resolve())) if p.is_absolute() else str(p)
    except ValueError:
        return str(p)


async def run_semgrep(root: Path) -> list[Finding]:
    code, out, err = await _exec(["semgrep", "scan", "--config", str(RULES_DIR), "--json", "--metrics=off",
                                  "--quiet", "--disable-version-check", "--no-git-ignore", str(root)])
    if not out.strip():
        raise RuntimeError(err.strip().splitlines()[-1] if err.strip() else f"semgrep exited {code}")
    findings: list[Finding] = []
    for r in json.loads(out).get("results", []):
        meta = r.get("extra", {}).get("metadata", {})
        rel = _rel(root, r["path"])
        line = r.get("start", {}).get("line")
        findings.append(Finding(
            severity=Severity(meta.get("mcpguard_severity", "MEDIUM")),
            category=Category(meta.get("mcpguard_category", "excess_access")),
            title=re.split(r"\.\s", r.get("extra", {}).get("message", r["check_id"]))[0].rstrip(".")[:140],
            evidence=_line(root, rel, line), fix=meta.get("fix", ""), source=Source.STATIC, confidence=0.85,
            rule_id=f"semgrep.{r['check_id'].split('.')[-1]}", file=rel, line=line, detectors=["semgrep"],
            extra={"cwe": meta.get("cwe")},
        ))
    return findings


async def run_bandit(root: Path) -> list[Finding]:
    _code, out, err = await _exec(["bandit", "-r", str(root), "-f", "json", "-q",
                                   "-x", ",".join(str(root / d) for d in ("node_modules", ".venv", "venv", "tests"))])
    if not out.strip():
        raise RuntimeError(err.strip().splitlines()[-1] if err.strip() else "bandit produced no output")
    findings: list[Finding] = []
    for r in json.loads(out).get("results", []):
        tid = r.get("test_id", "")
        if tid in _BANDIT_IGNORE:
            continue
        if tid in _BANDIT_MAP:
            cat, sev = _BANDIT_MAP[tid]
        else:
            cat = Category.EXCESS_ACCESS
            sev = {"HIGH": Severity.MEDIUM, "MEDIUM": Severity.LOW}.get(r.get("issue_severity"), Severity.INFO)
        conf = {"HIGH": 0.85, "MEDIUM": 0.65, "LOW": 0.45}.get(r.get("issue_confidence"), 0.5)
        rel = _rel(root, r["filename"])
        findings.append(Finding(
            severity=sev, category=cat, title=f"{r.get('issue_text', tid)}"[:140],
            evidence=(r.get("code") or "").strip()[:400], fix=r.get("more_info", ""), source=Source.STATIC,
            confidence=conf, rule_id=f"bandit.{tid}", file=rel, line=r.get("line_number"), detectors=["bandit"],
            extra={"cwe": (r.get("issue_cwe") or {}).get("id")},
        ))
    return findings


async def run_gitleaks(root: Path) -> list[Finding]:
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "gitleaks.json"
        code, _out, err = await _exec(["gitleaks", "dir", str(root), "--report-format", "json", "--report-path",
                                       str(report), "--redact", "--no-banner", "--exit-code", "0"])
        if not report.exists():  # older gitleaks without `dir`
            code, _out, err = await _exec(["gitleaks", "detect", "--no-git", "--source", str(root),
                                           "--report-format", "json", "--report-path", str(report), "--redact",
                                           "--no-banner", "--exit-code", "0"])
        if not report.exists():
            raise RuntimeError(err.strip().splitlines()[-1] if err.strip() else f"gitleaks exited {code}")
        data = json.loads(report.read_text() or "[]")
    return [Finding(
        severity=Severity.HIGH, category=Category.HARDCODED_SECRET,
        title=f"Hardcoded secret ({r.get('RuleID', 'secret')})",
        evidence=(r.get("Match") or r.get("Secret") or "")[:200],
        fix="Remove the secret from the repository (including git history), rotate it, and load it from the "
            "environment at runtime.",
        source=Source.STATIC, confidence=0.8, rule_id=f"gitleaks.{r.get('RuleID', 'secret')}",
        file=_rel(root, r.get("File", "")), line=r.get("StartLine"), detectors=["gitleaks"],
    ) for r in data]


def excess_access_findings(caps: Capabilities, verdicts: list[ToolVerdict]) -> list[Finding]:
    """Flag capabilities the code uses that no tool description claims to need."""
    claimed: set[str] = set()
    for v in verdicts:
        claimed |= set(v.claimed_capabilities)
    out: list[Finding] = []
    plan = [("network", Severity.MEDIUM, "Code makes network calls but no tool says it needs network access"),
            ("exec", Severity.MEDIUM, "Code can execute processes but no tool says it runs commands"),
            ("filesystem", Severity.LOW, "Code touches the filesystem but no tool mentions files")]
    for cap, sev, title in plan:
        evidence = getattr(caps, cap)
        if evidence and cap not in claimed:
            out.append(Finding(
                severity=sev, category=Category.EXCESS_ACCESS, title=title,
                evidence="\n".join(sorted(set(evidence))[:6]),
                fix=f"Remove the unused {cap} capability, or describe it in the tool descriptions so users can make "
                    "an informed decision.",
                source=Source.STATIC, confidence=0.7, rule_id=f"capability.undeclared_{cap}",
                detectors=["capability-check"], extra={"claimed": sorted(claimed)}))
    if caps.sensitive_paths:
        sev = Severity.HIGH if caps.network else Severity.MEDIUM
        out.append(Finding(
            severity=sev, category=Category.EXFILTRATION,
            title="Code references credential files" + (" and can send data over the network" if caps.network else ""),
            evidence="\n".join(sorted(set(caps.sensitive_paths))[:6]),
            fix="An MCP server should never read SSH keys, cloud credentials or .env files of the host. Remove this "
                "code or isolate the server so those files are not reachable.",
            source=Source.STATIC, confidence=0.8 if caps.network else 0.6,
            rule_id="capability.sensitive_paths", detectors=["capability-check"]))
    return out


async def scan(root: Path, log: Log | None = None) -> StaticResult:
    say = log or (lambda _m: None)
    result = StaticResult()
    findings, caps = await asyncio.to_thread(builtin.scan, root)
    result.findings += findings
    result.capabilities = caps
    result.engines["builtin"] = {"status": "online", "detail": f"{len(findings)} result(s)"}
    say(f"Built-in analyzer: {len(findings)} result(s); capabilities used: {', '.join(sorted(caps.used())) or 'none'}")

    runners = {"semgrep": run_semgrep, "bandit": run_bandit, "gitleaks": run_gitleaks}
    status = engine_status()

    async def one(name: str) -> None:
        if not status[name][0]:
            result.engines[name] = {"status": "offline", "detail": "not installed"}
            say(f"{name}: not installed, skipped")
            return
        try:
            found = await runners[name](root)
            result.findings.extend(found)
            result.engines[name] = {"status": "online", "detail": f"{len(found)} result(s)"}
            say(f"{name}: {len(found)} result(s)")
        except Exception as exc:  # noqa: BLE001 - one broken engine must not break the scan
            result.engines[name] = {"status": "error", "detail": str(exc)[:200]}
            say(f"{name} failed: {exc}")

    await asyncio.gather(*(one(n) for n in runners))
    return result
