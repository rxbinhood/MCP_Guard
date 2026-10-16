"""Built-in static analyzer (no external tools required).

Always runs, so static verdicts never depend on Semgrep/Bandit/Gitleaks being installed.
Python files are analyzed with the ``ast`` module; JS/TS with targeted regexes.
It also records which *capabilities* (network, exec, filesystem) the code uses, which
the pipeline compares against what the tool descriptions claim (excess access).
"""

from __future__ import annotations

import ast
import math
import re
from dataclasses import dataclass, field
from pathlib import Path

from mcpguard.findings import Category, Finding, Severity, Source
from mcpguard.ingest.source import iter_source_files

NETWORK_MODULES = {"requests", "httpx", "urllib.request", "urllib3", "http.client", "socket", "aiohttp",
                   "websockets", "websocket", "smtplib", "ftplib", "paramiko", "telnetlib", "grpc"}
EXEC_MODULES = {"subprocess", "pty", "commands"}
SENSITIVE_STRINGS = re.compile(
    r"(^|/)\.ssh(/|$)|\bid_(rsa|dsa|ecdsa|ed25519)\b|\.aws/credentials|(^|/)\.env$|\.npmrc|\.pypirc|\.netrc"
    r"|\.git-credentials|\.kube/config|/etc/shadow|\.docker/config\.json|\.bash_history|wallet\.dat", re.I)
SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("private-key", re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("generic-secret", re.compile(
        r"""(?i)\b[\w-]*(api[_-]?key|secret|token|passwd|password|auth)[\w-]*\b\s*[:=]\s*["']([^"'\s]{16,})["']""")),
]
_TEXT_SUFFIXES = (".py", ".js", ".ts", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".toml", ".env", ".cfg", ".ini",
                  ".txt", ".sh")


@dataclass
class Capabilities:
    network: list[str] = field(default_factory=list)  # evidence strings "file:line module"
    exec: list[str] = field(default_factory=list)
    filesystem: list[str] = field(default_factory=list)
    sensitive_paths: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, list[str]]:
        return {"network": self.network, "exec": self.exec, "filesystem": self.filesystem,
                "sensitive_paths": self.sensitive_paths}

    def used(self) -> set[str]:
        return {k for k in ("network", "exec", "filesystem") if getattr(self, k)}


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def redact(secret: str) -> str:
    return secret[:4] + "*" * max(4, min(16, len(secret) - 4))


def _call_name(node: ast.Call) -> str:
    parts: list[str] = []
    cur: ast.AST = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts))


def _is_dynamic(node: ast.AST | None) -> bool:
    """True if the value is built at runtime (f-string, concatenation, %, .format, variable)."""
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, (ast.List, ast.Tuple)):
        return any(_is_dynamic(e) for e in node.elts)
    return True


class _PyVisitor(ast.NodeVisitor):
    def __init__(self, rel: str, lines: list[str]) -> None:
        self.rel, self.lines = rel, lines
        self.findings: list[Finding] = []
        self.caps = Capabilities()
        self.aliases: dict[str, str] = {}
        self._tool_stack: list[str] = []

    # helpers -------------------------------------------------------------
    def _snippet(self, node: ast.AST) -> str:
        start = getattr(node, "lineno", 1)
        end = getattr(node, "end_lineno", start) or start
        return "\n".join(self.lines[start - 1:min(end, start + 3)]).strip()

    def _add(self, node: ast.AST, rule: str, cat: Category, sev: Severity, title: str, fix: str,
             conf: float = 0.8) -> None:
        self.findings.append(Finding(
            severity=sev, category=cat, tool=self._tool_stack[-1] if self._tool_stack else None, title=title,
            evidence=self._snippet(node), fix=fix, source=Source.STATIC, confidence=conf,
            rule_id=f"builtin.{rule}", file=self.rel, line=getattr(node, "lineno", None), detectors=["builtin"]))

    def _resolve(self, name: str) -> str:
        head, _, rest = name.partition(".")
        full = self.aliases.get(head, head)
        return f"{full}.{rest}" if rest else full

    # visitors ------------------------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            self.aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            self._record_module(a.name, node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for a in node.names:
            self.aliases[a.asname or a.name] = f"{mod}.{a.name}"
            self._record_module(f"{mod}.{a.name}", node)
        self.generic_visit(node)

    def _record_module(self, mod: str, node: ast.AST) -> None:
        where = f"{self.rel}:{node.lineno} import {mod}"
        if any(mod == m or mod.startswith(m + ".") for m in NETWORK_MODULES):
            self.caps.network.append(where)
        if any(mod == m or mod.startswith(m + ".") for m in EXEC_MODULES):
            self.caps.exec.append(where)

    def visit_FunctionDef(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        is_tool = any(
            isinstance(d.func if isinstance(d, ast.Call) else d, ast.Attribute)
            and (d.func if isinstance(d, ast.Call) else d).attr == "tool"
            for d in node.decorator_list
        )
        if is_tool:
            self._tool_stack.append(node.name)
        self.generic_visit(node)
        if is_tool:
            self._tool_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and len(node.value) < 200 and SENSITIVE_STRINGS.search(node.value):
            self.caps.sensitive_paths.append(f"{self.rel}:{node.lineno} {node.value!r}")

    def visit_Call(self, node: ast.Call) -> None:
        name = self._resolve(_call_name(node))
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        first = node.args[0] if node.args else kw.get("args") or kw.get("cmd")
        where = f"{self.rel}:{node.lineno} {name}()"

        if name.startswith("subprocess.") or name in ("os.system", "os.popen") or name.startswith("os.exec") \
                or name.startswith("os.spawn"):
            self.caps.exec.append(where)
        if name in ("open", "io.open") or name.endswith((".read_text", ".write_text", ".read_bytes",
                                                         ".write_bytes")) or name.startswith("shutil."):
            self.caps.filesystem.append(where)
        if name.startswith(("requests.", "httpx.", "urllib.request.", "aiohttp.", "socket.")):
            self.caps.network.append(where)

        shell_true = isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True
        if name.startswith("subprocess.") and shell_true:
            dyn = _is_dynamic(first)
            self._add(node, "subprocess-shell-true", Category.COMMAND_INJECTION,
                      Severity.HIGH if dyn else Severity.LOW,
                      "Command built from input and executed with shell=True" if dyn
                      else "subprocess call with shell=True",
                      "Pass the command as a list without shell=True (e.g. subprocess.run(['ping', '-c', '1', host])) "
                      "and validate inputs against an allowlist (e.g. ipaddress.ip_address / hostname regex).",
                      0.9 if dyn else 0.5)
        elif name in ("os.system", "os.popen") and _is_dynamic(first):
            self._add(node, "os-system", Category.COMMAND_INJECTION, Severity.HIGH,
                      f"{name}() called with a dynamic command string",
                      "Replace os.system/os.popen with subprocess.run([...]) using an argument list, never a "
                      "formatted string, and validate every argument.", 0.9)
        elif name in ("eval", "exec", "builtins.eval", "builtins.exec") and _is_dynamic(first):
            self._add(node, "eval-exec", Category.UNSAFE_DESERIALIZATION, Severity.HIGH,
                      f"{name.split('.')[-1]}() on dynamic input",
                      "Never eval/exec data. Parse it with a safe parser (ast.literal_eval, json, or a "
                      "whitelisted expression evaluator).", 0.85)
        elif name in ("pickle.loads", "pickle.load", "cPickle.loads", "dill.loads", "marshal.loads",
                      "jsonpickle.decode", "shelve.open"):
            self._add(node, "pickle", Category.UNSAFE_DESERIALIZATION, Severity.HIGH,
                      f"Unsafe deserialization with {name}()",
                      "Use a data-only format such as JSON and validate it with a schema; pickle executes code "
                      "while loading.", 0.9)
        elif name in ("yaml.load", "yaml.load_all", "yaml.unsafe_load"):
            loader = kw.get("Loader") or (node.args[1] if len(node.args) > 1 else None)
            loader_name = ast.unparse(loader) if loader is not None else ""
            if name == "yaml.unsafe_load" or "Safe" not in loader_name:
                self._add(node, "yaml-load", Category.UNSAFE_DESERIALIZATION, Severity.HIGH,
                          "yaml.load without SafeLoader", "Use yaml.safe_load() instead.", 0.85)
        elif name.startswith(("requests.", "httpx.")) and isinstance(kw.get("verify"), ast.Constant) \
                and kw["verify"].value is False:
            self._add(node, "tls-verify-disabled", Category.EXCESS_ACCESS, Severity.MEDIUM,
                      "TLS certificate verification disabled",
                      "Remove verify=False so outbound traffic cannot be intercepted.", 0.8)
        self.generic_visit(node)


def _scan_python(path: Path, rel: str) -> tuple[list[Finding], Capabilities]:
    text = path.read_text(errors="ignore")
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return [], Capabilities()
    v = _PyVisitor(rel, text.splitlines())
    v.visit(tree)
    return v.findings, v.caps


_JS_RULES = [
    ("js-child-process-exec", Category.COMMAND_INJECTION, Severity.HIGH,
     re.compile(r"\b(exec|execSync)\s*\(\s*(`[^`]*\$\{|[^,)]*\+)"),
     "Command string built from input passed to child_process.exec",
     "Use execFile/spawn with an argument array (shell: false) and validate inputs."),
    ("js-shell-true", Category.COMMAND_INJECTION, Severity.MEDIUM,
     re.compile(r"\bspawn(Sync)?\s*\([^)]*shell\s*:\s*true"),
     "spawn() with shell: true", "Remove shell: true and pass arguments as an array."),
    ("js-eval", Category.UNSAFE_DESERIALIZATION, Severity.HIGH,
     re.compile(r"(?<![\w.])eval\s*\(\s*[^'\"`)]|new\s+Function\s*\(|vm\.runIn\w*Context\s*\("),
     "Dynamic code evaluation", "Never evaluate input; use JSON.parse or a safe parser."),
    ("js-unsafe-yaml", Category.UNSAFE_DESERIALIZATION, Severity.HIGH,
     re.compile(r"\b(yaml\.load\s*\((?![^)]*(JSON_SCHEMA|FAILSAFE))|node-serialize|unserialize\s*\()"),
     "Unsafe deserialization", "Use a safe schema (yaml.load with JSON_SCHEMA) or JSON."),
]
_JS_NET = re.compile(r"\b(fetch\s*\(|axios|node-fetch|https?\.request|net\.connect|require\(['\"](http|https|net)['\"]\))")
_JS_EXEC = re.compile(r"child_process")
_JS_FS = re.compile(r"\bfs\.(read|write|unlink|rm|createReadStream)|from ['\"](node:)?fs")


def _scan_js(path: Path, rel: str) -> tuple[list[Finding], Capabilities]:
    text = path.read_text(errors="ignore")
    lines = text.splitlines()
    findings: list[Finding] = []
    caps = Capabilities()
    for i, line in enumerate(lines, 1):
        for rid, cat, sev, pat, title, fix in _JS_RULES:
            if pat.search(line):
                findings.append(Finding(severity=sev, category=cat, title=title, evidence=line.strip(), fix=fix,
                                        source=Source.STATIC, confidence=0.75, rule_id=f"builtin.{rid}",
                                        file=rel, line=i, detectors=["builtin"]))
        if _JS_NET.search(line):
            caps.network.append(f"{rel}:{i} {line.strip()[:60]}")
        if _JS_EXEC.search(line):
            caps.exec.append(f"{rel}:{i} {line.strip()[:60]}")
        if _JS_FS.search(line):
            caps.filesystem.append(f"{rel}:{i} {line.strip()[:60]}")
        m = SENSITIVE_STRINGS.search(line)
        if m and ("'" in line or '"' in line or "`" in line):
            caps.sensitive_paths.append(f"{rel}:{i} {m.group(0)}")
    return findings, caps


def _scan_secrets(path: Path, rel: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except OSError:
        return findings
    for i, line in enumerate(lines, 1):
        if len(line) > 2000:
            continue
        for rid, pat in SECRET_PATTERNS:
            m = pat.search(line)
            if not m:
                continue
            secret = m.group(m.lastindex or 0) if rid == "generic-secret" else m.group(0)
            if rid == "generic-secret" and (_entropy(secret) < 3.2 or secret.lower().startswith(("http", "${"))
                                            or "example" in secret.lower() or " " in secret):
                continue
            findings.append(Finding(
                severity=Severity.HIGH if rid != "generic-secret" else Severity.MEDIUM,
                category=Category.HARDCODED_SECRET, title=f"Hardcoded secret ({rid})",
                evidence=line.strip().replace(secret, redact(secret))[:200],
                fix="Remove the secret from source, rotate it, and load it from an environment variable or a "
                    "secret manager at runtime.",
                source=Source.STATIC, confidence=0.8 if rid != "generic-secret" else 0.65,
                rule_id=f"builtin.secret-{rid}", file=rel, line=i, detectors=["builtin"]))
            break
    return findings


def scan(root: Path) -> tuple[list[Finding], Capabilities]:
    findings: list[Finding] = []
    caps = Capabilities()
    for path in iter_source_files(root, _TEXT_SUFFIXES):
        rel = str(path.relative_to(root))
        if path.stat().st_size > 1_000_000 or path.name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
            continue
        if path.suffix == ".py":
            f, c = _scan_python(path, rel)
        elif path.suffix in (".js", ".ts", ".mjs", ".cjs"):
            f, c = _scan_js(path, rel)
        else:
            f, c = [], Capabilities()
        findings += f + _scan_secrets(path, rel)
        for k in ("network", "exec", "filesystem", "sensitive_paths"):
            getattr(caps, k).extend(getattr(c, k))
    return findings, caps
