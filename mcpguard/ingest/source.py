"""Resolve a scan target (GitHub URL or local folder) into a local project directory."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from mcpguard.config import get_settings

_GIT_URL = re.compile(r"^(https?://|git@)[\w.@:/~-]+?(\.git)?/?$")
_PY_ENTRY_CANDIDATES = ["server.py", "main.py", "app.py", "__main__.py", "src/server.py", "src/main.py"]
_IGNORED_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build", ".tox"}


class IngestError(RuntimeError):
    """Raised when a target cannot be resolved or prepared."""


@dataclass
class Project:
    target: str  # what the user typed
    server_key: str  # normalized identity used for pinning
    root: Path  # local directory containing the project
    language: str  # python | node | unknown
    entry: str | None  # entry file relative to root (python/node)
    command: list[str] = field(default_factory=list)  # command to start the server inside the sandbox

    @property
    def name(self) -> str:
        return self.root.name


def is_remote(target: str) -> bool:
    return bool(_GIT_URL.match(target.strip())) and not Path(target).exists()


def normalize_key(target: str) -> str:
    """Stable identity for a server: absolute path, or repo URL without scheme/.git/trailing slash."""
    t = target.strip()
    if is_remote(t):
        t = re.sub(r"^(https?://|git@)", "", t).replace(":", "/")
        return re.sub(r"(\.git)?/?$", "", t).lower()
    return str(Path(t).expanduser().resolve())


def clone(url: str) -> Path:
    """Shallow-clone a repository into the MCPGuard cache. Re-clones to always scan the latest code."""
    if shutil.which("git") is None:
        raise IngestError("git is not installed; cannot clone remote repositories")
    dest = get_settings().repos_dir / hashlib.sha256(normalize_key(url).encode()).hexdigest()[:16]
    if dest.exists():
        shutil.rmtree(dest)
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", url, str(dest)],
        capture_output=True, text=True, timeout=180,
        # Never prompt for credentials; disable hooks/fsmonitor that could run code.
        env={"GIT_TERMINAL_PROMPT": "0", "PATH": "/usr/bin:/bin:/usr/local/bin"},
    )
    if proc.returncode != 0:
        raise IngestError(f"git clone failed: {proc.stderr.strip() or proc.stdout.strip()}")
    return dest


def iter_source_files(root: Path, suffixes: tuple[str, ...]) -> list[Path]:
    out: list[Path] = []
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix in suffixes and not (_IGNORED_DIRS & set(p.relative_to(root).parts)):
            out.append(p)
    return out


def detect_language(root: Path) -> str:
    if (root / "package.json").exists():
        return "node"
    if any((root / f).exists() for f in ("pyproject.toml", "requirements.txt", "setup.py")):
        return "python"
    if iter_source_files(root, (".py",)):
        return "python"
    if iter_source_files(root, (".js", ".ts", ".mjs")):
        return "node"
    return "unknown"


def _python_entry(root: Path) -> tuple[str | None, list[str]]:
    for cand in _PY_ENTRY_CANDIDATES:
        if (root / cand).exists():
            return cand, ["python", cand]
    # pyproject console script, e.g. [project.scripts] my-server = "pkg.server:main"
    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        try:
            scripts = tomllib.loads(pyproject.read_text()).get("project", {}).get("scripts", {})
        except (tomllib.TOMLDecodeError, OSError):
            scripts = {}
        if scripts:
            name = next(iter(scripts))
            return None, [name]
    # Fall back to the first file that creates an MCP server.
    for path in iter_source_files(root, (".py",)):
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            continue
        if "FastMCP(" in text or ("Server(" in text and "mcp" in text):
            rel = str(path.relative_to(root))
            return rel, ["python", rel]
    return None, []


def _node_entry(root: Path) -> tuple[str | None, list[str]]:
    try:
        pkg = json.loads((root / "package.json").read_text())
    except (OSError, json.JSONDecodeError):
        pkg = {}
    bin_field = pkg.get("bin")
    entry = None
    if isinstance(bin_field, str):
        entry = bin_field
    elif isinstance(bin_field, dict) and bin_field:
        entry = next(iter(bin_field.values()))
    entry = entry or pkg.get("main")
    if not entry:
        for cand in ("index.js", "server.js", "dist/index.js", "build/index.js", "src/index.js"):
            if (root / cand).exists():
                entry = cand
                break
    return entry, (["node", entry] if entry else [])


def resolve(target: str, entry: str | None = None) -> Project:
    """Turn a target string into a :class:`Project`, cloning remote repositories first."""
    target = target.strip()
    if is_remote(target):
        root = clone(target)
    else:
        root = Path(target).expanduser().resolve()
        if not root.exists():
            raise IngestError(f"path does not exist: {target}")
        if root.is_file():
            entry = entry or root.name
            root = root.parent

    language = detect_language(root)
    if entry:
        runner = "node" if entry.endswith((".js", ".mjs", ".cjs")) else "python"
        command = [runner, entry]
        language = "node" if runner == "node" else language
    elif language == "python":
        entry, command = _python_entry(root)
    elif language == "node":
        entry, command = _node_entry(root)
    else:
        command = []

    return Project(target=target, server_key=normalize_key(target), root=root,
                   language=language, entry=entry, command=command)
