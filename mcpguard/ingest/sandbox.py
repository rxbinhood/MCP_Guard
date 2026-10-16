"""Docker sandbox: build an image for the target and produce a locked-down ``docker run`` command.

The target's source is sent as a *build context* (``docker build -f - <dir>``), never
bind-mounted, so this also works when MCPGuard itself runs in a container and talks
to the host daemon through ``/var/run/docker.sock``.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import shutil
import subprocess
from collections.abc import Callable
from functools import lru_cache

from mcpguard.config import get_settings
from mcpguard.ingest.source import Project

Log = Callable[[str], None]

RUNNER_TAG = {"python": "mcpguard/runner-python:1", "node": "mcpguard/runner-node:1"}

# Base images with the MCP SDK and strace preinstalled, built once and reused for every target.
RUNNER_DOCKERFILE = {
    "python": """
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends strace && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir "mcp>=1.9,<2"
RUN useradd -m -u 10001 mcp
""",
    "node": """
FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends strace && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 10001 mcp
""",
}

# Per-target layer: copy the code and install its dependencies (network allowed only at build time).
TARGET_DOCKERFILE = {
    "python": """
FROM {base}
WORKDIR /app
COPY . /app
RUN set -e; \\
    if [ -f requirements.txt ]; then pip install --no-cache-dir -q -r requirements.txt; \\
    elif [ -f pyproject.toml ] || [ -f setup.py ]; then pip install --no-cache-dir -q .; fi
RUN chown -R mcp:mcp /app
USER mcp
ENV HOME=/home/mcp PYTHONUNBUFFERED=1
""",
    "node": """
FROM {base}
WORKDIR /app
COPY . /app
RUN set -e; if [ -f package-lock.json ]; then npm ci --omit=dev; else npm install --omit=dev; fi; \\
    npm run build --if-present
RUN chown -R mcp:mcp /app
USER mcp
ENV HOME=/home/mcp
""",
}

# Hardening flags applied to every container that runs untrusted MCP server code.
HARDENING = [
    "--rm", "-i",
    "--network", "none",
    "--read-only",
    "--tmpfs", "/tmp:rw,size=64m",
    "--tmpfs", "/home/mcp:rw,size=16m,uid=10001,gid=10001",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--memory", "512m",
    "--pids-limit", "128",
    "--cpus", "1",
]


class SandboxError(RuntimeError):
    pass


_BUILD_STEP = re.compile(r"^#\d+ \[(\d+/\d+|\w+ \d+/\d+)\] (?!FROM)|ERROR|error:", re.I)


def _build_log(log: Log | None) -> Log | None:
    """Only forward build step headers and errors; full BuildKit output is too noisy for the UI."""
    if log is None:
        return None
    return lambda line: log(f"docker build {line.split('] ', 1)[-1][:160]}") if _BUILD_STEP.search(line) else None


@lru_cache(maxsize=1)
def _docker_info() -> tuple[bool, str]:
    if shutil.which("docker") is None:
        return False, "docker CLI not installed"
    try:
        proc = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"],
                              capture_output=True, text=True, timeout=8)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return False, f"docker daemon unreachable: {exc}"
    if proc.returncode != 0:
        return False, (proc.stderr.strip().splitlines() or ["docker daemon unreachable"])[-1]
    return True, f"Docker {proc.stdout.strip()}"


def docker_status(refresh: bool = False) -> tuple[bool, str]:
    """(available, detail). Cached because `docker info` is slow."""
    if refresh:
        _docker_info.cache_clear()
    return _docker_info()


def image_tag(project: Project) -> str:
    digest = hashlib.sha256(project.server_key.encode()).hexdigest()[:12]
    return f"mcpguard/target-{digest}:latest"


async def _run(cmd: list[str], stdin: str | None = None, timeout: float | None = None,
               log: Log | None = None) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    lines: list[str] = []

    async def pump() -> None:
        if stdin is not None:
            proc.stdin.write(stdin.encode())
            await proc.stdin.drain()
            proc.stdin.close()
        while True:
            raw = await proc.stdout.readline()
            if not raw:
                break
            line = raw.decode(errors="replace").rstrip()
            lines.append(line)
            if log and line.strip():
                log(line[:300])
        await proc.wait()

    try:
        await asyncio.wait_for(pump(), timeout or get_settings().docker_timeout)
    except TimeoutError as exc:
        proc.kill()
        raise SandboxError(f"timed out: {' '.join(cmd[:3])}") from exc
    return proc.returncode or 0, "\n".join(lines)


async def _image_exists(tag: str) -> bool:
    code, _ = await _run(["docker", "image", "inspect", tag], timeout=20)
    return code == 0


async def ensure_runner(language: str, log: Log | None = None) -> str:
    tag = RUNNER_TAG[language]
    if not await _image_exists(tag):
        if log:
            log(f"Building base sandbox image {tag} (first run only)...")
        code, out = await _run(["docker", "build", "--progress=plain", "-t", tag, "-"],
                               stdin=RUNNER_DOCKERFILE[language], log=_build_log(log))
        if code != 0:
            raise SandboxError(f"failed to build runner image: {out[-500:]}")
    return tag


async def build_target(project: Project, log: Log | None = None, extra: str = "") -> str:
    """Build the target image and return its tag. ``extra`` appends Dockerfile lines (used by the prober)."""
    if project.language not in TARGET_DOCKERFILE:
        raise SandboxError(f"unsupported language for sandboxed execution: {project.language}")
    base = await ensure_runner(project.language, log)
    tag = image_tag(project) if not extra else image_tag(project).replace(":latest", ":probe")
    dockerfile = TARGET_DOCKERFILE[project.language].format(base=base) + extra
    if log:
        log(f"Building sandbox image {tag} from {project.root.name}/")
    code, out = await _run(["docker", "build", "--progress=plain", "-t", tag, "-f", "-", str(project.root)],
                           stdin=dockerfile, log=_build_log(log))
    if code != 0:
        raise SandboxError(f"docker build failed: {out[-800:]}")
    return tag


def run_args(tag: str, command: list[str], extra_flags: list[str] | None = None,
             name: str | None = None) -> list[str]:
    """Arguments for ``docker`` that start the server with stdio attached."""
    flags = list(HARDENING)
    if extra_flags:
        flags += extra_flags
    if name:
        flags = [f for f in flags if f != "--rm"] + ["--name", name]
    return ["run", *flags, tag, *command]
