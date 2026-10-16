"""Scan pipeline: Ingest -> [Static | Description | Dynamic] -> Findings engine -> Report.

``run_scan`` emits progress events through a callback so the CLI can print them and the
API can stream them to the browser. A failing optional module never fails the scan.
"""

from __future__ import annotations

import asyncio
import time
import traceback
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from mcpguard import engine
from mcpguard.desc_analyzer.analyzer import analyze_tools
from mcpguard.findings import Finding, Manifest, ModuleStatus, ScanResult
from mcpguard.ingest import sandbox
from mcpguard.ingest.manifest import choose_mode, fetch_manifest
from mcpguard.ingest.source import resolve
from mcpguard.static_scan.scanner import excess_access_findings
from mcpguard.static_scan.scanner import scan as static_scan

MODULES = ["ingest", "static", "description", "dynamic", "report"]

Event = dict[str, Any]
Emit = Callable[[Event], Awaitable[None] | None]


@dataclass
class ScanOptions:
    static: bool = True
    ai: bool = True  # AI layers of the description analyzer (rules always run)
    dynamic: bool = False
    sandbox: str | None = None  # auto | docker | static | host
    entry: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"static": self.static, "ai": self.ai, "dynamic": self.dynamic, "sandbox": self.sandbox,
                "entry": self.entry}


def new_scan_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]


class _Progress:
    def __init__(self, result: ScanResult, emit: Emit | None) -> None:
        self.result, self._emit = result, emit
        self.current = "ingest"
        self._pending: list[Event] = []

    async def send(self, event: Event) -> None:
        event.setdefault("ts", time.time())
        if self._emit is None:
            return
        maybe = self._emit(event)
        if maybe is not None:
            await maybe

    def module(self, name: str) -> ModuleStatus:
        return next(m for m in self.result.modules if m.name == name)

    async def start(self, name: str, detail: str | None = None) -> None:
        self.current = name
        m = self.module(name)
        m.status, m.started_at, m.detail = "running", time.time(), detail
        await self.send({"type": "module", "module": name, "status": "running", "detail": detail})

    async def finish(self, name: str, status: str = "done", detail: str | None = None) -> None:
        m = self.module(name)
        m.status, m.finished_at = status, time.time()
        if m.started_at is None:
            m.started_at = m.finished_at
        m.detail = detail or m.detail
        await self.send({"type": "module", "module": name, "status": status, "detail": m.detail,
                         "elapsed": round(m.finished_at - m.started_at, 2)})

    def log_sync(self, message: str, level: str = "info") -> None:
        """Sync logger handed to modules; events are queued and flushed by the async emit."""
        self._pending.append({"type": "log", "module": self.current, "level": level, "message": message,
                              "ts": time.time()})

    async def flush(self) -> None:
        pending, self._pending = self._pending, []
        for e in pending:
            await self.send(e)



async def run_scan(target: str, options: ScanOptions | None = None, emit: Emit | None = None,
                   scan_id: str | None = None) -> ScanResult:
    options = options or ScanOptions()
    result = ScanResult(id=scan_id or new_scan_id(), target=target, started_at=time.time(),
                        options=options.as_dict(), modules=[ModuleStatus(name=m) for m in MODULES])
    progress = _Progress(result, emit)

    def log(msg: str) -> None:
        progress.log_sync(msg)

    async def logged(coro):
        """Await a module coroutine while periodically flushing its log lines."""
        task = asyncio.ensure_future(coro)
        while not task.done():
            await asyncio.wait({task}, timeout=0.25)
            await progress.flush()
        await progress.flush()
        return task.result()

    findings: list[Finding] = []
    await progress.send({"type": "scan", "status": "running", "scan_id": result.id, "target": target})

    # ---------------------------------------------------------------- 0. ingest
    await progress.start("ingest", "Resolving target")
    try:
        project = resolve(target, options.entry)
        result.server_name, result.language = project.name, project.language
        mode = choose_mode(options.sandbox)
        log(f"Target resolved to {project.root} ({project.language}, entry: {project.entry or 'n/a'})")
        docker_ok, docker_detail = sandbox.docker_status()
        result.engines["docker"] = {"status": "online" if docker_ok else "offline", "detail": docker_detail}
        if mode == "static":
            log("No sandbox available or static mode requested: the server will NOT be executed")
        manifest: Manifest = await logged(fetch_manifest(project, mode, log))
        result.manifest = manifest
        result.server_name = manifest.server_name or project.name
        result.engines["manifest"] = {"status": "online", "detail": f"via {manifest.method}"}
        await progress.finish("ingest", detail=f"{len(manifest.tools)} tools via {manifest.method}")
    except Exception as exc:  # noqa: BLE001 - ingest failure ends the scan with a clear error
        log(f"Ingest failed: {exc}")
        await progress.flush()
        await progress.finish("ingest", "failed", str(exc))
        for name in MODULES[1:]:
            await progress.finish(name, "skipped", "ingest failed")
        result.error = f"Ingest failed: {exc}"
        result.finished_at = time.time()
        await progress.send({"type": "scan", "status": "failed", "error": result.error})
        return result

    # ---------------------------------------------------------------- 1. static
    static_res = None
    if options.static:
        await progress.start("static", "Semgrep, Bandit, Gitleaks, built-in")
        try:
            static_res = await logged(static_scan(project.root, log))
            findings += static_res.findings
            result.engines.update(static_res.engines)
            await progress.finish("static", detail=f"{len(static_res.findings)} raw result(s)")
        except Exception as exc:  # noqa: BLE001
            log(f"Static scan error: {exc}")
            await progress.flush()
            await progress.finish("static", "failed", str(exc))
    else:
        await progress.finish("static", "skipped", "disabled")

    # ---------------------------------------------------------------- 2. description analyzer
    await progress.start("description", "Rules -> Prompt Guard 2 -> LLM judge" if options.ai else "Rules only")
    try:
        analysis = await logged(analyze_tools(manifest.tools, use_ai=options.ai, log=log))
        findings += analysis.findings
        result.tool_verdicts = analysis.verdicts
        result.engines.update(analysis.engines)
        if static_res is not None:
            findings += excess_access_findings(static_res.capabilities, analysis.verdicts)
        flagged = sum(1 for v in analysis.verdicts if v.verdict != "clean")
        await progress.finish("description", detail=f"{flagged} of {len(analysis.verdicts)} tool(s) flagged")
    except Exception as exc:  # noqa: BLE001
        log(f"Description analysis error: {exc}")
        await progress.flush()
        await progress.finish("description", "failed", str(exc))

    # ---------------------------------------------------------------- 3. dynamic prober (optional)
    if options.dynamic:
        await progress.start("dynamic", "strace + canaries + capture proxy")
        try:
            from mcpguard.dynamic.prober import probe

            dyn = await logged(probe(project, manifest, result.tool_verdicts, log))
            findings += dyn.findings
            result.engines["dynamic"] = {"status": dyn.status, "detail": dyn.detail}
            await progress.finish("dynamic", "done" if dyn.status == "online" else "skipped", dyn.detail)
        except Exception as exc:  # noqa: BLE001
            log(f"Dynamic probing error: {exc}")
            await progress.flush()
            await progress.finish("dynamic", "failed", str(exc))
    else:
        await progress.finish("dynamic", "skipped", "disabled")

    # ---------------------------------------------------------------- 4/5. engine + report
    await progress.start("report", "Merging findings")
    try:
        result.findings, result.verdict, result.risk_score = engine.process(findings)
        counts = result.counts()
        log(f"Verdict {result.verdict.value} · risk {result.risk_score}/100 · " +
            ", ".join(f"{v} {k}" for k, v in counts.items() if v))
        await progress.flush()
        await progress.finish("report", detail=f"{len(result.findings)} finding(s)")
    except Exception as exc:  # noqa: BLE001
        result.error = f"Findings engine failed: {exc}"
        log(traceback.format_exc(limit=3))
        await progress.flush()
        await progress.finish("report", "failed", str(exc))

    result.finished_at = time.time()
    await progress.send({"type": "scan", "status": "done", "verdict": result.verdict.value,
                         "risk_score": result.risk_score, "counts": result.counts()})
    return result
