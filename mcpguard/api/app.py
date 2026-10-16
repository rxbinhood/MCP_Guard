"""FastAPI backend: scans, findings, pins, diffs, reports, health, evaluation and settings.

Live scan progress is streamed with Server-Sent Events (``GET /api/scans/{id}/events``).
Events are persisted, so a client that connects late (or reconnects) gets a full replay.
The built frontend (``frontend/dist``) is served from ``/`` when present.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections import Counter, defaultdict
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel

from mcpguard import __version__
from mcpguard.api.health import engine_health
from mcpguard.config import PROJECT_ROOT, get_settings, update_settings
from mcpguard.db import get_db
from mcpguard.desc_analyzer import llm_judge, prompt_guard
from mcpguard.findings import ScanResult
from mcpguard.ingest import sandbox
from mcpguard.ingest.source import IngestError, normalize_key
from mcpguard.pipeline import ScanOptions, new_scan_id, run_scan
from mcpguard.report import EXTENSIONS, MEDIA_TYPES, render

FRONTEND_DIST = Path(os.environ.get("MCPGUARD_FRONTEND_DIST", PROJECT_ROOT / "frontend" / "dist"))
RUGPULL_TOGGLE = PROJECT_ROOT / "test_servers" / "rugpull_todo" / ".rugpull"
_tasks: set[asyncio.Task] = set()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    db = get_db()
    # Scans interrupted by a restart can never finish; mark them failed.
    for s in db.list_scans(500):
        if s["status"] in ("queued", "running"):
            db.update_scan(s["id"], status="failed", finished_at=time.time())
    if os.environ.get("MCPGUARD_SEED", "1") == "1":
        from mcpguard.api.seed import seed_if_empty

        seed_if_empty(db)
    yield


app = FastAPI(title="MCPGuard API", version=__version__, lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_methods=["*"], allow_headers=["*"])


# ----------------------------------------------------------------------------- models
class ScanRequest(BaseModel):
    target: str
    static: bool = True
    ai: bool = True
    dynamic: bool = False
    sandbox: str | None = None
    entry: str | None = None


class PinRequest(BaseModel):
    target: str


class VerifyRequest(BaseModel):
    server_key: str
    ai: bool = True


class SettingsUpdate(BaseModel):
    llm_base_url: str | None = None
    llm_model: str | None = None
    llm_api_key: str | None = None  # write-only, kept in memory only
    promptguard_url: str | None = None
    sandbox: str | None = None


class RugpullToggle(BaseModel):
    armed: bool


# ----------------------------------------------------------------------------- health & settings
@app.get("/api/health")
def health(refresh: bool = False) -> dict[str, Any]:
    engines = engine_health(refresh=refresh)
    ai_online = any(e["ok"] for e in engines if e["kind"] == "ai")
    return {"status": "ok", "version": __version__, "ai_online": ai_online, "engines": engines}


@app.get("/api/settings")
def get_settings_api() -> dict[str, Any]:
    s = get_settings()
    return {"llm_base_url": s.llm_base_url, "llm_model": s.llm_model, "llm_api_key_set": bool(s.llm_api_key),
            "promptguard_url": s.promptguard_url, "promptguard_model": s.promptguard_model,
            "sandbox": s.sandbox, "home": str(s.home)}


@app.put("/api/settings")
def put_settings(body: SettingsUpdate) -> dict[str, Any]:
    if body.sandbox and body.sandbox not in ("auto", "docker", "static", "host"):
        raise HTTPException(400, "sandbox must be auto, docker, static or host")
    update_settings(**body.model_dump(exclude_none=True))
    llm_judge.status(refresh=True)
    prompt_guard._status_cache = None  # noqa: SLF001 - force re-check
    sandbox.docker_status(refresh=True)
    return get_settings_api()


@app.get("/api/about")
def about() -> dict[str, Any]:
    s = get_settings()
    return {
        "version": __version__,
        "license": "MIT",
        "models": [
            {"role": "LLM description judge", "name": s.llm_model, "provider": "OpenAI-compatible API",
             "endpoint": s.llm_base_url, "parameters": "not disclosed (closed model)" if "openai.com" in s.llm_base_url
             else "see model card", "license_url": "https://openai.com/policies/terms-of-use/"
             if "openai.com" in s.llm_base_url else None},
            {"role": "Injection classifier (optional)", "name": "Llama Prompt Guard 2 86M",
             "provider": "Meta (open weights)", "parameters": "86M", "model_id": s.promptguard_model,
             "license_url": "https://www.llama.com/llama4/license/",
             "card_url": "https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M"},
        ],
    }


# ----------------------------------------------------------------------------- scans
async def _execute_scan(scan_id: str, req: ScanRequest) -> None:
    db = get_db()
    db.update_scan(scan_id, status="running")

    def emit(event: dict[str, Any]) -> None:
        db.add_event(scan_id, event)

    try:
        result = await run_scan(req.target, ScanOptions(static=req.static, ai=req.ai, dynamic=req.dynamic,
                                                        sandbox=req.sandbox, entry=req.entry),
                                emit=emit, scan_id=scan_id)
        db.update_scan(scan_id, server_name=result.server_name, status="failed" if result.error else "done",
                       verdict=result.verdict.value if not result.error else None, risk_score=result.risk_score,
                       counts=result.counts(), result=result.model_dump(mode="json"), finished_at=result.finished_at)
    except Exception as exc:  # noqa: BLE001 - never leave a scan stuck in "running"
        db.add_event(scan_id, {"type": "scan", "status": "failed", "error": str(exc), "ts": time.time()})
        db.update_scan(scan_id, status="failed", finished_at=time.time())


@app.post("/api/scans", status_code=202)
async def create_scan(req: ScanRequest) -> dict[str, Any]:
    target = req.target.strip()
    if not target:
        raise HTTPException(400, "target is required")
    local = Path(target).expanduser()
    if not local.is_absolute() and not target.startswith(("http://", "https://", "git@")):
        # Resolve relative paths (e.g. "test_servers/clean_calc") against the project root.
        candidate = PROJECT_ROOT / target
        if candidate.exists():
            req.target = str(candidate)
    elif not target.startswith(("http://", "https://", "git@")) and not local.exists():
        raise HTTPException(400, f"path not found: {target}")
    scan_id = new_scan_id()
    get_db().create_scan(scan_id, req.target, req.model_dump())
    task = asyncio.create_task(_execute_scan(scan_id, req))
    _tasks.add(task)
    task.add_done_callback(_tasks.discard)
    return {"id": scan_id, "status": "queued"}


def _summary(row: dict[str, Any]) -> dict[str, Any]:
    return {k: row.get(k) for k in ("id", "target", "server_name", "status", "verdict", "risk_score", "counts",
                                    "options", "started_at", "finished_at")}


@app.get("/api/scans")
def list_scans(limit: int = 50) -> list[dict[str, Any]]:
    return [_summary(r) for r in get_db().list_scans(limit)]


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> dict[str, Any]:
    row = get_db().get_scan(scan_id)
    if not row:
        raise HTTPException(404, "scan not found")
    return {**_summary(row), "result": row.get("result")}


@app.get("/api/scans/{scan_id}/findings")
def get_findings(scan_id: str, severity: str | None = None, category: str | None = None,
                 source: str | None = None, tool: str | None = None) -> list[dict[str, Any]]:
    row = get_db().get_scan(scan_id)
    if not row or not row.get("result"):
        raise HTTPException(404, "scan not found or not finished")
    out = row["result"]["findings"]
    for key, val in (("severity", severity), ("category", category), ("source", source), ("tool", tool)):
        if val:
            out = [f for f in out if str(f.get(key)).lower() == val.lower()]
    return out


@app.get("/api/scans/{scan_id}/events")
async def scan_events(scan_id: str, request: Request) -> StreamingResponse:
    db = get_db()
    if not db.get_scan(scan_id):
        raise HTTPException(404, "scan not found")
    last = int(request.headers.get("last-event-id") or 0)

    async def stream():
        nonlocal last
        idle = 0
        yield "retry: 1500\n\n"
        while True:
            if await request.is_disconnected():
                return
            events = db.get_events(scan_id, last)
            for e in events:
                last = e["seq"]
                yield f"id: {e['seq']}\nevent: {e['type']}\ndata: {json.dumps(e)}\n\n"
            row = db.get_scan(scan_id)
            if row and row["status"] in ("done", "failed") and not events:
                yield f"event: end\ndata: {json.dumps({'status': row['status']})}\n\n"
                return
            idle = 0 if events else idle + 1
            if idle and idle % 40 == 0:
                yield ": keep-alive\n\n"
            await asyncio.sleep(0.25)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/scans/{scan_id}/report")
def scan_report(scan_id: str, format: str = Query("md", pattern="^(md|json|sarif)$")) -> Response:  # noqa: A002
    row = get_db().get_scan(scan_id)
    if not row or not row.get("result"):
        raise HTTPException(404, "scan not found or not finished")
    result = ScanResult.model_validate(row["result"])
    name = f"mcpguard-{(result.server_name or 'scan').replace(' ', '_')}-{scan_id}.{EXTENSIONS[format]}"
    return Response(render(result, format), media_type=MEDIA_TYPES[format],
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@app.delete("/api/scans/{scan_id}", status_code=204)
def delete_scan(scan_id: str) -> Response:
    with get_db().connect() as c:
        c.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        c.execute("DELETE FROM scan_events WHERE scan_id = ?", (scan_id,))
    return Response(status_code=204)


# ----------------------------------------------------------------------------- dashboard stats
@app.get("/api/stats")
def stats() -> dict[str, Any]:
    db = get_db()
    scans = [s for s in db.list_scans(1000) if s["status"] == "done"]
    latest_by_target: dict[str, dict[str, Any]] = {}
    for s in sorted(scans, key=lambda s: s["started_at"]):
        latest_by_target[s["target"]] = s
    sev_totals: Counter = Counter()
    by_source: dict[str, Counter] = defaultdict(Counter)
    by_category: Counter = Counter()
    for s in latest_by_target.values():
        full = db.get_scan(s["id"])
        for f in (full.get("result") or {}).get("findings", []):
            sev_totals[f["severity"]] += 1
            by_source[f["source"]][f["severity"]] += 1
            by_category[f["category"]] += 1
    timeline: dict[str, Counter] = defaultdict(Counter)
    for s in scans:
        day = datetime.fromtimestamp(s["started_at"], UTC).strftime("%Y-%m-%d")
        timeline[day][s.get("verdict") or "UNKNOWN"] += 1
        for sev, n in (s.get("counts") or {}).items():
            timeline[day][f"f_{sev}"] += n
    pins = db.list_pins()
    return {
        "servers_scanned": len(latest_by_target),
        "total_scans": len(scans),
        "total_findings": sum(sev_totals.values()),
        "critical_high": sev_totals["CRITICAL"] + sev_totals["HIGH"],
        "pinned_servers": len(pins),
        "changed_pins": sum(1 for p in pins if p.get("last_status") == "changed"),
        "severity": {k: sev_totals.get(k, 0) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")},
        "by_source": {src: dict(c) for src, c in by_source.items()},
        "by_category": dict(by_category),
        "verdicts": dict(Counter(s.get("verdict") for s in latest_by_target.values())),
        "timeline": [{"date": d, **dict(c)} for d, c in sorted(timeline.items())][-30:],
    }


# ----------------------------------------------------------------------------- pins
def _pin_summary(p: dict[str, Any]) -> dict[str, Any]:
    manifest = p.get("manifest") or {}
    return {k: p.get(k) for k in ("server_key", "server_name", "server_version", "target", "manifest_hash",
                                  "tool_hashes", "pinned_at", "last_verified_at", "last_status")} | {
        "tools": len(manifest.get("tools", [])), "method": manifest.get("method")}


@app.get("/api/pins")
def list_pins() -> list[dict[str, Any]]:
    return [_pin_summary(p) for p in get_db().list_pins()]


@app.post("/api/pins")
async def create_pin(req: PinRequest) -> dict[str, Any]:
    from mcpguard.pin_diff.service import pin

    target = req.target.strip()
    if not Path(target).is_absolute() and (PROJECT_ROOT / target).exists():
        target = str(PROJECT_ROOT / target)
    try:
        record = await pin(target)
    except (IngestError, Exception) as exc:  # noqa: BLE001
        raise HTTPException(400, f"pin failed: {exc}") from exc
    return _pin_summary(get_db().get_pin(record.server_key))


@app.get("/api/pins/detail")
def pin_detail(server_key: str) -> dict[str, Any]:
    db = get_db()
    p = db.get_pin(server_key) or db.get_pin(normalize_key(server_key))
    if not p:
        raise HTTPException(404, "pin not found")
    return {**_pin_summary(p), "manifest": p["manifest"], "checks": db.list_checks(p["server_key"])}


@app.post("/api/pins/verify")
async def verify_pin(req: VerifyRequest) -> dict[str, Any]:
    from mcpguard.pin_diff.service import verify

    db = get_db()
    p = db.get_pin(req.server_key)
    if not p:
        raise HTTPException(404, "pin not found")
    try:
        res = await verify(p["target"], use_ai=req.ai)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from exc
    return res.model_dump(mode="json")


@app.delete("/api/pins", status_code=204)
def delete_pin(server_key: str) -> Response:
    get_db().delete_pin(server_key)
    return Response(status_code=204)


# ----------------------------------------------------------------------------- demo helpers
@app.get("/api/demo/rugpull")
def rugpull_state() -> dict[str, Any]:
    return {"armed": RUGPULL_TOGGLE.exists(), "target": str(RUGPULL_TOGGLE.parent),
            "server_key": normalize_key(str(RUGPULL_TOGGLE.parent))}


@app.post("/api/demo/rugpull")
def rugpull_toggle(body: RugpullToggle) -> dict[str, Any]:
    """Arm/disarm the rugpull_todo test server (demo only; touches nothing else)."""
    if body.armed:
        RUGPULL_TOGGLE.write_text("armed by MCPGuard demo\n")
    else:
        RUGPULL_TOGGLE.unlink(missing_ok=True)
    return rugpull_state()


# ----------------------------------------------------------------------------- evaluation
_eval_state: dict[str, Any] = {"running": False, "error": None}


async def _run_eval(use_ai: bool) -> None:
    from mcpguard.evaluation import run_evaluation, save_results

    _eval_state.update(running=True, error=None, started_at=time.time())
    try:
        save_results(await run_evaluation(use_ai=use_ai))
    except Exception as exc:  # noqa: BLE001
        _eval_state["error"] = str(exc)
    finally:
        _eval_state["running"] = False


@app.get("/api/eval")
def get_eval() -> dict[str, Any]:
    from mcpguard.evaluation import EXPECTED_SERVERS, load_results

    return {"state": _eval_state, "results": load_results(), "expected": EXPECTED_SERVERS}


@app.post("/api/eval", status_code=202)
async def start_eval(background: BackgroundTasks, ai: bool = True) -> dict[str, Any]:
    if _eval_state["running"]:
        raise HTTPException(409, "evaluation already running")
    background.add_task(_run_eval, ai)
    _eval_state["running"] = True
    return {"state": _eval_state}


# ----------------------------------------------------------------------------- frontend
@app.get("/{path:path}", include_in_schema=False)
def spa(path: str) -> Response:
    if path.startswith("api/"):
        return JSONResponse({"detail": "not found"}, status_code=404)
    if not FRONTEND_DIST.exists():
        return JSONResponse({"detail": "Frontend not built. Run `pnpm -C frontend build`, or use the Vite dev "
                                       "server on :5173.", "api_docs": "/docs"}, status_code=404)
    file = (FRONTEND_DIST / path).resolve()
    if path and file.is_file() and file.is_relative_to(FRONTEND_DIST.resolve()):
        return FileResponse(file)
    return FileResponse(FRONTEND_DIST / "index.html")
