"""Obtain an MCP server's tool manifest.

Order of preference (``MCPGUARD_SANDBOX=auto``):
  1. docker  - build the target and call tools/list over stdio inside a hardened container
  2. static  - parse FastMCP/TS-SDK tool declarations from source; the server is never executed

``host`` mode runs the server directly on this machine and must be requested explicitly.
"""

from __future__ import annotations

import ast
import asyncio
import os
import re
import sys
from collections.abc import Callable
from contextlib import asynccontextmanager
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, get_default_environment, stdio_client

from mcpguard.config import get_settings
from mcpguard.findings import Manifest, ToolDef
from mcpguard.ingest import sandbox
from mcpguard.ingest.source import Project, iter_source_files

Log = Callable[[str], None]
LIST_TIMEOUT = 60.0


class ManifestError(RuntimeError):
    pass


def choose_mode(requested: str | None = None) -> str:
    mode = (requested or get_settings().sandbox or "auto").lower()
    if mode == "auto":
        return "docker" if sandbox.docker_status()[0] else "static"
    return mode


def _server_params(project: Project, mode: str, image: str | None,
                   docker_flags: list[str] | None = None, container_name: str | None = None,
                   env: dict[str, str] | None = None) -> StdioServerParameters:
    if not project.command:
        raise ManifestError("could not determine how to start this server (no entry point found)")
    if mode == "docker":
        args = sandbox.run_args(image, project.command, docker_flags, container_name)
        return StdioServerParameters(command="docker", args=args)
    if mode == "host":
        cmd = list(project.command)
        if cmd[0] == "python":
            cmd[0] = sys.executable
        return StdioServerParameters(command=cmd[0], args=cmd[1:], cwd=str(project.root),
                                     env={**get_default_environment(), **(env or {})})
    raise ManifestError(f"mode {mode!r} cannot start a server")


@asynccontextmanager
async def open_session(project: Project, mode: str, image: str | None = None, **kwargs: Any):
    """Start the server and yield an initialized ``(ClientSession, InitializeResult)``."""
    params = _server_params(project, mode, image, **kwargs)
    with open(os.devnull, "w") as errlog:  # server stderr is noise for us
        async with stdio_client(params, errlog=errlog) as (read, write), ClientSession(read, write) as session:
            init = await asyncio.wait_for(session.initialize(), LIST_TIMEOUT)
            yield session, init


async def _list_live(project: Project, mode: str, log: Log | None) -> Manifest:
    image = None
    if mode == "docker":
        image = await sandbox.build_target(project, log)
    if log:
        log(f"Starting server ({mode}): {' '.join(project.command)}")
    async with open_session(project, mode, image) as (session, init):
        result = await asyncio.wait_for(session.list_tools(), LIST_TIMEOUT)
    tools = [
        ToolDef(name=t.name, description=t.description or "",
                inputSchema=t.inputSchema or {"type": "object", "properties": {}})
        for t in result.tools
    ]
    return Manifest(server_name=init.serverInfo.name or project.name,
                    server_version=init.serverInfo.version, tools=tools, method=mode)


async def fetch_manifest(project: Project, mode: str | None = None, log: Log | None = None) -> Manifest:
    """Fetch the tool manifest, falling back to static extraction if the sandbox is unavailable."""
    mode = choose_mode(mode)
    if mode in ("docker", "host"):
        try:
            return await _list_live(project, mode, log)
        except Exception as exc:  # noqa: BLE001 - any failure falls back to static extraction
            if log:
                log(f"Live tools/list failed ({type(exc).__name__}: {exc}); falling back to static extraction")
    manifest = extract_static(project)
    if log:
        log(f"Static extraction found {len(manifest.tools)} tool(s) (server was not executed)")
    return manifest


# --------------------------------------------------------------------------- static extraction
_PY_TYPES = {"str": "string", "int": "integer", "float": "number", "bool": "boolean",
             "list": "array", "dict": "object", "List": "array", "Dict": "object"}


def _literal(node: ast.AST | None) -> Any:
    if node is None:
        return None
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError, TypeError):
        return None


def _annotation_schema(ann: ast.AST | None) -> dict[str, Any]:
    """Approximate JSON schema for a Python annotation, including Annotated[..., Field(description=...)]."""
    if ann is None:
        return {}
    if isinstance(ann, ast.Name):
        return {"type": _PY_TYPES[ann.id]} if ann.id in _PY_TYPES else {}
    if isinstance(ann, ast.Subscript):
        base = ann.value.id if isinstance(ann.value, ast.Name) else getattr(ann.value, "attr", "")
        if base == "Annotated" and isinstance(ann.slice, ast.Tuple) and ann.slice.elts:
            schema = _annotation_schema(ann.slice.elts[0])
            for meta in ann.slice.elts[1:]:
                if isinstance(meta, ast.Call):
                    for kw in meta.keywords:
                        if kw.arg in ("description", "title") and isinstance(_literal(kw.value), str):
                            schema[kw.arg] = _literal(kw.value)
            return schema
        if base in _PY_TYPES:
            return {"type": _PY_TYPES[base]}
    return {}


def _is_tool_decorator(dec: ast.AST) -> ast.Call | ast.Attribute | None:
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute) and target.attr == "tool":
        return dec
    return None


def _python_tools(source: str) -> list[ToolDef]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    tools: list[ToolDef] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        dec = next((d for d in node.decorator_list if _is_tool_decorator(d)), None)
        if dec is None:
            continue
        name, description = node.name, ast.get_docstring(node) or ""
        if isinstance(dec, ast.Call):
            for kw in dec.keywords:
                if kw.arg == "name" and isinstance(_literal(kw.value), str):
                    name = _literal(kw.value)
                elif kw.arg == "description" and isinstance(_literal(kw.value), str):
                    description = _literal(kw.value)
        props: dict[str, Any] = {}
        required: list[str] = []
        args = [a for a in node.args.args if a.arg not in ("self", "ctx", "context_obj")]
        defaults_start = len(args) - len(node.args.defaults)
        for i, arg in enumerate(args):
            if isinstance(arg.annotation, ast.Name) and arg.annotation.id == "Context":
                continue
            props[arg.arg] = {"title": arg.arg.replace("_", " ").title(), **_annotation_schema(arg.annotation)}
            if i < defaults_start:
                required.append(arg.arg)
        schema: dict[str, Any] = {"type": "object", "properties": props}
        if required:
            schema["required"] = required
        tools.append(ToolDef(name=name, description=description.strip(), inputSchema=schema))
    return tools


# server.tool("name", "description", ...) / server.registerTool("name", { description: "..." })
_JS_TOOL = re.compile(
    r"""\.(?:tool|registerTool)\(\s*(['"`])(?P<name>[\w.-]+)\1\s*,\s*(?:\{[^}]*?description\s*:\s*)?"""
    r"""(['"`])(?P<desc>(?:\\.|(?!\3).)*)\3""",
    re.S,
)


def _js_tools(source: str) -> list[ToolDef]:
    return [
        ToolDef(name=m.group("name"), description=m.group("desc").encode().decode("unicode_escape", "ignore"))
        for m in _JS_TOOL.finditer(source)
    ]


def extract_static(project: Project) -> Manifest:
    """Best-effort manifest from source code alone. Used when no sandbox is available."""
    tools: list[ToolDef] = []
    if project.language in ("python", "unknown"):
        for path in iter_source_files(project.root, (".py",)):
            tools += _python_tools(path.read_text(errors="ignore"))
    if project.language in ("node", "unknown"):
        for path in iter_source_files(project.root, (".js", ".ts", ".mjs")):
            tools += _js_tools(path.read_text(errors="ignore"))
    # Dedupe by name, keep first occurrence.
    seen: dict[str, ToolDef] = {}
    for t in tools:
        seen.setdefault(t.name, t)
    return Manifest(server_name=project.name, tools=list(seen.values()), method="static")
