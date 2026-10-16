"""Canonical form and SHA-256 fingerprints of an MCP tool manifest.

Canonicalization makes hashes independent of cosmetic differences:
  * JSON keys are sorted and serialized without insignificant whitespace
  * runs of ordinary whitespace inside text are collapsed to one space and trimmed
  * tools are ordered by name for the whole-manifest hash

Invisible characters (zero-width spaces, Unicode tag characters...) are NOT
whitespace and are deliberately preserved, so hiding text with them changes the hash.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from mcpguard.findings import Manifest, ToolDef

_WS = re.compile(r"[ \t\r\n\f\v]+")


def normalize_text(text: str) -> str:
    return _WS.sub(" ", text).strip()


def _normalize(value: Any) -> Any:
    if isinstance(value, str):
        return normalize_text(value)
    if isinstance(value, dict):
        return {str(k): _normalize(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    return value


def canonical_tool(tool: ToolDef) -> dict[str, Any]:
    return {
        "name": tool.name,
        "description": normalize_text(tool.description or ""),
        "inputSchema": _normalize(tool.inputSchema or {}),
    }


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def tool_hash(tool: ToolDef) -> str:
    return sha256(canonical_json(canonical_tool(tool)))


def fingerprint(manifest: Manifest) -> tuple[str, dict[str, str]]:
    """Return (whole-manifest hash, {tool name: tool hash})."""
    per_tool = {t.name: tool_hash(t) for t in sorted(manifest.tools, key=lambda t: t.name)}
    whole = sha256(canonical_json(sorted(per_tool.items())))
    return whole, per_tool
