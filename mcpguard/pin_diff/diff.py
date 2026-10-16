"""Structured diff between a pinned manifest and a freshly fetched one."""

from __future__ import annotations

import json
import re
from typing import Any

from deepdiff import DeepDiff
from pydantic import BaseModel, Field

from mcpguard.findings import Manifest
from mcpguard.pin_diff.canonical import canonical_tool, fingerprint

_PATH_PART = re.compile(r"\[('([^']*)'|(\d+))\]")


class FieldChange(BaseModel):
    path: str  # e.g. "description" or "inputSchema.properties.tags.description"
    kind: str  # changed | added | removed | type_changed
    old: Any = None
    new: Any = None


class ToolChange(BaseModel):
    tool: str
    status: str  # added | removed | changed
    old_hash: str | None = None
    new_hash: str | None = None
    fields: list[FieldChange] = Field(default_factory=list)
    # Pretty-printed canonical JSON for side-by-side rendering in the UI.
    old_text: str = ""
    new_text: str = ""

    @property
    def description_changed(self) -> bool:
        return any(f.path == "description" or f.path.endswith(".description") for f in self.fields)


class ManifestDiff(BaseModel):
    status: str  # unchanged | changed
    old_hash: str
    new_hash: str
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    changed: list[str] = Field(default_factory=list)
    tools: list[ToolChange] = Field(default_factory=list)
    summary: str = ""


def _readable_path(deepdiff_path: str) -> str:
    parts = [m.group(2) if m.group(2) is not None else m.group(3) for m in _PATH_PART.finditer(deepdiff_path)]
    return ".".join(parts) or "(root)"


def _pretty(tool_canon: dict[str, Any] | None) -> str:
    return json.dumps(tool_canon, indent=2, sort_keys=True, ensure_ascii=False) if tool_canon else ""


def _field_changes(old: dict[str, Any], new: dict[str, Any]) -> list[FieldChange]:
    dd = DeepDiff(old, new, verbose_level=2)
    out: list[FieldChange] = []
    for path, change in dd.get("values_changed", {}).items():
        out.append(FieldChange(path=_readable_path(path), kind="changed",
                               old=change.get("old_value"), new=change.get("new_value")))
    for path, change in dd.get("type_changes", {}).items():
        out.append(FieldChange(path=_readable_path(path), kind="type_changed",
                               old=change.get("old_value"), new=change.get("new_value")))
    for key, kind in (("dictionary_item_added", "added"), ("iterable_item_added", "added"),
                      ("dictionary_item_removed", "removed"), ("iterable_item_removed", "removed")):
        for path, value in dd.get(key, {}).items():
            out.append(FieldChange(path=_readable_path(path), kind=kind,
                                   old=value if kind == "removed" else None,
                                   new=value if kind == "added" else None))
    return sorted(out, key=lambda f: f.path)


def diff_manifests(old: Manifest, new: Manifest) -> ManifestDiff:
    old_hash, old_tools = fingerprint(old)
    new_hash, new_tools = fingerprint(new)
    result = ManifestDiff(status="unchanged" if old_hash == new_hash else "changed",
                          old_hash=old_hash, new_hash=new_hash)
    if result.status == "unchanged":
        result.summary = f"Manifest unchanged ({len(new_tools)} tools)."
        return result

    old_by = {t.name: canonical_tool(t) for t in old.tools}
    new_by = {t.name: canonical_tool(t) for t in new.tools}
    for name in sorted(set(old_by) | set(new_by)):
        o, n = old_by.get(name), new_by.get(name)
        if o is None:
            result.added.append(name)
            result.tools.append(ToolChange(tool=name, status="added", new_hash=new_tools[name],
                                           new_text=_pretty(n)))
        elif n is None:
            result.removed.append(name)
            result.tools.append(ToolChange(tool=name, status="removed", old_hash=old_tools[name],
                                           old_text=_pretty(o)))
        elif old_tools[name] != new_tools[name]:
            result.changed.append(name)
            result.tools.append(ToolChange(tool=name, status="changed", old_hash=old_tools[name],
                                           new_hash=new_tools[name], fields=_field_changes(o, n),
                                           old_text=_pretty(o), new_text=_pretty(n)))

    bits = []
    if result.changed:
        bits.append(f"{len(result.changed)} changed ({', '.join(result.changed)})")
    if result.added:
        bits.append(f"{len(result.added)} added ({', '.join(result.added)})")
    if result.removed:
        bits.append(f"{len(result.removed)} removed ({', '.join(result.removed)})")
    result.summary = "Tool definitions changed since pin: " + "; ".join(bits) + "."
    return result
