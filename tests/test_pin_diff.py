"""Pin & Diff: canonical hashing, structured diffs and rug-pull findings."""

import asyncio

from mcpguard.db import Database
from mcpguard.findings import Category, Manifest, Severity, ToolDef
from mcpguard.ingest.manifest import extract_static
from mcpguard.ingest.source import resolve
from mcpguard.pin_diff.canonical import fingerprint, normalize_text, tool_hash
from mcpguard.pin_diff.diff import diff_manifests
from mcpguard.pin_diff.service import pin_manifest, rug_pull_findings


def _tool(desc="Add a new todo item.", schema=None, name="add_todo"):
    return ToolDef(name=name, description=desc,
                   inputSchema=schema or {"type": "object", "properties": {"title": {"type": "string"}}})


def test_whitespace_and_key_order_do_not_change_hash():
    a = _tool("Add a new\n   todo item.", {"properties": {"title": {"type": "string"}}, "type": "object"})
    b = _tool("Add a new todo item.", {"type": "object", "properties": {"title": {"type": "string"}}})
    assert tool_hash(a) == tool_hash(b)


def test_invisible_characters_change_hash():
    assert normalize_text("a​b") == "a​b"
    assert tool_hash(_tool("Add a todo.")) != tool_hash(_tool("Add a​ todo."))


def test_tool_order_does_not_change_manifest_hash():
    t1, t2 = _tool(name="a"), _tool(name="b")
    assert fingerprint(Manifest(tools=[t1, t2]))[0] == fingerprint(Manifest(tools=[t2, t1]))[0]


def test_unchanged_diff():
    m = Manifest(tools=[_tool()])
    d = diff_manifests(m, m.model_copy(deep=True))
    assert d.status == "unchanged" and not d.tools


def test_diff_reports_description_schema_added_removed():
    old = Manifest(tools=[_tool(), _tool(name="list_todos", desc="List todos.")])
    changed = _tool("Add a todo. Also do something else.",
                    {"type": "object", "properties": {"title": {"type": "string"}, "tags": {"type": "string"}}})
    new = Manifest(tools=[changed, _tool(name="export", desc="Export todos.")])
    d = diff_manifests(old, new)
    assert d.status == "changed"
    assert d.changed == ["add_todo"] and d.added == ["export"] and d.removed == ["list_todos"]
    paths = {f.path for f in d.tools[0].fields}
    assert "description" in paths and "inputSchema.properties.tags" in paths
    assert d.tools[0].old_text and d.tools[0].new_text


def test_pin_roundtrip(tmp_path):
    db = Database(tmp_path / "t.db")
    m = Manifest(server_name="x", tools=[_tool()])
    rec = pin_manifest("x", "key-x", m, db)
    stored = db.get_pin("key-x")
    assert stored["manifest_hash"] == rec.manifest_hash
    assert Manifest.model_validate(stored["manifest"]) == m


def test_benign_change_is_medium_not_critical():
    old = Manifest(tools=[_tool()])
    new = Manifest(tools=[_tool("Add a new todo item with an optional due date.")])
    findings, _ = asyncio.run(rug_pull_findings(diff_manifests(old, new), new, use_ai=False))
    assert [f.severity for f in findings] == [Severity.MEDIUM]


def test_malicious_change_is_critical_rug_pull(servers, monkeypatch):
    """Use the rugpull_todo fixture's own poisoned description as the 'new' definition."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("rp", servers / "rugpull_todo" / "server.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    old = extract_static(resolve(str(servers / "rugpull_todo")))
    new = old.model_copy(deep=True)
    new.tool("add_todo").description = mod.MALICIOUS_DESCRIPTION
    findings, _ = asyncio.run(rug_pull_findings(diff_manifests(old, new), new, use_ai=False))
    assert findings[0].category == Category.RUG_PULL
    assert findings[0].severity == Severity.CRITICAL
