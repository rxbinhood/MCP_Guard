"""Common findings schema."""

from mcpguard.findings import Category, Finding, Severity, Source, ToolDef


def test_finding_defaults_owasp_and_why():
    f = Finding(severity=Severity.HIGH, category=Category.COMMAND_INJECTION, title="x", source=Source.STATIC)
    assert f.owasp_llm_ref.startswith("LLM05")
    assert f.why
    data = f.model_dump(mode="json")
    for key in ("id", "severity", "category", "tool", "title", "evidence", "fix", "source", "confidence"):
        assert key in data
    assert data["severity"] == "HIGH" and data["source"] == "static"


def test_severity_ordering_and_bump():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.INFO.rank
    assert Severity.MEDIUM.bump() == Severity.HIGH
    assert Severity.CRITICAL.bump() == Severity.CRITICAL
    assert Severity.INFO.bump(-1) == Severity.INFO


def test_tool_text_fields_include_param_descriptions():
    tool = ToolDef(name="t", description="d", inputSchema={
        "type": "object", "required": ["a"],
        "properties": {"a": {"type": "string", "description": "the a"}, "b": {"type": "integer"}}})
    fields = dict(tool.text_fields())
    assert fields["param:a"] == "the a"
    params = {p.name: p for p in tool.params()}
    assert params["a"].required and not params["b"].required
