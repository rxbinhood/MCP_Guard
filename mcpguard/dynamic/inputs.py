"""Generate test inputs for a tool from its JSON schema: one valid call plus adversarial variants."""

from __future__ import annotations

from typing import Any

from mcpguard.findings import ToolDef

MAX_CALLS_PER_TOOL = 6


def injection_payloads(marker: str) -> list[str]:
    """Strings that reveal shell/command injection when executed. `marker` makes hits unambiguous."""
    return [
        f"127.0.0.1; echo {marker}",
        "127.0.0.1 && id",
        f"$(echo {marker})",
        "../../../../home/mcp/.ssh/id_rsa",
    ]


def _valid(spec: dict[str, Any], name: str) -> Any:
    if "default" in spec and spec["default"] not in (None, ""):
        return spec["default"]
    if spec.get("enum"):
        return spec["enum"][0]
    t = spec.get("type")
    if t is None and isinstance(spec.get("anyOf"), list):
        t = next((s.get("type") for s in spec["anyOf"] if s.get("type") not in (None, "null")), "string")
    if t == "integer":
        return 1
    if t == "number":
        return 1.5
    if t == "boolean":
        return True
    if t == "array":
        return []
    if t == "object":
        return {}
    lname = name.lower()
    if "host" in lname or "ip" in lname or "url" in lname:
        return "127.0.0.1"
    if "city" in lname:
        return "London"
    if "path" in lname or "file" in lname:
        return "notes.txt"
    return "test"


def generate_cases(tool: ToolDef, marker: str) -> list[dict[str, Any]]:
    """Return argument dicts: first a valid call, then string params swapped for payloads."""
    props: dict[str, Any] = (tool.inputSchema or {}).get("properties", {}) or {}
    base = {name: _valid(spec or {}, name) for name, spec in props.items()}
    cases: list[dict[str, Any]] = [base]
    string_params = [n for n, s in props.items() if (s or {}).get("type", "string") == "string"]
    for pname in string_params:
        for payload in injection_payloads(marker):
            cases.append({**base, pname: payload})
    # Edge cases for the first numeric param.
    for pname, spec in props.items():
        if (spec or {}).get("type") in ("integer", "number"):
            cases.append({**base, pname: -1})
            break
    return cases[:MAX_CALLS_PER_TOOL]
