"""Common data model shared by every MCPGuard module.

Every scanner (static, description, dynamic, pin/diff) emits :class:`Finding`
objects in exactly this shape so the findings engine, reports, API and UI can
treat them uniformly.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        """Higher is worse. Used for sorting and comparisons."""
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.value]

    def bump(self, steps: int = 1) -> Severity:
        """Return a severity ``steps`` levels higher (negative = lower), clamped."""
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order[max(0, min(len(order) - 1, self.rank + steps))]


class Category(StrEnum):
    TOOL_POISONING = "tool_poisoning"
    COMMAND_INJECTION = "command_injection"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    HARDCODED_SECRET = "hardcoded_secret"
    EXCESS_ACCESS = "excess_access"
    BEHAVIOR_MISMATCH = "behavior_mismatch"
    EXFILTRATION = "exfiltration"
    RUG_PULL = "rug_pull"


class Source(StrEnum):
    STATIC = "static"
    DESCRIPTION = "description"
    DYNAMIC = "dynamic"
    PIN_DIFF = "pin_diff"


# Short code used in finding IDs, e.g. MCPG-DESC-001.
SOURCE_CODES: dict[Source, str] = {
    Source.STATIC: "STAT",
    Source.DESCRIPTION: "DESC",
    Source.DYNAMIC: "DYN",
    Source.PIN_DIFF: "PIN",
}

# OWASP Top 10 for LLM Applications (2025) mapping per category.
OWASP_LLM_REFS: dict[Category, str] = {
    Category.TOOL_POISONING: "LLM01:2025 Prompt Injection",
    Category.COMMAND_INJECTION: "LLM05:2025 Improper Output Handling",
    Category.UNSAFE_DESERIALIZATION: "LLM05:2025 Improper Output Handling",
    Category.HARDCODED_SECRET: "LLM02:2025 Sensitive Information Disclosure",
    Category.EXCESS_ACCESS: "LLM06:2025 Excessive Agency",
    Category.BEHAVIOR_MISMATCH: "LLM06:2025 Excessive Agency",
    Category.EXFILTRATION: "LLM02:2025 Sensitive Information Disclosure",
    Category.RUG_PULL: "LLM03:2025 Supply Chain",
}

# Plain-language "why this matters" text shown in the UI drawer and reports.
CATEGORY_WHY: dict[Category, str] = {
    Category.TOOL_POISONING: (
        "AI agents read tool descriptions as trusted context. Text addressed to the model can hijack the "
        "agent into reading secrets, calling other tools or hiding actions from the user, without the user "
        "ever seeing the instruction."
    ),
    Category.COMMAND_INJECTION: (
        "Tool arguments are chosen by an LLM that may itself be manipulated by untrusted content. Passing "
        "them to a shell lets an attacker run arbitrary commands on the machine hosting the MCP server."
    ),
    Category.UNSAFE_DESERIALIZATION: (
        "Deserializing or evaluating attacker-influenced data (pickle, yaml.load, eval) can execute "
        "arbitrary code inside the server process."
    ),
    Category.HARDCODED_SECRET: (
        "Credentials committed to source are visible to anyone who can read the repository and are hard "
        "to rotate. They also hint at backend services the server talks to."
    ),
    Category.EXCESS_ACCESS: (
        "A server that requests more capability than its tools need (network, filesystem, process "
        "execution) widens the blast radius if it is compromised or malicious."
    ),
    Category.BEHAVIOR_MISMATCH: (
        "The server did something at runtime that its tool descriptions never mentioned. Undisclosed "
        "behavior is a strong indicator of a backdoor or data collection."
    ),
    Category.EXFILTRATION: (
        "Sensitive data (SSH keys, .env files, cloud credentials) leaving the machine is the end goal of "
        "most MCP attacks. Once exfiltrated, the secrets must be considered compromised."
    ),
    Category.RUG_PULL: (
        "The server's tool definitions changed after you approved it. A rug pull lets an attacker ship a "
        "clean server for review and swap in malicious instructions later."
    ),
}


class Finding(BaseModel):
    """A single security finding in the MCPGuard common schema."""

    id: str = Field("", description="Stable ID such as MCPG-DESC-001, assigned by the findings engine.")
    severity: Severity
    category: Category
    tool: str | None = Field(None, description="MCP tool name this finding relates to, if any.")
    title: str
    evidence: str = Field("", description="Code snippet, suspicious text or observed behavior.")
    fix: str = Field("", description="Concrete remediation advice.")
    source: Source
    confidence: float = Field(0.8, ge=0.0, le=1.0)
    owasp_llm_ref: str | None = None

    # --- Optional enrichment (not required by the core schema) ---
    rule_id: str | None = Field(None, description="Detector rule that fired, e.g. semgrep rule id.")
    file: str | None = Field(None, description="Path relative to the scanned project root.")
    line: int | None = None
    highlights: list[str] = Field(default_factory=list, description="Exact substrings to highlight.")
    detectors: list[str] = Field(default_factory=list, description="Engines that agreed on this finding.")
    why: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:  # noqa: D401 - pydantic hook
        if self.owasp_llm_ref is None:
            self.owasp_llm_ref = OWASP_LLM_REFS.get(self.category)
        if self.why is None:
            self.why = CATEGORY_WHY.get(self.category)
        if not self.detectors and self.rule_id:
            self.detectors = [self.rule_id.split(".")[0]]

    @property
    def dedupe_key(self) -> tuple:
        """Two findings with the same key describe the same underlying issue."""
        if self.file and self.line:
            return (self.category.value, self.file, self.line)
        return (self.category.value, self.source.value, self.tool, self.title)


class ToolParam(BaseModel):
    name: str
    type: str | None = None
    description: str | None = None
    required: bool = False


class ToolDef(BaseModel):
    """One entry of an MCP ``tools/list`` response."""

    name: str
    description: str = ""
    inputSchema: dict[str, Any] = Field(default_factory=lambda: {"type": "object", "properties": {}})

    def params(self) -> list[ToolParam]:
        props = (self.inputSchema or {}).get("properties", {}) or {}
        required = set((self.inputSchema or {}).get("required", []) or [])
        out: list[ToolParam] = []
        for pname, spec in props.items():
            spec = spec or {}
            ptype = spec.get("type")
            if ptype is None and "anyOf" in spec:
                ptype = "|".join(str(s.get("type")) for s in spec["anyOf"] if isinstance(s, dict))
            out.append(
                ToolParam(name=pname, type=str(ptype) if ptype else None,
                          description=spec.get("description"), required=pname in required)
            )
        return out

    def text_fields(self) -> list[tuple[str, str]]:
        """All human/AI-readable text in the tool definition as (field_path, text) pairs."""
        fields: list[tuple[str, str]] = [("name", self.name)]
        if self.description:
            fields.append(("description", self.description))
        for p in self.params():
            if p.description:
                fields.append((f"param:{p.name}", p.description))
        # Titles and enum values can also carry instructions.
        for pname, spec in ((self.inputSchema or {}).get("properties", {}) or {}).items():
            if isinstance(spec, dict):
                if spec.get("title") and spec["title"].lower() != pname.lower():
                    fields.append((f"param:{pname}.title", str(spec["title"])))
                if isinstance(spec.get("default"), str) and len(spec["default"]) > 20:
                    fields.append((f"param:{pname}.default", spec["default"]))
        return fields


class Manifest(BaseModel):
    """The complete tool manifest of an MCP server."""

    server_name: str = "unknown"
    server_version: str | None = None
    tools: list[ToolDef] = Field(default_factory=list)
    # How the manifest was obtained: docker | host | static (AST extraction, server never executed).
    method: str = "docker"

    def tool(self, name: str) -> ToolDef | None:
        return next((t for t in self.tools if t.name == name), None)


class Verdict(StrEnum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


class ToolVerdict(BaseModel):
    """Description-analyzer verdict for a single tool (drives the Tools Inspector UI)."""

    tool: str
    verdict: str = "clean"  # clean | suspicious | malicious
    score: float = 0.0
    claimed_behavior: str | None = None
    claimed_capabilities: list[str] = Field(default_factory=list)
    highlights: list[dict[str, str]] = Field(default_factory=list)  # [{field, text}]
    signals: list[dict[str, Any]] = Field(default_factory=list)  # per-layer detail
    layers_used: list[str] = Field(default_factory=list)


class ModuleStatus(BaseModel):
    name: str
    status: str = "pending"  # pending | running | done | skipped | failed
    started_at: float | None = None
    finished_at: float | None = None
    detail: str | None = None


class ScanResult(BaseModel):
    """Everything a scan produced. Persisted as JSON and rendered by the reports/UI."""

    id: str
    target: str
    server_name: str = "unknown"
    language: str | None = None
    started_at: float
    finished_at: float | None = None
    verdict: Verdict = Verdict.PASS
    risk_score: int = 0
    manifest: Manifest | None = None
    findings: list[Finding] = Field(default_factory=list)
    tool_verdicts: list[ToolVerdict] = Field(default_factory=list)
    modules: list[ModuleStatus] = Field(default_factory=list)
    engines: dict[str, Any] = Field(default_factory=dict)
    options: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None

    def counts(self) -> dict[str, int]:
        c = {s.value: 0 for s in Severity}
        for f in self.findings:
            c[f.severity.value] += 1
        return c
