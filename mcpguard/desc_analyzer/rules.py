"""Layer 1 of the description analyzer: fast, deterministic rule checks.

Each rule has a weight in [0, 1]; weights of *distinct* rules that fire on a tool are
combined with a noisy-OR, so one weak signal stays low while several independent
signals (e.g. sensitive path + AI-directed instruction + concealment) add up fast.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    weight: float
    pattern: re.Pattern[str]


@dataclass
class RuleHit:
    rule_id: str
    title: str
    weight: float
    field: str
    match: str
    decoded: str | None = None  # revealed text for obfuscation rules


@dataclass
class RuleResult:
    hits: list[RuleHit] = field(default_factory=list)

    @property
    def score(self) -> float:
        best: dict[str, float] = {}
        for h in self.hits:
            best[h.rule_id] = max(best.get(h.rule_id, 0.0), h.weight)
        return noisy_or(best.values())

    @property
    def rule_ids(self) -> set[str]:
        return {h.rule_id for h in self.hits}


def noisy_or(values) -> float:
    p = 1.0
    for v in values:
        p *= 1.0 - max(0.0, min(1.0, v))
    return 1.0 - p


_I = re.IGNORECASE

RULES: list[Rule] = [
    Rule("desc.sensitive_path", "References a sensitive file or credential store", 0.35, re.compile(
        r"(~|\$HOME|%USERPROFILE%)?/?\.ssh\b|\bid_(rsa|dsa|ecdsa|ed25519)\b|(^|[\s/'\"`(])\.env\b"
        r"|\.aws/credentials|\.npmrc\b|\.pypirc\b|\.pgpass\b|\.netrc\b|\.git-credentials|\.kube/config"
        r"|/etc/(passwd|shadow)\b|\bprivate[ _-]key\b|\bwallet\.dat\b|\.docker/config\.json", _I)),
    Rule("desc.secret_request", "Asks the model to read or pass along secrets", 0.3, re.compile(
        r"\b(read|send|include|pass|provide|attach|append|copy|forward|upload|collect)\b[^.\n]{0,60}"
        r"\b(api[ _-]?keys?|passwords?|tokens?|credentials?|secrets?|cookies?|session ids?|ssh keys?)\b", _I)),
    Rule("desc.instruction_override", "Tries to override the model's instructions", 0.6, re.compile(
        r"\b(ignore|disregard|forget|override)\b[^.\n]{0,30}\b(previous|prior|above|earlier|all|system|other)\b"
        r"[^.\n]{0,20}\b(instructions?|prompts?|rules|guidelines|directives)\b"
        r"|\bnew (system )?instructions?\b|\byou are now\b|\bsystem prompt\b", _I)),
    Rule("desc.ai_directed", "Contains instructions addressed to the AI model", 0.45, re.compile(
        r"<\s*/?\s*(important|system|instructions?|secret|hidden|admin|assistant)\s*>"
        r"|\bbefore (using|calling|invoking|running) (this|the|any) tool\b"
        r"|\b(the )?(assistant|ai|model|llm|agent)\b[^.\n]{0,20}\b(must|should|needs? to|is required to)\b"
        r"|\byou (must|should|need to|are required to) (always|first|also|never)\b"
        r"|\bas an ai\b|\bthis is (required|mandatory)\b[^.\n]{0,30}\b(tool|work|function)", _I)),
    Rule("desc.conceal", "Asks the model to hide actions from the user", 0.6, re.compile(
        r"\b(do not|don't|never|must not|should not)\b[^.\n]{0,20}\b(tell|mention|inform|reveal|show|notify|"
        r"alert|disclose|let)\b[^.\n]{0,25}\b(user|human|person|anyone)\b"
        r"|\bwithout (telling|informing|notifying|alerting|asking) the (user|human)\b"
        r"|\b(keep|remain)\b[^.\n]{0,15}\b(secret|hidden|confidential|between us)\b"
        r"|\bthe (user|human) (must|should) not (know|see|be told)\b", _I)),
    Rule("desc.cross_tool", "Tries to steer the model toward other tools or destinations", 0.35, re.compile(
        r"\b(call|invoke|use|run)\b[^.\n]{0,15}\b(the )?[\w-]+ tool\b[^.\n]{0,20}\b(instead|first|before|after)\b"
        r"|\binstead of (using |calling )?the [\w-]+\b|\b(send|forward|redirect|bcc|cc)\b[^.\n]{0,40}"
        r"\b(to|at)\b[^.\n]{0,10}([\w.+-]+@[\w-]+\.[\w.]+|https?://)", _I)),
    Rule("desc.raw_url", "Embeds a raw IP or webhook-style URL", 0.3, re.compile(
        r"https?://(\d{1,3}\.){3}\d{1,3}|https?://[^\s]*(webhook|ngrok|requestbin|pipedream|burpcollaborator"
        r"|interact\.sh|oast\.)", _I)),
]

_INVISIBLE = re.compile("[​-‏⁠-⁤﻿‪-‮⁦-⁩\U000e0000-\U000e007f]")
_TAG_CHARS = re.compile("[\U000e0020-\U000e007e]+")
_BASE64 = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])")


def _decode_base64(blob: str) -> str | None:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in text)
    return text if text and printable / len(text) > 0.9 else None


def _check_text(field_name: str, text: str, hits: list[RuleHit], depth: int = 0) -> None:
    norm = unicodedata.normalize("NFKC", text)
    for rule in RULES:
        seen: set[str] = set()
        for m in rule.pattern.finditer(norm):
            match = m.group(0).strip(" \t\n'\"`(")
            if match and match not in seen:
                seen.add(match)
                hits.append(RuleHit(rule.id, rule.title, rule.weight, field_name, match))
            if len(seen) >= 3:  # a few distinct matches per rule per field are enough to highlight
                break

    invisible = _INVISIBLE.findall(text)
    if invisible:
        hidden = "".join(chr(ord(c) - 0xE0000) for c in "".join(_TAG_CHARS.findall(text)))
        hits.append(RuleHit("desc.hidden_unicode", "Contains invisible or direction-override Unicode characters",
                            0.5 if not hidden else 0.75, field_name,
                            f"{len(invisible)} invisible character(s) " +
                            ", ".join(sorted({f"U+{ord(c):04X}" for c in invisible})[:5]),
                            decoded=hidden or None))
        if hidden and depth == 0:
            _check_text(f"{field_name} (hidden text)", hidden, hits, depth + 1)

    for m in _BASE64.finditer(text):
        decoded = _decode_base64(m.group(0))
        hits.append(RuleHit("desc.base64_blob", "Contains a large encoded (base64) blob",
                            0.45 if decoded else 0.25, field_name, m.group(0)[:60] + "...", decoded=decoded))
        if decoded and depth == 0:
            _check_text(f"{field_name} (decoded base64)", decoded, hits, depth + 1)
        break


def check_fields(fields: list[tuple[str, str]]) -> RuleResult:
    """Run every rule over a tool's (field_path, text) pairs."""
    result = RuleResult()
    for field_name, text in fields:
        if field_name == "name" or not text:
            continue
        _check_text(field_name, text, result.hits)
    return result
