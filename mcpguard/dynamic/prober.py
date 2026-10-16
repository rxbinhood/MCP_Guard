"""Dynamic prober: run the server in a locked-down container and watch what it actually does.

* Canary secrets with unique markers are planted in the image (~/.ssh/id_rsa, ~/.aws/credentials, .env).
* The server runs under ``strace -f`` (openat/execve/connect); strace writes to stderr, which the MCP
  stdio client captures into a host-side log file.
* A capture proxy on 127.0.0.1 (HTTP_PROXY/HTTPS_PROXY) records outbound HTTP even though the
  container has no network (``--network none``).
* Every tool is called with schema-derived valid and adversarial inputs. Log offsets around each call
  attribute observed behavior to the tool that caused it.

Findings: canary marker in outbound traffic (CRITICAL, confirmed exfiltration), canary file read (HIGH),
injected command executed (CRITICAL, confirmed injection), unexpected network (MEDIUM/HIGH), and
behavior that contradicts the tool's claimed capabilities (behavior_mismatch).
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import secrets
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from mcpguard.dynamic.inputs import generate_cases
from mcpguard.dynamic.sandbox_assets import CANARY_PATHS, SINK_PORT, probe_dockerfile_layer
from mcpguard.findings import Category, Finding, Manifest, Severity, Source, ToolVerdict
from mcpguard.ingest import sandbox
from mcpguard.ingest.source import Project

Log = Callable[[str], None]
CALL_TIMEOUT = 15.0
SETTLE = 0.3  # seconds to let strace flush after each call

_PID = r"^(?:\[pid\s+)?(?P<pid>\d+)\]?\s+"
RE_OPEN = re.compile(_PID + r'open(?:at)?\((?:[^,]+,\s*)?"(?P<path>[^"]+)",[^)]*\)\s*=\s*(?P<ret>-?\d+)')
RE_EXEC = re.compile(_PID + r'execve\("(?P<bin>[^"]+)",\s*\[(?P<argv>.*?)\](?:,|\))')
RE_CONNECT = re.compile(
    _PID + r'connect\(\d+,\s*\{sa_family=AF_INET6?,\s*sin6?_port=htons\((?P<port>\d+)\),\s*'
    r'(?:sin_addr=inet_addr\("(?P<ip4>[^"]+)"\)|.*?inet_pton\(AF_INET6,\s*"(?P<ip6>[^"]+)")'
)


@dataclass
class Observation:
    tool: str | None  # None = server startup
    opened: list[tuple[str, int]] = field(default_factory=list)
    execs: list[tuple[str, str]] = field(default_factory=list)
    connects: list[tuple[str, int]] = field(default_factory=list)
    http: list[dict[str, Any]] = field(default_factory=list)  # sink captures
    outputs: list[tuple[dict[str, Any], str]] = field(default_factory=list)


@dataclass
class DynamicResult:
    findings: list[Finding] = field(default_factory=list)
    status: str = "online"  # online | offline | error
    detail: str = ""
    observations: list[Observation] = field(default_factory=list)


def parse_log(text: str, obs: Observation) -> None:
    """Parse strace + sink lines into an Observation."""
    for line in text.splitlines():
        if line.startswith("MCPG-SINK "):
            rest = line[len("MCPG-SINK "):]
            if rest.startswith(("TLS ", "ERROR ")):
                continue
            first, _, b64 = rest.rpartition(" ")
            try:
                raw = base64.b64decode(b64).decode("latin-1")
            except (ValueError, UnicodeDecodeError):
                raw = ""
            host = re.search(r"(?im)^host:\s*(\S+)", raw)
            target = first.split(" ")[1] if " " in first else first
            obs.http.append({"request": first, "target": target, "host": host.group(1) if host else target,
                             "raw": raw})
            continue
        if m := RE_OPEN.search(line):
            obs.opened.append((m.group("path"), int(m.group("ret"))))
        elif m := RE_EXEC.search(line):
            obs.execs.append((m.group("bin"), m.group("argv")))
        elif m := RE_CONNECT.search(line):
            ip = m.group("ip4") or m.group("ip6") or "?"
            obs.connects.append((ip, int(m.group("port"))))


def _probe_run_args(tag: str, command: list[str], name: str) -> list[str]:
    hardening = [f for f in sandbox.HARDENING if f != "--rm"]
    # Keep /home/mcp from the image (canaries live there); only /tmp is writable.
    i = hardening.index("/home/mcp:rw,size=16m,uid=10001,gid=10001")
    del hardening[i - 1:i + 1]
    proxy = f"http://127.0.0.1:{SINK_PORT}"
    env: list[str] = []
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        env += ["-e", f"{k}={proxy}"]
    env += ["-e", "NO_PROXY=", "-e", "no_proxy="]
    inner = (f"python3 /opt/mcpguard/sink.py & sleep 0.3; exec strace -f -qq -s 512 "
             f"-e trace=open,openat,execve,connect {' '.join(command)}")
    return ["run", *hardening, *env, "--name", name, tag, "sh", "-c", inner]


def _result_text(result: Any) -> str:
    parts = []
    for c in getattr(result, "content", []) or []:
        parts.append(getattr(c, "text", "") or json.dumps(getattr(c, "model_dump", lambda: {})()))
    return "\n".join(parts)


def _canary_markers(token: str) -> list[str]:
    return [f"MCPG-CANARY-{k}-{token}" for k in ("SSH", "AWS", "ENV", "APP", "DB")] + [token]


def analyze(observations: list[Observation], verdicts: list[ToolVerdict], token: str,
            inject_marker: str) -> list[Finding]:
    claims = {v.tool: set(v.claimed_capabilities) for v in verdicts}
    markers = _canary_markers(token)
    canary_paths = set(CANARY_PATHS.values())
    findings: list[Finding] = []

    for obs in observations:
        tool = obs.tool
        claimed = claims.get(tool or "", set())
        where = f"tool `{tool}`" if tool else "server startup"

        # 1. Canary secrets in outbound traffic -> confirmed exfiltration.
        for req in obs.http:
            hit = next((m for m in markers if m in req["raw"]), None)
            if hit:
                findings.append(Finding(
                    severity=Severity.CRITICAL, category=Category.EXFILTRATION, tool=tool,
                    title=f"Confirmed exfiltration: canary secret sent to {req['host']}",
                    evidence=f"{req['request']}\n…{req['raw'][max(0, req['raw'].find(hit) - 80):req['raw'].find(hit) + 80]}…",
                    fix="This server steals secrets. Remove it everywhere it was installed and rotate every credential "
                        "that was reachable from those machines.",
                    source=Source.DYNAMIC, confidence=0.99, rule_id="dynamic.canary_exfiltrated",
                    highlights=[hit, req["host"]], detectors=["dynamic"], extra={"host": req["host"]}))
            else:
                unexpected = "network" not in claimed
                has_body = "\r\n\r\n" in req["raw"] and req["raw"].split("\r\n\r\n", 1)[1].strip()
                sev = (Severity.HIGH if has_body else Severity.MEDIUM) if unexpected else Severity.INFO
                findings.append(Finding(
                    severity=sev, category=Category.BEHAVIOR_MISMATCH if unexpected else Category.EXCESS_ACCESS,
                    tool=tool,
                    title=(f"Unexpected outbound request to {req['host']}" if unexpected
                           else f"Outbound request to {req['host']}"),
                    evidence=req["request"] + ("\n(request carried a body)" if has_body else ""),
                    fix="Document every network destination in the tool description, or remove the call.",
                    source=Source.DYNAMIC, confidence=0.9, rule_id="dynamic.outbound_http",
                    highlights=[req["host"]], detectors=["dynamic"]))

        # 2. Direct connections that bypassed the proxy.
        for ip, port in obs.connects:
            if ip in ("127.0.0.1", "::1") and port == SINK_PORT:
                continue
            if ip.startswith("127.") or ip == "::1":
                continue
            unexpected = "network" not in claimed
            findings.append(Finding(
                severity=Severity.HIGH if unexpected else Severity.LOW, category=Category.BEHAVIOR_MISMATCH,
                tool=tool, title=f"Direct network connection attempt to {ip}:{port} during {where}",
                evidence=f"connect() to {ip}:{port} (blocked by the sandbox)",
                fix="Explain why the server connects to this address, or remove the connection.",
                source=Source.DYNAMIC, confidence=0.85, rule_id="dynamic.direct_connect", detectors=["dynamic"]))

        # 3. Canary files opened.
        for path, ret in obs.opened:
            if path in canary_paths and ret >= 0:
                findings.append(Finding(
                    severity=Severity.HIGH, category=Category.EXFILTRATION, tool=tool,
                    title=f"Read planted canary secret {path.replace('/home/mcp', '~')} during {where}",
                    evidence=f"openat(\"{path}\") = {ret}",
                    fix="An MCP tool should never read SSH keys, cloud credentials or .env files. Remove this access.",
                    source=Source.DYNAMIC, confidence=0.95, rule_id="dynamic.canary_read",
                    highlights=[path], detectors=["dynamic"]))

        # 4. Process execution: confirmed injection and undeclared exec.
        if tool:
            injected = [argv for _bin, argv in obs.execs if inject_marker in argv and "-c" in argv]
            id_ran = [b for b, _argv in obs.execs if b.endswith("/id")]
            echoed = [out for args, out in obs.outputs
                      if inject_marker in out and f"echo {inject_marker}" not in out]
            if injected or id_ran or echoed:
                ev = injected[:1] or [f"execve(\"{b}\")" for b in id_ran[:1]] or echoed[:1]
                findings.append(Finding(
                    severity=Severity.CRITICAL, category=Category.COMMAND_INJECTION, tool=tool,
                    title=f"Command injection confirmed in `{tool}`: injected command executed",
                    evidence="\n".join(e[:400] for e in ev),
                    fix="Never pass tool arguments to a shell. Use an argument list with shell=False and validate input.",
                    source=Source.DYNAMIC, confidence=0.99, rule_id="dynamic.injection_confirmed",
                    highlights=[inject_marker, "id"], detectors=["dynamic"]))
            elif obs.execs and "exec" not in claimed:
                bins = sorted({b for b, _ in obs.execs})
                findings.append(Finding(
                    severity=Severity.MEDIUM, category=Category.BEHAVIOR_MISMATCH, tool=tool,
                    title=f"`{tool}` spawned processes but does not claim to run commands",
                    evidence=", ".join(bins[:6]),
                    fix="Describe process execution in the tool description, or remove it.",
                    source=Source.DYNAMIC, confidence=0.8, rule_id="dynamic.undeclared_exec", detectors=["dynamic"]))
    # Collapse repeats (same tool + rule + title).
    seen: dict[tuple, Finding] = {}
    for f in findings:
        seen.setdefault((f.tool, f.rule_id, f.title), f)
    return list(seen.values())


async def probe(project: Project, manifest: Manifest, verdicts: list[ToolVerdict],
                log: Log | None = None) -> DynamicResult:
    say = log or (lambda _m: None)
    ok, detail = sandbox.docker_status()
    if not ok:
        say(f"Dynamic probing needs Docker ({detail}); skipped")
        return DynamicResult(status="offline", detail=f"Docker unavailable: {detail}")
    if not project.command:
        return DynamicResult(status="error", detail="no entry point to run")

    token = secrets.token_hex(8)
    inject_marker = f"MCPG-INJ-{token}"
    tag = await sandbox.build_target(project, say, extra=probe_dockerfile_layer(token))
    name = f"mcpguard-probe-{token}"
    observations: list[Observation] = []

    with tempfile.TemporaryDirectory() as tmp:
        log_path = Path(tmp) / "probe.log"
        params = StdioServerParameters(command="docker", args=_probe_run_args(tag, project.command, name))
        say(f"Starting {manifest.server_name} under strace with canaries planted (network: none, proxy capture on)")
        try:
            with open(log_path, "w") as errlog:
                async with stdio_client(params, errlog=errlog) as (r, w), ClientSession(r, w) as session:
                    await asyncio.wait_for(session.initialize(), 60)
                    errlog.flush()
                    await asyncio.sleep(SETTLE)
                    startup = Observation(tool=None)
                    parse_log(log_path.read_text(errors="replace"), startup)
                    observations.append(startup)
                    calls = 0
                    for tool in manifest.tools:
                        for args in generate_cases(tool, inject_marker):
                            before = log_path.stat().st_size
                            obs = next((o for o in observations if o.tool == tool.name), None)
                            if obs is None:
                                obs = Observation(tool=tool.name)
                                observations.append(obs)
                            try:
                                res = await asyncio.wait_for(session.call_tool(tool.name, args), CALL_TIMEOUT)
                                obs.outputs.append((args, _result_text(res)))
                            except Exception as exc:  # noqa: BLE001 - a crashing tool is still informative
                                obs.outputs.append((args, f"<error: {type(exc).__name__}: {exc}>"))
                            calls += 1
                            await asyncio.sleep(SETTLE)
                            errlog.flush()
                            with open(log_path, errors="replace") as fh:
                                fh.seek(before)
                                parse_log(fh.read(), obs)
                        say(f"Probed {tool.name}: {sum(len(o.outputs) for o in observations if o.tool == tool.name)} call(s)")
            say(f"Dynamic probing done: {calls} call(s) across {len(manifest.tools)} tool(s)")
        except Exception as exc:  # noqa: BLE001
            say(f"Probe session error: {type(exc).__name__}: {exc}")
            if not observations:
                return DynamicResult(status="error", detail=str(exc)[:200])
        finally:
            proc = await asyncio.create_subprocess_exec("docker", "rm", "-f", name,
                                                        stdout=asyncio.subprocess.DEVNULL,
                                                        stderr=asyncio.subprocess.DEVNULL)
            await proc.wait()

    findings = analyze(observations, verdicts, token, inject_marker)
    n_http = sum(len(o.http) for o in observations)
    n_exec = sum(len(o.execs) for o in observations if o.tool)
    say(f"Observed: {n_http} outbound HTTP request(s), {n_exec} process exec(s) during tool calls, "
        f"{len(findings)} dynamic finding(s)")
    return DynamicResult(findings=findings, status="online",
                         detail=f"{len(findings)} finding(s), {n_http} HTTP capture(s)", observations=observations)
