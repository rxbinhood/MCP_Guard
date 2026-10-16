"""MCPGuard command-line interface.

    mcpguard scan <server> [--report md|json|sarif] [--dynamic]
    mcpguard pin <server>
    mcpguard verify <server>
    mcpguard serve
    mcpguard status
    mcpguard eval
"""

from __future__ import annotations

import asyncio
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from mcpguard import __version__

app = typer.Typer(add_completion=False, no_args_is_help=True,
                  help="MCPGuard: is this MCP server safe to plug into my AI agent, and has it stayed safe?")
console = Console(stderr=True)
SEV_STYLE = {"CRITICAL": "bold white on red", "HIGH": "bold red", "MEDIUM": "yellow", "LOW": "cyan", "INFO": "dim"}
VERDICT_STYLE = {"PASS": "bold green", "WARN": "bold yellow", "FAIL": "bold red"}


class ReportFormat(str, Enum):
    md = "md"
    json = "json"
    sarif = "sarif"


class SandboxMode(str, Enum):
    auto = "auto"
    docker = "docker"
    static = "static"
    host = "host"


def _print_event(event: dict) -> None:
    kind = event.get("type")
    if kind == "module":
        icon = {"running": "[cyan]▶[/]", "done": "[green]✔[/]", "failed": "[red]✖[/]",
                "skipped": "[dim]–[/]"}.get(event["status"], "•")
        elapsed = f" [dim]{event['elapsed']:.1f}s[/]" if event.get("elapsed") is not None else ""
        console.print(f"{icon} [bold]{event['module']}[/] {escape(event.get('detail') or '')}{elapsed}")
    elif kind == "log":
        console.print(f"   [dim]{escape(event['message'])}[/]", highlight=False)


def _record(result) -> None:
    """Persist CLI scans too, so they appear in the dashboard."""
    from mcpguard.db import get_db

    db = get_db()
    db.create_scan(result.id, result.target, result.options)
    db.update_scan(result.id, server_name=result.server_name, status="failed" if result.error else "done",
                   verdict=result.verdict.value, risk_score=result.risk_score, counts=result.counts(),
                   result=result.model_dump(mode="json"), finished_at=result.finished_at)


@app.command()
def scan(
    server: str = typer.Argument(..., help="GitHub URL or local folder of the MCP server"),
    report: ReportFormat | None = typer.Option(None, "--report", "-r", help="Print a report in this format"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write the report to a file"),
    dynamic: bool = typer.Option(False, "--dynamic", help="Also run the dynamic prober (needs Docker)"),
    no_static: bool = typer.Option(False, "--no-static", help="Skip static code analysis"),
    no_ai: bool = typer.Option(False, "--no-ai", help="Rule-based description analysis only"),
    sandbox: SandboxMode = typer.Option(SandboxMode.auto, help="How to obtain the manifest"),
    entry: str | None = typer.Option(None, help="Entry file, if auto-detection fails"),
    fail_on: str = typer.Option("FAIL", help="Exit non-zero on this verdict or worse: FAIL, WARN or never"),
) -> None:
    """Audit an MCP server and print a verdict."""
    from mcpguard.pipeline import ScanOptions, run_scan
    from mcpguard.report import render

    opts = ScanOptions(static=not no_static, ai=not no_ai, dynamic=dynamic, sandbox=sandbox.value, entry=entry)
    console.print(f"[bold]MCPGuard {__version__}[/] scanning [cyan]{server}[/]")
    result = asyncio.run(run_scan(server, opts, _print_event))
    _record(result)

    if result.error:
        console.print(f"[red]Error:[/] {result.error}")
        raise typer.Exit(2)

    table = Table(show_lines=False, header_style="bold")
    for col in ("ID", "Severity", "Category", "Tool", "Title", "Conf."):
        table.add_column(col)
    for f in result.findings:
        table.add_row(f.id, f"[{SEV_STYLE[f.severity.value]}]{f.severity.value}[/]", f.category.value,
                      f.tool or "—", f.title, f"{f.confidence:.0%}")
    if result.findings:
        console.print(table)
    console.print(f"\nVerdict: [{VERDICT_STYLE[result.verdict.value]}]{result.verdict.value}[/]  "
                  f"Risk score: [bold]{result.risk_score}[/]/100  Scan ID: {result.id}")

    if report:
        text = render(result, report.value)
        if output:
            output.write_text(text, encoding="utf-8")
            console.print(f"Report written to {output}")
        else:
            typer.echo(text)

    order = {"PASS": 0, "WARN": 1, "FAIL": 2}
    if fail_on.upper() in order and order[result.verdict.value] >= order[fail_on.upper()]:
        raise typer.Exit(1)


@app.command()
def pin(server: str = typer.Argument(..., help="GitHub URL or local folder"),
        sandbox: SandboxMode = typer.Option(SandboxMode.auto)) -> None:
    """Pin the server's current tool manifest (SHA-256 per tool + whole list)."""
    from mcpguard.pin_diff.service import pin as do_pin

    record = asyncio.run(do_pin(server, sandbox.value, log=lambda m: console.print(f"   [dim]{escape(m)}[/]")))
    console.print(f"[green]✔ Pinned[/] [bold]{record.server_name}[/] · {len(record.tool_hashes)} tools · "
                  f"fingerprint [cyan]{record.manifest_hash[:16]}[/] (via {record.manifest.method})")
    for name, h in record.tool_hashes.items():
        console.print(f"   {name:<28} {h[:16]}")


@app.command()
def verify(server: str = typer.Argument(..., help="GitHub URL or local folder that was pinned"),
           sandbox: SandboxMode = typer.Option(SandboxMode.auto),
           no_ai: bool = typer.Option(False, "--no-ai", help="Rule-based re-analysis only"),
           as_json: bool = typer.Option(False, "--json", help="Print the full result as JSON")) -> None:
    """Re-fetch the manifest and compare it with the pin (rug-pull detection)."""
    from mcpguard.pin_diff.service import verify as do_verify

    try:
        res = asyncio.run(do_verify(server, sandbox.value, use_ai=not no_ai,
                                    log=lambda m: console.print(f"   [dim]{escape(m)}[/]")))
    except LookupError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(2) from exc
    if as_json:
        typer.echo(res.model_dump_json(indent=2))
    if res.status == "error":
        console.print(f"[red]✖ Verification failed:[/] {res.error}")
        raise typer.Exit(2)
    if res.status == "unchanged":
        console.print(f"[green]✔ Unchanged[/] {res.server_name} matches its pin ({res.diff.new_hash[:16]})")
        return
    banner = "[bold white on red] RUG PULL DETECTED [/]" if res.rug_pull else "[bold yellow]⚠ CHANGED[/]"
    console.print(f"{banner} {res.diff.summary}")
    for change in res.diff.tools:
        console.print(f"  [bold]{change.tool}[/] ({change.status})")
        for fc in change.fields:
            if fc.kind == "changed":
                console.print(f"    [dim]{fc.path}[/]\n      [red]- {str(fc.old)[:200]}[/]\n      [green]+ {str(fc.new)[:200]}[/]")
            else:
                console.print(f"    [dim]{fc.path}[/] {fc.kind}")
    for f in res.findings:
        console.print(f"  [{SEV_STYLE[f.severity.value]}]{f.severity.value}[/] {f.id} {f.title}")
    raise typer.Exit(1)


@app.command()
def serve(host: str = typer.Option("127.0.0.1"), port: int = typer.Option(8000),
          reload: bool = typer.Option(False), seed: bool = typer.Option(True, help="Seed demo data if empty")) -> None:
    """Start the REST API and web UI."""
    import os

    import uvicorn

    os.environ.setdefault("MCPGUARD_SEED", "1" if seed else "0")
    console.print(f"[bold]MCPGuard[/] API + UI on [cyan]http://{host}:{port}[/]")
    uvicorn.run("mcpguard.api.app:app", host=host, port=port, reload=reload, log_level="info")


@app.command()
def status() -> None:
    """Show which engines are available (Docker, LLM, Prompt Guard, Semgrep, Bandit, Gitleaks)."""
    from mcpguard.api.health import engine_health

    table = Table(header_style="bold")
    for col in ("Engine", "Status", "Detail"):
        table.add_column(col)
    for e in engine_health(refresh=True):
        style = "green" if e["status"] == "online" else "red"
        table.add_row(e["label"], f"[{style}]{e['status']}[/]", e["detail"])
    console.print(table)


@app.command(name="eval")
def evaluate(samples: Path = typer.Option(Path("tests/description_samples.json"), help="Labeled samples"),
             no_ai: bool = typer.Option(False, "--no-ai"), servers: bool = typer.Option(True, help="Also scan test servers"),
             out: Path | None = typer.Option(None, help="Where to write results JSON")) -> None:
    """Evaluate detection rate / false positives on labeled samples and the bundled test servers."""
    from mcpguard.evaluation import run_evaluation, save_results

    res = asyncio.run(run_evaluation(samples, use_ai=not no_ai, include_servers=servers,
                                     log=lambda m: console.print(f"   [dim]{escape(m)}[/]")))
    path = save_results(res, out)
    d = res["descriptions"]
    if d.get("available"):
        for mode, m in d["modes"].items():
            console.print(f"[bold]{mode:<12}[/] detection {m['detection_rate']:.0%}  false positives "
                          f"{m['false_positive_rate']:.0%}  (n={m['n']}, TP={m['tp']}, FP={m['fp']})")
    else:
        console.print(f"[yellow]Description samples unavailable:[/] {d.get('reason')}")
    for s in res.get("servers", []):
        ok = "[green]✔[/]" if s["passed"] else "[red]✖[/]"
        console.print(f"{ok} {s['server']:<18} expected {s['expected']:<4} got {s['verdict']:<4} "
                      f"caught by: {', '.join(s['caught_by']) or '—'}")
    console.print(f"Results saved to {path}")


if __name__ == "__main__":
    app()
