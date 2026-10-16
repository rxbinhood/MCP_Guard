"""Generate mcpguard/api/seed_data.json from real scans of the bundled test servers.

Each server is scanned once; older "history" entries are copies re-dated into the past so the
dashboard charts have a timeline. Run from the repo root:

    python scripts/generate_seed.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mcpguard.findings import Manifest  # noqa: E402
from mcpguard.ingest.manifest import fetch_manifest  # noqa: E402
from mcpguard.ingest.source import resolve  # noqa: E402
from mcpguard.pin_diff.canonical import fingerprint  # noqa: E402
from mcpguard.pipeline import ScanOptions, run_scan  # noqa: E402

DAY = 86_400
# (server, ages in days for history copies). The first age is the "real" latest scan.
PLAN = [
    ("clean_calc", [0.05, 3.2, 9.4]),
    ("clean_notes", [0.08, 5.1]),
    ("vuln_shell", [0.11, 2.3, 6.8, 12.5]),
    ("poisoned_weather", [0.14, 1.4, 7.7]),
    ("rugpull_todo", [0.2, 4.6]),
]


def _relative(path: str) -> str:
    try:
        return str(Path(path).resolve().relative_to(ROOT))
    except ValueError:
        return path


async def main() -> None:
    scans = []
    for server, ages in PLAN:
        target = str(ROOT / "test_servers" / server)
        events: list[dict] = []
        result = await run_scan(target, ScanOptions(), emit=events.append)
        print(f"{server:<18} {result.verdict.value} risk={result.risk_score} findings={len(result.findings)}")
        for e in events:  # don't ship this machine's absolute paths in the seed
            for k in ("message", "detail", "target"):
                if isinstance(e.get(k), str):
                    e[k] = e[k].replace(str(ROOT) + "/", "").replace(str(ROOT), ".")
        data = result.model_dump(mode="json")
        data["target"] = _relative(data["target"])
        for i, age in enumerate(ages):
            copy = json.loads(json.dumps(data))
            copy["id"] = f"demo-{server}-{i}"
            scans.append({"age_seconds": age * DAY, "counts": result.counts(), "result": copy,
                          "events": events if i == 0 else []})

    project = resolve(str(ROOT / "test_servers" / "rugpull_todo"))
    manifest: Manifest = await fetch_manifest(project)
    whole, per_tool = fingerprint(manifest)
    pins = [{"target": "test_servers/rugpull_todo", "server_name": manifest.server_name,
             "server_version": manifest.server_version, "manifest_hash": whole, "tool_hashes": per_tool,
             "manifest": manifest.model_dump(mode="json"), "age_seconds": 0.5 * DAY}]
    out = ROOT / "mcpguard" / "api" / "seed_data.json"
    out.write_text(json.dumps({"scans": scans, "pins": pins}, indent=1), encoding="utf-8")
    print(f"wrote {out} ({len(scans)} scans, {len(pins)} pins)")


if __name__ == "__main__":
    asyncio.run(main())
