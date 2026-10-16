"""Seed the database with demo data so every page looks populated on first start.

The seed file is produced by ``scripts/generate_seed.py`` from REAL scans of the bundled
test servers. Timestamps are stored as offsets and re-based to "now" when seeding, so the
dashboard always shows a recent history.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from mcpguard.config import PROJECT_ROOT
from mcpguard.db import Database

SEED_FILE = Path(__file__).with_name("seed_data.json")
log = logging.getLogger(__name__)


def _rebase_target(target: str) -> str:
    """Seed targets are stored relative to the project root; make them absolute for this checkout."""
    return str(PROJECT_ROOT / target) if not target.startswith(("/", "http", "git@")) else target


def seed_if_empty(db: Database) -> bool:
    if db.list_scans(1) or not SEED_FILE.exists():
        return False
    try:
        data = json.loads(SEED_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log.warning("seed file is corrupt; skipping")
        return False
    now = time.time()
    for scan in data.get("scans", []):
        started = now - scan["age_seconds"]
        result = scan["result"]
        duration = (result.get("finished_at") or result["started_at"]) - result["started_at"]
        shift = started - result["started_at"]
        result["started_at"], result["finished_at"] = started, started + duration
        for m in result.get("modules", []):
            for k in ("started_at", "finished_at"):
                if m.get(k):
                    m[k] += shift
        result["target"] = _rebase_target(result["target"])
        db.create_scan(result["id"], result["target"], result.get("options", {}))
        db.update_scan(result["id"], server_name=result["server_name"], status="done", verdict=result["verdict"],
                       risk_score=result["risk_score"], counts=scan["counts"], result=result,
                       finished_at=result["finished_at"])
        with db.connect() as c:
            c.execute("UPDATE scans SET started_at = ? WHERE id = ?", (started, result["id"]))
        for i, event in enumerate(scan.get("events", []), 1):
            event["ts"] = event.get("ts", result["started_at"]) + shift
            db.add_event(result["id"], {**event, "seq": i})
    from mcpguard.ingest.source import normalize_key

    for pin in data.get("pins", []):
        target = _rebase_target(pin["target"])
        db.upsert_pin({**pin, "target": target, "server_key": normalize_key(target),
                       "pinned_at": now - pin["age_seconds"], "last_verified_at": None, "last_status": "pinned"})
    log.info("seeded %d demo scans", len(data.get("scans", [])))
    return True
