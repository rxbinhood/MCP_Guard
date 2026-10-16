"""SQLite persistence for scans, scan events, pins and pin verifications.

Plain ``sqlite3`` keeps the dependency footprint small. Large structures
(scan results, manifests, diffs) are stored as JSON text columns.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from mcpguard.config import get_settings

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    server_name TEXT,
    status TEXT NOT NULL DEFAULT 'queued',      -- queued | running | done | failed
    verdict TEXT,
    risk_score INTEGER,
    counts TEXT,                                -- JSON {severity: n}
    options TEXT,                               -- JSON
    result TEXT,                                -- JSON ScanResult
    started_at REAL NOT NULL,
    finished_at REAL
);
CREATE TABLE IF NOT EXISTS scan_events (
    scan_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    ts REAL NOT NULL,
    event TEXT NOT NULL,                        -- JSON event payload
    PRIMARY KEY (scan_id, seq)
);
CREATE TABLE IF NOT EXISTS pins (
    server_key TEXT PRIMARY KEY,                -- normalized target (abs path or repo URL)
    server_name TEXT,
    server_version TEXT,
    target TEXT NOT NULL,
    manifest_hash TEXT NOT NULL,
    tool_hashes TEXT NOT NULL,                  -- JSON {tool: sha256}
    manifest TEXT NOT NULL,                     -- JSON Manifest
    pinned_at REAL NOT NULL,
    last_verified_at REAL,
    last_status TEXT                            -- unchanged | changed | error
);
CREATE TABLE IF NOT EXISTS pin_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_key TEXT NOT NULL,
    ts REAL NOT NULL,
    status TEXT NOT NULL,
    manifest_hash TEXT,
    diff TEXT,                                  -- JSON ManifestDiff
    findings TEXT                               -- JSON [Finding]
);
"""


class Database:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path or get_settings().db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            with self._lock:
                yield conn
                conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------ scans
    def create_scan(self, scan_id: str, target: str, options: dict[str, Any]) -> None:
        with self.connect() as c:
            c.execute(
                "INSERT INTO scans (id, target, status, options, started_at) VALUES (?, ?, 'queued', ?, ?)",
                (scan_id, target, json.dumps(options), time.time()),
            )

    def update_scan(self, scan_id: str, **fields: Any) -> None:
        if not fields:
            return
        for key in ("counts", "options", "result"):
            if key in fields and not isinstance(fields[key], str):
                fields[key] = json.dumps(fields[key])
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self.connect() as c:
            c.execute(f"UPDATE scans SET {cols} WHERE id = ?", (*fields.values(), scan_id))

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self.connect() as c:
            row = c.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        return _scan_row(row) if row else None

    def list_scans(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as c:
            rows = c.execute(
                "SELECT id, target, server_name, status, verdict, risk_score, counts, options, started_at, "
                "finished_at FROM scans ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [_scan_row(r) for r in rows]

    def add_event(self, scan_id: str, event: dict[str, Any]) -> int:
        with self.connect() as c:
            seq = c.execute(
                "SELECT COALESCE(MAX(seq), 0) + 1 FROM scan_events WHERE scan_id = ?", (scan_id,)
            ).fetchone()[0]
            c.execute(
                "INSERT INTO scan_events (scan_id, seq, ts, event) VALUES (?, ?, ?, ?)",
                (scan_id, seq, event.get("ts", time.time()), json.dumps(event)),
            )
        return seq

    def get_events(self, scan_id: str, after: int = 0) -> list[dict[str, Any]]:
        with self.connect() as c:
            rows = c.execute(
                "SELECT seq, event FROM scan_events WHERE scan_id = ? AND seq > ? ORDER BY seq",
                (scan_id, after),
            ).fetchall()
        return [{**json.loads(r["event"]), "seq": r["seq"]} for r in rows]

    # ------------------------------------------------------------------- pins
    def upsert_pin(self, pin: dict[str, Any]) -> None:
        with self.connect() as c:
            c.execute(
                "INSERT OR REPLACE INTO pins (server_key, server_name, server_version, target, manifest_hash, "
                "tool_hashes, manifest, pinned_at, last_verified_at, last_status) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    pin["server_key"], pin.get("server_name"), pin.get("server_version"), pin["target"],
                    pin["manifest_hash"], json.dumps(pin["tool_hashes"]), json.dumps(pin["manifest"]),
                    pin.get("pinned_at", time.time()), pin.get("last_verified_at"), pin.get("last_status"),
                ),
            )

    def get_pin(self, server_key: str) -> dict[str, Any] | None:
        with self.connect() as c:
            row = c.execute("SELECT * FROM pins WHERE server_key = ?", (server_key,)).fetchone()
        return _pin_row(row) if row else None

    def list_pins(self) -> list[dict[str, Any]]:
        with self.connect() as c:
            rows = c.execute("SELECT * FROM pins ORDER BY pinned_at DESC").fetchall()
        return [_pin_row(r) for r in rows]

    def delete_pin(self, server_key: str) -> None:
        with self.connect() as c:
            c.execute("DELETE FROM pins WHERE server_key = ?", (server_key,))
            c.execute("DELETE FROM pin_checks WHERE server_key = ?", (server_key,))

    def record_check(self, server_key: str, status: str, manifest_hash: str | None,
                     diff: dict[str, Any] | None, findings: list[dict[str, Any]]) -> int:
        now = time.time()
        with self.connect() as c:
            cur = c.execute(
                "INSERT INTO pin_checks (server_key, ts, status, manifest_hash, diff, findings) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (server_key, now, status, manifest_hash, json.dumps(diff), json.dumps(findings)),
            )
            c.execute(
                "UPDATE pins SET last_verified_at = ?, last_status = ? WHERE server_key = ?",
                (now, status, server_key),
            )
            return int(cur.lastrowid)

    def list_checks(self, server_key: str, limit: int = 20) -> list[dict[str, Any]]:
        with self.connect() as c:
            rows = c.execute(
                "SELECT * FROM pin_checks WHERE server_key = ? ORDER BY ts DESC LIMIT ?", (server_key, limit)
            ).fetchall()
        return [
            {**dict(r), "diff": json.loads(r["diff"] or "null"), "findings": json.loads(r["findings"] or "[]")}
            for r in rows
        ]


def _scan_row(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    for key in ("counts", "options", "result"):
        if key in d and d[key]:
            d[key] = json.loads(d[key])
    return d


def _pin_row(row: sqlite3.Row) -> dict[str, Any]:
    d = dict(row)
    d["tool_hashes"] = json.loads(d["tool_hashes"])
    d["manifest"] = json.loads(d["manifest"])
    return d


_db: Database | None = None


def get_db() -> Database:
    global _db
    if _db is None:
        _db = Database()
    return _db
