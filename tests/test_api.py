"""API smoke tests (static sandbox so no Docker is needed)."""

import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("MCPGUARD_SEED", "0")
    monkeypatch.setenv("MCPGUARD_SANDBOX", "static")
    import mcpguard.config as config

    monkeypatch.setattr(config, "_settings", None)
    from mcpguard.api.app import app

    with TestClient(app) as c:
        yield c


def _wait(client, scan_id, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = client.get(f"/api/scans/{scan_id}").json()
        if data["status"] in ("done", "failed"):
            return data
        time.sleep(0.2)
    raise AssertionError("scan did not finish")


def test_health_reports_engines(client):
    data = client.get("/api/health").json()
    ids = {e["id"] for e in data["engines"]}
    assert {"llm", "prompt_guard", "docker", "semgrep", "gitleaks"} <= ids
    assert data["ai_online"] is False  # no API key in tests -> graceful offline


@pytest.mark.parametrize("server,expected", [("clean_calc", "PASS"), ("vuln_shell", "FAIL"),
                                             ("poisoned_weather", "FAIL")])
def test_scan_lifecycle(client, server, expected):
    r = client.post("/api/scans", json={"target": f"test_servers/{server}", "ai": False})
    assert r.status_code == 202
    data = _wait(client, r.json()["id"])
    assert data["status"] == "done" and data["verdict"] == expected
    events = client.get(f"/api/scans/{data['id']}/events").text
    assert "event: module" in events and "event: end" in events
    for fmt in ("md", "json", "sarif"):
        assert client.get(f"/api/scans/{data['id']}/report", params={"format": fmt}).status_code == 200


def test_bad_target(client):
    assert client.post("/api/scans", json={"target": "/definitely/not/here"}).status_code == 400


def test_pin_and_verify_rugpull(client, servers):
    toggle = servers / "rugpull_todo" / ".rugpull"
    toggle.unlink(missing_ok=True)
    pin = client.post("/api/pins", json={"target": "test_servers/rugpull_todo"}).json()
    key = pin["server_key"]
    assert client.post("/api/pins/verify", json={"server_key": key, "ai": False}).json()["status"] == "unchanged"
    # Static extraction cannot see a runtime toggle, so simulate the rug pull by editing the pinned manifest.
    from mcpguard.db import get_db

    db = get_db()
    stored = db.get_pin(key)
    stored["manifest"]["tools"][0]["description"] = "Add a todo item (older wording)."
    db.upsert_pin(stored)
    res = client.post("/api/pins/verify", json={"server_key": key, "ai": False}).json()
    assert res["status"] == "changed" and res["diff"]["changed"]
    assert client.get("/api/pins/detail", params={"server_key": key}).json()["checks"]
