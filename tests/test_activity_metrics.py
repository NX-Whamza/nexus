from __future__ import annotations

import importlib
import os
import sqlite3
import sys
from pathlib import Path


def _load_api_server():
    repo_root = Path(__file__).resolve().parents[1]
    vm_dep = repo_root / "vm_deployment"
    for p in (str(repo_root), str(vm_dep)):
        if p not in sys.path:
            sys.path.insert(0, p)
    return importlib.import_module("vm_deployment.api_server")


def test_log_activity_can_exclude_validation_blocked_attempts(monkeypatch, tmp_path):
    api_server = _load_api_server()
    secure_dir = tmp_path / "secure_data"
    secure_dir.mkdir()

    original_connect = sqlite3.connect

    def connect_override(path, *args, **kwargs):
        target = str(path)
        if target.endswith("activity_log.db"):
            return original_connect(str(secure_dir / "activity_log.db"), *args, **kwargs)
        if target.endswith("users.db"):
            return original_connect(str(secure_dir / "users.db"), *args, **kwargs)
        return original_connect(path, *args, **kwargs)

    monkeypatch.setattr(api_server.os.path, "exists", lambda p: True if str(p) == "secure_data" else os.path.exists(p))
    monkeypatch.setattr(api_server.os, "makedirs", lambda *args, **kwargs: None)
    monkeypatch.setattr(api_server.sqlite3, "connect", connect_override)

    client = api_server.app.test_client()
    resp = client.post(
        "/api/log-activity",
        json={
            "username": "tester",
            "type": "new-config",
            "device": "CCR2004",
            "siteName": "Validation Blocked",
            "routeros": "7.19.4",
            "success": False,
            "countsTowardMetrics": False,
        },
    )
    assert resp.status_code == 200

    rows = client.get("/api/get-activity?all=true&limit=10").get_json()["activities"]
    match = next(item for item in rows if item["siteName"] == "Validation Blocked")
    assert match["success"] is False
    assert match["countsTowardMetrics"] is False
