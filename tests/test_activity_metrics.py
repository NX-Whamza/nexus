from __future__ import annotations

import importlib
import os
import sqlite3
import sys
from functools import wraps
from pathlib import Path


def _load_api_server():
    repo_root = Path(__file__).resolve().parents[1]
    vm_dep = repo_root / "vm_deployment"
    for p in (str(repo_root), str(vm_dep)):
        if p not in sys.path:
            sys.path.insert(0, p)
    return importlib.import_module("vm_deployment.api_server")


def _patch_dbs(monkeypatch, api_server):
    """Redirect all SQLite opens to shared in-memory databases."""
    db_uris = {
        "activity_log.db": "file:act_metrics_activity?mode=memory&cache=shared",
        "users.db":        "file:act_metrics_users?mode=memory&cache=shared",
    }
    # Keep anchor connections so the in-memory DBs survive for the test duration
    anchors = {name: sqlite3.connect(uri, uri=True) for name, uri in db_uris.items()}
    original_connect = sqlite3.connect
    original_exists = os.path.exists

    def connect_override(path, *args, **kwargs):
        target = str(path)
        for suffix, uri in db_uris.items():
            if target.endswith(suffix):
                return original_connect(uri, uri=True, *args, **kwargs)
        return original_connect(path, *args, **kwargs)

    monkeypatch.setattr(api_server.sqlite3, "connect", connect_override)
    monkeypatch.setattr(
        api_server.os.path,
        "exists",
        lambda p: True if str(p) == "secure_data" else original_exists(p),
    )
    monkeypatch.setattr(api_server.os, "makedirs", lambda *a, **k: None)
    return anchors


def _patch_auth(monkeypatch, api_server):
    """Replace log_activity and get_activity view functions with auth-bypassed versions."""
    from flask import request as flask_request

    def fake_auth_wrapper(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            flask_request.current_user = {
                "id": 1,
                "user_id": 1,
                "email": "test@nxlink.com",
                "tenant_id": 1,
                "tenantId": 1,
                "tenant_role": "tenant_admin",
            }
            return f(*args, **kwargs)
        return wrapper

    for name in ("log_activity", "get_activity"):
        view = api_server.app.view_functions.get(name)
        if view:
            inner = getattr(view, "__wrapped__", view)
            # Use monkeypatch.setitem so Flask's view_functions dict is restored after the test
            monkeypatch.setitem(api_server.app.view_functions, name, fake_auth_wrapper(inner))


def test_log_activity_can_exclude_validation_blocked_attempts(monkeypatch):
    api_server = _load_api_server()
    anchors = _patch_dbs(monkeypatch, api_server)
    _patch_auth(monkeypatch, api_server)
    try:
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
    finally:
        for anchor in anchors.values():
            anchor.close()
