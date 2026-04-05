from __future__ import annotations
import importlib, os, sqlite3, sys, time
from pathlib import Path

def _load_api_server():
    repo_root = Path(__file__).resolve().parents[1]
    for p in (str(repo_root), str(repo_root / "vm_deployment")):
        if p not in sys.path: sys.path.insert(0, p)
    return importlib.import_module("vm_deployment.api_server")

def _patch_dbs(monkeypatch, api_server):
    uri = "file:audit_users?mode=memory&cache=shared"
    anchor = sqlite3.connect(uri, uri=True)
    orig = sqlite3.connect
    orig_exists = os.path.exists
    monkeypatch.setattr(api_server.sqlite3, "connect", lambda p, *a, **k: orig(uri, uri=True, *a, **k) if str(p).endswith("users.db") else orig(p, *a, **k))
    monkeypatch.setattr(api_server.os.path, "exists", lambda p: True if str(p) == "secure_data" else orig_exists(p))
    monkeypatch.setattr(api_server.os, "makedirs", lambda *a, **k: None)
    return uri, anchor

def _login(client, api_server, email):
    r = client.post("/api/auth/login", json={"email": email, "password": api_server.DEFAULT_PASSWORD})
    assert r.status_code == 200
    return (r.get_json() or {})["token"]

def test_login_creates_audit_event(monkeypatch):
    api = _load_api_server()
    uri, anchor = _patch_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        token = _login(client, api, "whamza@team.nxlink.com")
        r = client.get("/api/admin/audit-log", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        events = r.get_json()["events"]
        login_events = [e for e in events if e["event_type"] == "login"]
        assert len(login_events) >= 1
    finally:
        anchor.close()

def test_tenant_create_creates_audit_event(monkeypatch):
    api = _load_api_server()
    _, anchor = _patch_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        token = _login(client, api, "whamza@team.nxlink.com")
        client.post("/api/admin/tenants", json={"slug": "auditcorp", "name": "Audit Corp", "auth_mode": "password"},
                    headers={"Authorization": f"Bearer {token}"})
        r = client.get("/api/admin/audit-log?event_type=tenant_create", headers={"Authorization": f"Bearer {token}"})
        events = r.get_json()["events"]
        assert any(e["tenant_slug"] == "auditcorp" for e in events)
    finally:
        anchor.close()

def test_audit_log_requires_platform_admin(monkeypatch):
    api = _load_api_server()
    _, anchor = _patch_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        regular_token = _login(client, api, "regular@team.nxlink.com")
        r = client.get("/api/admin/audit-log", headers={"Authorization": f"Bearer {regular_token}"})
        assert r.status_code == 403
    finally:
        anchor.close()

def test_audit_log_event_type_filter(monkeypatch):
    api = _load_api_server()
    _, anchor = _patch_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        token = _login(client, api, "whamza@team.nxlink.com")
        r = client.get("/api/admin/audit-log?event_type=login", headers={"Authorization": f"Bearer {token}"})
        events = r.get_json()["events"]
        assert all(e["event_type"] == "login" for e in events)
    finally:
        anchor.close()
