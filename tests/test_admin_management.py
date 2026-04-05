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


def _patch_dbs(monkeypatch, api_server):
    db_uris = {
        "users.db": "file:admin_mgmt_users?mode=memory&cache=shared",
        "feedback.db": "file:admin_mgmt_feedback?mode=memory&cache=shared",
    }
    anchors = {name: sqlite3.connect(uri, uri=True) for name, uri in db_uris.items()}
    original_connect = sqlite3.connect
    original_exists = os.path.exists

    def connect_override(path, *args, **kwargs):
        target = str(path)
        for suffix, uri in db_uris.items():
            if target.endswith(suffix):
                return original_connect(uri, uri=True, *args, **kwargs)
        return original_connect(path, *args, **kwargs)

    monkeypatch.setattr(api_server.os.path, "exists", lambda p: True if str(p) == "secure_data" else original_exists(p))
    monkeypatch.setattr(api_server.os, "makedirs", lambda *args, **kwargs: None)
    monkeypatch.setattr(api_server.sqlite3, "connect", connect_override)
    return db_uris, anchors


def _login(client, api_server, email):
    resp = client.post("/api/auth/login", json={"email": email, "password": api_server.DEFAULT_PASSWORD})
    assert resp.status_code == 200
    token = (resp.get_json() or {}).get("token")
    assert token
    return token


def test_tenant_list_requires_platform_admin(monkeypatch):
    api_server = _load_api_server()
    _db_uris, anchors = _patch_dbs(monkeypatch, api_server)
    try:
        client = api_server.app.test_client()
        admin_token = _login(client, api_server, "whamza@team.nxlink.com")
        regular_token = _login(client, api_server, "regular@team.nxlink.com")

        admin_resp = client.get("/api/admin/tenants", headers={"Authorization": f"Bearer {admin_token}"})
        assert admin_resp.status_code == 200
        assert admin_resp.get_json()["success"] is True

        regular_resp = client.get("/api/admin/tenants", headers={"Authorization": f"Bearer {regular_token}"})
        assert regular_resp.status_code == 403
    finally:
        for conn in anchors.values():
            conn.close()


def test_create_and_list_tenant(monkeypatch):
    api_server = _load_api_server()
    _db_uris, anchors = _patch_dbs(monkeypatch, api_server)
    try:
        client = api_server.app.test_client()
        token = _login(client, api_server, "whamza@team.nxlink.com")

        create_resp = client.post(
            "/api/admin/tenants",
            json={"slug": "testcorp", "name": "Test Corp", "auth_mode": "password"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert create_resp.status_code == 200
        payload = create_resp.get_json()
        assert payload["success"] is True
        assert payload["tenant"]["slug"] == "testcorp"

        list_resp = client.get("/api/admin/tenants", headers={"Authorization": f"Bearer {token}"})
        slugs = [t["slug"] for t in list_resp.get_json()["tenants"]]
        assert "testcorp" in slugs
    finally:
        for conn in anchors.values():
            conn.close()


def test_deactivate_default_tenant_is_rejected(monkeypatch):
    api_server = _load_api_server()
    db_uris, anchors = _patch_dbs(monkeypatch, api_server)
    try:
        client = api_server.app.test_client()
        token = _login(client, api_server, "whamza@team.nxlink.com")

        list_resp = client.get("/api/admin/tenants", headers={"Authorization": f"Bearer {token}"}).get_json()
        default_tenant = next(t for t in list_resp["tenants"] if t["slug"] == api_server.DEFAULT_TENANT_SLUG)

        patch_resp = client.patch(
            f"/api/admin/tenants/{default_tenant['id']}/status",
            json={"status": "inactive"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert patch_resp.status_code == 400
        assert "default" in (patch_resp.get_json().get("error") or "").lower()
    finally:
        for conn in anchors.values():
            conn.close()


def test_user_list_filtered_by_tenant(monkeypatch):
    api_server = _load_api_server()
    db_uris, anchors = _patch_dbs(monkeypatch, api_server)
    try:
        client = api_server.app.test_client()
        token = _login(client, api_server, "whamza@team.nxlink.com")
        _login(client, api_server, "engineer@team.nxlink.com")

        list_resp = client.get("/api/admin/tenants", headers={"Authorization": f"Bearer {token}"}).get_json()
        default_tenant = next(t for t in list_resp["tenants"] if t["slug"] == api_server.DEFAULT_TENANT_SLUG)
        tenant_id = default_tenant["id"]

        users_resp = client.get(
            f"/api/admin/users?tenant_id={tenant_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert users_resp.status_code == 200
        payload = users_resp.get_json()
        assert payload["success"] is True
        emails = [u["email"] for u in payload["users"]]
        assert "engineer@team.nxlink.com" in emails
    finally:
        for conn in anchors.values():
            conn.close()


def test_tenant_admin_cannot_access_platform_endpoints(monkeypatch):
    api_server = _load_api_server()
    db_uris, anchors = _patch_dbs(monkeypatch, api_server)
    try:
        client = api_server.app.test_client()
        token = _login(client, api_server, "tadmin@team.nxlink.com")

        conn = sqlite3.connect(db_uris["users.db"], uri=True)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, home_tenant_id FROM users WHERE email = ?", ("tadmin@team.nxlink.com",))
        user = c.fetchone()
        c.execute("UPDATE user_tenant_memberships SET role = 'tenant_admin' WHERE user_id = ? AND tenant_id = ?",
                  (user["id"], user["home_tenant_id"]))
        conn.commit()
        conn.close()

        tenants_resp = client.get("/api/admin/tenants", headers={"Authorization": f"Bearer {token}"})
        assert tenants_resp.status_code == 403

        feedback_resp = client.get("/api/admin/feedback", headers={"Authorization": f"Bearer {token}"})
        assert feedback_resp.status_code == 200
    finally:
        for conn in anchors.values():
            conn.close()
