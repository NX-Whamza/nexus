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
        "users.db": "file:rbac_users?mode=memory&cache=shared",
        "feedback.db": "file:rbac_feedback?mode=memory&cache=shared",
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
    response = client.post(
        "/api/auth/login",
        json={"email": email, "password": api_server.DEFAULT_PASSWORD},
    )
    assert response.status_code == 200
    payload = response.get_json() or {}
    token = payload.get("token")
    assert token
    return token


def _set_membership_role(db_uri, email, role):
    conn = sqlite3.connect(db_uri, uri=True)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT id, home_tenant_id FROM users WHERE email = ?", (email,))
    user = c.fetchone()
    c.execute(
        "UPDATE user_tenant_memberships SET role = ? WHERE user_id = ? AND tenant_id = ?",
        (role, user["id"], user["home_tenant_id"]),
    )
    conn.commit()
    conn.close()


def test_platform_admin_bootstrap_has_super_admin_permissions(monkeypatch):
    api_server = _load_api_server()
    _db_uris, anchors = _patch_dbs(monkeypatch, api_server)
    try:
        client = api_server.app.test_client()
        token = _login(client, api_server, "whamza@team.nxlink.com")
        payload = client.get("/api/session/bootstrap", headers={"Authorization": f"Bearer {token}"}).get_json()
        assert payload["user"]["platformRole"] == "platform_admin"
        assert payload["permissions"]["platformAdmin"] is True
        assert payload["permissions"]["crossTenantVisibility"] is True
        assert payload["permissions"]["adminPanel"] is True
    finally:
        for conn in anchors.values():
            conn.close()


def test_platform_support_can_access_admin_feedback(monkeypatch):
    api_server = _load_api_server()
    _db_uris, anchors = _patch_dbs(monkeypatch, api_server)
    try:
        client = api_server.app.test_client()
        token = _login(client, api_server, "bgonzales@team.nxlink.com")
        bootstrap = client.get("/api/session/bootstrap", headers={"Authorization": f"Bearer {token}"}).get_json()
        assert bootstrap["user"]["platformRole"] == "platform_support"
        assert bootstrap["permissions"]["platformSupport"] is True
        assert bootstrap["permissions"]["crossTenantVisibility"] is False
        resp = client.get("/api/admin/feedback", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
    finally:
        for conn in anchors.values():
            conn.close()


def test_tenant_admin_can_access_admin_feedback_without_platform_role(monkeypatch):
    api_server = _load_api_server()
    db_uris, anchors = _patch_dbs(monkeypatch, api_server)
    try:
        client = api_server.app.test_client()
        token = _login(client, api_server, "tenant-admin@team.nxlink.com")
        _set_membership_role(db_uris["users.db"], "tenant-admin@team.nxlink.com", "tenant_admin")
        bootstrap = client.get("/api/session/bootstrap", headers={"Authorization": f"Bearer {token}"}).get_json()
        assert bootstrap["user"]["platformRole"] == "user"
        assert bootstrap["activeTenant"]["role"] == "tenant_admin"
        assert bootstrap["permissions"]["tenantAdmin"] is True
        assert bootstrap["permissions"]["adminPanel"] is True
        resp = client.get("/api/admin/feedback", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200
    finally:
        for conn in anchors.values():
            conn.close()


def test_regular_user_cannot_access_admin_feedback(monkeypatch):
    api_server = _load_api_server()
    _db_uris, anchors = _patch_dbs(monkeypatch, api_server)
    try:
        client = api_server.app.test_client()
        token = _login(client, api_server, "regular-user@team.nxlink.com")
        bootstrap = client.get("/api/session/bootstrap", headers={"Authorization": f"Bearer {token}"}).get_json()
        assert bootstrap["user"]["platformRole"] == "user"
        assert bootstrap["permissions"]["adminPanel"] is False
        resp = client.get("/api/admin/feedback", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 403
    finally:
        for conn in anchors.values():
            conn.close()
