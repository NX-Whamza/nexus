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
        "users.db": "file:tenant_scope_users?mode=memory&cache=shared",
        "completed_configs.db": "file:tenant_scope_configs?mode=memory&cache=shared",
        "feedback.db": "file:tenant_scope_feedback?mode=memory&cache=shared",
        "activity_log.db": "file:tenant_scope_activity?mode=memory&cache=shared",
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
    resp = client.post(
        "/api/auth/login",
        json={"email": email, "password": api_server.DEFAULT_PASSWORD},
    )
    assert resp.status_code == 200
    payload = resp.get_json() or {}
    assert payload.get("success") is True
    token = payload.get("token")
    assert token
    return token


def _set_active_tenant(db_uri, email, tenant_slug, tenant_name, azure_tenant_id, role='tenant_engineer'):
    conn = sqlite3.connect(db_uri, uri=True)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(
        """
        INSERT OR IGNORE INTO tenants
        (slug, name, status, auth_mode, azure_tenant_id, allowed_email_domains, settings_json)
        VALUES (?, ?, 'active', 'microsoft', ?, '[]', '{}')
        """,
        (tenant_slug, tenant_name, azure_tenant_id),
    )
    c.execute("SELECT id FROM users WHERE email = ?", (email,))
    user_id = c.fetchone()["id"]
    c.execute("SELECT id FROM tenants WHERE slug = ?", (tenant_slug,))
    tenant_id = c.fetchone()["id"]
    c.execute("UPDATE user_tenant_memberships SET is_default = 0 WHERE user_id = ?", (user_id,))
    c.execute(
        """
        INSERT OR REPLACE INTO user_tenant_memberships
        (id, user_id, tenant_id, role, status, is_default, created_at)
        VALUES (
            COALESCE((SELECT id FROM user_tenant_memberships WHERE user_id = ? AND tenant_id = ?), NULL),
            ?, ?, ?, 'active', 1, CURRENT_TIMESTAMP
        )
        """,
        (user_id, tenant_id, user_id, tenant_id, role),
    )
    c.execute("UPDATE users SET home_tenant_id = ? WHERE id = ?", (tenant_id, user_id))
    conn.commit()
    conn.close()


def test_completed_configs_are_tenant_scoped(monkeypatch):
    api_server = _load_api_server()
    db_uris, anchors = _patch_dbs(monkeypatch, api_server)

    try:
        client = api_server.app.test_client()
        acme_token = _login(client, api_server, "acme-user@team.nxlink.com")
        nextlink_token = _login(client, api_server, "nextlink-user@team.nxlink.com")
        _set_active_tenant(db_uris["users.db"], "acme-user@team.nxlink.com", "acme", "Acme", "acme-tenant-id")

        save_resp = client.post(
            "/api/save-completed-config",
            json={
                "config_type": "tower",
                "device_name": "RTR-ACME-1",
                "config_content": "/system identity\nset name=RTR-ACME-1\n",
                "created_by": "acme-user@team.nxlink.com",
            },
            headers={"Authorization": f"Bearer {acme_token}"},
        )
        assert save_resp.status_code == 200

        acme_list = client.get("/api/get-completed-configs", headers={"Authorization": f"Bearer {acme_token}"}).get_json()
        nextlink_list = client.get("/api/get-completed-configs", headers={"Authorization": f"Bearer {nextlink_token}"}).get_json()

        assert len(acme_list["configs"]) == 1
        assert acme_list["configs"][0]["device_name"] == "RTR-ACME-1"
        assert nextlink_list["configs"] == []
    finally:
        for conn in anchors.values():
            conn.close()


def test_feedback_and_admin_feedback_are_tenant_scoped(monkeypatch):
    api_server = _load_api_server()
    db_uris, anchors = _patch_dbs(monkeypatch, api_server)

    try:
        client = api_server.app.test_client()
        acme_admin = _login(client, api_server, "netops@team.nxlink.com")
        nextlink_admin = _login(client, api_server, "whamza@team.nxlink.com")
        _set_active_tenant(db_uris["users.db"], "netops@team.nxlink.com", "acme", "Acme", "acme-tenant-id", role='tenant_admin')

        submit = client.post(
            "/api/feedback",
            json={
                "type": "bug",
                "subject": "Acme issue",
                "category": "ui",
                "details": "Scoped to Acme",
                "name": "Acme Admin",
                "email": "netops@team.nxlink.com",
            },
            headers={"Authorization": f"Bearer {acme_admin}"},
        )
        assert submit.status_code == 200

        acme_status = client.get(
            "/api/feedback/my-status?name=Acme%20Admin",
            headers={"Authorization": f"Bearer {acme_admin}"},
        ).get_json()
        nextlink_admin_list = client.get(
            "/api/admin/feedback",
            headers={"Authorization": f"Bearer {nextlink_admin}"},
        ).get_json()
        acme_admin_list = client.get(
            "/api/admin/feedback",
            headers={"Authorization": f"Bearer {acme_admin}"},
        ).get_json()

        assert len(acme_status) == 1
        assert acme_status[0]["subject"] == "Acme issue"
        assert nextlink_admin_list["feedback"] == []
        assert len(acme_admin_list["feedback"]) == 1
    finally:
        for conn in anchors.values():
            conn.close()


def test_activity_is_tenant_scoped(monkeypatch):
    api_server = _load_api_server()
    db_uris, anchors = _patch_dbs(monkeypatch, api_server)

    try:
        client = api_server.app.test_client()
        acme_token = _login(client, api_server, "activity-acme@team.nxlink.com")
        nextlink_token = _login(client, api_server, "activity-nextlink@team.nxlink.com")
        _set_active_tenant(db_uris["users.db"], "activity-acme@team.nxlink.com", "acme", "Acme", "acme-tenant-id")

        logged = client.post(
            "/api/log-activity",
            json={"type": "new-config", "device": "CCR2004", "siteName": "Acme Tower", "routeros": "7.19.4", "success": True},
            headers={"Authorization": f"Bearer {acme_token}"},
        )
        assert logged.status_code == 200

        acme_rows = client.get("/api/get-activity?all=true&limit=10", headers={"Authorization": f"Bearer {acme_token}"}).get_json()
        nextlink_rows = client.get("/api/get-activity?all=true&limit=10", headers={"Authorization": f"Bearer {nextlink_token}"}).get_json()

        assert len(acme_rows["activities"]) == 1
        assert acme_rows["activities"][0]["siteName"] == "Acme Tower"
        assert nextlink_rows["activities"] == []
    finally:
        for conn in anchors.values():
            conn.close()
