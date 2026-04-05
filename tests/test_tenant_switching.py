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


def _patch_users_db(monkeypatch, api_server):
    db_uri = "file:tenant_switch_users?mode=memory&cache=shared"
    anchor = sqlite3.connect(db_uri, uri=True)
    original_connect = sqlite3.connect
    original_exists = os.path.exists

    def connect_override(path, *args, **kwargs):
        target = str(path)
        if target.endswith("users.db"):
            return original_connect(db_uri, uri=True, *args, **kwargs)
        return original_connect(path, *args, **kwargs)

    monkeypatch.setattr(api_server.os.path, "exists", lambda p: True if str(p) == "secure_data" else original_exists(p))
    monkeypatch.setattr(api_server.os, "makedirs", lambda *args, **kwargs: None)
    monkeypatch.setattr(api_server.sqlite3, "connect", connect_override)
    return db_uri, anchor


def test_switch_tenant_updates_active_tenant(monkeypatch):
    api_server = _load_api_server()
    db_uri, anchor = _patch_users_db(monkeypatch, api_server)

    try:
        client = api_server.app.test_client()
        login = client.post(
            "/api/auth/login",
            json={"email": "switcher@team.nxlink.com", "password": api_server.DEFAULT_PASSWORD},
        )
        assert login.status_code == 200
        token = (login.get_json() or {}).get("token")
        assert token

        conn = sqlite3.connect(db_uri, uri=True)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            """
            INSERT OR IGNORE INTO tenants
            (slug, name, status, auth_mode, azure_tenant_id, allowed_email_domains, settings_json)
            VALUES ('acme', 'Acme', 'active', 'microsoft', 'acme-tenant-id', '[]', '{}')
            """
        )
        c.execute("SELECT id FROM users WHERE email = ?", ("switcher@team.nxlink.com",))
        user_id = c.fetchone()["id"]
        c.execute("SELECT id FROM tenants WHERE slug = 'acme'")
        acme_id = c.fetchone()["id"]
        c.execute(
            """
            INSERT INTO user_tenant_memberships (user_id, tenant_id, role, status, is_default)
            VALUES (?, ?, 'tenant_engineer', 'active', 0)
            """,
            (user_id, acme_id),
        )
        conn.commit()
        conn.close()

        switched = client.post(
            "/api/session/switch-tenant",
            json={"tenant_id": acme_id},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert switched.status_code == 200
        payload = switched.get_json() or {}
        assert payload.get("success") is True
        assert payload["activeTenant"]["slug"] == "acme"
        assert payload["features"]["tenantSwitching"] is True

        bootstrap = client.get(
            "/api/session/bootstrap",
            headers={"Authorization": f"Bearer {token}"},
        ).get_json()
        assert bootstrap["activeTenant"]["slug"] == "acme"
    finally:
        anchor.close()


def test_platform_admin_can_switch_to_tenant_without_existing_membership(monkeypatch):
    api_server = _load_api_server()
    db_uri, anchor = _patch_users_db(monkeypatch, api_server)

    try:
        client = api_server.app.test_client()
        login = client.post(
            "/api/auth/login",
            json={"email": "whamza@team.nxlink.com", "password": api_server.DEFAULT_PASSWORD},
        )
        assert login.status_code == 200
        token = (login.get_json() or {}).get("token")
        assert token

        conn = sqlite3.connect(db_uri, uri=True)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            """
            INSERT OR IGNORE INTO tenants
            (slug, name, status, auth_mode, azure_tenant_id, allowed_email_domains, settings_json)
            VALUES ('customer-a', 'Customer A', 'active', 'microsoft', 'customer-a-tenant-id', '[]', '{}')
            """
        )
        c.execute("SELECT id FROM tenants WHERE slug = 'customer-a'")
        customer_tenant_id = c.fetchone()["id"]
        conn.commit()
        conn.close()

        switched = client.post(
            "/api/session/switch-tenant",
            json={"tenant_id": customer_tenant_id},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert switched.status_code == 200
        payload = switched.get_json() or {}
        assert payload.get("success") is True
        assert payload["activeTenant"]["slug"] == "customer-a"
        assert payload["user"]["platformRole"] == "platform_admin"
    finally:
        anchor.close()
