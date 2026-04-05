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
    db_uri = "file:tenant_foundation_db?mode=memory&cache=shared"
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


def test_init_users_db_seeds_default_tenant(monkeypatch):
    api_server = _load_api_server()
    db_uri, anchor = _patch_users_db(monkeypatch, api_server)

    try:
        api_server.init_users_db()

        conn = sqlite3.connect(db_uri, uri=True)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            "SELECT slug, name, auth_mode, azure_tenant_id, allowed_email_domains FROM tenants WHERE slug = ?",
            (api_server.DEFAULT_TENANT_SLUG,),
        )
        tenant = c.fetchone()
        conn.close()

        assert tenant is not None
        assert tenant["name"] == api_server.DEFAULT_TENANT_NAME
        assert tenant["auth_mode"] == api_server.DEFAULT_TENANT_AUTH_MODE
        assert tenant["azure_tenant_id"] == api_server.AZURE_TENANT_ID
        assert "team.nxlink.com" in (tenant["allowed_email_domains"] or "")
    finally:
        anchor.close()


def test_login_auto_creates_default_membership(monkeypatch):
    api_server = _load_api_server()
    db_uri, anchor = _patch_users_db(monkeypatch, api_server)

    try:
        client = api_server.app.test_client()
        response = client.post(
            "/api/auth/login",
            json={"email": "tenant-check@team.nxlink.com", "password": api_server.DEFAULT_PASSWORD},
        )
        assert response.status_code == 200
        payload = response.get_json() or {}
        assert payload.get("success") is True

        conn = sqlite3.connect(db_uri, uri=True)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute(
            """
            SELECT u.home_tenant_id, t.slug, m.role, m.status, m.is_default
            FROM users AS u
            JOIN user_tenant_memberships AS m ON m.user_id = u.id
            JOIN tenants AS t ON t.id = m.tenant_id
            WHERE u.email = ?
            """,
            ("tenant-check@team.nxlink.com",),
        )
        membership = c.fetchone()
        conn.close()

        assert membership is not None
        assert membership["home_tenant_id"] is not None
        assert membership["slug"] == api_server.DEFAULT_TENANT_SLUG
        assert membership["role"] == "tenant_engineer"
        assert membership["status"] == "active"
        assert membership["is_default"] == 1
    finally:
        anchor.close()
