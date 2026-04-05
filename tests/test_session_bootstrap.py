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
    db_uri = "file:session_bootstrap_db?mode=memory&cache=shared"
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


def test_session_bootstrap_returns_user_and_active_tenant(monkeypatch):
    api_server = _load_api_server()
    _db_uri, anchor = _patch_users_db(monkeypatch, api_server)

    try:
        client = api_server.app.test_client()
        login = client.post(
            "/api/auth/login",
            json={"email": "bootstrap-user@team.nxlink.com", "password": api_server.DEFAULT_PASSWORD},
        )
        assert login.status_code == 200
        login_payload = login.get_json() or {}
        token = login_payload.get("token")
        assert token

        resp = client.get(
            "/api/session/bootstrap",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 200
        payload = resp.get_json() or {}

        assert payload.get("success") is True
        assert payload["user"]["email"] == "bootstrap-user@team.nxlink.com"
        assert payload["user"]["homeTenantId"] is not None
        assert payload["activeTenant"]["slug"] == api_server.DEFAULT_TENANT_SLUG
        assert payload["activeTenant"]["role"] == "tenant_engineer"
        assert payload["memberships"]
        assert payload["features"]["tenantSwitching"] is False
    finally:
        anchor.close()
