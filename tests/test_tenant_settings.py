from __future__ import annotations
import importlib, os, sqlite3, sys
from pathlib import Path

def _load_api_server():
    repo_root = Path(__file__).resolve().parents[1]
    for p in (str(repo_root), str(repo_root / "vm_deployment")):
        if p not in sys.path: sys.path.insert(0, p)
    return importlib.import_module("vm_deployment.api_server")

def _patch_dbs(monkeypatch, api_server):
    uri = "file:ts_users?mode=memory&cache=shared"
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

def test_get_tenant_settings_returns_defaults(monkeypatch):
    api = _load_api_server()
    _, anchor = _patch_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        token = _login(client, api, "whamza@team.nxlink.com")
        r = client.get("/api/tenant-settings", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.get_json()
        assert data["success"] is True
        assert "dns_primary" in data["settings"]
    finally:
        anchor.close()

def test_tenant_admin_can_update_settings(monkeypatch):
    api = _load_api_server()
    uri, anchor = _patch_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        token = _login(client, api, "whamza@team.nxlink.com")
        r = client.put("/api/tenant-settings",
            json={"dns_primary": "1.1.1.1", "dns_secondary": "1.0.0.1"},
            headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert r.get_json()["settings"]["dns_primary"] == "1.1.1.1"
    finally:
        anchor.close()

def test_regular_user_cannot_update_settings(monkeypatch):
    api = _load_api_server()
    _, anchor = _patch_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        token = _login(client, api, "regular@team.nxlink.com")
        r = client.put("/api/tenant-settings",
            json={"dns_primary": "9.9.9.9"},
            headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 403
    finally:
        anchor.close()

def test_platform_admin_can_get_any_tenant_settings(monkeypatch):
    api = _load_api_server()
    uri, anchor = _patch_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        token = _login(client, api, "whamza@team.nxlink.com")
        list_r = client.get("/api/admin/tenants", headers={"Authorization": f"Bearer {token}"}).get_json()
        tid = list_r["tenants"][0]["id"]
        r = client.get(f"/api/admin/tenant-settings/{tid}", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        assert "dns_primary" in r.get_json()["settings"]
    finally:
        anchor.close()


def test_branding_syncs_to_tenants_table_via_tenant_settings(monkeypatch):
    api = _load_api_server()
    uri, anchor = _patch_dbs(monkeypatch, api)
    anchor.row_factory = sqlite3.Row
    try:
        client = api.app.test_client()
        token = _login(client, api, "whamza@team.nxlink.com")
        list_r = client.get("/api/admin/tenants", headers={"Authorization": f"Bearer {token}"}).get_json()
        tid = list_r["tenants"][0]["id"]
        rv = client.put("/api/tenant-settings", json={
            'brand_name': 'AcmeCorp',
            'logo_url': 'https://acme.com/logo.png',
            'primary_color': '#ff0000',
            'favicon_url': 'https://acme.com/fav.ico',
        }, headers={"Authorization": f"Bearer {token}"})
        assert rv.status_code == 200
        data = rv.get_json()
        assert data.get('success') is True
        row = anchor.execute(
            'SELECT company_name, logo_url, primary_color, favicon_url FROM tenants WHERE id = ?',
            (tid,)
        ).fetchone()
        assert row['company_name'] == 'AcmeCorp'
        assert row['logo_url'] == 'https://acme.com/logo.png'
        assert row['primary_color'] == '#ff0000'
        assert row['favicon_url'] == 'https://acme.com/fav.ico'
    finally:
        anchor.close()


def test_branding_syncs_to_tenants_table_via_admin_tenant_settings(monkeypatch):
    api = _load_api_server()
    uri, anchor = _patch_dbs(monkeypatch, api)
    anchor.row_factory = sqlite3.Row
    try:
        client = api.app.test_client()
        token = _login(client, api, "whamza@team.nxlink.com")
        list_r = client.get("/api/admin/tenants", headers={"Authorization": f"Bearer {token}"}).get_json()
        tid = list_r["tenants"][0]["id"]
        rv = client.put(f"/api/admin/tenant-settings/{tid}", json={
            'brand_name': 'AdminCorp',
            'logo_url': 'https://admin.com/logo.png',
            'primary_color': '#00ff00',
            'favicon_url': 'https://admin.com/fav.ico',
        }, headers={"Authorization": f"Bearer {token}"})
        assert rv.status_code == 200
        data = rv.get_json()
        assert data.get('success') is True
        row = anchor.execute(
            'SELECT company_name, logo_url, primary_color, favicon_url FROM tenants WHERE id = ?',
            (tid,)
        ).fetchone()
        assert row['company_name'] == 'AdminCorp'
        assert row['logo_url'] == 'https://admin.com/logo.png'
        assert row['primary_color'] == '#00ff00'
        assert row['favicon_url'] == 'https://admin.com/fav.ico'
    finally:
        anchor.close()
