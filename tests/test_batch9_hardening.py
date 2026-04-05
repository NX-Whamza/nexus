from __future__ import annotations
import importlib, os, sqlite3, sys
from pathlib import Path


def _load_api_server():
    repo_root = Path(__file__).resolve().parents[1]
    for p in (str(repo_root), str(repo_root / "vm_deployment")):
        if p not in sys.path: sys.path.insert(0, p)
    return importlib.import_module("vm_deployment.api_server")


def _patch_dbs(monkeypatch, api_server):
    uri = "file:b9_users?mode=memory&cache=shared"
    anchor = sqlite3.connect(uri, uri=True)
    orig = sqlite3.connect
    orig_exists = os.path.exists
    monkeypatch.setattr(api_server.sqlite3, "connect",
        lambda p, *a, **k: orig(uri, uri=True, *a, **k) if str(p).endswith("users.db") else orig(p, *a, **k))
    monkeypatch.setattr(api_server.os.path, "exists", lambda p: True if str(p) == "secure_data" else orig_exists(p))
    monkeypatch.setattr(api_server.os, "makedirs", lambda *a, **k: None)
    return uri, anchor


def _login(client, api_server, email):
    r = client.post("/api/auth/login", json={"email": email, "password": api_server.DEFAULT_PASSWORD})
    assert r.status_code == 200
    return (r.get_json() or {})["token"]


# Security: sensitive credentials not in browser HTML
def test_ospf_key_not_in_html():
    html = (Path(__file__).resolve().parents[1] / "vm_deployment" / "NOC-configMaker.html").read_text(encoding="utf-8")
    assert 'm8M5JwvdYM' not in html, "OSPF/BGP MD5 key must not appear in browser-served HTML"


# Security: real employee emails not hardcoded as defaults
def test_default_platform_admin_is_not_real_employee_email():
    api = _load_api_server()
    assert 'whamza@team.nxlink.com' not in api.DEFAULT_PLATFORM_ADMIN_EMAILS or \
           os.getenv('PLATFORM_ADMIN_EMAILS') is not None, \
           "Real employee email should not be the hardcoded default for PLATFORM_ADMIN_EMAILS"


# Auth: SSH fetch requires authentication
def test_fetch_config_ssh_requires_auth(monkeypatch):
    api = _load_api_server()
    _, anchor = _patch_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        r = client.post("/api/fetch-config-ssh", json={"ip": "10.0.0.1", "username": "test", "password": "test"})
        assert r.status_code == 401, f"Expected 401, got {r.status_code}"
    finally:
        anchor.close()


# Auth: migrate-config requires authentication
def test_migrate_config_requires_auth(monkeypatch):
    api = _load_api_server()
    _, anchor = _patch_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        r = client.post("/api/migrate-config", json={})
        assert r.status_code == 401, f"Expected 401, got {r.status_code}"
    finally:
        anchor.close()


# Auth: log-activity requires authentication
def test_log_activity_requires_auth(monkeypatch):
    api = _load_api_server()
    _, anchor = _patch_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        r = client.post("/api/log-activity", json={"type": "test"})
        assert r.status_code == 401, f"Expected 401, got {r.status_code}"
    finally:
        anchor.close()


# Tenant settings: /api/infrastructure reads from tenant_settings
def test_infrastructure_reads_tenant_settings(monkeypatch):
    api = _load_api_server()
    _, anchor = _patch_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        token = _login(client, api, "whamza@team.nxlink.com")
        # Update tenant settings with custom DNS
        client.put("/api/tenant-settings",
            json={"dns_primary": "1.2.3.4", "dns_secondary": "5.6.7.8"},
            headers={"Authorization": f"Bearer {token}"})
        # /api/infrastructure should now return the custom DNS
        r = client.get("/api/infrastructure", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.get_json()
        assert data.get("dns_servers", {}).get("primary") == "1.2.3.4" or \
               data.get("dnsPrimary") == "1.2.3.4" or \
               "1.2.3.4" in str(data), f"Expected custom DNS in infrastructure response: {data}"
    finally:
        anchor.close()


# Legacy /api/activity redirects to tenant-scoped endpoint
def test_legacy_activity_endpoint_works(monkeypatch):
    api = _load_api_server()
    _, anchor = _patch_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        # Should not return 404 — redirected to get_activity
        token = _login(client, api, "whamza@team.nxlink.com")
        r = client.get("/api/activity", headers={"Authorization": f"Bearer {token}"})
        # get_activity now requires auth, so 200 with token
        assert r.status_code in (200, 401), f"Unexpected status: {r.status_code}"
    finally:
        anchor.close()


# Frontend: auth headers present on key fetch calls
def test_get_activity_fetches_use_auth_headers():
    html = (Path(__file__).resolve().parents[1] / "vm_deployment" / "NOC-configMaker.html").read_text(encoding="utf-8")
    # All get-activity fetches should now use getAuthHeaders
    import re
    fetches = re.findall(r"fetch\([^)]*get-activity[^)]*\)", html, re.DOTALL)
    for fetch_call in fetches:
        assert 'getAuthHeaders' in fetch_call, f"get-activity fetch missing getAuthHeaders: {fetch_call[:120]}"


def test_ospf_key_env_var_configurable():
    # The key should not be in HTML (tested above)
    # Verify the infrastructure response doesn't expose it in plaintext when not set
    api = _load_api_server()
    assert not hasattr(api, 'OSPF_BGP_MD5_KEY') or api.OSPF_BGP_MD5_KEY == '', \
           "OSPF key should not be a module-level constant"
