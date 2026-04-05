from __future__ import annotations
import importlib, json, os, sqlite3, sys
from pathlib import Path


def _load_api_server():
    repo_root = Path(__file__).resolve().parents[1]
    for p in (str(repo_root), str(repo_root / "vm_deployment")):
        if p not in sys.path:
            sys.path.insert(0, p)
    return importlib.import_module("vm_deployment.api_server")


def _patch_dbs(monkeypatch, api_server):
    uri = "file:b10_users?mode=memory&cache=shared"
    anchor = sqlite3.connect(uri, uri=True)
    orig = sqlite3.connect
    orig_exists = os.path.exists
    monkeypatch.setattr(
        api_server.sqlite3, "connect",
        lambda p, *a, **k: orig(uri, uri=True, *a, **k) if str(p).endswith("users.db") else orig(p, *a, **k),
    )
    monkeypatch.setattr(
        api_server.os.path, "exists",
        lambda p: True if str(p) == "secure_data" else orig_exists(p),
    )
    monkeypatch.setattr(api_server.os, "makedirs", lambda *a, **k: None)
    return uri, anchor


def _login(client, api_server, email):
    r = client.post("/api/auth/login", json={"email": email, "password": api_server.DEFAULT_PASSWORD})
    assert r.status_code == 200, f"Login failed: {r.get_data(as_text=True)}"
    return (r.get_json() or {})["token"]


def test_nextlink_tenant_settings_have_cnm_urls(monkeypatch):
    api = _load_api_server()
    _, anchor = _patch_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        token = _login(client, api, "whamza@team.nxlink.com")
        r = client.get("/api/tenant-settings", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        s = r.get_json()["settings"]
        cnm_urls = json.loads(s.get("cambium_cnm_urls") or "[]")
        assert len(cnm_urls) > 0, "Nextlink should have CNM URLs seeded"
        assert any("nxlink" in u.get("url", "") for u in cnm_urls)
    finally:
        anchor.close()


def test_nextlink_compliance_fields_seeded(monkeypatch):
    api = _load_api_server()
    _, anchor = _patch_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        token = _login(client, api, "whamza@team.nxlink.com")
        r = client.get("/api/tenant-settings", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        s = r.get_json()["settings"]
        assert s.get("compliance_dns_primary") == "142.147.112.3"
        assert s.get("compliance_radius_primary") == "142.147.112.2"
        assert s.get("noc_monitor_ip") == "142.147.127.2"
        assert s.get("syslog_server") == "142.147.116.215"
    finally:
        anchor.close()


def test_compliance_checks_use_tenant_settings(monkeypatch):
    api = _load_api_server()
    _, anchor = _patch_dbs(monkeypatch, api)
    try:
        custom_ts = {
            "compliance_dns_primary": "10.0.0.1",
            "compliance_dns_secondary": "10.0.0.2",
            "compliance_ntp": "ntp.customcorp.com",
            "compliance_syslog": "10.0.0.3",
            "compliance_snmp_community": "CUSTOMpublic",
            "compliance_radius_primary": "10.0.0.4",
            "compliance_radius_secondary": "10.0.0.5",
        }
        checks = api._build_compliance_checks(custom_ts)
        check_patterns = [c["pattern"] for c in checks]
        assert "10.0.0.1" in check_patterns, "Custom DNS primary should be in checks"
        assert "10.0.0.4" in check_patterns, "Custom RADIUS should be in checks"
        assert "142.147.112.3" not in check_patterns, "Nextlink DNS should not appear for custom tenant"
    finally:
        anchor.close()


def test_infrastructure_endpoint_returns_new_fields(monkeypatch):
    api = _load_api_server()
    _, anchor = _patch_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        token = _login(client, api, "whamza@team.nxlink.com")
        r = client.get("/api/infrastructure", headers={"Authorization": f"Bearer {token}"})
        assert r.status_code == 200
        data = r.get_json()
        response_str = json.dumps(data)
        assert any(
            key in response_str
            for key in ["nocMonitorIp", "noc_monitor_ip", "ataProvisioningUrl", "cambiumCnmUrls"]
        ), f"Infrastructure response should include new tenant fields: {list(data.keys())}"
    finally:
        anchor.close()


def test_custom_tenant_compliance_checks_differ_from_nextlink(monkeypatch):
    api = _load_api_server()
    _, anchor = _patch_dbs(monkeypatch, api)
    try:
        nextlink_checks = api._build_compliance_checks(
            {
                "compliance_dns_primary": "142.147.112.3",
                "compliance_dns_secondary": "142.147.112.19",
            }
        )
        custom_checks = api._build_compliance_checks(
            {
                "compliance_dns_primary": "8.8.8.8",
                "compliance_dns_secondary": "8.8.4.4",
            }
        )
        nextlink_patterns = {c["pattern"] for c in nextlink_checks}
        custom_patterns = {c["pattern"] for c in custom_checks}
        assert "142.147.112.3" in nextlink_patterns
        assert "8.8.8.8" in custom_patterns
        assert "142.147.112.3" not in custom_patterns
    finally:
        anchor.close()


def test_html_uses_tenant_infra_variable_for_noc_monitor(monkeypatch):
    html = (
        Path(__file__).resolve().parents[1] / "vm_deployment" / "NOC-configMaker.html"
    ).read_text(encoding="utf-8")
    import re

    manager_ip_lines = re.findall(r"add address=.{0,80} list=managerIP", html)
    for line in manager_ip_lines:
        assert "142.147.127.2" not in line or "_tenantInfra" in line or "nocMonitorIp" in line, (
            f"managerIP config line should use tenant variable: {line}"
        )


def test_new_allowed_fields_accepted_by_update(monkeypatch):
    """Verify that new Batch 10 fields are accepted by the tenant settings PUT route."""
    api = _load_api_server()
    _, anchor = _patch_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        token = _login(client, api, "whamza@team.nxlink.com")
        payload = {
            "noc_monitor_ip": "10.1.2.3",
            "syslog_server": "10.1.2.4",
            "ata_provisioning_url": "http://example.com/cfg/$MA.cfg",
            "compliance_dns_primary": "10.10.10.1",
        }
        r = client.put(
            "/api/tenant-settings",
            json=payload,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        assert r.status_code == 200, f"PUT failed: {r.get_data(as_text=True)}"
        data = r.get_json()
        assert data.get("success") is True
        s = data.get("settings", {})
        assert s.get("noc_monitor_ip") == "10.1.2.3"
        assert s.get("compliance_dns_primary") == "10.10.10.1"
    finally:
        anchor.close()
