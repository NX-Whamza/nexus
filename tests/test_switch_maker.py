from __future__ import annotations

import json
import os
import sys
from pathlib import Path


repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))
os.environ.setdefault("AI_PROVIDER", "none")
os.environ.setdefault("NOC_CONFIGMAKER_TESTS", "1")

import api_server  # noqa: E402


app = api_server.app
app.config["TESTING"] = True


def _auth_headers(client):
    admin_email = os.getenv("PLATFORM_ADMIN_EMAILS", "whamza@team.nxlink.com").split(",")[0].strip()
    r = client.post("/api/auth/login", json={"email": admin_email, "password": api_server.DEFAULT_PASSWORD})
    token = (r.get_json() or {}).get("token", "")
    return {"Authorization": f"Bearer {token}"}


def test_generate_mt_switch_config_for_2004_no_bng():
    client = app.test_client()
    payload = {
        "switch_type": "2004",
        "profile": "no_bng",
        "routeros": "7.19.4",
        "switch_name": "SWT-CCR2004-1.TX-MARLIN-W-FC-2",
        "gps": "31.306,-96.898",
        "management_ip": "10.246.48.194/27",
        "gateway": "10.246.48.193",
        "uplink1": "sfp28-1",
        "state_scope": "instate",
        "apply_compliance": False,
        "ports": [
            {"port": "sfp-sfpplus1", "comment": "AP1 Cambium 6ghz"},
            {"port": "sfp-sfpplus2", "comment": "AP2 Cambium 6ghz"},
        ],
    }
    response = client.post(
        "/api/generate-mt-switch-config",
        data=json.dumps(payload),
        content_type="application/json",
        headers=_auth_headers(client),
    )
    assert response.status_code == 200
    data = response.get_json() or {}
    assert data.get("success") is True
    config = data.get("config") or ""
    assert "SWITCH PROFILE: CCR2004 NO BNG" in config
    assert "region-name=TX-MSTP" in config
    assert "gateway=10.246.48.193" in config
    assert "comment=\"AP1 Cambium 6ghz\"" in config
    assert "sfp28-1" in config


def test_generate_mt_switch_config_for_crs326_requires_bonded_uplinks():
    client = app.test_client()
    payload = {
        "switch_type": "326",
        "profile": "crs326",
        "routeros": "7.19.4",
        "switch_name": "SWT-CRS326-1.NE-ARLINGTON-NW-1",
        "gps": "41.459229, -96.36953",
        "management_ip": "10.249.168.43/20",
        "gateway": "10.249.160.1",
        "uplink1": "sfp-sfpplus23",
        "uplink2": "sfp-sfpplus24",
        "state_scope": "outstate",
        "apply_compliance": False,
        "ports": [
            {"port": "sfp-sfpplus10", "comment": "Tarana Alpha"},
            {"port": "sfp-sfpplus14", "comment": "FTTH site host"},
        ],
    }
    response = client.post(
        "/api/generate-mt-switch-config",
        data=json.dumps(payload),
        content_type="application/json",
        headers=_auth_headers(client),
    )
    assert response.status_code == 200
    data = response.get_json() or {}
    config = data.get("config") or ""
    assert "/interface bonding add lacp-user-key=1 mode=802.3ad name=bonding1 slaves=sfp-sfpplus23,sfp-sfpplus24" in config
    assert "comment=\"Tarana Alpha\"" in config
    assert "comment=\"FTTH site host\" auto-negotiation=no speed=1G-baseX" in config
    assert "/system identity set name=SWT-CRS326-1.NE-ARLINGTON-NW-1" in config
