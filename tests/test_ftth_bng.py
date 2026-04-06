#!/usr/bin/env python3
"""Tests for FTTH BNG generator endpoint."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))

os.environ["NOC_CONFIGMAKER_TESTS"] = "1"
os.environ["AI_PROVIDER"] = "none"

import api_server  # noqa: WPS433

app = api_server.app
app.config["TESTING"] = True
client = app.test_client()


def _auth_headers():
    admin_email = os.getenv("PLATFORM_ADMIN_EMAILS", "whamza@team.nxlink.com").split(",")[0].strip()
    r = client.post("/api/auth/login", json={"email": admin_email, "password": api_server.DEFAULT_PASSWORD})
    token = (r.get_json() or {}).get("token", "")
    return {"Authorization": f"Bearer {token}"}


def test_gen_ftth_bng_basic():
    payload = {
        "device": "ccr2004",
        "target_version": "7.19.4",
        "loopback_ip": "10.13.100.5/32",
        "cpe_cidr": "192.0.2.0/22",
        "cgnat_cidr": "100.64.0.0/22",
        "olt_cidr": "198.51.100.8/29",
        "olt_port": "sfp-sfpplus1",
        "olt_port_speed": "10g",
        "identity": "RTR-FTTH-EXAMPLE"
    }

    r = client.post("/api/gen-ftth-bng", data=json.dumps(payload), content_type="application/json", headers=_auth_headers())
    assert r.status_code == 200
    data = r.get_json() or {}
    assert data.get("success") is True
    cfg = data.get("config", "")

    # FTTH generator is fixed to CCR2216 - assert device and identity are updated accordingly
    assert data.get('device') == 'CCR2216'
    assert "RTR-CCR2216" in cfg or "RTR-FTTH-EXAMPLE" in cfg
    assert "bridge3000" in cfg
    assert "OLT-GW" in cfg
    assert "FTTH-CPE-NAT" in cfg
    assert "add name=cpe_pool" in cfg
    # OLT speed should be represented in the interface comment
    assert "OLT-speed:10g" in cfg


if __name__ == "__main__":
    tests = [test_gen_ftth_bng_basic]
    ok = True
    for t in tests:
        try:
            t()
            print(f"[OK] {t.__name__}")
        except Exception as e:
            print(f"[FAIL] {t.__name__}: {e}")
            ok = False
    raise SystemExit(0 if ok else 1)
