#!/usr/bin/env python3
"""Tests for FTTH preview API endpoint."""

from __future__ import annotations

import json
import os
import sys
from contextlib import contextmanager
from pathlib import Path

repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))

os.environ["NOC_CONFIGMAKER_TESTS"] = "1"

import api_server  # noqa: WPS433

app = api_server.app
app.config["TESTING"] = True
client = app.test_client()
BACKEND_MODULE = sys.modules.get("_noc_configmaker_vm_api_server", api_server)


def _auth_headers():
    admin_email = os.getenv("PLATFORM_ADMIN_EMAILS", "whamza@team.nxlink.com").split(",")[0].strip()
    r = client.post("/api/auth/login", json={"email": admin_email, "password": api_server.DEFAULT_PASSWORD})
    token = (r.get_json() or {}).get("token", "")
    return {"Authorization": f"Bearer {token}"}

MOCK_GITLAB_COMPLIANCE = (
    "/ip dns\n"
    "set allow-remote-requests=yes servers=142.147.112.3,142.147.112.19\n"
    "/ip firewall address-list\n"
    "add address=142.147.112.3 list=managerIP\n"
    "/system ntp client\n"
    "set enabled=yes\n"
)


@contextmanager
def _mock_gitlab_compliance(raw_text: str | None):
    original = BACKEND_MODULE._get_raw_gitlab_compliance_text
    BACKEND_MODULE._get_raw_gitlab_compliance_text = lambda loopback_ip='10.0.0.1': raw_text
    try:
        yield
    finally:
        BACKEND_MODULE._get_raw_gitlab_compliance_text = original


def test_preview_ftth_bng_basic():
    payload = {
        "loopback_ip": "10.13.100.5/32",
        "cpe_cidr": "192.0.2.0/22",
        "cgnat_cidr": "100.64.0.0/22",
        "olt_cidr": "198.51.100.8/29",
    }

    r = client.post("/api/preview-ftth-bng", data=json.dumps(payload), content_type="application/json", headers=_auth_headers())
    assert r.status_code == 200
    data = r.get_json() or {}
    assert data.get("success") is True
    p = data.get("preview") or {}
    assert "loopback" in p
    assert "olt" in p and "network" in p["olt"]
    assert "cpe" in p and "network" in p["cpe"]
    assert "cgnat" in p and "network" in p["cgnat"]


def test_generate_ftth_fiber_customer_with_compliance():
    payload = {
        "routerboard": "ccr2004",
        "routeros": "7.19.4",
        "provider": "ATT",
        "port": "sfp-sfpplus1",
        "address": "10.42.10.2/30",
        "network": "10.42.10.0/30",
        "loopback_ip": "10.26.0.7/32",
        "vlan_mode": "tagged",
        "vlan_id": "300",
        "apply_compliance": True,
    }

    with _mock_gitlab_compliance(MOCK_GITLAB_COMPLIANCE):
        r = client.post("/api/generate-ftth-fiber-customer", data=json.dumps(payload), content_type="application/json", headers=_auth_headers())
    assert r.status_code == 200
    data = r.get_json() or {}
    assert data.get("success") is True
    assert data.get("selected_port") == "sfp-sfpplus1"
    assert data.get("compliance_source") == "gitlab-verbatim"
    text = data.get("config", "")
    assert '/routing ospf area' in text
    assert 'comment="ATT VLAN 300"' in text
    assert 'add interface="sfp-sfpplus1" name="VLAN 300" vlan-id="300"' in text
    assert "142.147.112.3" in text


def test_generate_ftth_fiber_customer_requires_loopback_when_compliance_enabled():
    payload = {
        "routerboard": "ccr2004",
        "routeros": "7.19.4",
        "provider": "ATT",
        "address": "10.42.10.2/30",
        "network": "10.42.10.0/30",
        "vlan_mode": "none",
        "apply_compliance": True,
    }

    r = client.post("/api/generate-ftth-fiber-customer", data=json.dumps(payload), content_type="application/json", headers=_auth_headers())
    assert r.status_code == 400
    data = r.get_json() or {}
    assert "loopback_ip" in (data.get("error") or "")


def test_generate_ftth_fiber_customer_requires_gitlab_compliance_when_enabled():
    payload = {
        "routerboard": "ccr2004",
        "routeros": "7.19.4",
        "provider": "ATT",
        "port": "sfp-sfpplus1",
        "address": "10.42.10.2/30",
        "network": "10.42.10.0/30",
        "loopback_ip": "10.26.0.7/32",
        "vlan_mode": "none",
        "apply_compliance": True,
    }

    with _mock_gitlab_compliance(None):
        r = client.post("/api/generate-ftth-fiber-customer", data=json.dumps(payload), content_type="application/json", headers=_auth_headers())
    assert r.status_code == 503
    data = r.get_json() or {}
    assert "GitLab compliance script is required" in (data.get("error") or "")


def test_generate_ftth_fiber_site_bundle():
    payload = {
        "tower_name": "TX-MARLIN-W-FC-2",
        "tower_gps": "30.1,-96.1",
        "asn": "26077",
        "routeros_1072": "7.19.4",
        "loopback_1072": "10.26.0.7/32",
        "loopback_1036": "10.26.0.8/32",
        "bh1_subnet": "10.25.10.0/29",
        "link_1072_1036_a": "10.25.10.8/30",
        "link_1072_1036_b": "10.25.10.12/30",
        "cpe_subnet": "10.40.0.0/22",
        "unauth_subnet": "10.130.0.0/22",
        "cgn_priv_subnet": "100.64.0.0/22",
        "cgn_pub_ip": "132.147.184.147/32",
        "fiber_provider": "ATT",
        "fiber_port": "sfp-sfpplus8",
        "fiber_port_ip": "10.42.10.2/30",
        "fiber_vlan_mode": "tagged",
        "fiber_vlan_id": "300",
        "peer1_name": "CR7",
        "peer1_ip": "10.2.0.107",
        "peer2_name": "CR8",
        "peer2_ip": "10.2.0.108",
        "apply_compliance": True,
        "backhauls": [
            {"port": "3", "name": "BH-TO-SITE-A", "subnet": "10.25.10.16/29", "master": "yes", "bandwidth": "1G"}
        ],
    }
    with _mock_gitlab_compliance(MOCK_GITLAB_COMPLIANCE):
        r = client.post("/api/generate-ftth-fiber-site", data=json.dumps(payload), content_type="application/json", headers=_auth_headers())
    assert r.status_code == 200
    body = r.get_json() or {}
    assert body.get("success") is True
    assert "RTR-MTCCR1072-1.TX-MARLIN-W-FC-2" in body.get("router_1072_config", "")
    assert "RTR-MTCCR1036-1.TX-MARLIN-W-FC-2" in body.get("router_1036_config", "")
    assert "BH-TO-SITE-A" in body.get("port_map", "")
    assert body.get("compliance_source") == "gitlab-verbatim"


def test_generate_ftth_isd_fiber_bundle():
    payload = {
        "router_type": "2004",
        "routeros": "7.19.4",
        "tower_name": "TX-MARLIN-W-FC-2",
        "tower_gps": "30.1,-96.1",
        "loopback_subnet": "10.26.0.7/32",
        "bh1_subnet": "10.25.10.0/29",
        "private_ip": "10.50.0.0/24",
        "public_ip": "198.51.100.0/29",
        "fiber_provider": "ATT",
        "fiber_port": "sfp-sfpplus1",
        "fiber_port_ip": "10.42.10.2/30",
        "has_vlan": True,
        "fiber_vlan_num": "300",
        "apply_compliance": True,
        "backhauls": [
            {"port": "4", "name": "BH-TO-SITE-B", "subnet": "10.25.10.24/29", "master": "no", "bandwidth": "1G"}
        ],
    }
    with _mock_gitlab_compliance(MOCK_GITLAB_COMPLIANCE):
        r = client.post("/api/generate-ftth-isd-fiber", data=json.dumps(payload), content_type="application/json", headers=_auth_headers())
    assert r.status_code == 200
    body = r.get_json() or {}
    assert body.get("success") is True
    assert "RTR-MTCCR2004-1.TX-MARLIN-W-FC-2" in body.get("config", "")
    assert "BH-TO-SITE-B" in body.get("port_map", "")
    assert body.get("compliance_source") == "gitlab-verbatim"


if __name__ == "__main__":
    tests = [
        test_preview_ftth_bng_basic,
        test_generate_ftth_fiber_customer_with_compliance,
        test_generate_ftth_fiber_customer_requires_loopback_when_compliance_enabled,
        test_generate_ftth_fiber_site_bundle,
        test_generate_ftth_isd_fiber_bundle,
    ]
    ok = True
    for t in tests:
        try:
            t()
            print(f"[OK] {t.__name__}")
        except Exception as e:
            print(f"[FAIL] {t.__name__}: {e}")
            ok = False
    raise SystemExit(0 if ok else 1)
