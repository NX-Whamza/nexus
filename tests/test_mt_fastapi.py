#!/usr/bin/env python3
"""FastAPI regression tests for MikroTik tower/BNG2 generation."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient


repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root / "vm_deployment"))

# Keep tests deterministic when env is sparse in local/dev CI.
os.environ.setdefault("NEXTLINK_RADIUS_SECRET", "TEST_RADIUS_SECRET")

from fastapi_server import app  # noqa: E402
import api_server as _api_server  # noqa: E402


client = TestClient(app)


def _fastapi_auth_headers() -> dict:
    """Obtain a valid JWT via the Flask login endpoint and return auth headers."""
    admin_email = os.getenv("PLATFORM_ADMIN_EMAILS", "whamza@team.nxlink.com").split(",")[0].strip()
    r = client.post(
        "/api/auth/login",
        json={"email": admin_email, "password": _api_server.DEFAULT_PASSWORD},
    )
    token = (r.json() or {}).get("token")
    return {"Authorization": f"Bearer {token}"} if token else {}


def _gitlab_compliance_configured() -> bool:
    return bool(os.getenv("GITLAB_COMPLIANCE_TOKEN")) and bool(os.getenv("GITLAB_COMPLIANCE_PROJECT_ID"))


def _tower_payload() -> dict:
    return {
        "router_type": "MT2004",
        "tower_name": "WALLYWEST-CN-1",
        "loopback_subnet": "10.25.0.46/32",
        "cpe_subnet": "10.45.40.0/22",
        "unauth_subnet": "10.145.40.0/22",
        "cgn_priv": "100.64.112.0/22",
        "cgn_pub": "143.55.44.107",
        "latitude": "32.7699508667",
        "longitude": "-98.0892105103",
        "state_code": "TX",
        "asn": "26077",
        "peer_1_name": "CR7",
        "peer_1_address": "10.2.0.107/32",
        "peer_2_name": "CR8",
        "peer_2_address": "10.2.0.108/32",
        "switches": [
            {"name": "Switch1", "port": "sfp-sfpplus1", "comment": "Switch Uplink #1"},
            {"name": "Switch2", "port": "sfp-sfpplus2", "comment": "Switch Uplink #2"},
        ],
        "backhauls": [
            {"name": "HOGHILL", "subnet": "10.36.3.56/30", "port": "sfp-sfpplus4", "bandwidth": "10000", "master": True},
            {"name": "JACK-CN-1", "subnet": "10.45.67.0/29", "port": "sfp-sfpplus5", "bandwidth": "10000", "master": False},
        ],
        "apply_compliance": False,
    }


def _bng2_payload() -> dict:
    return {
        "router_type": "MT2004",
        "tower_name": "WALLY-BNG2-CN-1",
        "loop_ip": "10.248.86.11/32",
        "gateway": "10.248.249.9/29",
        "switch_ip": "10.248.249.16/29",
        "latitude": "39.7696990967",
        "longitude": "-99.3080825806",
        "state_code": "KS",
        "ospf_area": "248",
        "bng_1_ip": "10.249.0.200",
        "bng_2_ip": "10.249.0.201",
        "vlan_1000_cisco": "1248",
        "vlan_2000_cisco": "2248",
        "vlan_3000_cisco": "3248",
        "vlan_4000_cisco": "4248",
        "mpls_mtu": "9000",
        "vpls_l2_mtu": "1580",
        "backhauls": [
            {"name": "KS-GLADE-NO-1", "subnet": "10.248.90.248/29", "master": True, "port": "sfp-sfpplus4"},
        ],
        "is_switchless": False,
        "is_lte": False,
        "is_tarana": False,
        "is_326": False,
        "apply_compliance": False,
    }


def test_tower_config_contains_required_routing_blocks():
    r = client.post("/api/mt/tower/config", json=_tower_payload())
    assert r.status_code == 200
    text = r.json()
    assert isinstance(text, str)
    assert "/routing ospf instance" in text
    assert "/routing bgp connection" in text
    assert "/interface bridge port" in text
    assert "/ip pool" in text
    assert "/ip dhcp-server" in text
    assert "/ip dhcp-server network" in text
    assert "address-pool=cust" in text
    assert "vlan2000-sfp-sfpplus1" in text


def test_tower_compliance_requires_gitlab_configuration():
    if not _gitlab_compliance_configured():
        return
    payload = _tower_payload()
    payload["apply_compliance"] = True
    r = client.post("/api/mt/tower/config", json=payload)
    assert r.status_code == 200
    text = r.json()
    assert text.count("# ENGINEERING-COMPLIANCE-APPLIED") == 1


def test_bng2_config_is_not_tower_and_contains_vpls():
    r = client.post("/api/mt/bng2/config", json=_bng2_payload())
    assert r.status_code == 200
    text = r.json()
    assert isinstance(text, str)
    assert "/interface vpls" in text
    assert "vpls1000-bng1" in text
    assert "name=bridge1000" in text
    assert "lan-bridge" not in text
    assert "nat-public-bridge" not in text


def test_tower_policy_violation_returns_422():
    payload = _tower_payload()
    payload["is_tarana"] = True
    payload["tarana_subnet"] = "10.248.249.8/29"
    payload["tarana_sector_count"] = 3
    payload["tarana_sector_start"] = 0
    payload["backhauls"][0]["port"] = "sfp-sfpplus6"  # Reserved by Tarana policy.
    r = client.post("/api/mt/tower/config", json=payload)
    assert r.status_code == 422
    detail = r.json().get("detail", "")
    assert "policy violation" in detail.lower() or "reserved" in detail.lower()


def test_tower_custom_tarana_ports_reserve_matching_backhaul_ports():
    payload = _tower_payload()
    payload["is_tarana"] = True
    payload["tarana_subnet"] = "10.248.249.8/29"
    payload["tarana_sector_count"] = 3
    payload["tarana_sector_start"] = 0
    payload["tarana_sectors"] = [
        {"name": "Alpha", "port": "sfp-sfpplus10"},
        {"name": "Beta", "port": "sfp-sfpplus11"},
        {"name": "Gamma", "port": "sfp-sfpplus12"},
    ]
    payload["backhauls"][0]["port"] = "sfp-sfpplus10"
    r = client.post("/api/mt/tower/config", json=payload)
    assert r.status_code == 422
    detail = r.json().get("detail", "")
    assert "policy violation" in detail.lower() or "reserved" in detail.lower()


def test_ido_proxy_blocks_site_checker_paths():
    caps = client.get("/api/ido/capabilities")
    assert caps.status_code == 200
    allowed = caps.json().get("allowed_prefixes", [])
    assert "/api/7250config/" in allowed

    r = client.get("/api/ido/proxy/api/sites/list")
    assert r.status_code == 503 or r.status_code == 403
    if r.status_code == 403:
        detail = r.json().get("detail", "")
        assert "not allowed" in detail.lower()


def test_compliance_blocks_endpoint_returns_blocks_without_gitlab():
    r = client.get("/api/compliance/blocks", params={"loopback_ip": "10.5.0.1/32"})
    assert r.status_code == 200
    data = r.json()
    assert data.get("success") is True
    assert data.get("source") in {"gitlab", "bundled-local"}
    blocks = data.get("blocks", {})
    assert isinstance(blocks, dict)
    assert len(blocks) > 5
    assert "ip_services" in blocks
    assert "dns" in blocks
    assert "snmp" in blocks


def test_apply_compliance_endpoint_uses_available_compliance_blocks():
    config = "\n".join(
        [
            "# jan/01/1970 00:00:12 by RouterOS 7.16.1",
            "/system identity",
            'set name="TEST-CN-1"',
            "/interface bridge",
            "add name=bridge1",
            "/routing ospf instance",
            "add name=default-v2 router-id=10.248.86.11",
            "/interface vpls",
            "add disabled=no l2mtu=1500 mac-address=02:AA:BB:CC:DD:EE name=vpls1000-bng1 remote-peer=10.249.0.200 vpls-id=1000:1",
        ]
    )
    headers = _fastapi_auth_headers()
    r = client.post("/api/apply-compliance", json={"config": config, "loopback_ip": "10.248.86.11/32"}, headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body.get("success") is True
    text = body.get("config", "")
    assert isinstance(text, str)
    assert 'set name="TEST-CN-1"' in text
    assert "vpls1000-bng1" in text
    assert "142.147.112.3" in text
    assert "ntp-pool.nxlink.com" in text
    assert "list=managerIP" in text


def test_bng2_custom_tarana_ports_are_rendered_from_flat_fields():
    payload = _bng2_payload()
    payload.update(
        {
            "is_tarana": True,
            "tarana_subnet": "10.248.249.8/29",
            "tarana_sector_count": 3,
            "tarana_sector_start": 0,
            "tarana_bng2_alphaPort": "sfp-sfpplus8",
            "tarana_bng2_betaPort": "sfp-sfpplus9",
            "tarana_bng2_gammaPort": "sfp-sfpplus10",
        }
    )
    r = client.post("/api/mt/bng2/config", json=payload)
    assert r.status_code == 200
    text = r.json()
    assert 'default-name=sfp-sfpplus8' in text
    assert 'default-name=sfp-sfpplus9' in text
    assert 'default-name=sfp-sfpplus10' in text
    assert 'default-name=sfp-sfpplus11' not in text


def test_tarana_validation_corrects_quoted_bridge3000_network_fields():
    config = """/interface bridge
add comment="UNICORN MGMT" name=bridge3000
add comment=STATIC name=bridge2000
/interface ethernet
set [ find default-name=sfp-sfpplus8 ] comment="Alpha"
/interface vlan
add interface=sfp-sfpplus8 name=vlan1000-sfp-sfpplus8 vlan-id=1000
add interface=sfp-sfpplus8 name=vlan2000-sfp-sfpplus8 vlan-id=2000
add interface=sfp-sfpplus8 name=vlan3000-sfp-sfpplus8 vlan-id=3000
/interface bridge port
add bridge=bridge3000 ingress-filtering=no interface=vlan3000-sfp-sfpplus8
add bridge=lan-bridge ingress-filtering=no interface=vlan1000-sfp-sfpplus8
add bridge=bridge2000 ingress-filtering=no interface=vlan2000-sfp-sfpplus8
/ip address
add address=10.246.2.25/29 comment="UNICORN MGMT" interface=bridge3000 network=10.246.2.25
/routing ospf interface-template add interfaces=bridge3000 cost=10 priority=1 area=backbone type=broadcast comment="UNICORN MGMT" network=10.246.2.25/29
"""
    headers = _fastapi_auth_headers()
    r = client.post(
        "/api/gen-tarana-config",
        json={"config": config, "device": "ccr2004", "routeros_version": "7.19.4"},
        headers=headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body.get("success") is True
    corrected = body.get("config", "")
    assert 'interface=bridge3000 network=10.246.2.24' in corrected
    assert 'network=10.246.2.24/29' in corrected


def test_bng2_switch_uplink_generates_vlan_interfaces_on_correct_bridges():
    """Switch uplinks must get VLAN 1000/2000/3000/4000 tagged interfaces mapped to their bridges."""
    payload = _bng2_payload()
    payload["switches"] = [{"name": "Switch-1", "port": "sfp-sfpplus1", "comment": "SW-UPLINK"}]
    r = client.post("/api/mt/bng2/config", json=payload)
    assert r.status_code == 200
    text = r.json()
    # VLAN interfaces must exist on the switch port
    assert "vlan1000-sfp-sfpplus1" in text
    assert "vlan2000-sfp-sfpplus1" in text
    assert "vlan3000-sfp-sfpplus1" in text
    assert "vlan4000-sfp-sfpplus1" in text
    # Each VLAN interface must be added to its respective bridge
    assert "bridge=bridge1000" in text and "interface=vlan1000-sfp-sfpplus1" in text
    assert "bridge=bridge2000" in text and "interface=vlan2000-sfp-sfpplus1" in text
    assert "bridge=bridge3000" in text and "interface=vlan3000-sfp-sfpplus1" in text
    assert "bridge=bridge4000" in text and "interface=vlan4000-sfp-sfpplus1" in text
    # Switch port must NOT be added raw to vpls-bridge
    assert "bridge=vpls-bridge ingress-filtering=no interface=sfp-sfpplus1" not in text


def test_bng2_ldp_interface_entries_generated_for_each_backhaul():
    """Each backhaul port must have an explicit /mpls ldp interface entry."""
    payload = _bng2_payload()
    payload["backhauls"] = [
        {"name": "KS-GLADE-NO-1", "subnet": "10.248.90.248/29", "master": True, "port": "sfp-sfpplus4"},
        {"name": "KS-GLADE-NO-2", "subnet": "10.248.90.240/29", "master": False, "port": "sfp-sfpplus5"},
    ]
    r = client.post("/api/mt/bng2/config", json=payload)
    assert r.status_code == 200
    text = r.json()
    assert "/mpls ldp interface" in text
    assert "interface=sfp-sfpplus4" in text
    assert "interface=sfp-sfpplus5" in text
