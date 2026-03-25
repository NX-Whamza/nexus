#!/usr/bin/env python3
"""UI-to-backend contract tests for FTTH BNG generation."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient


repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root / "vm_deployment"))

os.environ.setdefault("NOC_CONFIGMAKER_TESTS", "1")

from fastapi_server import app  # noqa: E402


client = TestClient(app)


def _ui_payload(deployment_type: str) -> dict:
    return {
        "deployment_type": deployment_type,
        "router_identity": "RTR-MT2216-AR1.NE-WESTERN-WE-1",
        "location": "41.8500,-103.6600",
        "routeros_version": "7.19.4",
        "loopback_ip": "10.249.7.137/32",
        "cpe_network": "10.249.96.0/22",
        "cgnat_private": "100.64.96.0/22",
        "cgnat_public": "143.55.44.107",
        "unauth_network": "10.149.96.0/22",
        "olt_network": "10.249.180.0/29",
        "olt_network_secondary": "",
        "olt_network_100g": "",
        "olt_name_primary": "NE-WESTERN-MF2-1",
        "olt_name_secondary": "",
        "olt_name_100g": "",
        "uplinks": [
            {
                "port": "sfp28-3",
                "type": "routed",
                "ip": "10.249.79.178/30",
                "speed": "10G-baseSR-LR",
                "comment": "NE-WESTERN-EA-1",
                "cost": "10",
                "mtu": "9198",
                "l2mtu": "9212",
                "auto_negotiation": False,
            }
        ],
        "olt_ports": [
            {"port": "sfp28-6", "speed": "10G-baseSR-LR", "comment": "NOKIA OLT", "group": "1"},
            {"port": "sfp28-7", "speed": "10G-baseSR-LR", "comment": "NOKIA OLT", "group": "1"},
            {"port": "sfp28-8", "speed": "10G-baseSR-LR", "comment": "NOKIA OLT", "group": "1"},
            {"port": "sfp28-10", "speed": "10G-baseSR-LR", "comment": "NOKIA OLT", "group": "1"},
        ],
    }


def test_ftth_ui_contract_outstate_renders_nebraska_style_blocks():
    response = client.post("/api/generate-ftth-bng", json=_ui_payload("outstate"))
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("success") is True
    config = payload.get("config", "")

    assert "add comment=DYNAMIC name=bridge1000" in config
    assert "add comment=STATIC name=bridge2000" in config
    assert "/interface vpls" in config
    assert "/routing bgp template" in config
    assert "/routing bgp connection" in config
    assert "name=vpls1000-bng1" in config
    assert "cisco-static-id=1249" in config
    assert "# ENGINEERING-COMPLIANCE-APPLIED" in config
    assert "name=CR7" in config
    assert "name=CR8" in config
    assert "output.network=bgp-networks" in config
    assert "WALLED-GARDEN" in config
    assert 'dst-address-list=!WALLED-GARDEN src-address-list=unauth' in config
    assert "EOIP-ALLOW" in config
    assert "managerIP" in config

    # Outstate remains transport-focused: no DHCP servers or pools.
    assert "/ip dhcp-server\n" not in config
    assert "/ip pool" not in config


def test_ftth_ui_contract_instate_keeps_standard_bridge_layout():
    response = client.post("/api/generate-ftth-bng", json=_ui_payload("instate"))
    assert response.status_code == 200
    payload = response.json()
    assert payload.get("success") is True
    config = payload.get("config", "")

    assert "add name=bridge1000" in config
    assert "add comment=DYNAMIC name=bridge1000" not in config
    assert "name=vpls1000-bng1" not in config
    assert "/routing bgp template" in config
    assert "/routing bgp connection" in config
    assert "name=CR7" in config
    assert "name=CR8" in config
    assert "/ip dhcp-server option" in config
    assert "add code=43 name=opt43 value=0x012d68747470733a2f2f6e61342e6e6f6b69616163732e6e6f6b69612e636f6d3a31373534372f6e6578746c696e6b020561646d696e030561646d696e" in config
    assert "/ip dhcp-server option sets" in config
    assert "add name=optset options=opt43" in config
    assert "/ip dhcp-server" in config
    assert "add address-pool=cust dhcp-option-set=optset interface=bridge1000 lease-time=10m name=server1 use-radius=yes" in config
    assert "/ip dhcp-server network" in config
    assert "add address=10.249.96.0/22 dns-server=142.147.112.3,142.147.112.19 gateway=10.249.96.1 netmask=22" in config
    assert "add address=10.149.96.0/22 dns-server=142.147.112.3,142.147.112.19 gateway=10.149.96.1 netmask=22" in config
    assert "add address=100.64.96.0/22 dhcp-option-set=optset dns-server=142.147.112.3,142.147.112.19 gateway=100.64.96.1 netmask=22" in config


def test_ftth_outstate_allows_missing_ftth_pool_fields():
    payload = _ui_payload("outstate")
    payload["cpe_network"] = ""
    payload["cgnat_private"] = ""
    payload["cgnat_public"] = ""
    payload["unauth_network"] = ""

    response = client.post("/api/generate-ftth-bng", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data.get("success") is True
    config = data.get("config", "")
    assert "name=vpls1000-bng1" in config


def test_ftth_outstate_state_profile_ia_maps_ospf_and_vpls_ids():
    payload = _ui_payload("outstate")
    payload["state_code"] = "IA"
    payload["ospf_area"] = "42"
    payload["ospf_area_id"] = "0.0.0.42"
    payload["vpls_state_id"] = "245"

    response = client.post("/api/generate-ftth-bng", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data.get("success") is True
    config = data.get("config", "")
    assert "cisco-static-id=1245" in config
    assert "cisco-static-id=2245" in config
    assert "/routing ospf area" in config
    assert "area-id=0.0.0.42" in config
    assert "name=area42" in config

def test_ftth_auto_speed_renders_auto_negotiation_yes_without_speed():
    payload = _ui_payload("outstate")
    payload["uplinks"][0]["speed"] = "auto"
    payload["uplinks"][0]["auto_negotiation"] = False
    payload["olt_ports"][0]["speed"] = "auto"
    payload["olt_ports"][1]["speed"] = "25G-baseSR-LR"

    response = client.post("/api/generate-ftth-bng", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data.get("success") is True
    config = data.get("config", "")

    assert "set [ find default-name=sfp28-3 ] comment=NE-WESTERN-EA-1 l2mtu=9212 mtu=9198 auto-negotiation=yes" in config
    assert "set [ find default-name=sfp28-3 ] comment=NE-WESTERN-EA-1 l2mtu=9212 mtu=9198 auto-negotiation=no" not in config
    assert "set [ find default-name=sfp28-6 ] comment=\"NOKIA OLT\" auto-negotiation=yes" in config
    assert "set [ find default-name=sfp28-6 ] comment=\"NOKIA OLT\" auto-negotiation=no" not in config
    assert "set [ find default-name=sfp28-7 ] comment=\"NOKIA OLT\" auto-negotiation=no speed=25G-baseSR-LR" in config


def test_ftth_forced_speed_keeps_auto_negotiation_no_with_speed():
    payload = _ui_payload("outstate")
    payload["uplinks"][0]["speed"] = "25G-baseSR-LR"
    payload["olt_ports"][0]["speed"] = "25G-baseSR-LR"

    response = client.post("/api/generate-ftth-bng", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data.get("success") is True
    config = data.get("config", "")

    assert "set [ find default-name=sfp28-3 ] comment=NE-WESTERN-EA-1 l2mtu=9212 mtu=9198 auto-negotiation=no speed=25G-baseSR-LR" in config
    assert "set [ find default-name=sfp28-6 ] comment=\"NOKIA OLT\" auto-negotiation=no speed=25G-baseSR-LR" in config


def test_ftth_bgp_connections_use_dynamic_peer_inputs_and_loopback_router_id():
    payload = _ui_payload("instate")
    payload["loopback_ip"] = "10.26.1.108/32"
    payload["peer_1_name"] = "CR7"
    payload["peer_1_address"] = "10.2.0.107/32"
    payload["peer_2_name"] = "CR8"
    payload["peer_2_address"] = "10.2.0.108/32"

    response = client.post("/api/generate-ftth-bng", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data.get("success") is True
    config = data.get("config", "")

    assert "set default as=26077 disabled=no output.network=bgp-networks router-id=10.26.1.108" in config
    assert "add as=26077 cisco-vpls-nlri-len-fmt=auto-bits connect=yes disabled=no listen=yes local.address=10.26.1.108 .role=ibgp multihop=yes name=CR7 output.network=bgp-networks remote.address=10.2.0.107/32 .as=26077 .port=179 router-id=10.26.1.108 routing-table=main" in config
    assert "add as=26077 cisco-vpls-nlri-len-fmt=auto-bits connect=yes disabled=no listen=yes local.address=10.26.1.108 .role=ibgp multihop=yes name=CR8 output.network=bgp-networks remote.address=10.2.0.108/32 .as=26077 .port=179 router-id=10.26.1.108 routing-table=main" in config
