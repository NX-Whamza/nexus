from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _load_app():
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    os.environ["AI_PROVIDER"] = "none"
    os.environ["NOKIA7250_SNMP_COMMUNITY"] = "test-snmp"
    os.environ["NOKIA7250_NLROOT_PW"] = "test-nlroot"
    os.environ["NOKIA7250_ADMIN_PW"] = "test-admin"
    os.environ["NOKIA7250_BGP_AUTH_KEY"] = "test-bgp"
    import api_server

    app = api_server.app
    app.config["TESTING"] = True
    return app.test_client(), api_server


def test_build_interface_migration_map_no_local_re_shadow() -> None:
    _, api_server = _load_app()
    result = api_server.build_interface_migration_map("CCR1072-12G-4S+", "CCR2216-1G-12XS-2XQ")
    assert isinstance(result, dict)
    assert result["ether1"] == "ether1"


def test_migrate_config_returns_analysis_and_validation() -> None:
    client, _ = _load_app()
    export = (
        "# 2025-12-22 12:34:47 by RouterOS 6.49.10\n"
        "# model = CCR1072-12G-4S+\n"
        "/interface ethernet\n"
        "set [ find default-name=ether2 ] comment=UPLINK\n"
        "/ip address\n"
        "add address=10.42.2.57/29 interface=ether2 comment=BH network=10.42.2.56\n"
        "/system identity\n"
        "set name=RTR-MT1072-AR1.TEST\n"
    )
    response = client.post(
        "/api/migrate-config",
        data=json.dumps(
            {
                "config": export,
                "target_device": "CCR2216-1G-12XS-2XQ",
                "target_version": "7",
                "apply_compliance": False,
            }
        ),
        content_type="application/json",
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    data = response.get_json() or {}
    assert data.get("success") is True
    assert data.get("translated_config")
    assert data.get("migration_analysis", {}).get("needs_device_migration") is True
    assert data.get("migration_analysis", {}).get("needs_version_migration") is True
    assert data.get("migration_analysis", {}).get("interface_map", {}).get("ether1") == "ether1"
    assert "validation" in data


def test_nextlink_policy_detects_roles_and_keeps_target_ether1_management_only() -> None:
    client, _ = _load_app()
    export = (
        "# 2025-12-22 12:34:47 by RouterOS 6.49.10\n"
        "# model = CCR1072-12G-4S+\n"
        "/interface ethernet\n"
        "set [ find default-name=ether1 ] comment=BACKHAUL_MAIN\n"
        "set [ find default-name=ether2 ] comment=NETONIX_SWITCH\n"
        "set [ find default-name=ether3 ] comment=ALPHA_TARANA\n"
        "/ip address\n"
        "add address=10.42.2.57/29 interface=ether1 comment=BH network=10.42.2.56\n"
        "add address=192.168.88.2/24 interface=ether2 comment=LAN network=192.168.88.0\n"
        "/system identity\n"
        "set name=RTR-MT1072-AR1.TEST\n"
    )
    response = client.post(
        "/api/migrate-config",
        data=json.dumps(
            {
                "config": export,
                "target_device": "CCR2004-1G-12S+2XS",
                "target_version": "7",
                "apply_compliance": False,
            }
        ),
        content_type="application/json",
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    data = response.get_json() or {}
    analysis = data.get("migration_analysis", {})
    ports = {row["source_port"]: row for row in analysis.get("port_analysis", [])}

    assert ports["ether1"]["detected_role"] == "backhaul"
    assert ports["ether1"]["policy_conflict"] is True
    assert ports["ether1"]["target_port"] != "ether1"
    assert ports["ether2"]["detected_role"] == "switch"
    assert ports["ether2"]["target_port"] in {"sfp-sfpplus1", "sfp-sfpplus2"}
    assert ports["ether3"]["detected_role"] == "tarana"
    assert ports["ether3"]["target_port"] in {"sfp-sfpplus7", "sfp-sfpplus8", "sfp-sfpplus9", "sfp-sfpplus10", "sfp-sfpplus11"}


def test_logical_vlan_and_routing_signals_flow_back_to_physical_port() -> None:
    client, _ = _load_app()
    export = (
        "# 2025-12-22 12:34:47 by RouterOS 7.19.4\n"
        "# model = CCR2004-1G-12S+2XS\n"
        "/interface ethernet\n"
        "set [ find default-name=sfp-sfpplus5 ] comment=CORE_FIBER\n"
        "/interface vlan\n"
        "add name=vlan3000-bh interface=sfp-sfpplus5 vlan-id=3000 comment=TX-CORE-BH\n"
        "/ip address\n"
        "add address=10.10.10.1/30 interface=vlan3000-bh network=10.10.10.0\n"
        "/routing ospf interface-template\n"
        "add area=backbone-v2 interfaces=vlan3000-bh networks=10.10.10.0/30 type=ptp\n"
        "/routing bgp connection\n"
        "add as=26077 local.address=10.10.10.1 remote.address=10.10.10.2 remote.as=26077\n"
        "/system identity\n"
        "set name=RTR-MT2004-AR1.TEST\n"
    )
    response = client.post(
        "/api/migrate-config",
        data=json.dumps(
            {
                "config": export,
                "target_device": "CCR2216-1G-12XS-2XQ",
                "target_version": "7",
                "apply_compliance": False,
            }
        ),
        content_type="application/json",
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    data = response.get_json() or {}
    ports = {row["source_port"]: row for row in data.get("migration_analysis", {}).get("port_analysis", [])}
    sfp5 = ports["sfp-sfpplus5"]
    assert sfp5["detected_role"] == "backhaul"
    joined = " | ".join(sfp5["role_evidence"])
    assert "logical_comment:vlan3000-bh:TX-CORE-BH" in joined
    assert "ospf_interface_template" in joined or "ospf_network_ref:vlan3000-bh" in joined
    assert "bgp_local_address:vlan3000-bh:10.10.10.1" in joined
    assert sfp5["target_port"] in {"sfp28-4", "sfp28-5", "sfp28-6"}


def test_legacy_lte_and_6ghz_patterns_are_detected_from_full_config() -> None:
    client, _ = _load_app()
    export = (
        "# 2026-03-22 09:15:00 by RouterOS 7.19.4\n"
        "# model = CCR2004-1G-12S+2XS\n"
        "/interface ethernet\n"
        "set [ find default-name=sfp-sfpplus3 ] comment=\"Nokia BBU Uplink\"\n"
        "set [ find default-name=sfp-sfpplus8 ] comment=AP-CNEP3K-5-AL60-000-1.TESTSITE\n"
        "/interface vlan\n"
        "add interface=sfp-sfpplus3 name=\"VLAN 75\" vlan-id=75\n"
        "add interface=sfp-sfpplus3 name=\"VLAN 444\" vlan-id=444\n"
        "/ip address\n"
        "add address=10.55.75.1/30 interface=\"VLAN 75\" comment=\"Nokia BBU S1\" network=10.55.75.0\n"
        "add address=10.55.44.1/30 interface=\"VLAN 444\" comment=\"Nokia BBU MGMT\" network=10.55.44.0\n"
        "add address=192.168.60.1/24 interface=sfp-sfpplus8 comment=AL60 network=192.168.60.0\n"
    )
    response = client.post(
        "/api/migrate-config",
        data=json.dumps(
            {
                "config": export,
                "target_device": "CCR2216-1G-12XS-2XQ",
                "target_version": "7",
                "apply_compliance": False,
            }
        ),
        content_type="application/json",
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    ports = {
        row["source_port"]: row
        for row in (response.get_json() or {}).get("migration_analysis", {}).get("port_analysis", [])
    }
    assert ports["sfp-sfpplus3"]["detected_role"] == "lte"
    assert ports["sfp-sfpplus3"]["target_port"] in {"sfp28-7", "sfp28-8", "sfp28-9", "sfp28-10", "sfp28-11"}
    assert ports["sfp-sfpplus8"]["detected_role"] == "6ghz"
    assert ports["sfp-sfpplus8"]["target_port"] in {"sfp28-7", "sfp28-8", "sfp28-9", "sfp28-10", "sfp28-11"}


def test_toolbox_inventory_endpoint_exposes_porting_reference() -> None:
    client, _ = _load_app()
    response = client.get("/api/toolbox-inventory")
    assert response.status_code == 200, response.get_data(as_text=True)
    data = response.get_json() or {}
    assert data.get("success") is True
    assert "mikrotik" in data.get("inventory", {})
    assert "nokia" in data.get("inventory", {})
    assert "switch" in data.get("role_patterns", {})


def test_enterprise_generator_uses_device_profile_defaults_for_ccr2216() -> None:
    client, _ = _load_app()
    response = client.post(
        "/api/gen-enterprise-non-mpls",
        data=json.dumps(
            {
                "device": "ccr2216",
                "target_version": "7.19.4",
                "public_cidr": "100.64.10.1/30",
                "bh_cidr": "10.10.10.2/30",
                "loopback_ip": "10.255.255.1/32",
                "identity": "RTR-MT2216-TEST",
            }
        ),
        content_type="application/json",
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    data = response.get_json() or {}
    assert data.get("success") is True
    profile = data.get("profile") or {}
    assert profile.get("public_port") == "sfp28-7"
    assert profile.get("nat_port") == "sfp28-8"
    assert profile.get("uplink_interface") == "sfp28-1"
    config = data.get("config", "")
    assert 'default-name=sfp28-7' in config
    assert 'default-name=sfp28-8' in config
    assert 'default-name=sfp28-1' in config


def test_enterprise_generator_rejects_overlapping_interface_roles() -> None:
    client, _ = _load_app()
    response = client.post(
        "/api/gen-enterprise-non-mpls",
        data=json.dumps(
            {
                "device": "rb5009",
                "target_version": "7.19.4",
                "public_cidr": "100.64.10.1/30",
                "bh_cidr": "10.10.10.2/30",
                "loopback_ip": "10.255.255.1/32",
                "public_port": "ether7",
                "nat_port": "ether7",
                "uplink_interface": "sfp-sfpplus1",
            }
        ),
        content_type="application/json",
    )
    assert response.status_code == 400, response.get_data(as_text=True)
    data = response.get_json() or {}
    assert data.get("success") is False
    assert "must be unique" in (data.get("error") or "")


def test_nokia_configurator_backend_generates_7210_isd() -> None:
    client, _ = _load_app()
    response = client.post(
        "/api/generate-nokia-configurator",
        data=json.dumps(
            {
                "model": "7210",
                "profile": "isd",
                "system_name": "RTR-NK7210-TEST",
                "system_ip": "10.25.0.46/32",
                "latitude": "29.1",
                "longitude": "-96.1",
                "timezone": "CST",
                "static_hop": "10.25.1.1",
                "isd_public": "172.16.10.1/24",
                "isd_private": "192.168.10.1/24",
                "uplinks": [{"port": "1/1/1", "desc": "BH-1", "ip": "10.45.248.105/30", "speed": "10000"}],
            }
        ),
        content_type="application/json",
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    data = response.get_json() or {}
    assert data.get("success") is True
    assert data.get("config_type") == "nokia-7210-isd"
    config = data.get("config", "")
    assert "NOKIA 7210 ISD CONFIG" in config
    assert '/configure service ies 100 interface "public" address 172.16.10.1/24' in config
    assert '/configure port 1/1/1 description "BH-1"' in config


def test_nokia_configurator_backend_generates_7750_tunnel() -> None:
    client, _ = _load_app()
    response = client.post(
        "/api/generate-nokia-configurator",
        data=json.dumps(
            {
                "model": "7750",
                "profile": "standard",
                "system_name": "RTR-NK7750-TEST",
                "system_ip": "10.26.0.46/32",
                "sdp_number": "201",
                "sdp_description": "OMAHA-BNG",
                "sdp_far_end": "10.249.0.200",
                "vpls_cgn": "1245",
                "vpls_static": "2245",
                "vpls_infra": "3245",
                "vpls_cpe": "4245",
            }
        ),
        content_type="application/json",
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    data = response.get_json() or {}
    assert data.get("success") is True
    assert data.get("config_type") == "nokia-7750-standard"
    config = data.get("config", "")
    assert "NOKIA 7750 TUNNEL CONFIG" in config
    assert '/configure service sdp 201 mpls description "OMAHA-BNG"' in config
    assert '/configure service vpls 2245 mesh-sdp 201:2245 create' in config
