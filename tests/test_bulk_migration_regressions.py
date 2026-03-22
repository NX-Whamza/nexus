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
