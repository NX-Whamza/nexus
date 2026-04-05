from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest


def _load_app():
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    os.environ["AI_PROVIDER"] = "none"
    os.environ["NOKIA7250_SNMP_COMMUNITY"] = "test-snmp"
    os.environ["NOKIA7250_NLROOT_PW"] = "test-nlroot"
    os.environ["NOKIA7250_ADMIN_PW"] = "test-admin"
    os.environ["NOKIA7250_BGP_AUTH_KEY"] = "test-bgp"
    os.environ["NOKIA7250_OSPF_AUTH_KEY"] = "test-ospf"
    import api_server

    app = api_server.app
    app.config["TESTING"] = True
    return app.test_client(), api_server


def _auth_headers(client, api_server_mod) -> dict:
    admin_email = os.getenv("PLATFORM_ADMIN_EMAILS", "whamza@team.nxlink.com").split(",")[0].strip()
    login = client.post(
        "/api/auth/login",
        json={"email": admin_email, "password": api_server_mod.DEFAULT_PASSWORD},
    )
    token = (login.get_json() or {}).get("token")
    return {"Authorization": f"Bearer {token}"} if token else {}


def test_nokia7250_defaults_exposes_distinct_ospf_auth_key() -> None:
    client, api_mod = _load_app()
    headers = _auth_headers(client, api_mod)
    response = client.get("/api/nokia7250-defaults", headers=headers)
    assert response.status_code == 200, response.get_data(as_text=True)
    data = response.get_json() or {}
    assert data.get("bgp_auth_key") == "test-bgp"
    assert data.get("ospf_auth_key") == "test-ospf"


def test_generate_nokia7250_uses_env_secrets_and_unique_backhaul_ports() -> None:
    client, _ = _load_app()
    response = client.post(
        "/api/generate-nokia7250",
        json={
            "system_name": "NOKIA-7250-TEST-1",
            "system_ip": "10.42.13.4/32",
            "location": "Lab",
            "port1_desc": "Switch-A",
            "port2_desc": "Switch-B",
            "backhauls": [
                {"description": "BH-1", "port": "1/1/3", "ip": "10.0.0.1/30"},
                {"name": "BH-2", "port": "1/1/4", "ip": "10.0.0.5/30"},
            ],
            "enable_fiber": True,
            "fiber_interface": "FIBERCOMM",
            "fiber_ip": "10.0.0.9/30",
        },
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    data = response.get_json() or {}
    cfg = data.get("config") or ""
    assert '/configure system security snmp community "test-snmp" r version both' in cfg
    assert '/configure system security user nlroot password test-nlroot' in cfg
    assert '/configure router bgp group "DALLAS-RR" authentication-key "test-bgp"' in cfg
    assert '/configure router ospf 1 area 0.0.0.0 interface "BH-1" message-digest-key 1 md5 "test-ospf"' in cfg
    assert '/configure router ospf 1 area 0.0.0.0 interface "FIBERCOMM" message-digest-key 1 md5 "test-ospf"' in cfg
    assert '/configure router interface "BH-1" port 1/1/3' in cfg
    assert '/configure router interface "BH-2" port 1/1/4' in cfg
    assert '/configure router interface "BH-2" port 1/1/1' not in cfg


def test_generate_nokia7250_rejects_reserved_or_duplicate_backhaul_ports() -> None:
    client, _ = _load_app()
    reserved = client.post(
        "/api/generate-nokia7250",
        json={
            "system_name": "NOKIA-7250-TEST-1",
            "system_ip": "10.42.13.4/32",
            "backhauls": [{"name": "BH-1", "port": "1/1/1", "ip": "10.0.0.1/30"}],
        },
    )
    assert reserved.status_code == 400, reserved.get_data(as_text=True)
    assert "reserved" in (reserved.get_json() or {}).get("error", "").lower()

    duplicate = client.post(
        "/api/generate-nokia7250",
        json={
            "system_name": "NOKIA-7250-TEST-1",
            "system_ip": "10.42.13.4/32",
            "backhauls": [
                {"name": "BH-1", "port": "1/1/3", "ip": "10.0.0.1/30"},
                {"name": "BH-2", "port": "1/1/3", "ip": "10.0.0.5/30"},
            ],
        },
    )
    assert duplicate.status_code == 400, duplicate.get_data(as_text=True)
    assert "more than once" in (duplicate.get_json() or {}).get("error", "").lower()


def test_build_interface_migration_map_no_local_re_shadow() -> None:
    _, api_server = _load_app()
    result = api_server.build_interface_migration_map("CCR1072-12G-4S+", "CCR2216-1G-12XS-2XQ")
    assert isinstance(result, dict)
    assert result["ether1"] == "ether1"


@pytest.mark.parametrize(
    ("source_model", "target_model"),
    [
        ("CCR1036-12G-4S", "CCR2004-1G-12S+2XS"),
        ("CCR1036-12G-4S", "CCR2216-1G-12XS-2XQ"),
        ("CCR1072-12G-4S+", "CCR2216-1G-12XS-2XQ"),
        ("CCR2004-1G-12S+2XS", "CCR2216-1G-12XS-2XQ"),
        ("CCR2004-1G-12S+2XS", "CCR2116-12G-4S+"),
        ("CCR2116-12G-4S+", "CCR2004-1G-12S+2XS"),
        ("CCR2216-1G-12XS-2XQ", "CCR2004-1G-12S+2XS"),
        ("RB5009UG+S+", "CCR2004-1G-12S+2XS"),
    ],
)
def test_build_interface_migration_map_only_uses_target_ports(source_model: str, target_model: str) -> None:
    _, api_server = _load_app()
    result = api_server.build_interface_migration_map(source_model, target_model)
    target_ports = set(api_server._all_device_ports(target_model))
    assert result, f"Expected a migration map for {source_model} -> {target_model}"
    assert set(result.values()).issubset(target_ports)


@pytest.mark.parametrize(
    ("alias", "full_model"),
    [
        ("ccr1036", "CCR1036-12G-4S"),
        ("ccr1072", "CCR1072-12G-4S+"),
        ("ccr2004", "CCR2004-1G-12S+2XS"),
        ("ccr2116", "CCR2116-12G-4S+"),
        ("ccr2216", "CCR2216-1G-12XS-2XQ"),
        ("rb1009", "RB1009UG+S+"),
        ("rb2011", "RB2011UiAS"),
        ("rb5009", "RB5009UG+S+"),
    ],
)
def test_routerboard_aliases_resolve_to_supported_full_models(alias: str, full_model: str) -> None:
    _, api_server = _load_app()
    assert api_server.resolve_routerboard_model_key(alias) == full_model
    assert api_server._all_device_ports(full_model), f"Missing inventory for {full_model}"


def test_ccr2216_inventory_uses_qsfp28_names() -> None:
    _, api_server = _load_app()
    ports = api_server._all_device_ports("CCR2216-1G-12XS-2XQ")
    assert "qsfp28-1-1" in ports
    assert "qsfp28-2-1" in ports
    assert "qsfpplus1-1" not in ports


@pytest.mark.parametrize(
    ("source_config", "target_device", "expected_any", "unexpected_tokens"),
    [
        (
            "# 2026-03-24 08:00:00 by RouterOS 7.19.4\n"
            "# model = CCR1072-12G-4S+\n"
            "/interface ethernet\n"
            "set [ find default-name=sfp1 ] comment=EAGLEMOUNTAIN-BH-1\n"
            "/ip address\n"
            "add address=10.33.0.95/32 interface=loop0 comment=Loopback\n"
            "add address=10.42.2.57/29 interface=sfp1 comment=BH network=10.42.2.56\n"
            "/system identity\n"
            "set name=RTR-MT1072-AR1.EAGLEMOUNTAIN\n",
            "CCR2216-1G-12XS-2XQ",
            ["sfp28-"],
            ["default-name=sfp1", " interface=sfp1 "],
        ),
        (
            "# 2026-03-24 08:00:00 by RouterOS 7.19.4\n"
            "# model = RB1009UG+S+\n"
            "/interface ethernet\n"
            "set [ find default-name=combo1 ] comment=BACKHAUL-A\n"
            "/ip address\n"
            "add address=10.55.0.9/30 interface=combo1 comment=BH network=10.55.0.8\n"
            "/system identity\n"
            "set name=RTR-MT1009-TESTSITE\n",
            "CCR2004-1G-12S+2XS",
            ["sfp-sfpplus1", "sfp-sfpplus"],
            ["combo1"],
        ),
        (
            "# 2026-03-24 08:00:00 by RouterOS 7.19.4\n"
            "# model = CCR2216-1G-12XS-2XQ\n"
            "/interface ethernet\n"
            "set [ find default-name=qsfp28-1-1 ] disabled=no\n"
            "set [ find default-name=sfp28-3 ] comment=BACKHAUL-B\n"
            "/ip address\n"
            "add address=10.60.0.1/30 interface=sfp28-3 comment=BH network=10.60.0.0\n"
            "/system identity\n"
            "set name=RTR-MT2216-TESTSITE\n",
            "CCR2004-1G-12S+2XS",
            ["/system identity", "/ip address"],
            ["qsfp28-1-1"],
        ),
    ],
)
def test_routerboard_migrations_translate_across_port_families(
    source_config: str,
    target_device: str,
    expected_any: list[str],
    unexpected_tokens: list[str],
) -> None:
    client, api_mod = _load_app()
    headers = _auth_headers(client, api_mod)
    response = client.post(
        "/api/migrate-config",
        data=json.dumps(
            {
                "config": source_config,
                "target_device": target_device,
                "target_version": "7.19.4",
                "apply_compliance": False,
            }
        ),
        content_type="application/json",
        headers=headers,
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    data = response.get_json() or {}
    assert data.get("success") is True, data
    translated = data.get("translated_config", "")
    assert translated
    assert any(token in translated for token in expected_any), translated
    for token in unexpected_tokens:
        assert token not in translated, translated
    validation = data.get("validation") or {}
    assert not validation.get("missing_ips"), validation


def test_migrate_config_returns_analysis_and_validation() -> None:
    client, api_mod = _load_app()
    headers = _auth_headers(client, api_mod)
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
        headers=headers,
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
    client, api_mod = _load_app()
    headers = _auth_headers(client, api_mod)
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
        headers=headers,
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
    client, api_mod = _load_app()
    headers = _auth_headers(client, api_mod)
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
        headers=headers,
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
    client, api_mod = _load_app()
    headers = _auth_headers(client, api_mod)
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
        headers=headers,
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


def test_migrate_config_normalizes_existing_target_family_ports_and_identity() -> None:
    client, api_mod = _load_app()
    headers = _auth_headers(client, api_mod)
    export = (
        "# 2026-04-01 22:00:27 by RouterOS 7.16.2\n"
        "# model=CCR2004-1G-12S+2XS\n"
        "/interface ethernet\n"
        "set [ find default-name=sfp28-4 ] auto-negotiation=no comment=\"Netonix Uplink #1\" speed=1G-baseX\n"
        "set [ find default-name=sfp28-5 ] comment=\"Netonix Uplink #2\" disabled=yes\n"
        "set [ find default-name=sfp28-6 ] auto-negotiation=no comment=TX-OTTO-SE-1 speed=10G-baseSR-LR\n"
        "set [ find default-name=qsfp28-1-1 ] auto-negotiation=no comment=TX-KOSSE-EA-1 speed=10G-baseSR-LR\n"
        "/ip address\n"
        "add address=10.43.129.196/29 comment=TX-OTTO-SE-1 interface=sfp28-6 network=10.43.129.192\n"
        "add address=10.43.129.201/29 comment=TX-KOSSE-EA-1 interface=qsfp28-1-1 network=10.43.129.200\n"
        "/system identity\n"
        "set name=RTR-MT2004-AR1.TX-STRANGER-NE-1\n"
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
        headers=headers,
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    data = response.get_json() or {}
    assert data.get("success") is True
    assert data.get("effective_source_device") == "CCR2216-1G-12XS-2XQ"
    translated = data.get("translated_config") or ""
    analysis = data.get("migration_analysis") or {}
    ports = {row["source_port"]: row for row in analysis.get("port_analysis", [])}

    assert ports["sfp28-4"]["detected_role"] == "switch"
    assert ports["sfp28-4"]["target_port"] == "sfp28-1"
    assert ports["sfp28-5"]["detected_role"] == "switch"
    assert ports["sfp28-5"]["target_port"] == "sfp28-2"
    assert ports["sfp28-6"]["detected_role"] == "backhaul"
    assert ports["sfp28-6"]["target_port"] == "sfp28-4"
    assert ports["qsfp28-1-1"]["target_port"] in {"sfp28-5", "sfp28-6"}
    assert "set name=RTR-MT2216-AR1.TX-STRANGER-NE-1" in translated
    assert "# model =CCR2216-1G-12XS-2XQ" in translated
    assert "default-name=sfp28-1" in translated
    assert "default-name=sfp28-2" in translated
    assert "default-name=sfp28-5 ] auto-negotiation=no comment=TX-KOSSE-EA-1" in translated
    assert "default-name=qsfp28-1-1 ] auto-negotiation=no comment=TX-KOSSE-EA-1" not in translated


def test_generic_logical_labels_do_not_override_physical_port_mapping() -> None:
    client, api_mod = _load_app()
    headers = _auth_headers(client, api_mod)
    export = (
        "# 2026-04-01 22:00:27 by RouterOS 7.19.4\n"
        "# model=CCR2004-1G-12S+2XS\n"
        "/interface bridge\n"
        "add name=lan-bridge\n"
        "/interface ethernet\n"
        "set [ find default-name=sfp-sfpplus1 ] comment=\"Netonix Uplink #1\"\n"
        "set [ find default-name=sfp-sfpplus7 ] comment=TX-BACKHAUL-1\n"
        "/interface bridge port\n"
        "add bridge=lan-bridge interface=sfp-sfpplus1\n"
        "add bridge=lan-bridge interface=sfp-sfpplus7\n"
        "/ip address\n"
        "add address=10.22.176.1/22 comment=\"CPE/Tower Gear\" interface=lan-bridge network=10.22.176.0\n"
        "add address=10.43.129.193/29 comment=TX-BACKHAUL-1 interface=sfp-sfpplus7 network=10.43.129.192\n"
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
        headers=headers,
    )
    assert response.status_code == 200, response.get_data(as_text=True)
    data = response.get_json() or {}
    ports = {row["source_port"]: row for row in data.get("migration_analysis", {}).get("port_analysis", [])}

    assert ports["sfp-sfpplus1"]["detected_role"] == "switch"
    assert ports["sfp-sfpplus1"]["target_port"] in {"sfp28-1", "sfp28-2"}
    assert ports["sfp-sfpplus7"]["detected_role"] == "backhaul"
    assert ports["sfp-sfpplus7"]["target_port"] in {"sfp28-4", "sfp28-5", "sfp28-6"}
    joined = " | ".join(ports["sfp-sfpplus1"]["role_evidence"])
    assert "address_comment:lan-bridge:CPE/Tower Gear" not in joined
    assert "logical_interface:lan-bridge" not in joined


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
