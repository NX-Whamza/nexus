#!/usr/bin/env python3
"""
Minimal smoke tests for NEXUS backend.

Run:
  python tests/smoke_api.py

This uses Flask's test client (no network, no docker).
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path


def _fail(msg: str) -> None:
    raise SystemExit(f"[FAIL] {msg}")


def _assert(cond: bool, msg: str) -> None:
    if not cond:
        _fail(msg)


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(repo_root))

    # Disable AI for deterministic testing
    os.environ["AI_PROVIDER"] = "none"

    import api_server  # noqa: WPS433 - repo-local import (shim -> vm_deployment)

    app = api_server.app
    app.config["TESTING"] = True

    client = app.test_client()

    # Health
    r = client.get("/api/health")
    _assert(r.status_code == 200, f"/api/health expected 200, got {r.status_code}")
    health = r.get_json() or {}
    _assert(health.get("status") == "online", f"/api/health status=online, got {health!r}")

    # App-config
    r = client.get("/api/app-config")
    _assert(r.status_code == 200, f"/api/app-config expected 200, got {r.status_code}")
    cfg = r.get_json() or {}
    _assert("bng_peers" in cfg, f"/api/app-config missing bng_peers: {cfg!r}")

    # Enterprise generator: ensure no SMTP remnants
    payload = {
        "device": "RB5009",
        "target_version": "7.19.4",
        "public_cidr": "67.219.124.128/29",
        "bh_cidr": "10.1.248.200/29",
        "loopback_ip": "10.13.0.84/32",
        "uplink_interface": "sfp-sfpplus1",
        "public_port": "ether7",
        "nat_port": "ether8",
        "snmp_community": "TEST",
        "identity": "RTR-RB5009.TEST",
        "uplink_comment": "TX-DELEON-NO-1",
    }
    r = client.post(
        "/api/gen-enterprise-non-mpls",
        data=json.dumps(payload),
        content_type="application/json",
    )
    _assert(r.status_code == 200, f"/api/gen-enterprise-non-mpls expected 200, got {r.status_code}")
    data = r.get_json() or {}
    _assert(data.get("success") is True, f"/api/gen-enterprise-non-mpls success=true, got {data!r}")
    generated = data.get("config") or ""
    _assert("SMTP" not in generated, "Enterprise config still contains SMTP rules")

    # Nokia migration: must return usable output even when AI is unavailable.
    source_config = (
        "/ip address\n"
        "add address=192.168.88.1/24 interface=ether1 comment=LAN\n"
        "add address=10.1.0.245/32 interface=loop0 comment=loop\n"
        "/ip route\n"
        "add dst-address=0.0.0.0/0 gateway=192.168.88.254\n"
        "/system identity\n"
        "set name=RTR-MT2216-TEST\n"
    )
    r = client.post(
        "/api/migrate-mikrotik-to-nokia",
        data=json.dumps({"source_config": source_config, "preserve_ips": True}),
        content_type="application/json",
    )
    _assert(r.status_code == 200, f"/api/migrate-mikrotik-to-nokia expected 200, got {r.status_code}")
    data = r.get_json() or {}
    _assert(data.get("success") is True, f"/api/migrate-mikrotik-to-nokia success=true, got {data!r}")
    nokia = data.get("nokia_config") or ""
    _assert(
        ('/configure router interface' in nokia) or ('interface "system"' in nokia),
        "Nokia migration output missing router interface config",
    )

    # Translate: CCR2216 -> CCR2004 interface mapping must happen.
    export = (
        "# 2025-12-22 12:34:47 by RouterOS 7.19.4.2\n"
        "# model =CCR2216-1G-12XS-2XQ\n"
        "\n"
        "/interface ethernet\n"
        "set [ find default-name=qsfp28-1-1 ] disabled=yes\n"
        "set [ find default-name=sfp28-3 ] comment=TX-TEST-BH\n"
        "\n"
        "/ip address\n"
        "add address=10.42.2.57/29 interface=sfp28-3 comment=TX-TEST-BH network=10.42.2.56\n"
        "\n"
        "/system identity\n"
        "set name=RTR-MT2216-AR1.TEST\n"
    )
    r = client.post(
        "/api/translate-config",
        data=json.dumps({"source_config": export, "target_device": "ccr2004", "target_version": "7.19.4"}),
        content_type="application/json",
    )
    _assert(r.status_code == 200, f"/api/translate-config expected 200, got {r.status_code}")
    data = r.get_json() or {}
    _assert(data.get("success") is True, f"/api/translate-config success=true, got {data!r}")
    translated = data.get("translated_config") or ""
    _assert("qsfp28" not in translated, "Translated config still contains qsfp ports for CCR2004 target")
    _assert("sfp-sfpplus4" in translated, "Translated config did not map sfp28-3 -> sfp-sfpplus4 (backhaul policy)")
    model = re.search(r"(?m)^#\s*model\s*=(.*)$", translated)
    _assert(model and "CCR2004" in model.group(1), "Translated config header model not updated to CCR2004")
    # Identity should be rewritten to avoid retaining source device digits (e.g., MT2216 -> MT2004)
    id_block = re.search(r'(?m)^\s*/system identity\s*\n\s*set\s+name=([^\n]+)', translated)
    _assert(id_block and ("MT2216" not in id_block.group(1)) and ("CCR2004" in id_block.group(1) or "2004" in id_block.group(1)), "Identity not updated to target model/digits")

    # Switch-maker backend: CCR2004 no-BNG profile should use proper uplink family.
    r = client.post(
        "/api/generate-mt-switch-config",
        data=json.dumps(
            {
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
                "ports": [{"port": "sfp-sfpplus1", "comment": "AP1 Cambium 6ghz"}],
            }
        ),
        content_type="application/json",
    )
    _assert(r.status_code == 200, f"/api/generate-mt-switch-config expected 200, got {r.status_code}")
    data = r.get_json() or {}
    _assert(data.get("success") is True, f"/api/generate-mt-switch-config success=true, got {data!r}")
    switch_config = data.get("config") or ""
    _assert("SWITCH PROFILE: CCR2004 NO BNG" in switch_config, "Switch config missing CCR2004 no-BNG profile header")
    _assert("sfp28-1" in switch_config, "Switch config missing CCR2004 sfp28 uplink")
    _assert("comment=\"AP1 Cambium 6ghz\"" in switch_config, "Switch config missing custom port comment")

    # Translate (strict): CCR2004 -> CCR2216 must preserve critical sections and map embedded VLAN names.
    export = (
        "# 2025-12-29 12:34:47 by RouterOS 7.19.4\n"
        "# model =CCR2004-1G-12S+2XS\n"
        "\n"
        "/interface ethernet\n"
        "set [ find default-name=sfp-sfpplus7 ] auto-negotiation=no comment=\"ZAYO DF to ALEDO-NO-1\" l2mtu=9212 mtu=9198 speed=10G-baseCR\n"
        "\n"
        "/interface vlan\n"
        "add interface=sfp-sfpplus7 name=vlan1000sfp-sfpplus7 vlan-id=1000\n"
        "\n"
        "/ip address\n"
        "add address=10.4.1.161/30 comment=ALEDO-NO-1 interface=sfp-sfpplus7 network=10.4.1.160\n"
        "\n"
        "/routing ospf instance\n"
        "add disabled=no name=default-v2 router-id=10.4.1.161\n"
        "/routing ospf area\n"
        "add disabled=no instance=default-v2 name=backbone-v2\n"
        "/routing ospf interface-template\n"
        "add area=backbone-v2 interfaces=sfp-sfpplus7 networks=10.4.1.160/30\n"
        "\n"
        "/routing bgp connection\n"
        "add as=26077 remote.address=10.4.0.1 remote.as=26077 tcp-md5-key=m8M5JwvdYM templates=core\n"
        "\n"
        "/routing filter rule\n"
        "add chain=bgr-a-bgp-in-filter action=accept\n"
        "\n"
        "/ip firewall filter\n"
        "add chain=input action=accept comment=\"ALLOW BGP\" protocol=tcp dst-port=179\n"
        "\n"
        "/ip firewall mangle\n"
        "add action=return chain=CONN-MARK comment=\"BREAK CONN-MARK\"\n"
        "\n"
        "/radius\n"
        "add address=142.147.112.18 secret=RADIUS_SECRET service=login\n"
        "\n"
        "/system identity\n"
        "set name=RTR-MT2004-AR1.CATTLEBARON\n"
        "\n"
        "/system scheduler\n"
        "add interval=1d name=nightly on-event=\"/system script run backup\"\n"
        "\n"
        "/system script\n"
        "add name=backup source=\":log info test\"\n"
    )
    r = client.post(
        "/api/translate-config",
        data=json.dumps(
            {
                "source_config": export,
                "target_device": "ccr2216",
                "target_version": "7.19.4",
                "strict_preserve": True,
                "apply_compliance": False,
            }
        ),
        content_type="application/json",
    )
    _assert(r.status_code == 200, f"/api/translate-config (strict) expected 200, got {r.status_code}")
    data = r.get_json() or {}
    _assert(data.get("success") is True, f"/api/translate-config (strict) success=true, got {data!r}")
    translated = data.get("translated_config") or ""
    _assert("default-name=sfp28-4" in translated, "Strict translate did not map sfp-sfpplus7 -> sfp28-4 in ethernet tuning (backhaul policy)")
    _assert("interface=sfp28-4" in translated, "Strict translate did not map IP address interface to sfp28-4")
    _assert("vlan1000sfp28-4" in translated, "Strict translate did not rewrite embedded VLAN name vlan1000sfp-sfpplus7 -> vlan1000sfp28-4")
    _assert("/routing ospf area" in translated and "name=backbone-v2" in translated, "Strict translate lost OSPF area backbone-v2")
    _assert("/routing bgp connection" in translated and "tcp-md5-key=m8M5JwvdYM" in translated, "Strict translate lost BGP connection or tcp-md5-key")
    _assert("/ip firewall mangle" in translated and "action=return chain=CONN-MARK" in translated, "Strict translate lost mangle return chain scaffolding")
    _assert("/radius" in translated and "RADIUS_SECRET" in translated, "Strict translate lost /radius section")
    _assert("/system scheduler" in translated and "name=nightly" in translated, "Strict translate lost scheduler")
    _assert("/system script" in translated and "name=backup" in translated, "Strict translate lost scripts")
    # Identity should be rewritten to reflect target model/digits (MT2004 -> MT2216)
    id_block = re.search(r'(?m)^\s*/system identity\s*\n\s*set\s+name=([^\n]+)', translated)
    _assert(id_block and ("MT2216" in id_block.group(1) or "CCR2216" in id_block.group(1)), "Identity was not updated to target model/digits")

    print("[OK] Smoke tests passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
