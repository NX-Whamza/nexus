#!/usr/bin/env python3
"""Identity edge-case tests for NOC Config Maker backend."""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))

# Disable AI for deterministic testing
os.environ["AI_PROVIDER"] = "none"

import api_server  # noqa: WPS433 - repo-local import (shim -> vm_deployment)

app = api_server.app
app.config["TESTING"] = True
client = app.test_client()


def _auth_headers():
    admin_email = os.getenv("PLATFORM_ADMIN_EMAILS", "whamza@team.nxlink.com").split(",")[0].strip()
    r = client.post("/api/auth/login", json={"email": admin_email, "password": api_server.DEFAULT_PASSWORD})
    token = (r.get_json() or {}).get("token", "")
    return {"Authorization": f"Bearer {token}"}


def _translate_and_get_identity(src_cfg: str, target_device: str = "ccr2216") -> str:
    r = client.post(
        "/api/translate-config",
        data=json.dumps({"source_config": src_cfg, "target_device": target_device, "target_version": "7.19.4"}),
        content_type="application/json",
    )
    assert r.status_code == 200
    data = r.get_json() or {}
    assert data.get("success") is True
    translated = data.get("translated_config") or ""
    m = re.search(r'(?m)^\s*/system identity\s*\n\s*set\s+name=([^\n]+)', translated)
    return m.group(1).strip() if m else ""


def test_unquoted_identity_rewrites_digits():
    src = (
        "/system identity\n"
        "set name=RTR-MT2004-EXAMPLE\n"
    )
    out = _translate_and_get_identity(src, target_device="ccr2216")
    assert ("MT2216" in out) or ("CCR2216" in out) or ("2216" in out)


def test_quoted_identity_with_space_keeps_and_rewrites():
    src = (
        "/system identity\n"
        "set name=\"RTR-MT2004 Example Site\"\n"
    )
    out = _translate_and_get_identity(src, target_device="ccr2216")
    # Should be quoted in output and contain target digits
    assert ("MT2216" in out) or ("CCR2216" in out) or ("2216" in out)
    assert out.startswith('"') and out.endswith('"')


def test_digits_only_identity_replaced():
    src = (
        "/system identity\n"
        "set name=2216\n"
    )
    out = _translate_and_get_identity(src, target_device="ccr2004")
    assert ("2004" in out) or (" CCR2004" in out)


def test_missing_identity_inserts_target():
    src = (
        "/ip address\n"
        "add address=10.1.1.1/32 interface=loop0 comment=loop\n"
    )
    out = _translate_and_get_identity(src, target_device="ccr2004")
    assert out != ""
    assert ("2004" in out) or ("CCR2004" in out) or ("CCR" in out)


def test_enterprise_default_identity_uses_mt_prefix():
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
        "uplink_comment": "TX-DELEON-NO-1",
    }
    r = client.post(
        "/api/gen-enterprise-non-mpls",
        data=json.dumps(payload),
        content_type="application/json",
        headers=_auth_headers(),
    )
    assert r.status_code == 200
    body = r.get_json() or {}
    assert body.get("success") is True
    config_text = body.get("config") or ""
    assert "set name=RTR-MTRB5009.AUTO-GEN" in config_text


if __name__ == "__main__":
    # Run tests without pytest to avoid requiring extra deps in minimal dev envs.
    tests = [
        test_unquoted_identity_rewrites_digits,
        test_quoted_identity_with_space_keeps_and_rewrites,
        test_digits_only_identity_replaced,
        test_missing_identity_inserts_target,
        test_enterprise_default_identity_uses_mt_prefix,
    ]
    ok = True
    for t in tests:
        try:
            t()
            print(f"[OK] {t.__name__}")
        except AssertionError as e:
            print(f"[FAIL] {t.__name__}: {e}")
            ok = False
        except Exception as e:
            print(f"[ERROR] {t.__name__}: {e}")
            ok = False
    raise SystemExit(0 if ok else 1)
