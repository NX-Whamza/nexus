#!/usr/bin/env python3
"""
Comprehensive config generator test suite.
Tests ALL backend config generators against the VM/local app to verify:
  1. Endpoint responds (no crashes)
  2. Compliance blocks are injected from the active compliance source
  3. Output is consistent and complete
  4. Key compliance markers present
"""
import json
import os
import sys
import re
import requests

BASE_URL = (os.getenv("NOC_CONFIGMAKER_BASE_URL") or "").strip().rstrip("/")

if BASE_URL:
    CLIENT = requests

    def build_url(path: str) -> str:
        return f"{BASE_URL}{path}"
else:
    os.environ.setdefault("NOC_CONFIGMAKER_TESTS", "1")
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "vm_deployment"))
    from fastapi.testclient import TestClient
    from fastapi_server import app

    CLIENT = TestClient(app)

    def build_url(path: str) -> str:
        return path

PASS = 0
FAIL = 0

COMPLIANCE_MARKERS = {
    "snmp_community": ("FBZ1yYdphf", "SNMP community string"),
    "dns_primary": ("142.147.112.3", "Primary DNS server"),
    "dns_secondary": ("142.147.112.19", "Secondary DNS server"),
    "ntp_server": ("ntp-pool.nxlink.com", "NTP pool server"),
    "syslog_server": ("142.147.116.215", "Syslog remote server"),
    "dhcp_radius_1": ("142.147.112.2", "DHCP RADIUS server 1"),
    "dhcp_radius_2": ("142.147.112.18", "DHCP RADIUS server 2"),
    "timezone": ("America/Chicago", "Timezone setting"),
    "winbox_port": ("8291", "Winbox port"),
    "firewall_drop": ("DROP INPUT", "Firewall input drop rule"),
    "manager_acl": ("managerIP", "Manager IP ACL"),
    "snmp_acl": ("list=SNMP", "SNMP ACL"),
    "bgp_acl": ("BGP-ALLOW", "BGP-ALLOW ACL"),
}

def check(label, condition):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"    [PASS] {label}")
    else:
        FAIL += 1
        print(f"    [FAIL] {label}")
    return condition

def check_compliance(config, label, skip_markers=None):
    """Check compliance markers in a config string."""
    skip = skip_markers or []
    present = 0
    missing = 0
    for key, (marker, desc) in COMPLIANCE_MARKERS.items():
        if key in skip:
            continue
        if marker in config:
            present += 1
        else:
            missing += 1
            print(f"    [WARN] Missing compliance marker: {desc} ({marker})")
    total = present + missing
    pct = int(100 * present / total) if total > 0 else 0
    check(f"{label}: {present}/{total} compliance markers ({pct}%)", missing == 0)
    return present, total

# ════════════════════════════════════════════════════
# TEST 1: GET /api/compliance/blocks (shared by all)
# ════════════════════════════════════════════════════
print("=" * 70)
print("TEST 1: GET /api/compliance/blocks?loopback_ip=10.5.0.1")
print("=" * 70)
try:
    r = CLIENT.get(build_url("/api/compliance/blocks"),
                     params={"loopback_ip": "10.5.0.1"}, timeout=15)
    check("Status 200", r.status_code == 200)
    data = r.json()
    check("success=true", data.get("success") is True)
    source = data.get("source", "unknown")
    check(f"source supported (got: {source})", source in {"gitlab", "bundled-local"})
    blocks = data.get("blocks", {})
    check(f"Has blocks ({len(blocks)} keys)", len(blocks) > 5)
    # Check key blocks have real content
    for bk in ["ip_services", "dns", "snmp", "clock_ntp", "user_aaa"]:
        val = blocks.get(bk, "")
        check(f"Block '{bk}' has content ({len(val)} chars)", len(val) > 10)
except Exception as e:
    FAIL += 1
    print(f"    [EXCEPTION] {e}")

# ════════════════════════════════════════════════════
# TEST 2: Tower / Non-MPLS Config
# ════════════════════════════════════════════════════
print()
print("=" * 70)
print("TEST 2: POST /api/mt/tower/config (Tower Non-MPLS)")
print("=" * 70)
tower_payload = {
    "router_type": "MT2004",
    "tower_name": "COMPLIANCE-TEST-CN-1",
    "latitude": "33.123456",
    "longitude": "-97.654321",
    "state_code": "TX",
    "asn": "400307",
    "peer_1_address": "10.2.0.10",
    "peer_1_name": "CORE1",
    "peer_2_address": "10.2.0.11",
    "peer_2_name": "CORE2",
    "loopback_subnet": "10.5.0.1/32",
    "cpe_subnet": "10.50.0.0/22",
    "unauth_subnet": "10.50.4.0/24",
    "cgn_priv": "100.64.0.0/22",
    "cgn_pub": "132.147.184.91/32",
    "backhauls": [
        {
            "name": "BH-CORE",
            "subnet": "10.100.0.2/30",
            "master": True,
            "port": "sfp-sfpplus4",
            "bandwidth": "1G"
        }
    ],
    "apply_compliance": True
}
try:
    r = CLIENT.post(build_url("/api/mt/tower/config"), json=tower_payload, timeout=60)
    check(f"Status 200 (got {r.status_code})", r.status_code == 200)
    if r.status_code == 200:
        result = r.json()
        config = result if isinstance(result, str) else result.get("config", str(result))
        check(f"Config is string ({len(config)} chars)", isinstance(config, str) and len(config) > 500)
        check("Has system identity", "COMPLIANCE-TEST-CN-1" in config)
        check("Has bridge config", "/interface bridge" in config)
        check("Has OSPF", "ospf" in config.lower())
        check("Has BGP", "bgp" in config.lower())
        check("Has DHCP", "dhcp" in config.lower())
        check("Has loop0", "loop0" in config)
        check_compliance(config, "Tower compliance")
    elif r.status_code == 422:
        print(f"    422 detail: {r.json().get('detail', r.text[:300])}")
        FAIL += 1
    else:
        print(f"    Error: {r.text[:400]}")
except Exception as e:
    FAIL += 1
    print(f"    [EXCEPTION] {e}")

# ════════════════════════════════════════════════════
# TEST 3: Non-MPLS Enterprise Config
# ════════════════════════════════════════════════════
print()
print("=" * 70)
print("TEST 3: POST /api/gen-enterprise-non-mpls (Non-MPLS Enterprise)")
print("=" * 70)
enterprise_payload = {
    "public_cidr": "203.0.113.0/30",
    "bh_cidr": "10.100.0.0/30",
    "loopback_ip": "10.5.0.50/32",
    "identity": "ENT-COMPLIANCE-TEST",
    "device": "RB5009",
    "target_version": "7.19.4",
    "uplink_interface": "sfp-sfpplus1",
    "uplink_comment": "Uplink to ISP",
    "public_port": "ether7",
    "nat_port": "ether8",
    "coords": "33.123,-97.654"
}
try:
    r = CLIENT.post(build_url("/api/gen-enterprise-non-mpls"), json=enterprise_payload, timeout=30)
    check(f"Status 200 (got {r.status_code})", r.status_code == 200)
    if r.status_code == 200:
        data = r.json()
        config = data.get("config", "") if isinstance(data, dict) else str(data)
        check(f"Config length ({len(config)} chars)", len(config) > 200)
        check("Has identity", "ENT-COMPLIANCE-TEST" in config)
        check("Has public IP", "203.0.113" in config)
        check("Has backhaul", "10.100.0" in config)
        check("Has NAT", "nat" in config.lower())
        # Non-MPLS enterprise uses inject_compliance_blocks()
        check_compliance(config, "Non-MPLS Enterprise compliance")
    else:
        print(f"    Error ({r.status_code}): {r.text[:400]}")
except Exception as e:
    FAIL += 1
    print(f"    [EXCEPTION] {e}")

# ════════════════════════════════════════════════════
# TEST 4: MPLS Enterprise / BNG2 Config
# ════════════════════════════════════════════════════
print()
print("=" * 70)
print("TEST 4: POST /api/mt/bng2/config (MPLS Enterprise / BNG2)")
print("=" * 70)
bng2_payload = {
    "router_type": "MT2004",
    "tower_name": "BNG2-COMPLIANCE-TEST",
    "latitude": "33.123456",
    "longitude": "-97.654321",
    "state_code": "IA",
    "ospf_area": "42",
    "loop_ip": "10.5.0.2/32",
    "gateway": "10.100.0.0/30",
    "bng_1_ip": "10.2.0.10",
    "bng_2_ip": "10.2.0.11",
    "vlan_1000_cisco": "100",
    "vlan_2000_cisco": "200",
    "vlan_3000_cisco": "300",
    "vlan_4000_cisco": "400",
    "mpls_mtu": "9000",
    "vpls_l2_mtu": "9212",
    "switch_ip": "10.50.0.1/24",
    "backhauls": [
        {
            "name": "BH-CORE",
            "subnet": "10.100.0.2/30",
            "master": True,
            "port": "sfp-sfpplus4"
        }
    ],
    "apply_compliance": True
}
try:
    r = CLIENT.post(build_url("/api/mt/bng2/config"), json=bng2_payload, timeout=60)
    check(f"Status 200 (got {r.status_code})", r.status_code == 200)
    if r.status_code == 200:
        result = r.json()
        config = result if isinstance(result, str) else result.get("config", str(result))
        check(f"Config is string ({len(config)} chars)", isinstance(config, str) and len(config) > 500)
        check("Has system identity", "BNG2-COMPLIANCE-TEST" in config)
        check("Has VPLS", "vpls" in config.lower())
        check("Has MPLS/LDP", "ldp" in config.lower() or "mpls" in config.lower())
        check("Has OSPF", "ospf" in config.lower())
        check("Has bridge", "/interface bridge" in config)
        check_compliance(config, "BNG2/MPLS compliance")
    elif r.status_code == 422:
        print(f"    422 detail: {r.json().get('detail', r.text[:300])}")
        FAIL += 1
    else:
        print(f"    Error: {r.text[:400]}")
except Exception as e:
    FAIL += 1
    print(f"    [EXCEPTION] {e}")

# ════════════════════════════════════════════════════
# TEST 5: FTTH BNG Config (generate)
# ════════════════════════════════════════════════════
print()
print("=" * 70)
print("TEST 5: POST /api/generate-ftth-bng (FTTH BNG)")
print("=" * 70)
ftth_payload = {
    "loopback_ip": "10.5.0.3/32",
    "cpe_network": "10.50.0.0/22",
    "cgnat_private": "100.64.0.0/22",
    "cgnat_public": "132.147.184.91/32",
    "unauth_network": "10.50.4.0/22",
    "olt_network": "10.60.0.0/29",
    "router_identity": "FTTH-COMPLIANCE-TEST",
    "deployment_type": "instate"
}
try:
    r = CLIENT.post(build_url("/api/generate-ftth-bng"), json=ftth_payload, timeout=30)
    check(f"Status 200 (got {r.status_code})", r.status_code == 200)
    if r.status_code == 200:
        data = r.json()
        config = data.get("config", "") if isinstance(data, dict) else str(data)
        check(f"Config length ({len(config)} chars)", len(config) > 200)
        check("Has system identity", "FTTH-COMPLIANCE-TEST" in config or "ftth" in config.lower())
        check("Has loop0", "loop0" in config)
        check("Has OLT", "olt" in config.lower() or "10.60.0" in config)
        # FTTH renderer has its own compliance injection
        check_compliance(config, "FTTH BNG compliance", skip_markers=[])
    else:
        print(f"    Error ({r.status_code}): {r.text[:400]}")
except Exception as e:
    FAIL += 1
    print(f"    [EXCEPTION] {e}")

# ════════════════════════════════════════════════════
# TEST 5b: FTTH BNG OUT-OF-STATE
# ════════════════════════════════════════════════════
print()
print("=" * 70)
print("TEST 5b: POST /api/generate-ftth-bng (FTTH BNG OUT-OF-STATE)")
print("=" * 70)
ftth_outstate = dict(ftth_payload)
ftth_outstate["deployment_type"] = "outstate"
ftth_outstate["router_identity"] = "FTTH-OUTSTATE-TEST"
try:
    r = CLIENT.post(build_url("/api/generate-ftth-bng"), json=ftth_outstate, timeout=30)
    check(f"Status 200 (got {r.status_code})", r.status_code == 200)
    if r.status_code == 200:
        data = r.json()
        config = data.get("config", "") if isinstance(data, dict) else str(data)
        check(f"Config length ({len(config)} chars)", len(config) > 200)
        check("Has OSPF (out-of-state)", "ospf" in config.lower())
        check_compliance(config, "FTTH out-of-state compliance", skip_markers=[])
    else:
        print(f"    Error ({r.status_code}): {r.text[:400]}")
except Exception as e:
    FAIL += 1
    print(f"    [EXCEPTION] {e}")

# ════════════════════════════════════════════════════
# TEST 5c: FTTH Preview
# ════════════════════════════════════════════════════
print()
print("=" * 70)
print("TEST 5c: POST /api/preview-ftth-bng (FTTH Preview)")
print("=" * 70)
ftth_preview_payload = {
    "loopback_ip": "10.5.0.3/32",
    "cpe_cidr": "10.50.0.0/22",
    "cgnat_cidr": "100.64.0.0/22",
    "olt_cidr": "10.60.0.0/29",
    "deployment_type": "instate"
}
try:
    r = CLIENT.post(build_url("/api/preview-ftth-bng"), json=ftth_preview_payload, timeout=30)
    check(f"Status 200 (got {r.status_code})", r.status_code == 200)
    if r.status_code == 200:
        data = r.json()
        # Preview might have different response structure
        has_config = "config" in data or "preview" in data or isinstance(data, str)
        check("Has config in response", has_config)
        if "config" in data:
            check(f"Preview length ({len(data['config'])} chars)", len(data["config"]) > 100)
    else:
        print(f"    Status {r.status_code}: {r.text[:300]}")
except Exception as e:
    FAIL += 1
    print(f"    [EXCEPTION] {e}")

# ════════════════════════════════════════════════════
# TEST 6: /api/apply-compliance (used by frontend MPLS Enterprise)
# ════════════════════════════════════════════════════
print()
print("=" * 70)
print("TEST 6: POST /api/apply-compliance (MPLS Enterprise frontend path)")
print("=" * 70)
mpls_frontend_config = """/system identity
set name=MPLS-ENT-TEST

/interface bridge
add name=loop0 protocol-mode=none
add name=bridge2000 protocol-mode=none
add name=bridge3000 protocol-mode=none

/ip address
add address=10.5.0.100/32 interface=loop0 network=10.5.0.100

/routing ospf instance
add disabled=no name=default router-id=10.5.0.100

/mpls ldp
set enabled=yes transport-addresses=10.5.0.100

/interface vpls
add disabled=no name=vpls2000 remote-peer=10.2.0.10 vpls-id=200:0
add disabled=no name=vpls3000 remote-peer=10.2.0.10 vpls-id=300:0
"""
try:
    r = CLIENT.post(build_url("/api/apply-compliance"),
                     json={"config": mpls_frontend_config, "loopback_ip": "10.5.0.100"},
                     timeout=15)
    check(f"Status 200 (got {r.status_code})", r.status_code == 200)
    if r.status_code == 200:
        data = r.json()
        config = data if isinstance(data, str) else data.get("config", str(data))
        check(f"Config length ({len(config)} chars) > input", len(config) > len(mpls_frontend_config) + 500)
        check("Original identity preserved", "MPLS-ENT-TEST" in config)
        check("Original VPLS preserved", "vpls2000" in config)
        check("Original OSPF preserved", "ospf" in config.lower())
        check_compliance(config, "apply-compliance overlay")
    else:
        print(f"    Error: {r.text[:400]}")
except Exception as e:
    FAIL += 1
    print(f"    [EXCEPTION] {e}")

# ════════════════════════════════════════════════════
# TEST 7: Tarana should be SKIPPED (regression)
# ════════════════════════════════════════════════════
print()
print("=" * 70)
print("TEST 7: Tarana config - compliance should be SKIPPED")
print("=" * 70)
tarana_config = """# Tarana Sector Configuration
# Site: TESTSITE
# Device: tarana-sector-1

interface eth0
  ip address 10.3.24.200/24
"""
try:
    r = CLIENT.post(build_url("/api/apply-compliance"),
                     json={"config": tarana_config, "loopback_ip": "10.3.24.200"}, timeout=15)
    check("Status 200", r.status_code == 200)
    if r.status_code == 200:
        data = r.json()
        result = data if isinstance(data, str) else data.get("config", str(data))
        check("No MikroTik SNMP injected", "FBZ1yYdphf" not in result)
        check("No MikroTik firewall injected", "/ip firewall filter" not in result)
        check("Config unchanged", len(result) < len(tarana_config) + 200)
except Exception as e:
    FAIL += 1
    print(f"    [EXCEPTION] {e}")

# ════════════════════════════════════════════════════
# TEST 8: Health endpoint
# ════════════════════════════════════════════════════
print()
print("=" * 70)
print("TEST 8: GET /api/health")
print("=" * 70)
try:
    r = CLIENT.get(build_url("/api/health"), timeout=10)
    check("Status 200", r.status_code == 200)
    data = r.json()
    check("Status online", data.get("status") == "online")
except Exception as e:
    FAIL += 1
    print(f"    [EXCEPTION] {e}")

# ════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════
print()
print("=" * 70)
total = PASS + FAIL
print(f"RESULTS: {PASS} passed, {FAIL} failed out of {total} checks")
print("=" * 70)
if FAIL > 0:
    print(f"\n{FAIL} checks need attention.")
    sys.exit(1)
else:
    print("\nALL CHECKS PASSED!")
    sys.exit(0)
