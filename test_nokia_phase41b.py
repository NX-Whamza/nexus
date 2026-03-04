#!/usr/bin/env python3
"""Quick test for Nokia migration Phase 41b fixes."""
import sys, os, re, json

src = open('vm_deployment/api_server.py', encoding='utf-8').read()

# Create minimal mocks for constants the functions need
ROUTERBOARD_INTERFACES = {
    'CCR2004-1G-12S+2XS': {'model': 'CCR2004-1G-12S+2XS', 'series': 'CCR', 'management_port': 'ether1'}
}
_NOKIA_TZ_MAP = {
    'CST': {'zone': 'CST', 'dst': 'CDT', 'start': 'second sunday march 02:00', 'end': 'first sunday november 02:00'},
}
_NOKIA_DEFAULT_MGMT_ACL = ['10.10.103.91/32', '192.168.128.0/21', '10.0.0.0/8']
_NOKIA_DEFAULT_NTP = ['52.128.59.240', '52.128.59.241']
_NOKIA_DEFAULT_LDP_DENY = ['10.2.0.14/32', '10.2.0.21/32']

# Extract state profiles and helpers (Phase 41c dependencies)
# Find the block from _NOKIA_OOS_DEFAULT_MGMT_ACL through _generate_nokia_system_name
helpers_start = src.index('_NOKIA_OOS_DEFAULT_MGMT_ACL')
helpers_end = src.index('\ndef _parse_mikrotik_for_nokia(', helpers_start)
exec(compile(src[helpers_start:helpers_end], '<helpers>', 'exec'))

# Extract _parse_mikrotik_for_nokia function
fn_start = src.index('def _parse_mikrotik_for_nokia(')
fn_end = src.index('\ndef _build_nokia_config(', fn_start)
exec(compile(src[fn_start:fn_end], '<parser>', 'exec'))

# Extract _build_nokia_config function
fn2_start = src.index('def _build_nokia_config(')
fn2_end = src.index("\n@app.route('/api/parse-mikrotik-for-nokia'", fn2_start)
# Inject 'import os' so os.getenv calls work inside exec'd builder
exec(compile('import os\n' + src[fn2_start:fn2_end], '<builder>', 'exec'))

# Test config (simulated BLUEGRASS2 CCR2004)
test_config = """
# 2025-01-31 05:00:06 by RouterOS 7.18.2
# model = CCR2004-1G-12S+2XS
/interface bridge
add name=bridgeLocal
add name=lan-bridge
add name=nat-public-bridge
/interface bridge port
add bridge=lan-bridge interface=sfp-sfpplus4
add bridge=lan-bridge interface=sfp-sfpplus5
add bridge=lan-bridge interface=sfp-sfpplus6
add bridge=lan-bridge interface=sfp-sfpplus7
/interface ethernet
set [find default-name=sfp-sfpplus2] comment="UPLINK-1" speed=1G-baseT-full
set [find default-name=sfp-sfpplus3] comment="UPLINK-2"
/ip address
add address=10.1.0.169/32 interface=loop0
add address=10.1.212.1/22 interface=lan-bridge
add address=10.101.212.1/22 interface=lan-bridge
add address=100.83.212.1/22 interface=lan-bridge
add address=10.30.248.30/30 interface=sfp-sfpplus2
add address=10.30.248.26/30 interface=sfp-sfpplus3
/ip firewall filter
add action=accept chain=forward comment="NTP Allow" dst-address=10.0.0.1 dst-port=123 in-interface=lan-bridge protocol=udp
add action=drop chain=input comment="Traceroute Drop" dst-address=10.0.0.0/8 in-interface=lan-bridge protocol=udp
/routing bgp connection
add name=CR7 remote.address=10.2.0.107 .as=26077
add name=CR8 remote.address=10.2.0.108 .as=26077
add disabled=yes name=CR5 remote.address=10.2.0.105 .as=26077
add disabled=yes name=CR6 remote.address=10.2.0.106 .as=26077
/routing ospf interface-template
add area=backbone-v2 interfaces=loop0
add area=backbone-v2 interfaces=lan-bridge
add area=backbone-v2 interfaces=sfp-sfpplus2 type=ptp
add area=backbone-v2 interfaces=sfp-sfpplus3 type=ptp
/mpls ldp
/mpls ldp accept-filter
add accept=no prefix=10.2.0.14/32
add accept=no prefix=10.2.0.21/32
add accept=no prefix=10.17.0.10/32
add accept=no prefix=10.0.0.87/32
/system identity
set name=RTR-MTCCR2004-1.BLUEGRASS2
/snmp community
add name=FBZ1yYdphf
"""

parsed = _parse_mikrotik_for_nokia(test_config)
errors = []

# TEST 1: No firewall-leaked IPs
ip_ifaces = [e['interface'] for e in parsed['ip_addresses']]
for bad in ['NTP Allow', 'Traceroute Drop', 'Private Space Protect']:
    if bad in ip_ifaces:
        errors.append(f"FAIL: Firewall rule '{bad}' leaked into IP addresses")
print(f"[1] Firewall leak prevention: {'PASS' if not any('FAIL' in e and 'Firewall' in e for e in errors) else 'FAIL'}")
print(f"    IP interfaces found: {ip_ifaces}")

# TEST 2: Bridge interfaces NOT in port_mapping as physical ports
for bn in ['lan-bridge', 'nat-public-bridge', 'bridgeLocal']:
    pm = parsed['port_mapping'].get(bn, {})
    if pm.get('type') not in ('bridge', None):
        errors.append(f"FAIL: Bridge '{bn}' mapped as '{pm.get('type')}' instead of 'bridge'")
print(f"[2] Bridge interfaces as VPLS/SAP: {'PASS' if not any('Bridge' in e for e in errors) else 'FAIL'}")
print(f"    Bridge names: {parsed.get('bridge_names', [])}")

# TEST 3: Bridge member ports marked as bridge-member, NOT physical
for bp in ['sfp-sfpplus4', 'sfp-sfpplus5', 'sfp-sfpplus6', 'sfp-sfpplus7']:
    pm = parsed['port_mapping'].get(bp, {})
    if pm.get('type') != 'bridge-member':
        errors.append(f"FAIL: Bridge member '{bp}' has type '{pm.get('type')}' instead of 'bridge-member'")
print(f"[3] Bridge member ports excluded: {'PASS' if not any('Bridge member' in e for e in errors) else 'FAIL'}")

# TEST 4: BGP peers found (CR7, CR8 — CR5/CR6 disabled)
bgp_peers = parsed.get('bgp', {}).get('peers', [])
peer_names = [p['name'] for p in bgp_peers]
if 'CR7' not in peer_names or 'CR8' not in peer_names:
    errors.append(f"FAIL: BGP peers CR7/CR8 not found. Found: {peer_names}")
if 'CR5' in peer_names or 'CR6' in peer_names:
    errors.append(f"FAIL: Disabled BGP peers CR5/CR6 should be excluded. Found: {peer_names}")
print(f"[4] BGP v7 parsing: {'PASS' if not any('BGP' in e for e in errors) else 'FAIL'}")
print(f"    Peers: {[(p['name'], p['address'], p['remote_as']) for p in bgp_peers]}")
print(f"    AS: {parsed.get('bgp', {}).get('as_number')}")

# TEST 5: LDP deny prefixes extracted from config
ldp_deny = parsed.get('ldp_deny_prefixes', [])
if len(ldp_deny) < 4:
    errors.append(f"FAIL: Expected 4+ LDP deny prefixes, got {len(ldp_deny)}")
print(f"[5] LDP deny from config: {'PASS' if len(ldp_deny) >= 4 else 'FAIL'}")
print(f"    Prefixes ({len(ldp_deny)}): {ldp_deny}")

# TEST 6: OSPF area backbone-v2 recognized
ospf_areas = parsed.get('ospf', {}).get('areas', [])
print(f"[6] OSPF areas: {ospf_areas}")
print(f"    Interfaces: {[(o['interface'], o['area'], o.get('type','')) for o in parsed.get('ospf',{}).get('interfaces',[])]}")

# TEST 7: Interface speed extracted
speeds = parsed.get('interface_speeds', {})
if speeds.get('sfp-sfpplus2') != '1000':
    errors.append(f"FAIL: sfp-sfpplus2 speed should be '1000', got '{speeds.get('sfp-sfpplus2')}'")
print(f"[7] Interface speeds: {'PASS' if speeds.get('sfp-sfpplus2') == '1000' else 'FAIL'}")
print(f"    Extracted: {speeds}")

# TEST 8: Build Nokia config and check for no duplicates / no bridge ports
nokia = _build_nokia_config(parsed)
# Only count top-level "    port 1/1/" lines (4-space indent = Port Configuration section)
port_lines = [l for l in nokia.splitlines() if re.match(r'^    port 1/1/', l)]
unique_ports = set(port_lines)
if len(port_lines) != len(unique_ports):
    errors.append(f"FAIL: Duplicate port lines: {len(port_lines)} total vs {len(unique_ports)} unique")
print(f"[8] No duplicate ports: {'PASS' if len(port_lines) == len(unique_ports) else 'FAIL'}")
print(f"    Port config entries: {[l.strip() for l in port_lines]}")

# Check that no bridge member port appears in nokia config
for bp in ['sfp-sfpplus4', 'sfp-sfpplus5', 'sfp-sfpplus6', 'sfp-sfpplus7']:
    if bp in nokia:
        errors.append(f"FAIL: Bridge member '{bp}' appears in Nokia config")
print(f"[9] Bridge members absent from Nokia: {'PASS' if not any('Bridge member' in e and 'appears' in e for e in errors) else 'FAIL'}")

# Check BGP appears in Nokia config
if 'group "CR"' not in nokia and 'neighbor 10.2.0.107' not in nokia:
    errors.append("FAIL: BGP section missing from Nokia output")
print(f"[10] BGP in Nokia output: {'PASS' if 'neighbor 10.2.0.107' in nokia else 'FAIL'}")

# Check OSPF area is 0.0.0.0 (not backbone-v2)
if 'area backbone-v2' in nokia:
    errors.append("FAIL: OSPF still has literal 'area backbone-v2'")
print(f"[11] OSPF area normalized: {'PASS' if 'area 0.0.0.0' in nokia and 'area backbone-v2' not in nokia else 'FAIL'}")

# Check LDP deny uses config prefixes (10.17.0.10)
if '10.17.0.10/32' not in nokia:
    errors.append("FAIL: Config-extracted LDP deny prefix 10.17.0.10/32 not in Nokia output")
print(f"[12] LDP deny from config: {'PASS' if '10.17.0.10/32' in nokia else 'FAIL'}")

# Check speed on sfp-sfpplus2 port
if 'speed 1000' not in nokia:
    errors.append("FAIL: speed 1000 not in Nokia output for sfp-sfpplus2")
print(f"[13] Speed 1000 in output: {'PASS' if 'speed 1000' in nokia else 'FAIL'}")

print(f"\n{'='*50}")
if errors:
    print(f"ERRORS ({len(errors)}):")
    for e in errors:
        print(f"  {e}")
else:
    print("ALL 13 TESTS PASSED!")

# Show a snippet of the Nokia output around BGP
bgp_start = nokia.find('BGP Configuration')
if bgp_start > 0:
    print(f"\n--- BGP section preview ---")
    print(nokia[bgp_start-60:bgp_start+400])
