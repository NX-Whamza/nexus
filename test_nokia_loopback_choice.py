#!/usr/bin/env python3
"""Tests: Nokia loopback IP choice — keep MikroTik loopback vs new Nokia loopback.
Verifies that the loopback_override parameter correctly propagates to:
  - System interface address
  - Router-id
  - OSPF instance IDs
  - BGP router-id and local-address
  - Preamble comment
Across all 7 state profiles (TX, OK, NE, KS, IL, IA, IN).
"""
import sys, os, re

os.environ['PYTHONIOENCODING'] = 'utf-8'

src = open('vm_deployment/api_server.py', encoding='utf-8').read()

# Mocks
ROUTERBOARD_INTERFACES = {
    'CCR2004-1G-12S+2XS': {'model': 'CCR2004-1G-12S+2XS', 'series': 'CCR', 'management_port': 'ether1'},
    'CCR2116-12G-4S+':    {'model': 'CCR2116-12G-4S+',    'series': 'CCR', 'management_port': 'ether1'},
}
_NOKIA_TZ_MAP = {
    'CST': {'zone': 'CST', 'dst': 'CDT', 'start': 'second sunday march 02:00', 'end': 'first sunday november 02:00'},
    'EST': {'zone': 'EST', 'dst': 'EDT', 'start': 'second sunday march 02:00', 'end': 'first sunday november 02:00'},
}
_NOKIA_DEFAULT_MGMT_ACL  = ['10.10.103.91/32', '192.168.128.0/21', '10.0.0.0/8']
_NOKIA_DEFAULT_NTP        = ['52.128.59.240', '52.128.59.241']
_NOKIA_DEFAULT_LDP_DENY   = ['10.2.0.14/32', '10.2.0.21/32']

# Extract helpers, parser, builder
helpers_start = src.index('_NOKIA_OOS_DEFAULT_MGMT_ACL')
helpers_end   = src.index('\ndef _parse_mikrotik_for_nokia(', helpers_start)
exec(compile(src[helpers_start:helpers_end], '<helpers>', 'exec'))

fn_start = src.index('def _parse_mikrotik_for_nokia(')
fn_end   = src.index('\ndef _build_nokia_config(', fn_start)
exec(compile(src[fn_start:fn_end], '<parser>', 'exec'))

fn2_start = src.index('def _build_nokia_config(')
fn2_end   = src.index("\n@app.route('/api/parse-mikrotik-for-nokia'", fn2_start)
exec(compile('import os\n' + src[fn2_start:fn2_end], '<builder>', 'exec'))

errors = []

# ===========================================================================
# TEST CONFIG: Greenwood site with known loopback 10.39.0.196/32
# ===========================================================================
greenwood_config = """
# 2026-03-03 23:53:10 by RouterOS 7.11.2
# model = CCR2004-1G-12S+2XS
/interface bridge
add comment=DYNAMIC name=bridge1000
add name=loop0
/interface ethernet
set [ find default-name=sfp-sfpplus4 ] auto-negotiation=no comment=GREENWOOD
set [ find default-name=sfp-sfpplus5 ] auto-negotiation=no comment=" TX-FORESTBURG-NW-1"
/ip address
add address=10.39.0.196 comment=loop0 interface=loop0 network=10.39.0.196
add address=10.45.129.156/29 comment=GREENWOOD interface=sfp-sfpplus4 network=10.45.129.152
add address=10.33.251.212/29 comment=" TX-FORESTBURG-NW-1" interface=sfp-sfpplus5 network=10.33.251.208
/routing bgp connection
add connect=yes listen=yes local.address=10.39.0.196 .role=ibgp multihop=yes name=CR7 remote.address=10.2.0.107 .as=26077
add connect=yes listen=yes local.address=10.39.0.196 .role=ibgp multihop=yes name=CR8 remote.address=10.2.0.108 .as=26077
/routing bgp template
set default as=26077
/routing ospf instance
add disabled=no name=default-v2 originate-default=never router-id=10.39.0.196
/routing ospf area
add disabled=no instance=default-v2 name=backbone-v2
/routing ospf interface-template
add area=backbone-v2 cost=10 disabled=no interfaces=loop0 networks=10.39.0.196/32 passive priority=1
add area=backbone-v2 auth=md5 auth-id=1 auth-key=m8M5JwvdYM comment=GREENWOOD cost=30 disabled=no interfaces=sfp-sfpplus4 networks=10.45.129.152/29 priority=1 type=ptp
add area=backbone-v2 auth=md5 auth-id=1 auth-key=m8M5JwvdYM comment=" TX-FORESTBURG-NW-1" cost=10 disabled=no interfaces=sfp-sfpplus5 networks=10.33.251.208/29 priority=1 type=ptp
/system identity
set name=RTR-CCR2004-1.TX-GREENWOOD-NO-1
/snmp community
add name=FBZ1yYdphf
"""

parsed = _parse_mikrotik_for_nokia(greenwood_config)

# ===========================================================================
# TEST GROUP 1: "Keep" — No override (default behavior)
# ===========================================================================

print("=" * 60)
print("GROUP 1: Keep MikroTik Loopback (no override)")
print("=" * 60)

nokia_keep = _build_nokia_config(parsed, {'state_code': 'TX'})

# [T1] System interface uses original MikroTik loopback
ok1 = 'address 10.39.0.196/32' in nokia_keep
if not ok1:
    errors.append("FAIL T1: System address should be 10.39.0.196/32 when keeping MikroTik loopback")
print(f"[T1] Keep: system address = 10.39.0.196/32: {'PASS' if ok1 else 'FAIL'}")

# [T2] Router-id uses original loopback
ok2 = 'router-id 10.39.0.196' in nokia_keep
if not ok2:
    errors.append("FAIL T2: Router-id should be 10.39.0.196 when keeping loopback")
print(f"[T2] Keep: router-id = 10.39.0.196: {'PASS' if ok2 else 'FAIL'}")

# [T3] Preamble says "from MikroTik"
ok3 = 'Loopback: 10.39.0.196/32 (from MikroTik)' in nokia_keep
if not ok3:
    errors.append("FAIL T3: Preamble should say 'from MikroTik' when keeping loopback")
print(f"[T3] Keep: preamble says 'from MikroTik': {'PASS' if ok3 else 'FAIL'}")

# [T4] BGP local-address uses original loopback
ok4 = 'local-address 10.39.0.196' in nokia_keep
if not ok4:
    errors.append("FAIL T4: BGP local-address should be 10.39.0.196")
print(f"[T4] Keep: BGP local-address = 10.39.0.196: {'PASS' if ok4 else 'FAIL'}")

# ===========================================================================
# TEST GROUP 2: "New" — Override with new IP
# ===========================================================================

print()
print("=" * 60)
print("GROUP 2: New Loopback IP override (10.42.12.88/32)")
print("=" * 60)

new_ip = '10.42.12.88/32'
nokia_new = _build_nokia_config(parsed, {'state_code': 'TX', 'loopback_override': new_ip})

# [T5] System interface uses new loopback
ok5 = 'address 10.42.12.88/32' in nokia_new
if not ok5:
    errors.append(f"FAIL T5: System address should be {new_ip} with override")
print(f"[T5] New: system address = {new_ip}: {'PASS' if ok5 else 'FAIL'}")

# [T6] Router-id uses new loopback (without mask)
ok6 = 'router-id 10.42.12.88' in nokia_new
if not ok6:
    errors.append("FAIL T6: Router-id should be 10.42.12.88 with override")
print(f"[T6] New: router-id = 10.42.12.88: {'PASS' if ok6 else 'FAIL'}")

# [T7] OLD loopback NOT in system address
ok7 = 'address 10.39.0.196/32' not in nokia_new
if not ok7:
    errors.append("FAIL T7: Old loopback should NOT be system address with override")
print(f"[T7] New: old loopback NOT in system: {'PASS' if ok7 else 'FAIL'}")

# [T8] Preamble says "NEW" with old IP reference
ok8 = 'NEW 10.42.12.88/32' in nokia_new and 'overriding MikroTik 10.39.0.196/32' in nokia_new
if not ok8:
    errors.append("FAIL T8: Preamble should say NEW with override details")
print(f"[T8] New: preamble shows override: {'PASS' if ok8 else 'FAIL'}")

# [T9] BGP local-address uses new IP
ok9 = 'local-address 10.42.12.88' in nokia_new
if not ok9:
    errors.append("FAIL T9: BGP local-address should be 10.42.12.88 with override")
print(f"[T9] New: BGP local-address = 10.42.12.88: {'PASS' if ok9 else 'FAIL'}")

# [T10] BGP router-id uses new IP
bgp_idx = nokia_new.find('bgp')
bgp_section = nokia_new[bgp_idx:bgp_idx + 1000] if bgp_idx > 0 else ''
ok10 = 'router-id 10.42.12.88' in bgp_section
if not ok10:
    errors.append("FAIL T10: BGP router-id should be 10.42.12.88 in BGP section")
print(f"[T10] New: BGP router-id = 10.42.12.88: {'PASS' if ok10 else 'FAIL'}")

# [T11] Transport interface IPs are NOT affected by loopback override
ok11a = '10.45.129.156/29' in nokia_new  # GREENWOOD IP
ok11b = '10.33.251.212/29' in nokia_new  # FORESTBURG IP
ok11 = ok11a and ok11b
if not ok11:
    errors.append("FAIL T11: Transport interface IPs should NOT change with loopback override")
print(f"[T11] New: transport IPs unchanged: {'PASS' if ok11 else 'FAIL'}")

# ===========================================================================
# TEST GROUP 3: Override works across ALL 7 state profiles
# ===========================================================================

print()
print("=" * 60)
print("GROUP 3: Loopback override across all 7 states")
print("=" * 60)

states = ['TX', 'OK', 'NE', 'KS', 'IL', 'IA', 'IN']
override_ip = '10.99.1.50/32'
override_addr = '10.99.1.50'

all_states_ok = True
for state in states:
    out = _build_nokia_config(parsed, {'state_code': state, 'loopback_override': override_ip})
    
    has_system_addr = f'address {override_ip}' in out
    has_router_id = f'router-id {override_addr}' in out
    has_bgp_local = f'local-address {override_addr}' in out
    no_old_system = 'address 10.39.0.196/32' not in out
    has_new_preamble = f'NEW {override_ip}' in out
    
    state_ok = has_system_addr and has_router_id and has_bgp_local and no_old_system and has_new_preamble
    if not state_ok:
        all_states_ok = False
        details = []
        if not has_system_addr: details.append('system addr')
        if not has_router_id: details.append('router-id')
        if not has_bgp_local: details.append('bgp local-addr')
        if not no_old_system: details.append('old loopback still present')
        if not has_new_preamble: details.append('preamble')
        errors.append(f"FAIL T12: State {state} missing: {', '.join(details)}")
    
print(f"[T12] Override in all 7 states: {'PASS' if all_states_ok else 'FAIL'} ({', '.join(states)})")

# ===========================================================================
# TEST GROUP 4: Out-of-state OSPF uses override correctly
# ===========================================================================

print()
print("=" * 60)
print("GROUP 4: Out-of-state OSPF with override")
print("=" * 60)

# NE is out-of-state with dual OSPF instances
nokia_ne = _build_nokia_config(parsed, {'state_code': 'NE', 'loopback_override': '10.77.0.1/32'})

# [T13] Out-of-state OSPF 0 is shutdown (no router-id), OSPF 1 uses new router-id
# For out-of-state: ospf 0 is shutdown, ospf 1 has the router-id
ok13a = 'ospf 0' in nokia_ne  # ospf 0 exists (shutdown)
ok13b = 'ospf 1 10.77.0.1' in nokia_ne  # ospf 1 uses new IP
ok13 = ok13a and ok13b
if not ok13:
    errors.append(f"FAIL T13: NE OSPF - ospf 0 present: {ok13a}, ospf 1 with new IP: {ok13b}")
print(f"[T13] NE OSPF 0/1 structure correct: {'PASS' if ok13 else 'FAIL'}")

# [T14] OSPF 1 also uses new router-id (NE has dual-instance)
ok14 = f'ospf 1 10.77.0.1' in nokia_ne
if not ok14:
    errors.append("FAIL T14: OSPF 1 should use new router-id 10.77.0.1 for NE")
print(f"[T14] NE OSPF 1 uses new IP: {'PASS' if ok14 else 'FAIL'}")

# ===========================================================================
# TEST GROUP 5: In-state (TX) OSPF with override
# ===========================================================================

print()
print("=" * 60)
print("GROUP 5: In-state (TX) OSPF with override")
print("=" * 60)

nokia_tx = _build_nokia_config(parsed, {'state_code': 'TX', 'loopback_override': '10.77.0.1/32'})

# [T15] In-state OSPF 0 uses new router-id
ok15 = f'ospf 0 10.77.0.1' in nokia_tx
if not ok15:
    errors.append("FAIL T15: OSPF 0 should use new router-id 10.77.0.1 for TX")
print(f"[T15] TX OSPF 0 uses new IP: {'PASS' if ok15 else 'FAIL'}")

# ===========================================================================
# TEST GROUP 6: Override with IP that has no mask (auto-append /32)
# ===========================================================================

print()
print("=" * 60)
print("GROUP 6: Override with no mask (auto-append /32)")
print("=" * 60)

nokia_nomask = _build_nokia_config(parsed, {'state_code': 'TX', 'loopback_override': '10.88.0.5'})

# [T16] Should auto-append /32
ok16 = 'address 10.88.0.5/32' in nokia_nomask
if not ok16:
    errors.append("FAIL T16: Override without mask should auto-append /32")
print(f"[T16] No-mask -> /32 appended: {'PASS' if ok16 else 'FAIL'}")

# [T17] Router-id should be just IP without mask
ok17 = 'router-id 10.88.0.5' in nokia_nomask and 'router-id 10.88.0.5/' not in nokia_nomask
if not ok17:
    errors.append("FAIL T17: Router-id should be bare IP (no mask)")
print(f"[T17] Router-id bare IP: {'PASS' if ok17 else 'FAIL'}")

# ===========================================================================
# TEST GROUP 7: Empty override string = keep behavior
# ===========================================================================

print()
print("=" * 60)
print("GROUP 7: Edge cases")
print("=" * 60)

# [T18] Empty override string → falls back to parsed loopback
nokia_empty = _build_nokia_config(parsed, {'state_code': 'TX', 'loopback_override': ''})
ok18 = 'address 10.39.0.196/32' in nokia_empty
if not ok18:
    errors.append("FAIL T18: Empty override should fall back to parsed loopback")
print(f"[T18] Empty override -> keep: {'PASS' if ok18 else 'FAIL'}")

# [T19] Whitespace-only override → falls back to parsed loopback
nokia_ws = _build_nokia_config(parsed, {'state_code': 'TX', 'loopback_override': '   '})
ok19 = 'address 10.39.0.196/32' in nokia_ws
if not ok19:
    errors.append("FAIL T19: Whitespace-only override should fall back to parsed loopback")
print(f"[T19] Whitespace override -> keep: {'PASS' if ok19 else 'FAIL'}")

# [T20] No loopback_override key at all → keep
nokia_nokey = _build_nokia_config(parsed, {'state_code': 'TX'})
ok20 = 'address 10.39.0.196/32' in nokia_nokey
if not ok20:
    errors.append("FAIL T20: No override key should keep parsed loopback")
print(f"[T20] No override key -> keep: {'PASS' if ok20 else 'FAIL'}")

# ===========================================================================
# SUMMARY
# ===========================================================================

print()
print("=" * 60)
total = 20
passed = total - len(errors)
if errors:
    print(f"FAILURES ({len(errors)}):")
    for e in errors:
        print(f"  {e}")
    print(f"\n{passed}/{total} loopback choice tests passed")
    sys.exit(1)
else:
    print(f"ALL {total} LOOPBACK CHOICE TESTS PASSED!")
    sys.exit(0)
