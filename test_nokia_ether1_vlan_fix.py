#!/usr/bin/env python3
"""Tests: ether1 and VLAN interface exclusion from Nokia migration.

Verifies:
  - ether1 (management port) NEVER appears in Nokia transport/router/OSPF/MPLS/RSVP/LDP
  - VLAN sub-interfaces (vlan1000-sfp-sfpplus8 etc.) NEVER get Nokia port assignments
  - VLAN sub-interfaces NEVER appear in router interfaces, OSPF, MPLS, RSVP, or LDP
  - Physical transport interfaces still work correctly alongside excluded VLANs
  - All fixes work across all 7 state profiles
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
# CONFIG 1: Full Greenwood-style config with ether1 IP, VLANs, and OSPF on
# both VLANs/ether1 and real transport interfaces
# ===========================================================================

config_full = """
# 2026-03-03 23:53:10 by RouterOS 7.11.2
# model = CCR2004-1G-12S+2XS
/interface bridge
add comment=DYNAMIC name=bridge1000
add comment=STATIC name=bridge2000
add comment="UNICORN MGMT" name=bridge3000
add name=lan-bridge priority=0x1
add name=loop0
/interface ethernet
set [ find default-name=ether1 ] comment="MANAGEMENT INTERFACE"
set [ find default-name=sfp-sfpplus1 ] comment="Netonix Uplink #1"
set [ find default-name=sfp-sfpplus4 ] auto-negotiation=no comment=GREENWOOD
set [ find default-name=sfp-sfpplus5 ] auto-negotiation=no comment=" TX-FORESTBURG-NW-1"
set [ find default-name=sfp-sfpplus8 ] auto-negotiation=no comment="Alpha 090"
set [ find default-name=sfp-sfpplus10 ] comment="Beta 210"
set [ find default-name=sfp-sfpplus11 ] auto-negotiation=no comment="Gamma 330"
/interface vlan
add interface=sfp-sfpplus8 name=vlan1000-sfp-sfpplus8 vlan-id=1000
add interface=sfp-sfpplus10 name=vlan1000-sfp-sfpplus10 vlan-id=1000
add interface=sfp-sfpplus11 name=vlan1000-sfp-sfpplus11 vlan-id=1000
add interface=sfp-sfpplus8 name=vlan2000-sfp-sfpplus8 vlan-id=2000
add interface=sfp-sfpplus10 name=vlan2000-sfp-sfpplus10 vlan-id=2000
add interface=sfp-sfpplus11 name=vlan2000-sfp-sfpplus11 vlan-id=2000
add interface=sfp-sfpplus8 name=vlan3000-sfp-sfpplus8 vlan-id=3000
add interface=sfp-sfpplus10 name=vlan3000-sfp-sfpplus10 vlan-id=3000
add interface=sfp-sfpplus11 name=vlan3000-sfp-sfpplus11 vlan-id=3000
/interface bridge port
add bridge=lan-bridge interface=sfp-sfpplus1
add bridge=bridge3000 interface=vlan3000-sfp-sfpplus8
add bridge=bridge3000 interface=vlan3000-sfp-sfpplus11
add bridge=bridge3000 interface=vlan3000-sfp-sfpplus10
add bridge=lan-bridge interface=vlan1000-sfp-sfpplus8
add bridge=lan-bridge interface=vlan1000-sfp-sfpplus10
add bridge=bridge2000 interface=vlan2000-sfp-sfpplus8
add bridge=bridge2000 interface=vlan2000-sfp-sfpplus11
add bridge=bridge2000 interface=vlan2000-sfp-sfpplus10
/ip address
add address=10.39.0.196 comment=loop0 interface=loop0 network=10.39.0.196
add address=10.47.124.1/22 comment="MANAGEMENT SUBNET" interface=ether1 network=10.47.124.0
add address=100.81.80.1/22 comment="CGNAT Private" interface=lan-bridge network=100.81.80.0
add address=10.45.129.156/29 comment=GREENWOOD interface=sfp-sfpplus4 network=10.45.129.152
add address=10.33.251.212/29 comment=" TX-FORESTBURG-NW-1" interface=sfp-sfpplus5 network=10.33.251.208
add address=10.246.4.105/29 comment="UNICORN MGMT" interface=bridge3000 network=10.246.4.104
add address=10.50.1.1/30 interface=vlan1000-sfp-sfpplus8 network=10.50.1.0
add address=10.50.2.1/30 interface=vlan2000-sfp-sfpplus10 network=10.50.2.0
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
add area=backbone-v2 cost=10 disabled=no interfaces=ether1 networks=10.47.124.0/22 priority=1
add area=backbone-v2 auth=md5 auth-id=1 auth-key=m8M5JwvdYM comment=GREENWOOD cost=30 disabled=no interfaces=sfp-sfpplus4 networks=10.45.129.152/29 priority=1 type=ptp
add area=backbone-v2 auth=md5 auth-id=1 auth-key=m8M5JwvdYM comment=" TX-FORESTBURG-NW-1" cost=10 disabled=no interfaces=sfp-sfpplus5 networks=10.33.251.208/29 priority=1 type=ptp
add area=backbone-v2 cost=10 disabled=no interfaces=vlan1000-sfp-sfpplus8 networks=10.50.1.0/30 priority=1
add area=backbone-v2 cost=10 disabled=no interfaces=vlan2000-sfp-sfpplus10 networks=10.50.2.0/30 priority=1
/system identity
set name=RTR-CCR2004-1.TX-GREENWOOD-NO-1
/snmp community
add name=FBZ1yYdphf
"""

parsed = _parse_mikrotik_for_nokia(config_full)
pm = parsed['port_mapping']

# ===========================================================================
# TEST GROUP 1: ether1 Exclusion
# ===========================================================================

print("=" * 60)
print("GROUP 1: ether1 (management port) exclusion")
print("=" * 60)

# [T1] ether1 should only be A/1 (management), NEVER 1/1/X
e1 = pm.get('ether1', {})
ok1 = e1.get('nokia_port') == 'A/1' and e1.get('type') == 'management'
if not ok1:
    errors.append(f"FAIL T1: ether1 should be A/1 management, got {e1}")
print(f"[T1] ether1 = A/1 management: {'PASS' if ok1 else 'FAIL'}")

# [T2] ether1 NOT in interface_roles (skipped by classification)
# We check by proxy — ether1 should NOT be in transport_ifaces or excluded_ifaces
# (it's handled separately as management)
ok2 = 'ether1' not in {k for k, v in pm.items() if v.get('nokia_port', '').startswith('1/1/')}
if not ok2:
    errors.append("FAIL T2: ether1 should NOT have a 1/1/X port assignment")
print(f"[T2] ether1 not in 1/1/X ports: {'PASS' if ok2 else 'FAIL'}")

# [T3] ether1 does NOT appear as a router interface in Nokia output
# Note: 'port A/1' in the Port Configuration section is EXPECTED (management port bootstrap)
# What must NOT exist: a router interface with port A/1, or ether1/MANAGEMENT named interface
nokia_tx = _build_nokia_config(parsed, {'state_code': 'TX'})
# Extract Router Base section for checking
rb_idx = nokia_tx.find('Router Base Configuration')
rb_end = nokia_tx.find('OSPF Configuration', rb_idx) if rb_idx >= 0 else -1
router_base = nokia_tx[rb_idx:rb_end] if rb_idx >= 0 and rb_end >= 0 else ''
ok3a = 'interface "MANAGEMENT' not in router_base
ok3b = 'interface "ether1"' not in router_base
ok3c = 'port A/1' not in router_base  # A/1 should NOT be in router-interface section
ok3 = ok3a and ok3b and ok3c
if not ok3:
    details = []
    if not ok3a: details.append('MANAGEMENT in router base')
    if not ok3b: details.append('ether1 in router base')
    if not ok3c: details.append('port A/1 in router base')
    errors.append(f"FAIL T3: ether1 leaking into router interfaces: {', '.join(details)}")
print(f"[T3] ether1 not in router interfaces: {'PASS' if ok3 else 'FAIL'}")

# [T4] ether1 with OSPF does NOT inflate interface count
# Only sfp-sfpplus4 and sfp-sfpplus5 are real transport
transport_ports = [k for k, v in pm.items() if v.get('nokia_port', '').startswith('1/1/')]
ok4 = len(transport_ports) == 2 and 'sfp-sfpplus4' in transport_ports and 'sfp-sfpplus5' in transport_ports
if not ok4:
    errors.append(f"FAIL T4: Expected 2 transport ports (sfp4,sfp5), got {transport_ports}")
print(f"[T4] Exactly 2 transport ports: {'PASS' if ok4 else 'FAIL'} ({transport_ports})")

# ===========================================================================
# TEST GROUP 2: VLAN Sub-Interface Exclusion
# ===========================================================================

print()
print("=" * 60)
print("GROUP 2: VLAN sub-interface exclusion")
print("=" * 60)

# [T5] VLAN interfaces detected and tracked
vlan_names = parsed.get('vlan_iface_names', [])
ok5 = 'vlan1000-sfp-sfpplus8' in vlan_names and 'vlan2000-sfp-sfpplus10' in vlan_names
if not ok5:
    errors.append(f"FAIL T5: VLAN names not tracked, got {vlan_names}")
print(f"[T5] VLAN names detected ({len(vlan_names)}): {'PASS' if ok5 else 'FAIL'}")

# [T6] NO VLAN interface has a Nokia port assignment
vlan_with_ports = [(k, v['nokia_port']) for k, v in pm.items()
                   if k.startswith('vlan') and v.get('nokia_port', '').startswith('1/1/')]
ok6 = len(vlan_with_ports) == 0
if not ok6:
    errors.append(f"FAIL T6: VLAN interfaces have Nokia ports: {vlan_with_ports}")
print(f"[T6] No VLANs have Nokia ports: {'PASS' if ok6 else 'FAIL'}")

# [T7] VLAN interface names do NOT appear in Nokia output at all
ok7a = 'vlan1000' not in nokia_tx
ok7b = 'vlan2000' not in nokia_tx
ok7c = 'vlan3000' not in nokia_tx
ok7 = ok7a and ok7b and ok7c
if not ok7:
    leaks = []
    if not ok7a: leaks.append('vlan1000')
    if not ok7b: leaks.append('vlan2000')
    if not ok7c: leaks.append('vlan3000')
    errors.append(f"FAIL T7: VLAN names in Nokia output: {leaks}")
print(f"[T7] No VLANs in Nokia output: {'PASS' if ok7 else 'FAIL'}")

# [T8] VLAN interfaces with OSPF still excluded (OSPF on VLAN sub-interface = still not physical)
# Our config has OSPF on vlan1000-sfp-sfpplus8 and vlan2000-sfp-sfpplus10
ok8a = pm.get('vlan1000-sfp-sfpplus8', {}).get('nokia_port', '').startswith('1/1/') == False
ok8b = pm.get('vlan2000-sfp-sfpplus10', {}).get('nokia_port', '').startswith('1/1/') == False
ok8 = ok8a and ok8b
if not ok8:
    errors.append(f"FAIL T8: VLAN+OSPF still getting ports: 8={pm.get('vlan1000-sfp-sfpplus8',{})}, 10={pm.get('vlan2000-sfp-sfpplus10',{})}")
print(f"[T8] VLAN+OSPF still excluded: {'PASS' if ok8 else 'FAIL'}")

# [T9] VLAN with /30 address still excluded (Rule 4 doesn't apply to VLANs)
# Our config has vlan1000-sfp-sfpplus8 with 10.50.1.1/30 — should NOT get transport classification
ok9 = 'vlan1000-sfp-sfpplus8' not in {k for k, v in pm.items() if v.get('nokia_port', '').startswith('1/1/')}
if not ok9:
    errors.append("FAIL T9: VLAN with /30 address should not get transport port")
print(f"[T9] VLAN+/30 still excluded: {'PASS' if ok9 else 'FAIL'}")

# ===========================================================================
# TEST GROUP 3: Transport Interfaces Unaffected
# ===========================================================================

print()
print("=" * 60)
print("GROUP 3: Transport interfaces still work correctly")
print("=" * 60)

# [T10] GREENWOOD still on Nokia
ok10 = pm.get('sfp-sfpplus4', {}).get('nokia_port') == '1/1/1'
if not ok10:
    errors.append(f"FAIL T10: GREENWOOD should be 1/1/1, got {pm.get('sfp-sfpplus4', {})}")
print(f"[T10] GREENWOOD = 1/1/1: {'PASS' if ok10 else 'FAIL'}")

# [T11] FORESTBURG still on Nokia
ok11 = pm.get('sfp-sfpplus5', {}).get('nokia_port') == '1/1/2'
if not ok11:
    errors.append(f"FAIL T11: FORESTBURG should be 1/1/2, got {pm.get('sfp-sfpplus5', {})}")
print(f"[T11] FORESTBURG = 1/1/2: {'PASS' if ok11 else 'FAIL'}")

# [T12] Nokia output has correct transport interfaces
ok12a = 'interface "GREENWOOD"' in nokia_tx
ok12b = 'interface "TX-FORESTBURG-NW-1"' in nokia_tx
ok12c = '10.45.129.156/29' in nokia_tx
ok12d = '10.33.251.212/29' in nokia_tx
ok12 = ok12a and ok12b and ok12c and ok12d
if not ok12:
    errors.append(f"FAIL T12: Transport ifaces missing from Nokia output")
print(f"[T12] Transport ifaces in output: {'PASS' if ok12 else 'FAIL'}")

# [T13] Port numbering NOT shifted by VLANs (sfp4=1/1/1, sfp5=1/1/2, no 1/1/3)
has_113 = 'port 1/1/3' in nokia_tx
ok13 = 'port 1/1/1' in nokia_tx and 'port 1/1/2' in nokia_tx and not has_113
if not ok13:
    errors.append(f"FAIL T13: Port numbering shifted, 1/1/3 present: {has_113}")
print(f"[T13] Port numbering correct (no shift): {'PASS' if ok13 else 'FAIL'}")

# ===========================================================================
# TEST GROUP 4: All 7 States — ether1 and VLANs Excluded in Every State
# ===========================================================================

print()
print("=" * 60)
print("GROUP 4: All 7 states clean (no ether1/VLAN leaks)")
print("=" * 60)

states = ['TX', 'OK', 'NE', 'KS', 'IL', 'IA', 'IN']
all_states_clean = True
for state in states:
    out = _build_nokia_config(parsed, {'state_code': state})
    # Extract Router Base + OSPF sections — that's where leaks matter
    rb_i = out.find('Router Base Configuration')
    ospf_end_i = out.find('MPLS Configuration', rb_i) if rb_i >= 0 else -1
    router_ospf = out[rb_i:ospf_end_i] if rb_i >= 0 and ospf_end_i >= 0 else ''
    has_ether1 = 'ether1' in router_ospf.lower()
    has_mgmt_ri = 'interface "MANAGEMENT' in router_ospf
    has_vlan = 'vlan1000' in router_ospf or 'vlan2000' in router_ospf or 'vlan3000' in router_ospf
    has_transport = 'GREENWOOD' in out and 'FORESTBURG' in out
    state_ok = not has_ether1 and not has_mgmt_ri and not has_vlan and has_transport
    if not state_ok:
        all_states_clean = False
        issues = []
        if has_ether1: issues.append('ether1')
        if has_mgmt_ri: issues.append('MANAGEMENT iface')
        if has_vlan: issues.append('VLAN')
        if not has_transport: issues.append('missing transport')
        errors.append(f"FAIL T14: State {state} has: {', '.join(issues)}")

print(f"[T14] All 7 states clean: {'PASS' if all_states_clean else 'FAIL'}")

# ===========================================================================
# TEST GROUP 5: OSPF Section — Only Physical Transport in OSPF
# ===========================================================================

print()
print("=" * 60)
print("GROUP 5: OSPF section correctness")
print("=" * 60)

# [T15] OSPF section should have GREENWOOD and FORESTBURG but NOT ether1 or VLANs
ospf_start = nokia_tx.find('OSPFv2 Configuration')
if ospf_start < 0:
    ospf_start = nokia_tx.find('OSPFv2 (Inst: 1) Configuration')
ospf_end_mark = nokia_tx.find('MPLS Configuration', ospf_start) if ospf_start >= 0 else -1
if ospf_end_mark < 0 and ospf_start >= 0:
    ospf_end_mark = ospf_start + 3000
ospf_section = nokia_tx[ospf_start:ospf_end_mark] if ospf_start >= 0 else ''
ok15a = 'GREENWOOD' in ospf_section
ok15b = 'FORESTBURG' in ospf_section
ok15c = 'ether1' not in ospf_section.lower() and 'MANAGEMENT' not in ospf_section
ok15d = 'vlan' not in ospf_section.lower()
ok15 = ok15a and ok15b and ok15c and ok15d
if not ok15:
    details = []
    if not ok15a: details.append('GREENWOOD missing')
    if not ok15b: details.append('FORESTBURG missing')
    if not ok15c: details.append('ether1/MANAGEMENT in OSPF')
    if not ok15d: details.append('VLAN in OSPF')
    errors.append(f"FAIL T15: OSPF issues: {', '.join(details)}")
print(f"[T15] OSPF clean (no ether1/VLAN): {'PASS' if ok15 else 'FAIL'}")

# ===========================================================================
# TEST GROUP 6: MPLS, RSVP, LDP — No Leaks
# ===========================================================================

print()
print("=" * 60)
print("GROUP 6: MPLS/RSVP/LDP clean")
print("=" * 60)

# [T16] MPLS section: no ether1, no VLANs
mpls_idx = nokia_tx.find('MPLS Configuration')
mpls_section = nokia_tx[mpls_idx:mpls_idx + 2000] if mpls_idx >= 0 else ''
ok16a = 'ether1' not in mpls_section.lower()
ok16b = 'vlan' not in mpls_section.lower()
ok16c = 'GREENWOOD' in mpls_section or 'system' in mpls_section  # transport should be there
ok16 = ok16a and ok16b and ok16c
if not ok16:
    errors.append(f"FAIL T16: MPLS has ether1={not ok16a} vlan={not ok16b}")
print(f"[T16] MPLS clean: {'PASS' if ok16 else 'FAIL'}")

# [T17] RSVP section: no ether1, no VLANs
rsvp_idx = nokia_tx.find('RSVP Configuration')
rsvp_section = nokia_tx[rsvp_idx:rsvp_idx + 2000] if rsvp_idx >= 0 else ''
ok17a = 'ether1' not in rsvp_section.lower()
ok17b = 'vlan' not in rsvp_section.lower()
ok17 = ok17a and ok17b
if not ok17:
    errors.append(f"FAIL T17: RSVP has ether1={not ok17a} vlan={not ok17b}")
print(f"[T17] RSVP clean: {'PASS' if ok17 else 'FAIL'}")

# [T18] LDP section: no ether1, no VLANs
ldp_idx = nokia_tx.find('LDP Configuration')
ldp_section = nokia_tx[ldp_idx:ldp_idx + 2000] if ldp_idx >= 0 else ''
ok18a = 'ether1' not in ldp_section.lower()
ok18b = 'vlan' not in ldp_section.lower()
ok18 = ok18a and ok18b
if not ok18:
    errors.append(f"FAIL T18: LDP has ether1={not ok18a} vlan={not ok18b}")
print(f"[T18] LDP clean: {'PASS' if ok18 else 'FAIL'}")

# ===========================================================================
# TEST GROUP 7: Edge Cases
# ===========================================================================

print()
print("=" * 60)
print("GROUP 7: Edge cases")
print("=" * 60)

# [T19] Config with ONLY ether1 + loop0 (no SFP) — management still handled
ether_only_config = """
# model = CCR2004-1G-12S+2XS
/interface ethernet
set [ find default-name=ether1 ] comment="Management"
/ip address
add address=10.1.0.1/32 interface=loop0
add address=10.47.1.1/22 interface=ether1
/routing ospf interface-template
add area=backbone-v2 interfaces=loop0
add area=backbone-v2 interfaces=ether1
/system identity
set name=RTR-CCR2004-1.TX-TEST
/snmp community
add name=test
"""
p_ether = _parse_mikrotik_for_nokia(ether_only_config)
pm_ether = p_ether['port_mapping']
nokia_ether = _build_nokia_config(p_ether, {'state_code': 'TX'})

ok19a = pm_ether.get('ether1', {}).get('nokia_port') == 'A/1'
# port A/1 in Port Config section is OK, but NOT in Router Base / OSPF
rb_ether = nokia_ether[nokia_ether.find('Router Base Configuration'):] if 'Router Base Configuration' in nokia_ether else ''
ok19b = 'port A/1' not in rb_ether  # No router interface for A/1
# Should only have system interface (loopback), no transport interfaces
ok19d = 'port 1/1/' not in nokia_ether
ok19 = ok19a and ok19b and ok19d
if not ok19:
    errors.append(f"FAIL T19: Ether1-only config: A/1={ok19a}, port A/1 in router base={not ok19b}, has 1/1/X={not ok19d}")
print(f"[T19] Ether1-only config handled: {'PASS' if ok19 else 'FAIL'}")

# [T20] Config with VLANs that also have /30 and OSPF — triple signal but still excluded
triple_vlan_config = """
# model = CCR2004-1G-12S+2XS
/interface ethernet
set [ find default-name=sfp-sfpplus1 ] comment="BACKHAUL-1"
set [ find default-name=sfp-sfpplus2 ] comment="ACCESS-RADIO"
/interface vlan
add interface=sfp-sfpplus2 name=vlan100-sfp2 vlan-id=100
/ip address
add address=10.1.0.99/32 interface=loop0
add address=10.30.248.30/30 interface=sfp-sfpplus1
add address=10.44.1.1/30 interface=vlan100-sfp2
/routing ospf interface-template
add area=backbone-v2 interfaces=loop0
add area=backbone-v2 interfaces=sfp-sfpplus1 type=ptp
add area=backbone-v2 interfaces=vlan100-sfp2 type=ptp
/system identity
set name=RTR-MTCCR2004-1.TX-VLANTEST
/snmp community
add name=testcomm
"""
p_triple = _parse_mikrotik_for_nokia(triple_vlan_config)
pm_triple = p_triple['port_mapping']
nokia_triple = _build_nokia_config(p_triple, {'state_code': 'TX'})

# VLAN with OSPF + /30 — should still be excluded
ok20a = 'vlan100-sfp2' not in {k for k, v in pm_triple.items() if v.get('nokia_port', '').startswith('1/1/')}
# Only sfp-sfpplus1 should get 1/1/1
ok20b = pm_triple.get('sfp-sfpplus1', {}).get('nokia_port') == '1/1/1'
# VLAN not in Nokia output
ok20c = 'vlan100' not in nokia_triple
ok20 = ok20a and ok20b and ok20c
if not ok20:
    errors.append(f"FAIL T20: Triple-signal VLAN leak: excluded={ok20a}, backhaul={ok20b}, no vlan={ok20c}")
print(f"[T20] VLAN+OSPF+/30 still excluded: {'PASS' if ok20 else 'FAIL'}")

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
    print(f"\n{passed}/{total} ether1/VLAN exclusion tests passed")
    sys.exit(1)
else:
    print(f"ALL {total} ETHER1/VLAN EXCLUSION TESTS PASSED!")
    sys.exit(0)
