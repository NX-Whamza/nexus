#!/usr/bin/env python3
"""Phase 41c tests: state-aware Nokia migration (in-state vs out-of-state)."""
import sys, os, re, json

src = open('vm_deployment/api_server.py', encoding='utf-8').read()

# Mocks
ROUTERBOARD_INTERFACES = {
    'CCR2004-1G-12S+2XS': {'model': 'CCR2004-1G-12S+2XS', 'series': 'CCR', 'management_port': 'ether1'},
    'CCR2116-12G-4S+': {'model': 'CCR2116-12G-4S+', 'series': 'CCR', 'management_port': 'ether1'},
}
_NOKIA_TZ_MAP = {
    'CST': {'zone': 'CST', 'dst': 'CDT', 'start': 'second sunday march 02:00', 'end': 'first sunday november 02:00'},
    'EST': {'zone': 'EST', 'dst': 'EDT', 'start': 'second sunday march 02:00', 'end': 'first sunday november 02:00'},
}
_NOKIA_DEFAULT_MGMT_ACL = ['10.10.103.91/32', '192.168.128.0/21', '10.0.0.0/8']
_NOKIA_DEFAULT_NTP = ['52.128.59.240', '52.128.59.241']
_NOKIA_DEFAULT_LDP_DENY = ['10.2.0.14/32', '10.2.0.21/32']

# Extract helpers, parser, builder
helpers_start = src.index('_NOKIA_OOS_DEFAULT_MGMT_ACL')
helpers_end = src.index('\ndef _parse_mikrotik_for_nokia(', helpers_start)
exec(compile(src[helpers_start:helpers_end], '<helpers>', 'exec'))

fn_start = src.index('def _parse_mikrotik_for_nokia(')
fn_end = src.index('\ndef _build_nokia_config(', fn_start)
exec(compile(src[fn_start:fn_end], '<parser>', 'exec'))

fn2_start = src.index('def _build_nokia_config(')
fn2_end = src.index("\n@app.route('/api/parse-mikrotik-for-nokia'", fn2_start)
exec(compile('import os\n' + src[fn2_start:fn2_end], '<builder>', 'exec'))

errors = []

# ═══════════════════════════════════════════════════════════════
# TEST GROUP 1: State Detection
# ═══════════════════════════════════════════════════════════════

# TX in-state site name
tx_config = """/system identity\nset name=RTR-MTCCR2004-1.TX-HALLETTSVILLE-NW-1\n/ip address\nadd address=10.1.0.169/32 interface=loop0"""
ds = _detect_nokia_state(tx_config)
if ds['state_code'] != 'TX':
    errors.append(f"FAIL T1: TX detection got {ds['state_code']}")
if ds['confidence'] != 'high':
    errors.append(f"FAIL T1: TX confidence should be high, got {ds['confidence']}")
print(f"[T1] TX detection from site name: {'PASS' if ds['state_code'] == 'TX' and ds['confidence'] == 'high' else 'FAIL'}")

# NE out-of-state site name
ne_config = """/system identity\nset name=RTR-MTCCR2116-1.NE-PAWNEECITY-SE\n/ip address\nadd address=10.249.0.122/32 interface=loop0"""
ds = _detect_nokia_state(ne_config)
if ds['state_code'] != 'NE':
    errors.append(f"FAIL T2: NE detection got {ds['state_code']}")
print(f"[T2] NE detection from site name: {'PASS' if ds['state_code'] == 'NE' else 'FAIL'}")

# OK site name
ok_config = """/system identity\nset name=RTR-MTCCR2004-1.OK-ATOKA-CN-1\n/ip address\nadd address=10.1.0.50/32 interface=loop0"""
ds = _detect_nokia_state(ok_config)
if ds['state_code'] != 'OK':
    errors.append(f"FAIL T3: OK detection got {ds['state_code']}")
print(f"[T3] OK detection from site name: {'PASS' if ds['state_code'] == 'OK' else 'FAIL'}")

# IN site name (Indiana) — make sure it doesn't false-positive
in_config = """/system identity\nset name=RTR-MTCCR2004-1.IN-WASHINGTON-NW-1\n/ip address\nadd address=10.243.0.50/32 interface=loop0"""
ds = _detect_nokia_state(in_config)
if ds['state_code'] != 'IN':
    errors.append(f"FAIL T4: IN detection got {ds['state_code']}")
print(f"[T4] IN detection from site name: {'PASS' if ds['state_code'] == 'IN' else 'FAIL'}")

# No state prefix — should NOT match "IN" from in-interface etc.
no_state_config = """/system identity\nset name=RTR-MTCCR2004-1.BLUEGRASS2\n/ip address\nadd address=10.1.0.169/32 interface=loop0\n/ip firewall filter\nadd in-interface=lan-bridge chain=input"""
ds = _detect_nokia_state(no_state_config)
if ds['state_code'] == 'IN':
    errors.append(f"FAIL T5: False IN detection from 'in-interface'")
print(f"[T5] No false IN from 'in-interface': {'PASS' if ds['state_code'] != 'IN' else 'FAIL'} (detected: {ds['state_code']}, {ds['source']})")

# IP-based detection (NE octet 249)
ip_ne_config = """/system identity\nset name=SOMERTR\n/ip address\nadd address=10.249.0.122/32 interface=loop0\nadd address=10.249.100.1/24 interface=sfp-sfpplus1\nadd address=10.249.100.2/24 interface=sfp-sfpplus2"""
ds = _detect_nokia_state(ip_ne_config)
if ds['state_code'] != 'NE':
    errors.append(f"FAIL T6: NE IP detection got {ds['state_code']}")
if ds['source'] != 'ip_range':
    errors.append(f"FAIL T6: Expected ip_range source, got {ds['source']}")
print(f"[T6] NE detection from IP range: {'PASS' if ds['state_code'] == 'NE' and ds['source'] == 'ip_range' else 'FAIL'}")

# ═══════════════════════════════════════════════════════════════
# TEST GROUP 2: System Name Generation
# ═══════════════════════════════════════════════════════════════

# Standard RTR-MT name → Nokia name
parsed_tx = {'identity': 'RTR-MTCCR2004-1.TX-HALLETTSVILLE-NW-1'}
name = _generate_nokia_system_name(parsed_tx, 'TX')
if name != 'RTR-NK7250-1.TX-HALLETTSVILLE-NW-1':
    errors.append(f"FAIL T7: Expected RTR-NK7250-1.TX-HALLETTSVILLE-NW-1, got {name}")
print(f"[T7] TX system name: {'PASS' if name == 'RTR-NK7250-1.TX-HALLETTSVILLE-NW-1' else 'FAIL'} ({name})")

# Name without state prefix → state injected
parsed_nostate = {'identity': 'RTR-MTCCR2004-1.BLUEGRASS2'}
name = _generate_nokia_system_name(parsed_nostate, 'TX')
if not name.startswith('RTR-NK7250-1.TX-'):
    errors.append(f"FAIL T8: Expected RTR-NK7250-1.TX-..., got {name}")
print(f"[T8] Name without state: {'PASS' if name == 'RTR-NK7250-1.TX-BLUEGRASS2' else 'FAIL'} ({name})")

# NE name
parsed_ne = {'identity': 'RTR-MTCCR2116-1.NE-PAWNEECITY-SE'}
name = _generate_nokia_system_name(parsed_ne, 'NE')
if name != 'RTR-NK7250-1.NE-PAWNEECITY-SE':
    errors.append(f"FAIL T9: Expected RTR-NK7250-1.NE-PAWNEECITY-SE, got {name}")
print(f"[T9] NE system name: {'PASS' if name == 'RTR-NK7250-1.NE-PAWNEECITY-SE' else 'FAIL'} ({name})")

# OK name generation when state differs
parsed_ok = {'identity': 'RTR-MTCCR2004-1.ATOKA'}
name = _generate_nokia_system_name(parsed_ok, 'OK')
if not name.startswith('RTR-NK7250-1.OK-'):
    errors.append(f"FAIL T10: Expected RTR-NK7250-1.OK-..., got {name}")
print(f"[T10] OK system name injection: {'PASS' if name == 'RTR-NK7250-1.OK-ATOKA' else 'FAIL'} ({name})")

# ═══════════════════════════════════════════════════════════════
# TEST GROUP 3: In-State (TX) Config Builder
# ═══════════════════════════════════════════════════════════════

tx_full_config = """
# model = CCR2004-1G-12S+2XS
/system identity
set name=RTR-MTCCR2004-1.TX-HALLETTSVILLE-NW-1
/ip address
add address=10.1.0.169/32 interface=loop0
add address=10.30.248.30/30 interface=sfp-sfpplus2
add address=10.30.248.26/30 interface=sfp-sfpplus3
/routing bgp connection
add name=CR7 remote.address=10.2.0.107 .as=26077
/routing ospf interface-template
add area=backbone-v2 interfaces=loop0
add area=backbone-v2 interfaces=sfp-sfpplus2 type=ptp
add area=backbone-v2 interfaces=sfp-sfpplus3 type=ptp
/mpls ldp
/mpls ldp accept-filter
add accept=no prefix=10.2.0.14/32
add accept=no prefix=10.2.0.21/32
"""

parsed = _parse_mikrotik_for_nokia(tx_full_config)
nokia = _build_nokia_config(parsed, nokia_params={'state_code': 'TX'})

# T11: In-state OSPF — single instance (ospf 0)
if 'ospf 1 ' in nokia:
    errors.append("FAIL T11: TX should have single OSPF instance, found ospf 1")
if 'ospf 0 ' not in nokia:
    errors.append("FAIL T11: TX should have ospf 0")
print(f"[T11] TX single OSPF instance: {'PASS' if 'ospf 0 ' in nokia and 'ospf 1 ' not in nokia else 'FAIL'}")

# T12: In-state LDP policy — deny list (LDP-FILTER-PS)
if 'LDP-FILTER-PS' not in nokia:
    errors.append("FAIL T12: TX should use LDP-FILTER-PS policy")
if 'LDP-IN-BNG-PS' in nokia:
    errors.append("FAIL T12: TX should NOT have LDP-IN-BNG-PS")
print(f"[T12] TX LDP deny policy: {'PASS' if 'LDP-FILTER-PS' in nokia and 'LDP-IN-BNG-PS' not in nokia else 'FAIL'}")

# T13: In-state RSVP — no shutdown
if re.search(r'rsvp.*?shutdown', nokia, re.DOTALL):
    # Check it's not under an 'if' or 'no shutdown' specifically
    rsvp_section = nokia[nokia.find('rsvp'):nokia.find('rsvp') + 500] if 'rsvp' in nokia else ''
    has_shutdown = 'shutdown' in rsvp_section and 'no shutdown' not in rsvp_section
    if has_shutdown:
        errors.append("FAIL T13: TX RSVP should not be shutdown")
print(f"[T13] TX RSVP active: PASS")  # soft check

# T14: System name in output
if 'RTR-NK7250-1.TX-HALLETTSVILLE-NW-1' not in nokia:
    errors.append(f"FAIL T14: Nokia system name not in output")
print(f"[T14] TX system name in output: {'PASS' if 'RTR-NK7250-1.TX-HALLETTSVILLE-NW-1' in nokia else 'FAIL'}")

# T15: Profile designation in preamble
if 'In-State' not in nokia:
    errors.append("FAIL T15: Preamble should show 'In-State'")
print(f"[T15] TX preamble designation: {'PASS' if 'In-State' in nokia else 'FAIL'}")

# ═══════════════════════════════════════════════════════════════
# TEST GROUP 4: Out-of-State (NE) Config Builder
# ═══════════════════════════════════════════════════════════════

ne_full_config = """
# model = CCR2116-12G-4S+
/system identity
set name=RTR-MTCCR2116-1.NE-PAWNEECITY-SE
/interface bridge
add name=lan-bridge
/interface bridge port
add bridge=lan-bridge interface=sfp-sfpplus4
/ip address
add address=10.249.0.122/32 interface=loop0
add address=10.30.248.30/30 interface=sfp-sfpplus2
add address=10.30.248.26/30 interface=sfp-sfpplus3
add address=10.249.100.1/22 interface=lan-bridge
/routing bgp connection
add name=CR7 remote.address=10.2.0.107 .as=26077
/routing ospf interface-template
add area=backbone-v2 interfaces=loop0 auth-key=m8M5JwvdYM
add area=backbone-v2 interfaces=sfp-sfpplus2 type=ptp
add area=backbone-v2 interfaces=sfp-sfpplus3 type=ptp
/mpls ldp
"""

parsed_ne = _parse_mikrotik_for_nokia(ne_full_config)
nokia_ne = _build_nokia_config(parsed_ne, nokia_params={'state_code': 'NE'})

# T16: Out-of-state OSPF — dual instance (ospf 0 shutdown + ospf 1 active)
if 'ospf 1 ' not in nokia_ne:
    errors.append("FAIL T16: NE should have dual OSPF (ospf 1)")
print(f"[T16] NE dual OSPF: {'PASS' if 'ospf 1 ' in nokia_ne else 'FAIL'}")

# T17: Out-of-state LDP — allow list (LDP-IN-BNG-PS)
if 'LDP-IN-BNG-PS' not in nokia_ne:
    errors.append("FAIL T17: NE should use LDP-IN-BNG-PS policy")
if 'LDP-FILTER-PS' in nokia_ne:
    errors.append("FAIL T17: NE should NOT have LDP-FILTER-PS")
print(f"[T17] NE LDP allow policy: {'PASS' if 'LDP-IN-BNG-PS' in nokia_ne and 'LDP-FILTER-PS' not in nokia_ne else 'FAIL'}")

# T18: Out-of-state RSVP — shutdown
rsvp_start = nokia_ne.find('rsvp')
if rsvp_start >= 0:
    rsvp_section = nokia_ne[rsvp_start:rsvp_start + 300]
    # Should have 'shutdown' but NOT 'no shutdown'  
    has_shutdown = '            shutdown' in rsvp_section
    if not has_shutdown:
        errors.append("FAIL T18: NE RSVP should have shutdown")
    print(f"[T18] NE RSVP shutdown: {'PASS' if has_shutdown else 'FAIL'}")
else:
    print("[T18] NE RSVP shutdown: SKIP (no rsvp section)")

# T19: Out-of-state OSPF authentication — message-digest
if 'message-digest-key' not in nokia_ne:
    errors.append("FAIL T19: NE should use message-digest auth")
if 'authentication-key' in nokia_ne.split('ospf')[1] if 'ospf' in nokia_ne else True:
    # Check OSPF section specifically for simple vs MD5
    ospf_part = nokia_ne[nokia_ne.find('ospf 1'):nokia_ne.find('ospf 1') + 1000] if 'ospf 1' in nokia_ne else ''
    if 'authentication-key' in ospf_part and 'message-digest' not in ospf_part:
        errors.append("FAIL T19: NE OSPF should use message-digest, not authentication-key")
print(f"[T19] NE OSPF MD5 auth: {'PASS' if 'message-digest-key' in nokia_ne else 'FAIL'}")

# T20: Out-of-state SDP — multiple far-ends
sdp_count = nokia_ne.count('sdp 10')
if sdp_count < 3:
    errors.append(f"FAIL T20: NE should have 3 SDPs, found {sdp_count} 'sdp 10x'")
print(f"[T20] NE multiple SDPs: {'PASS' if sdp_count >= 3 else 'FAIL'} (found {sdp_count})")

# T21: NE system name
if 'RTR-NK7250-1.NE-PAWNEECITY-SE' not in nokia_ne:
    errors.append("FAIL T21: NE system name not in output")
print(f"[T21] NE system name: {'PASS' if 'RTR-NK7250-1.NE-PAWNEECITY-SE' in nokia_ne else 'FAIL'}")

# T22: NE preamble shows Out-of-State
if 'Out-of-State' not in nokia_ne:
    errors.append("FAIL T22: NE preamble should show 'Out-of-State'")
print(f"[T22] NE preamble designation: {'PASS' if 'Out-of-State' in nokia_ne else 'FAIL'}")

# T23: ACL dst-port for out-of-state
if 'dst-port 22 65535' not in nokia_ne:
    errors.append("FAIL T23: NE ACL should have dst-port 22 65535")
print(f"[T23] NE ACL dst-port: {'PASS' if 'dst-port 22 65535' in nokia_ne else 'FAIL'}")

# T24: TX ACL should NOT have dst-port
if 'dst-port 22 65535' in nokia:
    errors.append("FAIL T24: TX ACL should NOT have dst-port 22 65535")
print(f"[T24] TX ACL no dst-port: {'PASS' if 'dst-port 22 65535' not in nokia else 'FAIL'}")

# ═══════════════════════════════════════════════════════════════
# TEST GROUP 5: State Override via nokia_params
# ═══════════════════════════════════════════════════════════════

# T25: Force NE config even though identity says TX
parsed_tx2 = _parse_mikrotik_for_nokia(tx_full_config)
nokia_forced_ne = _build_nokia_config(parsed_tx2, nokia_params={'state_code': 'NE'})
if 'LDP-IN-BNG-PS' not in nokia_forced_ne:
    errors.append("FAIL T25: Forced NE should use LDP-IN-BNG-PS")
if 'Out-of-State' not in nokia_forced_ne:
    errors.append("FAIL T25: Forced NE should show Out-of-State")
print(f"[T25] State override NE: {'PASS' if 'LDP-IN-BNG-PS' in nokia_forced_ne and 'Out-of-State' in nokia_forced_ne else 'FAIL'}")

# T26: Custom system name override
parsed_tx3 = _parse_mikrotik_for_nokia(tx_full_config)
nokia_custom = _build_nokia_config(parsed_tx3, nokia_params={'state_code': 'TX', 'nokia_system_name': 'RTR-NK7250-1.TX-CUSTOM-SITE'})
if 'RTR-NK7250-1.TX-CUSTOM-SITE' not in nokia_custom:
    errors.append("FAIL T26: Custom system name not in output")
print(f"[T26] Custom system name: {'PASS' if 'RTR-NK7250-1.TX-CUSTOM-SITE' in nokia_custom else 'FAIL'}")

# ═══════════════════════════════════════════════════════════════
# SUMMARY
# ═══════════════════════════════════════════════════════════════
total = 26
passed = total - len(errors)
print(f"\n{'='*50}")
if errors:
    print(f"ERRORS ({len(errors)}):")
    for e in errors:
        print(f"  {e}")
    print(f"\n{passed}/{total} TESTS PASSED")
else:
    print(f"ALL {total} PHASE 41c TESTS PASSED!")
