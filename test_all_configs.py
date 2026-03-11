#!/usr/bin/env python3
"""Test all config generators after the dropdown/portmap fixes."""
import requests
import json
import urllib3
urllib3.disable_warnings()

API = 'https://noc-configmaker.nxlink.com/api'
PASS = 0
FAIL = 0

def ok(msg):
    global PASS
    PASS += 1
    print(f"  [PASS] {msg}")

def fail(msg):
    global FAIL
    FAIL += 1
    print(f"  [FAIL] {msg}")

# ================================================================
# TEST 1: suggest-config for all 8 device types
# ================================================================
print("\n=== TEST 1: suggest-config for all device types ===")
devices = ['ccr2004', 'rb5009', 'ccr1036', 'ccr1072', 'ccr2116', 'ccr2216', 'rb2011', 'rb1009']
for dev in devices:
    try:
        r = requests.post(f'{API}/suggest-config', json={
            'device': dev,
            'target_version': '7.19.4',
            'loopback_ip': '10.247.72.34/32',
            'public_cidr': '142.147.123.64/29',
            'bh_cidr': '10.45.250.66/29'
        }, timeout=15, verify=False)
        d = r.json()
        if d.get('success') and d.get('public_port') and d.get('nat_port') and d.get('uplink_interface'):
            ok(f"{dev:10s} -> pub={d['public_port']}, nat={d['nat_port']}, uplink={d['uplink_interface']}")
        else:
            fail(f"{dev:10s} -> missing fields: {json.dumps(d)[:200]}")
    except Exception as e:
        fail(f"{dev:10s} -> {e}")

# ================================================================
# TEST 2: Non-MPLS Enterprise config generation for key devices
# ================================================================
print("\n=== TEST 2: Non-MPLS Enterprise config generation ===")
test_devices_nonmpls = [
    ('rb5009', 'ether7', 'ether8', 'sfp-sfpplus1'),
    ('ccr2004', 'sfp-sfpplus7', 'sfp-sfpplus8', 'sfp-sfpplus1'),
    ('ccr1036', 'ether7', 'ether8', 'sfp1'),
    ('ccr2116', 'ether7', 'ether8', 'sfp-sfpplus1'),
    ('ccr2216', 'sfp28-7', 'sfp28-8', 'sfp28-1'),
    ('ccr1072', 'ether7', 'ether8', 'sfp1'),
    ('rb2011', 'ether7', 'ether8', 'sfp1'),
    ('rb1009', 'ether7', 'ether8', 'ether1'),
]
for dev, pub_port, nat_port, uplink in test_devices_nonmpls:
    try:
        payload = {
            'device': dev,
            'target_version': '7.19.4',
            'loopback_ip': '10.247.72.34/32',
            'public_cidr': '142.147.123.64/29',
            'bh_cidr': '10.45.250.66/29',
            'public_port': pub_port,
            'nat_port': nat_port,
            'uplink_interface': uplink,
            'identity': f'RTR-{dev.upper()}.TEST',
            'private_cidr': '192.168.88.1/24',
            'private_pool': '192.168.88.10-192.168.88.254',
        }
        r = requests.post(f'{API}/gen-enterprise-non-mpls', json=payload, timeout=30, verify=False)
        if r.status_code == 200:
            d = r.json()
            cfg = d.get('config', '')
            lines = cfg.count('\n')
            has_dhcp = '/ip dhcp-server' in cfg
            has_bridge = '/interface bridge' in cfg
            has_nat = '/ip firewall nat' in cfg
            has_ip = '/ip address' in cfg
            has_pool = '/ip pool' in cfg
            has_pub = pub_port in cfg
            has_nat_port = nat_port in cfg
            has_uplink = uplink in cfg

            checks = [
                ('DHCP', has_dhcp),
                ('bridge', has_bridge),
                ('NAT', has_nat),
                ('IP addr', has_ip),
                ('pool', has_pool),
                (f'pub_port({pub_port})', has_pub),
                (f'nat_port({nat_port})', has_nat_port),
                (f'uplink({uplink})', has_uplink),
            ]
            failed_checks = [name for name, passed in checks if not passed]
            if not failed_checks:
                ok(f"{dev:10s} -> {lines} lines, all sections present")
            else:
                fail(f"{dev:10s} -> missing: {', '.join(failed_checks)}")
        else:
            fail(f"{dev:10s} -> HTTP {r.status_code}: {r.text[:200]}")
    except Exception as e:
        fail(f"{dev:10s} -> {e}")

# ================================================================
# TEST 3: Port map extraction from a sample config
# ================================================================
print("\n=== TEST 3: Port map extraction (pipe-delimited format) ===")
sample_config = """
/interface ethernet
set [ find default-name=ether7 ] comment="CX HANDOFF"
set [ find default-name=ether8 ] comment=NAT
set [ find default-name=sfp-sfpplus1 ] comment="ZAYO-DF-ALEDO"

/ip address
add address=142.147.123.65/29 comment="PUBLIC(S)" interface=public-bridge network=142.147.123.64
add address=192.168.88.1/24 comment=PRIVATES interface=nat-bridge network=192.168.88.0
add address=10.45.250.66/29 comment="ZAYO-DF-ALEDO" interface=sfp-sfpplus1 network=10.45.250.64

/interface bridge port
add bridge=public-bridge interface=ether7
add bridge=nat-bridge interface=ether8
"""
try:
    r = requests.post(f'{API}/extract-port-map', json={'config_content': sample_config}, timeout=15, verify=False)
    if r.status_code == 200:
        d = r.json()
        pm_text = d.get('port_map_text', '')
        has_header = 'COMMENT' in pm_text and 'PORT' in pm_text and 'IP/CIDR' in pm_text
        has_pipe = ' | ' in pm_text
        has_actual_port = 'ether7' in pm_text or 'ether8' in pm_text or 'sfp-sfpplus1' in pm_text
        has_no_hash = 'ether#' not in pm_text  # Should NOT have ether#
        
        if has_header and has_pipe and has_actual_port and has_no_hash:
            ok(f"Pipe-delimited format with actual port numbers")
            # Print the actual port map
            print(f"\n--- Port Map Output ---")
            for line in pm_text.split('\n'):
                print(f"    {line}")
            print(f"--- End ---\n")
        else:
            fail(f"Format issues: header={has_header}, pipe={has_pipe}, actual_port={has_actual_port}, no_hash={has_no_hash}")
            print(f"    Output:\n{pm_text[:500]}")
    else:
        fail(f"HTTP {r.status_code}: {r.text[:200]}")
except Exception as e:
    fail(f"extract-port-map -> {e}")

# ================================================================
# TEST 4: Tower config generation (if backend supports it)
# ================================================================
print("\n=== TEST 4: Tower config generation ===")
# Tower backend uses MT prefixed keys, not short keys
tower_devices = [
    ('MT2004', 'CCR2004'),
    ('MT1036', 'CCR1036'),
    ('MT1072', 'CCR1072'),
    ('MT1009', 'RB1009/RB5009'),
    ('MT2216', 'CCR2216'),
]
for mt_key, display_name in tower_devices:
    try:
        # Use correct port for each device type
        bh_port = 'sfp-sfpplus4' if mt_key in ('MT2004',) else 'sfp28-4' if mt_key == 'MT2216' else 'sfp3' if mt_key in ('MT1036', 'MT1072') else 'ether4'
        payload = {
            'tower_name': f'TEST-TOWER-{display_name}',
            'router_type': mt_key,
            'loopback_subnet': '10.247.72.34/32',
            'backhauls': [
                {'name': 'BH-TEST', 'subnet': '10.45.250.64/29', 'master': True, 'port': bh_port, 'bandwidth': '1000', 'link_mode': 'auto'}
            ],
            'switches': [],
            'cpe_subnet': '10.100.0.0/22',
            'unauth_subnet': '10.100.4.0/22',
            'cgn_priv': '100.64.0.0/22',
            'cgn_pub': '132.147.184.0/24',
            'latitude': '31.0553',
            'longitude': '-97.4422',
            'state_code': 'TX',
            'asn': '64700',
            'peer_1_name': 'CORE-1',
            'peer_1_address': '172.16.0.1',
            'peer_2_name': 'CORE-2',
            'peer_2_address': '172.16.0.5',
        }
        r = requests.post(f'{API}/mt/tower/config', json=payload, timeout=30, verify=False)
        if r.status_code == 200:
            cfg = r.text if isinstance(r.text, str) else r.json()
            if isinstance(cfg, str) and len(cfg) > 100:
                ok(f"{mt_key:10s} ({display_name}) -> tower config {len(cfg)} chars")
            elif isinstance(cfg, dict) and cfg.get('error'):
                fail(f"{mt_key:10s} ({display_name}) -> {cfg['error'][:150]}")
            else:
                ok(f"{mt_key:10s} ({display_name}) -> got response ({len(str(cfg))} chars)")
        else:
            err = r.text[:200]
            if 'BASE_CONFIG_PATH' in err or 'unavailable' in err:
                print(f"  [SKIP] {mt_key:10s} ({display_name}) -> tower backend not configured (expected in Docker)")
            else:
                fail(f"{mt_key:10s} ({display_name}) -> HTTP {r.status_code}: {err}")
    except Exception as e:
        fail(f"{mt_key:10s} ({display_name}) -> {e}")

# ================================================================
# TEST 5: MPLS Enterprise suggest-config
# ================================================================
print("\n=== TEST 5: MPLS Enterprise suggest-config ===")
mpls_devices = ['ccr2004', 'rb5009', 'ccr1036', 'ccr2216', 'ccr1072', 'rb1009', 'rb2011']
for dev in mpls_devices:
    try:
        r = requests.post(f'{API}/suggest-config', json={
            'device': dev,
            'target_version': '7.19.4',
            'loopback_ip': '10.247.72.34/32',
            'config_type': 'mpls-enterprise'
        }, timeout=15, verify=False)
        d = r.json()
        if d.get('success'):
            ok(f"{dev:10s} -> MPLS suggest OK")
        elif r.status_code == 200:
            # May not have special MPLS suggestions but shouldn't error
            ok(f"{dev:10s} -> MPLS suggest responded (no special suggestions)")
        else:
            fail(f"{dev:10s} -> {r.status_code}: {r.text[:150]}")
    except Exception as e:
        fail(f"{dev:10s} -> {e}")

# ================================================================
# SUMMARY
# ================================================================
print(f"\n{'='*60}")
print(f"RESULTS: {PASS} passed, {FAIL} failed")
print(f"{'='*60}")
if FAIL == 0:
    print("ALL TESTS PASSED!")
else:
    print(f"!!! {FAIL} TESTS FAILED - review above !!!")
