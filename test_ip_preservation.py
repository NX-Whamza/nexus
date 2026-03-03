#!/usr/bin/env python3
"""
IP Preservation Diagnostic Test
================================
Traces IPs through every stage of the translate-config pipeline to find
exactly WHERE IPs are being lost.

Tests multiple migration paths with rich configs (many IPs, OSPF, firewall,
VLANs, bonding, etc.) and checks IP counts at every stage.
"""
import sys, os, re, json

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vm_deployment'))
sys.path.insert(0, '.')

os.environ['NOC_CONFIGMAKER_TESTS'] = '1'

from api_server import app

PASS = 0
FAIL = 0


def check(label, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {label}")
    else:
        FAIL += 1
        print(f"  [FAIL] {label}")
        if detail:
            print(f"         -> {detail}")
    return condition


def extract_all_ips(text):
    """Extract all IP addresses from config (excluding comments and PORT-EXHAUSTION lines)."""
    ips = set()
    for line in text.splitlines():
        stripped = line.strip()
        # Skip full-line comments BUT include inline comments (they have IPs in address= fields)
        if stripped.startswith('#'):
            continue
        for m in re.finditer(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b', line):
            ip = m.group(1)
            # Skip obviously irrelevant ones
            if ip.startswith('0.0.') or ip.startswith('255.255.'):
                continue
            ips.add(ip)
    return ips


def extract_ip_address_lines(text):
    """Extract /ip address add lines (the most critical IP carriers)."""
    lines = []
    in_ip_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('/ip address'):
            in_ip_section = True
            continue
        if stripped.startswith('/') and not stripped.startswith('/ip address'):
            in_ip_section = False
            continue
        if in_ip_section and stripped.startswith('add ') and 'address=' in stripped:
            lines.append(stripped)
        # Also catch single-line format
        if stripped.startswith('/ip address add') and 'address=' in stripped:
            lines.append(stripped)
    return lines


def extract_ip_with_interface(text):
    """Extract {ip: interface} mappings from /ip address section."""
    mappings = {}
    in_ip_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('# PORT-EXHAUSTION'):
            continue
        if stripped.startswith('/ip address'):
            in_ip_section = True
            continue
        if stripped.startswith('/') and not stripped.startswith('/ip address'):
            in_ip_section = False
            continue
        if in_ip_section or '/ip address add' in stripped:
            addr_m = re.search(r'address=([^\s]+)', stripped)
            iface_m = re.search(r'interface=([^\s]+)', stripped)
            if addr_m and iface_m:
                mappings[addr_m.group(1)] = iface_m.group(1)
    return mappings


# ═══════════════════════════════════════════════════════════════
# RICH SOURCE CONFIGS (many IPs, diverse sections)
# ═══════════════════════════════════════════════════════════════

def make_rich_ccr1072_config():
    """CCR1072-12G-4S+ with 16 IP addresses, OSPF, MPLS, firewall, VLANs."""
    return r"""# 2025-01-10 08:30:00 by RouterOS 7.19.4
# model = CCR1072-12G-4S+

/interface bridge
add name=bridge1 protocol-mode=rstp

/interface ethernet
set [ find default-name=ether1 ] comment="Management" speed=1G-baseT-full
set [ find default-name=ether2 ] comment="Switch-Netonix-1" speed=1G-baseT-full
set [ find default-name=ether3 ] comment="Switch-Netonix-2" speed=1G-baseT-full
set [ find default-name=ether4 ] comment="ICT-UPS-1" speed=1G-baseT-full
set [ find default-name=ether5 ] comment="TX-DALLAS-BH-1" speed=1G-baseT-full
set [ find default-name=ether6 ] comment="TX-HOUSTON-BH-2" speed=1G-baseT-full
set [ find default-name=ether7 ] comment="KS-TOPEKA-BH-3" speed=1G-baseT-full
set [ find default-name=ether8 ] comment="Tarana-Alpha-1" speed=1G-baseT-full
set [ find default-name=ether9 ] comment="LTE-Backup" speed=1G-baseT-full
set [ find default-name=ether10 ] comment="Spare-1" speed=1G-baseT-full
set [ find default-name=ether11 ] comment="Spare-2" speed=1G-baseT-full
set [ find default-name=ether12 ] comment="Spare-3" speed=1G-baseT-full
set [ find default-name=sfp1 ] comment="Uplink-Fiber-1"
set [ find default-name=sfp2 ] comment="Uplink-Fiber-2"
set [ find default-name=sfp3 ] comment="Ring-Fiber-A"
set [ find default-name=sfp4 ] comment="Ring-Fiber-B"

/interface vlan
add interface=ether2 name=vlan100-mgmt vlan-id=100
add interface=ether3 name=vlan200-data vlan-id=200

/ip address
add address=192.168.88.1/24 interface=ether1 comment="Management"
add address=10.10.1.1/29 interface=ether2 comment="Switch-1"
add address=10.10.2.1/29 interface=ether3 comment="Switch-2"
add address=10.10.3.1/29 interface=ether4 comment="UPS"
add address=10.10.4.1/30 interface=ether5 comment="BH-Dallas"
add address=10.10.5.1/30 interface=ether6 comment="BH-Houston"
add address=10.10.6.1/30 interface=ether7 comment="BH-Topeka"
add address=10.10.7.1/30 interface=ether8 comment="Tarana"
add address=10.10.8.1/30 interface=ether9 comment="LTE"
add address=10.10.9.1/30 interface=ether10 comment="Spare-Link-1"
add address=10.10.10.1/30 interface=ether11 comment="Spare-Link-2"
add address=10.20.1.1/30 interface=sfp1 comment="Uplink-1"
add address=10.20.2.1/30 interface=sfp2 comment="Uplink-2"
add address=10.20.3.1/30 interface=sfp3 comment="Ring-A"
add address=10.20.4.1/30 interface=sfp4 comment="Ring-B"
add address=10.0.0.1/32 interface=loop0 comment="Loopback"
add address=172.16.100.1/24 interface=vlan100-mgmt comment="VLAN-100-Mgmt"
add address=172.16.200.1/24 interface=vlan200-data comment="VLAN-200-Data"

/routing ospf instance
add disabled=no name=default-v2 router-id=10.0.0.1

/routing ospf area
add disabled=no instance=default-v2 name=backbone-v2

/routing ospf interface-template
add area=backbone-v2 interfaces=ether5 type=ptp networks=10.10.4.0/30
add area=backbone-v2 interfaces=ether6 type=ptp networks=10.10.5.0/30
add area=backbone-v2 interfaces=ether7 type=ptp networks=10.10.6.0/30
add area=backbone-v2 interfaces=sfp1 type=ptp networks=10.20.1.0/30
add area=backbone-v2 interfaces=sfp2 type=ptp networks=10.20.2.0/30
add area=backbone-v2 interfaces=loop0 passive type=ptp networks=10.0.0.1/32

/mpls ldp
set enabled=yes lsr-id=10.0.0.1 transport-addresses=10.0.0.1

/mpls ldp interface
add interface=ether5
add interface=ether6
add interface=sfp1
add interface=sfp2

/ip firewall filter
add chain=input action=accept protocol=icmp
add chain=input action=accept connection-state=established,related
add chain=input action=accept src-address=192.168.88.0/24 comment="Allow management subnet"
add chain=input action=accept src-address=10.0.0.0/8 comment="Allow internal"
add chain=forward action=accept connection-state=established,related
add chain=forward action=drop connection-state=invalid

/ip firewall nat
add chain=srcnat action=masquerade out-interface=sfp1 src-address=172.16.0.0/16

/ip route
add dst-address=0.0.0.0/0 gateway=10.20.1.2 comment="Default route via Uplink-1"

/system identity
set name=RTR-MT1072-TOWER-A
"""


def make_rich_ccr2004_12s_config():
    """CCR2004-1G-12S+2XS with diverse IPs across sfp-sfpplus and sfp28."""
    return r"""# 2025-01-10 08:30:00 by RouterOS 7.19.4
# model = CCR2004-1G-12S+2XS

/interface bridge
add name=bridge1 protocol-mode=rstp

/interface ethernet
set [ find default-name=ether1 ] comment="Management" speed=1G-baseT-full
set [ find default-name=sfp-sfpplus1 ] comment="Switch-Netonix-1" speed=10G-baseSR-LR
set [ find default-name=sfp-sfpplus2 ] comment="Switch-Netonix-2" speed=10G-baseSR-LR
set [ find default-name=sfp-sfpplus3 ] comment="ICT-UPS-1" speed=10G-baseSR-LR
set [ find default-name=sfp-sfpplus4 ] comment="TX-DALLAS-BH-1" speed=10G-baseSR-LR
set [ find default-name=sfp-sfpplus5 ] comment="TX-HOUSTON-BH-2" speed=10G-baseSR-LR
set [ find default-name=sfp-sfpplus6 ] comment="KS-TOPEKA-BH-3" speed=10G-baseSR-LR
set [ find default-name=sfp-sfpplus7 ] comment="Tarana-Alpha-1" speed=10G-baseSR-LR
set [ find default-name=sfp-sfpplus8 ] comment="LTE-Backup" speed=10G-baseSR-LR
set [ find default-name=sfp-sfpplus9 ] comment="Spare-1"
set [ find default-name=sfp-sfpplus10 ] comment="Spare-2"
set [ find default-name=sfp-sfpplus11 ] comment="Spare-3"
set [ find default-name=sfp-sfpplus12 ] comment="Spare-4"
set [ find default-name=sfp28-1 ] comment="Core-Uplink-25G-A" speed=25G-baseR
set [ find default-name=sfp28-2 ] comment="Core-Uplink-25G-B" speed=25G-baseR

/ip address
add address=192.168.88.1/24 interface=ether1 comment="Management"
add address=10.10.1.1/29 interface=sfp-sfpplus1 comment="Switch-1"
add address=10.10.2.1/29 interface=sfp-sfpplus2 comment="Switch-2"
add address=10.10.3.1/29 interface=sfp-sfpplus3 comment="UPS"
add address=10.10.4.1/29 interface=sfp-sfpplus4 comment="BH-Dallas"
add address=10.10.5.1/29 interface=sfp-sfpplus5 comment="BH-Houston"
add address=10.10.6.1/29 interface=sfp-sfpplus6 comment="BH-Topeka"
add address=10.10.7.1/30 interface=sfp-sfpplus7 comment="Tarana"
add address=10.10.8.1/30 interface=sfp-sfpplus8 comment="LTE"
add address=10.10.9.1/30 interface=sfp-sfpplus9 comment="Spare-Link-1"
add address=10.10.10.1/30 interface=sfp-sfpplus10 comment="Spare-Link-2"
add address=10.10.11.1/30 interface=sfp-sfpplus11 comment="Spare-Link-3"
add address=10.10.12.1/30 interface=sfp-sfpplus12 comment="Spare-Link-4"
add address=10.20.1.1/30 interface=sfp28-1 comment="Core-A"
add address=10.20.2.1/30 interface=sfp28-2 comment="Core-B"
add address=10.0.0.1/32 interface=loop0 comment="Loopback"

/routing ospf instance
add disabled=no name=default-v2 router-id=10.0.0.1

/routing ospf area
add disabled=no instance=default-v2 name=backbone-v2

/routing ospf interface-template
add area=backbone-v2 interfaces=sfp-sfpplus4 type=ptp networks=10.10.4.0/29
add area=backbone-v2 interfaces=sfp-sfpplus5 type=ptp networks=10.10.5.0/29
add area=backbone-v2 interfaces=sfp-sfpplus6 type=ptp networks=10.10.6.0/29
add area=backbone-v2 interfaces=sfp28-1 type=ptp networks=10.20.1.0/30
add area=backbone-v2 interfaces=sfp28-2 type=ptp networks=10.20.2.0/30
add area=backbone-v2 interfaces=loop0 passive type=ptp networks=10.0.0.1/32

/mpls ldp
set enabled=yes lsr-id=10.0.0.1 transport-addresses=10.0.0.1

/mpls ldp interface
add interface=sfp-sfpplus4
add interface=sfp-sfpplus5
add interface=sfp28-1

/ip firewall filter
add chain=input action=accept protocol=icmp
add chain=input action=accept connection-state=established,related
add chain=input action=accept src-address=192.168.88.0/24 comment="Allow management"
add chain=forward action=accept connection-state=established,related
add chain=forward action=drop connection-state=invalid

/ip route
add dst-address=0.0.0.0/0 gateway=10.20.1.2 comment="Default via Core-A"

/system identity
set name=RTR-MT2004-TOWER-A
"""


def make_rich_ccr2116_config():
    """CCR2116-12G-4S+ with 12 ether + 4 sfp-sfpplus, all populated."""
    return r"""# 2025-01-10 08:30:00 by RouterOS 7.19.4
# model = CCR2116-12G-4S+

/interface ethernet
set [ find default-name=ether1 ] comment="Management" speed=1G-baseT-full
set [ find default-name=ether2 ] comment="Switch-Netonix-1" speed=1G-baseT-full
set [ find default-name=ether3 ] comment="Switch-Netonix-2" speed=1G-baseT-full
set [ find default-name=ether4 ] comment="ICT-UPS-1" speed=1G-baseT-full
set [ find default-name=ether5 ] comment="TX-DALLAS-BH-1" speed=1G-baseT-full
set [ find default-name=ether6 ] comment="TX-HOUSTON-BH-2" speed=1G-baseT-full
set [ find default-name=ether7 ] comment="KS-TOPEKA-BH-3" speed=1G-baseT-full
set [ find default-name=ether8 ] comment="Tarana-Alpha-1" speed=1G-baseT-full
set [ find default-name=ether9 ] comment="LTE-Backup" speed=1G-baseT-full
set [ find default-name=ether10 ] comment="Spare-1" speed=1G-baseT-full
set [ find default-name=ether11 ] comment="Spare-2" speed=1G-baseT-full
set [ find default-name=ether12 ] comment="Spare-3" speed=1G-baseT-full
set [ find default-name=sfp-sfpplus1 ] comment="Uplink-Fiber-1" speed=10G-baseSR-LR
set [ find default-name=sfp-sfpplus2 ] comment="Uplink-Fiber-2" speed=10G-baseSR-LR
set [ find default-name=sfp-sfpplus3 ] comment="Ring-Fiber-A" speed=10G-baseSR-LR
set [ find default-name=sfp-sfpplus4 ] comment="Ring-Fiber-B" speed=10G-baseSR-LR

/ip address
add address=192.168.88.1/24 interface=ether1 comment="Management"
add address=10.10.1.1/29 interface=ether2 comment="Switch-1"
add address=10.10.2.1/29 interface=ether3 comment="Switch-2"
add address=10.10.3.1/29 interface=ether4 comment="UPS"
add address=10.10.4.1/30 interface=ether5 comment="BH-Dallas"
add address=10.10.5.1/30 interface=ether6 comment="BH-Houston"
add address=10.10.6.1/30 interface=ether7 comment="BH-Topeka"
add address=10.10.7.1/30 interface=ether8 comment="Tarana"
add address=10.10.8.1/30 interface=ether9 comment="LTE"
add address=10.10.9.1/30 interface=ether10 comment="Spare-1"
add address=10.10.10.1/30 interface=ether11 comment="Spare-2"
add address=10.10.11.1/30 interface=ether12 comment="Spare-3"
add address=10.20.1.1/30 interface=sfp-sfpplus1 comment="Uplink-1"
add address=10.20.2.1/30 interface=sfp-sfpplus2 comment="Uplink-2"
add address=10.20.3.1/30 interface=sfp-sfpplus3 comment="Ring-A"
add address=10.20.4.1/30 interface=sfp-sfpplus4 comment="Ring-B"
add address=10.0.0.5/32 interface=loop0 comment="Loopback"

/routing ospf instance
add disabled=no name=default-v2 router-id=10.0.0.5

/routing ospf area
add disabled=no instance=default-v2 name=backbone-v2

/routing ospf interface-template
add area=backbone-v2 interfaces=ether5 type=ptp networks=10.10.4.0/30
add area=backbone-v2 interfaces=ether6 type=ptp networks=10.10.5.0/30
add area=backbone-v2 interfaces=ether7 type=ptp networks=10.10.6.0/30
add area=backbone-v2 interfaces=sfp-sfpplus1 type=ptp networks=10.20.1.0/30
add area=backbone-v2 interfaces=sfp-sfpplus2 type=ptp networks=10.20.2.0/30
add area=backbone-v2 interfaces=sfp-sfpplus3 type=ptp networks=10.20.3.0/30
add area=backbone-v2 interfaces=loop0 passive type=ptp networks=10.0.0.5/32

/mpls ldp
set enabled=yes lsr-id=10.0.0.5 transport-addresses=10.0.0.5

/ip firewall filter
add chain=input action=accept protocol=icmp
add chain=input action=accept connection-state=established,related
add chain=forward action=accept connection-state=established,related

/ip route
add dst-address=0.0.0.0/0 gateway=10.20.1.2

/system identity
set name=RTR-MT2116-TOWER-D
"""


# ═══════════════════════════════════════════════════════════════
# TEST RUNNER
# ═══════════════════════════════════════════════════════════════

def run_ip_test(source_config, target_device, test_name, expected_ip_count):
    """Run a migration and deeply validate IP preservation."""
    print(f"\n{'━' * 70}")
    print(f"TEST: {test_name}")
    print(f"{'━' * 70}")

    # Count source IPs
    source_ip_lines = extract_ip_address_lines(source_config)
    source_ip_map = extract_ip_with_interface(source_config)
    source_all_ips = extract_all_ips(source_config)

    print(f"  Source: {len(source_ip_lines)} /ip address lines, {len(source_ip_map)} IP→interface mappings, {len(source_all_ips)} total IPs")

    check(f"Source has expected IP count ({expected_ip_count})",
          len(source_ip_map) >= expected_ip_count,
          f"Expected >={expected_ip_count}, got {len(source_ip_map)}")

    with app.test_client() as client:
        # Test with strict_preserve=True (the default "Upgrade Existing" path)
        payload = {
            'source_config': source_config,
            'target_device': target_device,
            'target_version': '7.19.4',
            'strict_preserve': True,
            'apply_compliance': False,
        }

        resp = client.post('/api/translate-config',
                           data=json.dumps(payload),
                           content_type='application/json')

        if not check("HTTP 200", resp.status_code == 200, f"Got {resp.status_code}"):
            return

        data = resp.get_json()
        if not check("success=true", data.get('success') is True, f"Got: {data.get('error', 'unknown')}"):
            return

        translated = data.get('translated_config', '')

        # Extract IPs from translated config
        trans_ip_lines = extract_ip_address_lines(translated)
        trans_ip_map = extract_ip_with_interface(translated)
        trans_all_ips = extract_all_ips(translated)

        print(f"  Translated: {len(trans_ip_lines)} /ip address lines, {len(trans_ip_map)} IP→interface mappings, {len(trans_all_ips)} total IPs")

        # ── Core IP preservation checks ──

        # 1. Every source IP address value must exist in translated
        source_addr_values = set()
        for addr in source_ip_map.keys():
            base = addr.split('/')[0]
            source_addr_values.add(base)

        trans_addr_values = set()
        for addr in trans_ip_map.keys():
            base = addr.split('/')[0]
            trans_addr_values.add(base)

        missing_base_ips = source_addr_values - trans_addr_values
        # Check if missing IPs are in PORT-EXHAUSTION comment lines (acceptable)
        port_exhaustion_ips = set()
        for line in translated.splitlines():
            if line.strip().startswith('# PORT-EXHAUSTION'):
                for m in re.finditer(r'address=([^\s]+)', line):
                    base = m.group(1).split('/')[0]
                    port_exhaustion_ips.add(base)

        truly_missing = missing_base_ips - port_exhaustion_ips

        check(f"All {len(source_addr_values)} IP base addresses preserved",
              len(truly_missing) == 0,
              f"MISSING IPs: {sorted(truly_missing)}" if truly_missing else "")

        if truly_missing:
            print(f"  *** CRITICAL: {len(truly_missing)} IPs LOST ***")
            for ip in sorted(truly_missing):
                # Find the original line
                for addr, iface in source_ip_map.items():
                    if addr.split('/')[0] == ip:
                        print(f"      LOST: address={addr} interface={iface}")
                        break

        # 2. Check /ip address line count
        ip_line_diff = len(source_ip_lines) - len(trans_ip_lines)
        # PORT-EXHAUSTION lines are acceptable losses
        port_exhaustion_count = sum(1 for l in translated.splitlines() 
                                     if l.strip().startswith('# PORT-EXHAUSTION') and 'address=' in l)
        adjusted_diff = ip_line_diff - port_exhaustion_count

        check(f"IP address line count preserved (source={len(source_ip_lines)}, trans={len(trans_ip_lines)}, exhaustion={port_exhaustion_count})",
              adjusted_diff <= 0,
              f"Lost {adjusted_diff} IP address lines (not in PORT-EXHAUSTION)")

        # 3. Check that /ip address section exists at all
        check("/ip address section exists",
              '/ip address' in translated.lower() or 'address=' in translated,
              "ENTIRE /ip address section missing!")

        # 4. Check loopback IP preserved
        has_loopback = bool(re.search(r'interface=loop0', translated))
        check("Loopback IP (loop0) preserved",
              has_loopback,
              "interface=loop0 missing from translated config")

        # 5. Management IP preserved  
        has_mgmt_ip = bool(re.search(r'192\.168\.88\.1', translated))
        check("Management IP 192.168.88.1 preserved",
              has_mgmt_ip,
              "Management IP missing")

        # 6. Check OSPF networks reference IPs that exist in /ip address
        ospf_networks = set()
        for m in re.finditer(r'networks?=([^\s]+)', translated):
            net = m.group(1)
            ospf_networks.add(net)

        # 7. Check that validation result matches
        validation = data.get('validation', {})
        val_missing = validation.get('missing_ips', [])
        check(f"Validation reports no missing IPs",
              len(val_missing) == 0,
              f"Validation missing_ips: {val_missing[:5]}")

        # 8. Check firewall rules preserved
        source_fw_count = len(re.findall(r'(?m)^add\s+chain=', source_config))
        trans_fw_count = len(re.findall(r'(?m)^add\s+chain=', translated))
        check(f"Firewall rules preserved ({source_fw_count} → {trans_fw_count})",
              trans_fw_count >= source_fw_count,
              f"Lost {source_fw_count - trans_fw_count} firewall rules")

        # 9. Check OSPF templates preserved
        source_ospf_count = len(re.findall(r'(?m)^add\s+area=', source_config))
        trans_ospf_count = len(re.findall(r'(?m)^add\s+area=', translated))
        check(f"OSPF interface-templates preserved ({source_ospf_count} → {trans_ospf_count})",
              trans_ospf_count >= source_ospf_count,
              f"Lost {source_ospf_count - trans_ospf_count} OSPF templates")

        # 10. Check /ip route preserved
        source_routes = len(re.findall(r'(?m)^add\s+dst-address=', source_config))
        if source_routes > 0:
            trans_routes = len(re.findall(r'(?m)^add\s+dst-address=', translated))
            check(f"IP routes preserved ({source_routes} → {trans_routes})",
                  trans_routes >= source_routes,
                  f"Lost {source_routes - trans_routes} routes")

        return translated


# ═══════════════════════════════════════════════════════════════
# MAIN TEST SUITE
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("=" * 70)
    print("IP PRESERVATION DIAGNOSTIC TEST")
    print("Traces IPs through the full translate-config pipeline")
    print("=" * 70)

    # ── 1. CCR1072 → CCR2216 (12 ether + 4 sfp → 1 ether + 12 sfp28 + 2 qsfp) ──
    # This is the hardest case: 16 source ports → 15 target ports, different families
    run_ip_test(
        make_rich_ccr1072_config(),
        'CCR2216-1G-12XS-2XQ',
        'CCR1072 → CCR2216 (18 IPs, port family change)',
        18
    )

    # ── 2. CCR1072 → CCR2004-1G-12S+2XS (12 ether + 4 sfp → 1 ether + 12 sfp-sfpplus + 2 sfp28) ──
    run_ip_test(
        make_rich_ccr1072_config(),
        'CCR2004-1G-12S+2XS',
        'CCR1072 → CCR2004-12S (18 IPs, ether→sfp-sfpplus)',
        18
    )

    # ── 3. CCR1072 → CCR2004-16G-2S+ (12 ether → 16 ether, sfp → sfp-sfpplus) ──
    run_ip_test(
        make_rich_ccr1072_config(),
        'CCR2004-16G-2S+',
        'CCR1072 → CCR2004-16G (18 IPs, more ether available)',
        18
    )

    # ── 4. CCR1072 → CCR2116 (12 ether + 4 sfp → 12 ether + 4 sfp-sfpplus) ──
    run_ip_test(
        make_rich_ccr1072_config(),
        'CCR2116-12G-4S+',
        'CCR1072 → CCR2116 (18 IPs, same ether count)',
        18
    )

    # ── 5. CCR2004-12S → CCR2216 (hybrid sfp-sfpplus+sfp28 → sfp28-only) ──
    run_ip_test(
        make_rich_ccr2004_12s_config(),
        'CCR2216-1G-12XS-2XQ',
        'CCR2004-12S → CCR2216 (16 IPs, hybrid→sfp28)',
        16
    )

    # ── 6. CCR2004-12S → CCR2116 (hybrid → ether+sfp-sfpplus, port count mismatch) ──
    run_ip_test(
        make_rich_ccr2004_12s_config(),
        'CCR2116-12G-4S+',
        'CCR2004-12S → CCR2116 (16 IPs, 15 ports→16 ports)',
        16
    )

    # ── 7. CCR2116 → CCR2216 (ether+sfp-sfpplus → sfp28, port family change) ──
    run_ip_test(
        make_rich_ccr2116_config(),
        'CCR2216-1G-12XS-2XQ',
        'CCR2116 → CCR2216 (17 IPs, ether→sfp28)',
        17
    )

    # ── 8. CCR2116 → CCR2004-16G-2S+ (4 sfp-sfpplus → 2, ether mismatch) ──
    run_ip_test(
        make_rich_ccr2116_config(),
        'CCR2004-16G-2S+',
        'CCR2116 → CCR2004-16G (17 IPs, sfp-sfpplus count mismatch)',
        17
    )

    # ═══════════════════════════════════════════════════════════
    # FINAL RESULTS
    # ═══════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print(f"RESULTS: {PASS}/{PASS + FAIL} passed, {FAIL} failed")
    print("=" * 70)

    if FAIL == 0:
        print("ALL TESTS PASSED - No IP loss detected")
    else:
        print(f"SOME TESTS FAILED - {FAIL} IP preservation issues found")

    sys.exit(0 if FAIL == 0 else 1)
