#!/usr/bin/env python3
"""
CCR2004 / All-Routerboard Interface Migration Test
===================================================
Validates LIVE translate-config pipeline for:
  1. CCR2004-1G-12S+2XS → CCR2216 (hybrid sfp-sfpplus + sfp28 → sfp28-only)
  2. CCR2004-16G-2S+ → CCR2216 (16 ethernet → sfp28)
  3. CCR2216 → CCR2004-1G-12S+2XS (sfp28-only → hybrid)
  4. CCR2216 → CCR2004-16G-2S+ (sfp28 → 16 ethernet)
  5. CCR1072 → CCR2004-1G-12S+2XS (12 ether + sfp → sfp-sfpplus + sfp28)
  6. CCR1072 → CCR2004-16G-2S+ (12 ether + sfp → 16 ether + sfp-sfpplus)
  7. CCR2116 → CCR2004-16G-2S+ (12 ether + 4 sfp-sfpplus → 16 ether + 2 sfp-sfpplus)
  8. CCR2004-1G-12S+2XS → CCR2116 (hybrid → 12 ether + sfp-sfpplus)
  9. CCR2004-16G-2S+ → CCR2116 (16 ether → 12 ether)
  10. RB5009 → CCR2004-1G-12S+2XS
  11. RB5009 → CCR2216

Checks per migration:
  - HTTP 200, success=true
  - No port collisions (each target port used at most once in /interface ethernet set lines)
  - No dangling source ports (no reference to ports that don't exist on target)
  - Management port preserved (ether1)
  - Critical config sections preserved
  - Correct speed formats (no copper speeds on optical ports)
"""
import sys, os, re, json

os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'vm_deployment'))
sys.path.insert(0, '.')

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


# ── Target port definitions (mirror of ROUTERBOARD_INTERFACES) ──
TARGET_PORTS = {
    'CCR2004-1G-12S+2XS': ['ether1'] + [f'sfp-sfpplus{i}' for i in range(1, 13)] + ['sfp28-1', 'sfp28-2'],
    'CCR2004-16G-2S+': [f'ether{i}' for i in range(1, 17)] + ['sfp-sfpplus1', 'sfp-sfpplus2'],
    'CCR2116-12G-4S+': [f'ether{i}' for i in range(1, 13)] + [f'sfp-sfpplus{i}' for i in range(1, 5)],
    'CCR2216-1G-12XS-2XQ': ['ether1'] + [f'sfp28-{i}' for i in range(1, 13)] + ['qsfpplus1-1', 'qsfpplus2-1'],
    'CCR1072-12G-4S+': [f'ether{i}' for i in range(1, 13)] + [f'sfp{i}' for i in range(1, 5)],
    'RB5009UG+S+': [f'ether{i}' for i in range(1, 11)] + ['sfp-sfpplus1'],
}


COPPER_SPEEDS = {'1G-baseT-full', '100M-baseT-full', '1G-baseTX', '2.5G-baseT', '5G-baseT', '10G-baseT',
                 '1Gbps', '100Mbps'}

# ═══════════════════════════════════════════════════════════════
# SOURCE CONFIG GENERATORS
# ═══════════════════════════════════════════════════════════════

def make_ccr2004_12s_config():
    """CCR2004-1G-12S+2XS source config with BOTH sfp-sfpplus AND sfp28 ports."""
    return r"""# 2025-01-10 08:30:00 by RouterOS 7.19.4
# model = CCR2004-1G-12S+2XS

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

/mpls ldp
set enabled=yes lsr-id=10.0.0.1 transport-addresses=10.0.0.1

/mpls ldp interface
add interface=sfp-sfpplus4
add interface=sfp-sfpplus5
add interface=sfp28-1

/ip firewall filter
add chain=input action=accept protocol=icmp
add chain=forward action=accept connection-state=established,related

/system identity
set name=RTR-MT2004-TOWER-A
"""


def make_ccr2004_16g_config():
    """CCR2004-16G-2S+ source config with 16 ethernet + 2 sfp-sfpplus."""
    return r"""# 2025-01-10 08:30:00 by RouterOS 7.19.4
# model = CCR2004-16G-2S+

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
set [ find default-name=ether13 ] comment="Spare-4" speed=1G-baseT-full
set [ find default-name=ether14 ] comment="Spare-5" speed=1G-baseT-full
set [ find default-name=ether15 ] comment="Spare-6" speed=1G-baseT-full
set [ find default-name=ether16 ] comment="Spare-7" speed=1G-baseT-full
set [ find default-name=sfp-sfpplus1 ] comment="Uplink-Fiber-1" speed=10G-baseSR-LR
set [ find default-name=sfp-sfpplus2 ] comment="Uplink-Fiber-2" speed=10G-baseSR-LR

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
add address=10.20.1.1/30 interface=sfp-sfpplus1 comment="Uplink-1"
add address=10.20.2.1/30 interface=sfp-sfpplus2 comment="Uplink-2"
add address=10.0.0.2/32 interface=loop0 comment="Loopback"

/routing ospf instance
add disabled=no name=default-v2 router-id=10.0.0.2

/routing ospf area
add disabled=no instance=default-v2 name=backbone-v2

/routing ospf interface-template
add area=backbone-v2 interfaces=ether5 type=ptp networks=10.10.4.0/30
add area=backbone-v2 interfaces=ether6 type=ptp networks=10.10.5.0/30
add area=backbone-v2 interfaces=sfp-sfpplus1 type=ptp networks=10.20.1.0/30

/ip firewall filter
add chain=input action=accept protocol=icmp
add chain=forward action=accept connection-state=established,related

/system identity
set name=RTR-MT2004-16G-SITE
"""


def make_ccr2216_config():
    """CCR2216-1G-12XS-2XQ source config with sfp28 ports."""
    return r"""# 2025-01-10 08:30:00 by RouterOS 7.19.4
# model = CCR2216-1G-12XS-2XQ

/interface ethernet
set [ find default-name=ether1 ] comment="Management" speed=1G-baseT-full
set [ find default-name=sfp28-1 ] comment="Switch-Netonix-1" speed=10G-baseSR-LR
set [ find default-name=sfp28-2 ] comment="Switch-Netonix-2" speed=10G-baseSR-LR
set [ find default-name=sfp28-3 ] comment="ICT-UPS-1" speed=10G-baseSR-LR
set [ find default-name=sfp28-4 ] comment="TX-DALLAS-BH-1" speed=10G-baseSR-LR
set [ find default-name=sfp28-5 ] comment="TX-HOUSTON-BH-2" speed=10G-baseSR-LR
set [ find default-name=sfp28-6 ] comment="KS-TOPEKA-BH-3" speed=10G-baseSR-LR
set [ find default-name=sfp28-7 ] comment="Tarana-Alpha-1" speed=10G-baseSR-LR
set [ find default-name=sfp28-8 ] comment="LTE-Backup" speed=10G-baseSR-LR
set [ find default-name=sfp28-9 ] comment="Spare-1"
set [ find default-name=sfp28-10 ] comment="Spare-2"
set [ find default-name=sfp28-11 ] comment="Spare-3"
set [ find default-name=sfp28-12 ] comment="Spare-4"
set [ find default-name=qsfpplus1-1 ] comment="100G-Core-A"
set [ find default-name=qsfpplus2-1 ] comment="100G-Core-B"

/ip address
add address=192.168.88.1/24 interface=ether1 comment="Management"
add address=10.10.1.1/29 interface=sfp28-1 comment="Switch-1"
add address=10.10.2.1/29 interface=sfp28-2 comment="Switch-2"
add address=10.10.3.1/29 interface=sfp28-3 comment="UPS"
add address=10.10.4.1/29 interface=sfp28-4 comment="BH-Dallas"
add address=10.10.5.1/29 interface=sfp28-5 comment="BH-Houston"
add address=10.10.6.1/29 interface=sfp28-6 comment="BH-Topeka"
add address=10.10.7.1/30 interface=sfp28-7 comment="Tarana"
add address=10.10.8.1/30 interface=sfp28-8 comment="LTE"
add address=10.0.0.3/32 interface=loop0 comment="Loopback"

/routing ospf instance
add disabled=no name=default-v2 router-id=10.0.0.3

/routing ospf area
add disabled=no instance=default-v2 name=backbone-v2

/routing ospf interface-template
add area=backbone-v2 interfaces=sfp28-4 type=ptp networks=10.10.4.0/29
add area=backbone-v2 interfaces=sfp28-5 type=ptp networks=10.10.5.0/29
add area=backbone-v2 interfaces=sfp28-6 type=ptp networks=10.10.6.0/29

/ip firewall filter
add chain=input action=accept protocol=icmp
add chain=forward action=accept connection-state=established,related

/system identity
set name=RTR-MT2216-TOWER-B
"""


def make_ccr1072_config():
    """CCR1072-12G-4S+ source config with 12 ether + 4 sfp."""
    return r"""# 2025-01-10 08:30:00 by RouterOS 7.19.4
# model = CCR1072-12G-4S+

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
set [ find default-name=sfp1 ] comment="Uplink-1"
set [ find default-name=sfp2 ] comment="Uplink-2"
set [ find default-name=sfp3 ] comment="Spare"
set [ find default-name=sfp4 ] comment="Spare"

/ip address
add address=192.168.88.1/24 interface=ether1 comment="Management"
add address=10.10.1.1/29 interface=ether2 comment="Switch-1"
add address=10.10.2.1/29 interface=ether3 comment="Switch-2"
add address=10.10.3.1/29 interface=ether4 comment="UPS"
add address=10.10.4.1/30 interface=ether5 comment="BH-Dallas"
add address=10.10.5.1/30 interface=ether6 comment="BH-Houston"
add address=10.10.6.1/30 interface=ether7 comment="BH-Topeka"
add address=10.0.0.4/32 interface=loop0 comment="Loopback"

/routing ospf instance
add disabled=no name=default-v2 router-id=10.0.0.4

/routing ospf area
add disabled=no instance=default-v2 name=backbone-v2

/routing ospf interface-template
add area=backbone-v2 interfaces=ether5 type=ptp networks=10.10.4.0/30
add area=backbone-v2 interfaces=ether6 type=ptp networks=10.10.5.0/30

/ip firewall filter
add chain=input action=accept protocol=icmp
add chain=forward action=accept connection-state=established,related

/system identity
set name=RTR-MT1072-TOWER-C
"""


def make_ccr2116_config():
    """CCR2116-12G-4S+ source config with 12 ether + 4 sfp-sfpplus."""
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
set [ find default-name=sfp-sfpplus3 ] comment="Ring-A" speed=10G-baseSR-LR
set [ find default-name=sfp-sfpplus4 ] comment="Ring-B" speed=10G-baseSR-LR

/ip address
add address=192.168.88.1/24 interface=ether1 comment="Management"
add address=10.10.1.1/29 interface=ether2 comment="Switch-1"
add address=10.10.2.1/29 interface=ether3 comment="Switch-2"
add address=10.10.3.1/29 interface=ether4 comment="UPS"
add address=10.10.4.1/30 interface=ether5 comment="BH-Dallas"
add address=10.10.5.1/30 interface=ether6 comment="BH-Houston"
add address=10.10.6.1/30 interface=ether7 comment="BH-Topeka"
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
add area=backbone-v2 interfaces=sfp-sfpplus1 type=ptp networks=10.20.1.0/30
add area=backbone-v2 interfaces=sfp-sfpplus3 type=ptp networks=10.20.3.0/30

/ip firewall filter
add chain=input action=accept protocol=icmp
add chain=forward action=accept connection-state=established,related

/system identity
set name=RTR-MT2116-TOWER-D
"""


def make_rb5009_config():
    """RB5009UG+S+ source config with 10 ether + 1 sfp-sfpplus."""
    return r"""# 2025-01-10 08:30:00 by RouterOS 7.19.4
# model = RB5009UG+S+

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
set [ find default-name=ether10 ] comment="Spare" speed=1G-baseT-full
set [ find default-name=sfp-sfpplus1 ] comment="Uplink-Fiber" speed=10G-baseSR-LR

/ip address
add address=192.168.88.1/24 interface=ether1 comment="Management"
add address=10.10.1.1/29 interface=ether2 comment="Switch-1"
add address=10.10.2.1/29 interface=ether3 comment="Switch-2"
add address=10.10.3.1/29 interface=ether4 comment="UPS"
add address=10.10.4.1/30 interface=ether5 comment="BH-Dallas"
add address=10.10.5.1/30 interface=ether6 comment="BH-Houston"
add address=10.10.6.1/30 interface=ether7 comment="BH-Topeka"
add address=10.20.1.1/30 interface=sfp-sfpplus1 comment="Uplink"
add address=10.0.0.6/32 interface=loop0 comment="Loopback"

/routing ospf instance
add disabled=no name=default-v2 router-id=10.0.0.6

/routing ospf area
add disabled=no instance=default-v2 name=backbone-v2

/routing ospf interface-template
add area=backbone-v2 interfaces=ether5 type=ptp networks=10.10.4.0/30
add area=backbone-v2 interfaces=ether6 type=ptp networks=10.10.5.0/30

/ip firewall filter
add chain=input action=accept protocol=icmp
add chain=forward action=accept connection-state=established,related

/system identity
set name=RTR-RB5009-TOWER-E
"""


# ═══════════════════════════════════════════════════════════════
# VALIDATION HELPERS
# ═══════════════════════════════════════════════════════════════

def find_all_interface_refs(config_text):
    """Find all interface references in the translated config (excluding commented-out lines)."""
    # Filter out PORT-EXHAUSTION commented lines before searching
    active_lines = '\n'.join(
        line for line in config_text.splitlines()
        if not line.strip().startswith('# PORT-EXHAUSTION')
    )
    # Order matters: sfp28-\d+ must come before sfp\d+ to avoid partial match
    return set(re.findall(
        r'\b(ether\d+|sfp28-\d+|sfp-sfpplus\d+|qsfp28-\d+-\d+|qsfpplus\d+-\d+|sfp(?!28)(?!-sfpplus)\d+|combo\d+)\b',
        active_lines
    ))


def find_ethernet_set_ports(config_text):
    """Extract ports from /interface ethernet set lines, checking for collisions.
    Excludes PORT-EXHAUSTION commented lines."""
    active_lines = '\n'.join(
        line for line in config_text.splitlines()
        if not line.strip().startswith('# PORT-EXHAUSTION')
    )
    ports = re.findall(r'set\s+\[\s*find\s+default-name=(\S+)\s*\]', active_lines)
    return ports


def check_no_copper_on_optical(config_text, target_model):
    """Verify no copper speed formats appear on optical ports in the translated config."""
    violations = []
    for line in config_text.splitlines():
        if line.strip().startswith('# PORT-EXHAUSTION'):
            continue
        m = re.search(r'set\s+\[\s*find\s+default-name=(\S+)\s*\][^\n]*speed=(\S+)', line)
        if m:
            port, speed = m.group(1), m.group(2)
            is_optical = port.startswith('sfp28-') or port.startswith('sfp-sfpplus') or port.startswith('qsfp')
            if is_optical and speed in COPPER_SPEEDS:
                violations.append(f"{port} has copper speed {speed}")
    return violations


def run_migration(source_config, target_device, test_name):
    """Run a single migration test and validate the results."""
    print(f"\n{'─' * 70}")
    print(f"TEST: {test_name}")
    print(f"{'─' * 70}")

    target_ports = TARGET_PORTS.get(target_device, [])

    with app.test_client() as client:
        payload = {
            'source_config': source_config,
            'target_device': target_device,
            'target_version': '7.19.4',
            'strict_preserve': True,
            'apply_compliance': False,  # Skip compliance to focus on interface mapping
        }

        resp = client.post('/api/translate-config',
                           data=json.dumps(payload),
                           content_type='application/json')

        if not check(f"HTTP 200", resp.status_code == 200, f"Got {resp.status_code}"):
            return ""

        data = resp.get_json()
        if not check(f"success=true", data.get('success') is True, f"Got {data.get('success')}"):
            if data.get('error'):
                print(f"         Error: {data['error']}")
            return ""

        translated = data.get('translated_config', '')
        check(f"Non-empty output", len(translated) > 200, f"Got {len(translated)} chars")

        # ── Port collision check ──
        set_ports = find_ethernet_set_ports(translated)
        port_counts = {}
        for p in set_ports:
            port_counts[p] = port_counts.get(p, 0) + 1
        collisions = {p: c for p, c in port_counts.items() if c > 1}
        check(f"No port collisions in /interface ethernet set",
              len(collisions) == 0,
              f"Collisions: {collisions}" if collisions else "")

        # ── Dangling source port check ──
        all_refs = find_all_interface_refs(translated)
        valid_ports = set(target_ports) | {'loop0'}  # loop0 is virtual
        dangling = set()
        for ref in all_refs:
            if ref not in valid_ports:
                # Allow ether1 always (management)
                dangling.add(ref)
        check(f"No dangling/invalid ports",
              len(dangling) == 0,
              f"Invalid port refs: {sorted(dangling)}" if dangling else "")

        # ── Management port preserved ──
        check(f"Management port ether1 present",
              'ether1' in translated,
              "ether1 reference missing")

        # ── Critical sections preserved ──
        check(f"OSPF instance preserved",
              'routing ospf instance' in translated or 'ospf instance' in translated.lower())
        check(f"Firewall filter preserved",
              'firewall filter' in translated or 'ip firewall' in translated.lower())

        # ── Speed format check ──
        copper_violations = check_no_copper_on_optical(translated, target_device)
        check(f"No copper speeds on optical ports",
              len(copper_violations) == 0,
              f"Violations: {copper_violations}" if copper_violations else "")

        # ── IP address section preserved ──
        check(f"IP addresses preserved",
              'ip address' in translated.lower() and '10.10.' in translated)

        return translated


# ═══════════════════════════════════════════════════════════════
# MAIN TEST SUITE
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    print("=" * 70)
    print("CCR2004 / ALL-ROUTERBOARD INTERFACE MIGRATION TEST")
    print("Live translate-config pipeline via Flask test client")
    print("=" * 70)

    results = {}

    # ── 1. CCR2004-1G-12S+2XS → CCR2216 (THE PRIMARY BUG: hybrid ports) ──
    t = run_migration(make_ccr2004_12s_config(), 'CCR2216-1G-12XS-2XQ',
                      'CCR2004-1G-12S+2XS → CCR2216 (hybrid sfp-sfpplus+sfp28 → sfp28)')
    if t:
        # Extra: verify BOTH sfp-sfpplus AND sfp28 ports from source got mapped
        has_sfp_sfpplus = bool(re.search(r'\bsfp-sfpplus\d+\b', t))
        check("No sfp-sfpplus refs remain (target has no sfp-sfpplus)",
              not has_sfp_sfpplus,
              f"Found sfp-sfpplus in output (CCR2216 has no sfp-sfpplus ports)")
        # Verify sfp28 and/or qsfp ports used
        sfp28_refs = set(re.findall(r'\bsfp28-\d+\b', t))
        check("sfp28 ports used in output",
              len(sfp28_refs) > 0,
              f"No sfp28 references found")

    # ── 2. CCR2004-16G-2S+ → CCR2216 ──
    t = run_migration(make_ccr2004_16g_config(), 'CCR2216-1G-12XS-2XQ',
                      'CCR2004-16G-2S+ → CCR2216 (16 ether → sfp28)')
    if t:
        # Active (non-commented) ether refs should only be ether1 (management)
        active_lines = '\n'.join(l for l in t.splitlines() if not l.strip().startswith('# PORT-EXHAUSTION'))
        ether_refs = set(re.findall(r'\bether\d+\b', active_lines))
        non_mgmt_ether = ether_refs - {'ether1'}
        check("Excess ether ports handled (mapped or commented out)",
              len(non_mgmt_ether) == 0,
              f"Remaining active non-mgmt ethers: {sorted(non_mgmt_ether)}")

    # ── 3. CCR2216 → CCR2004-1G-12S+2XS ──
    t = run_migration(make_ccr2216_config(), 'CCR2004-1G-12S+2XS',
                      'CCR2216 → CCR2004-1G-12S+2XS (sfp28 → hybrid)')
    if t:
        # sfp28-3 through sfp28-12 should be remapped (target only has sfp28-1,2)
        high_sfp28 = set(re.findall(r'\bsfp28-([3-9]|1[0-2])\b', t))
        check("High sfp28 indices (3-12) remapped to sfp-sfpplus or sfp28-1/2",
              len(high_sfp28) == 0,
              f"Dangling high sfp28 refs: sfp28-{sorted(high_sfp28)}")

    # ── 4. CCR2216 → CCR2004-16G-2S+ ──
    t = run_migration(make_ccr2216_config(), 'CCR2004-16G-2S+',
                      'CCR2216 → CCR2004-16G-2S+ (sfp28 → 16 ether)')
    if t:
        # All sfp28 ports should be remapped to ether or sfp-sfpplus
        remaining_sfp28 = set(re.findall(r'\bsfp28-\d+\b', t))
        check("All sfp28 refs remapped (target has no sfp28 ports)",
              len(remaining_sfp28) == 0,
              f"Remaining sfp28: {sorted(remaining_sfp28)}")

    # ── 5. CCR1072 → CCR2004-1G-12S+2XS ──
    t = run_migration(make_ccr1072_config(), 'CCR2004-1G-12S+2XS',
                      'CCR1072 → CCR2004-1G-12S+2XS (12 ether+sfp → sfp-sfpplus+sfp28)')
    if t:
        dangling_high_ether = set(re.findall(r'\bether(1[0-2]|[2-9])\b', t))
        # Source ether ports should be remapped to sfp-sfpplus
        sfp_refs = set(re.findall(r'\bsfp-sfpplus\d+\b', t))
        check("sfp-sfpplus ports used for ether→optical mapping",
              len(sfp_refs) > 0,
              "No sfp-sfpplus ports found in output")

    # ── 6. CCR1072 → CCR2004-16G-2S+ ──
    t = run_migration(make_ccr1072_config(), 'CCR2004-16G-2S+',
                      'CCR1072 → CCR2004-16G-2S+ (12 ether+sfp → 16 ether+sfp-sfpplus)')

    # ── 7. CCR2116 → CCR2004-16G-2S+ (sfp-sfpplus count mismatch) ──
    t = run_migration(make_ccr2116_config(), 'CCR2004-16G-2S+',
                      'CCR2116 → CCR2004-16G-2S+ (4 sfp-sfpplus → 2 sfp-sfpplus)')
    if t:
        # sfp-sfpplus3 and sfp-sfpplus4 don't exist on target - should be remapped
        invalid_sfpplus = set()
        for idx in re.findall(r'\bsfp-sfpplus(\d+)\b', t):
            if int(idx) > 2:
                invalid_sfpplus.add(f'sfp-sfpplus{idx}')
        check("No dangling sfp-sfpplus3/4 (target only has 1-2)",
              len(invalid_sfpplus) == 0,
              f"Dangling: {sorted(invalid_sfpplus)}")

    # ── 8. CCR2004-1G-12S+2XS → CCR2116 ──
    t = run_migration(make_ccr2004_12s_config(), 'CCR2116-12G-4S+',
                      'CCR2004-1G-12S+2XS → CCR2116 (hybrid → 12 ether+sfp-sfpplus)')
    if t:
        remaining_sfp28 = set(re.findall(r'\bsfp28-\d+\b', t))
        check("No sfp28 refs remain (CCR2116 has no sfp28 ports)",
              len(remaining_sfp28) == 0,
              f"Remaining sfp28: {sorted(remaining_sfp28)}")

    # ── 9. CCR2004-16G-2S+ → CCR2116 ──
    t = run_migration(make_ccr2004_16g_config(), 'CCR2116-12G-4S+',
                      'CCR2004-16G-2S+ → CCR2116 (16 ether → 12 ether)')
    if t:
        active_lines = '\n'.join(l for l in t.splitlines() if not l.strip().startswith('# PORT-EXHAUSTION'))
        dangling_high = set()
        for idx in re.findall(r'\bether(\d+)\b', active_lines):
            if int(idx) > 12:
                dangling_high.add(f'ether{idx}')
        check("No active ether13-16 refs (CCR2116 has 12 ether max)",
              len(dangling_high) == 0,
              f"Dangling: {sorted(dangling_high)}")

    # ── 10. RB5009 → CCR2004-1G-12S+2XS ──
    t = run_migration(make_rb5009_config(), 'CCR2004-1G-12S+2XS',
                      'RB5009 → CCR2004-1G-12S+2XS')

    # ── 11. RB5009 → CCR2216 ──
    t = run_migration(make_rb5009_config(), 'CCR2216-1G-12XS-2XQ',
                      'RB5009 → CCR2216')
    if t:
        has_sfp_sfpplus = bool(re.search(r'\bsfp-sfpplus\d+\b', t))
        check("No sfp-sfpplus refs remain (CCR2216 has no sfp-sfpplus)",
              not has_sfp_sfpplus,
              f"Found sfp-sfpplus in output")

    # ═══════════════════════════════════════════════════════════
    # FINAL RESULTS
    # ═══════════════════════════════════════════════════════════
    print("\n" + "=" * 70)
    print(f"RESULTS: {PASS}/{PASS + FAIL} passed, {FAIL} failed")
    print("=" * 70)

    if FAIL == 0:
        print("ALL TESTS PASSED")
    else:
        print("SOME TESTS FAILED")

    sys.exit(0 if FAIL == 0 else 1)
