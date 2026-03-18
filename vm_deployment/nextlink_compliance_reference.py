"""
NextLink RFC-09-10-25 Compliance Reference
This file contains compliance validation and the GitLab compliance loader interface.
Based on RFC-09-10-25-Compliance Script Rollout

GitLab is the SINGLE SOURCE OF TRUTH for all compliance data.
get_all_compliance_blocks() fetches live compliance from the GitLab
netforge/compliance repository.  There is NO hardcoded fallback —
when GitLab is unavailable, an empty dict is returned with a clear warning.

The COMPLIANCE_* constants below are DEPRECATED references only (retained
for historical context).  They are NOT used as fallbacks.
"""

# GitLab dynamic compliance loader — single source of truth
try:
    from gitlab_compliance import get_loader as _get_gitlab_loader
    _HAS_GITLAB_NCR = True
except ImportError:
    try:
        from vm_deployment.gitlab_compliance import get_loader as _get_gitlab_loader
        _HAS_GITLAB_NCR = True
    except ImportError:
        _HAS_GITLAB_NCR = False
        _get_gitlab_loader = None  # type: ignore[assignment]

# ========================================
# COMPLIANCE: IP SERVICES
# ========================================
COMPLIANCE_IP_SERVICES = """
/ip service
set telnet disabled=yes port=5023
set ftp disabled=yes port=5021
set www disabled=yes port=1234
set api disabled=yes
set api-ssl disabled=yes
set www-ssl disabled=no port=443
set winbox port=8291 address="" disabled=no
set ssh port=22 address="" disabled=no
"""

# ========================================
# COMPLIANCE: DNS SERVERS
# ========================================
COMPLIANCE_DNS_SERVERS = "142.147.112.3,142.147.112.19"

COMPLIANCE_DNS = f"""
/ip dns
set servers={COMPLIANCE_DNS_SERVERS}
"""

# ========================================
# COMPLIANCE: FIREWALL ADDRESS LISTS
# ========================================
# Each entry is (address, comment) to match GitLab TX-ARv2.rsc format.
COMPLIANCE_FIREWALL_ADDRESS_LISTS = {
    'EOIP-ALLOW': [
        ('10.0.0.0/8', 'Internal Network'),
    ],
    'managerIP': [
        ('192.168.128.0/21', 'NOC Management'),
        ('107.178.5.97', 'NOC Monitor'),
        ('198.100.53.0/25', 'NOC VPN'),
        ('143.55.62.143', 'NOC Monitor'),
        ('143.55.37.42', 'NOC Monitor'),
        ('143.55.37.43', 'NOC Monitor'),
        ('142.147.127.2', 'NOC Monitor'),
        ('132.147.147.67', 'NOC Monitor'),
        ('132.147.147.68', 'NOC Monitor'),
        ('132.147.132.6', 'NOC Monitor'),
        ('132.147.132.96', 'NOC Monitor'),
        ('132.147.132.97', 'NOC Monitor'),
        ('132.147.132.205', 'NOC Monitor'),
        ('67.219.122.201', 'NOC Monitor'),
        ('132.147.138.52', 'NOC Monitor'),
        ('132.147.138.53', 'NOC Monitor'),
        ('132.147.138.54', 'NOC Monitor'),
        ('10.249.1.26', 'NOC Monitor'),
        ('10.0.0.0/8', 'Internal Network'),
    ],
    'BGP-ALLOW': [
        ('10.0.0.0/8', 'Internal Network'),
    ],
    'SNMP': [
        ('143.55.35.47', 'SNMP Monitor'),
        ('107.178.15.15', 'SNMP Monitor'),
        ('107.178.15.162', 'SNMP Monitor'),
        ('142.147.112.4', 'SNMP Monitor'),
        ('142.147.124.26', 'SNMP Monitor'),
        ('107.178.5.97', 'SNMP Monitor'),
        ('52.128.51.70', 'SNMP Monitor'),
        ('52.128.51.80', 'SNMP Monitor'),
        ('67.219.126.240/28', 'SNMP Monitor'),
        ('198.100.53.120', 'SNMP Monitor'),
        ('143.55.62.143', 'SNMP Monitor'),
        ('132.147.138.2', 'SNMP Monitor'),
        ('132.147.138.0', 'SNMP Monitor'),
        ('132.147.138.6', 'SNMP Monitor'),
        ('132.147.138.23', 'SNMP Monitor'),
        ('132.147.138.29', 'SNMP Monitor'),
        ('132.147.138.30', 'SNMP Monitor'),
        ('132.147.138.31', 'SNMP Monitor'),
        ('143.55.37.40', 'SNMP Monitor'),
        ('143.55.37.41', 'SNMP Monitor'),
        ('132.147.132.24', 'SNMP Monitor'),
        ('198.100.49.99', 'SNMP Monitor'),
        ('132.147.132.26', 'SNMP Monitor'),
        ('132.147.132.40', 'SNMP Monitor'),
        ('204.11.183.126', 'SNMP Monitor'),
        ('173.215.67.124', 'SNMP Monitor'),
        ('132.147.138.3', 'SNMP Monitor'),
        ('132.147.138.7', 'SNMP Monitor'),
        ('132.147.138.21', 'SNMP Monitor'),
        ('132.147.138.26', 'SNMP Monitor'),
    ]
}

def get_compliance_address_lists_block():
    """Generate compliance firewall address-list block with comments on every entry."""
    lines = ["/ip firewall address-list"]
    # Remove existing lists first using foreach to remove ALL entries (not just one)
    # RouterOS: rem [find list=X] only removes one entry, so we use foreach to remove all
    lines.append(":foreach i in=[/ip firewall address-list find list=EOIP-ALLOW] do={/ip firewall address-list remove $i}")
    lines.append(":foreach i in=[/ip firewall address-list find list=managerIP] do={/ip firewall address-list remove $i}")
    lines.append(":foreach i in=[/ip firewall address-list find list=BGP-ALLOW] do={/ip firewall address-list remove $i}")
    lines.append(":foreach i in=[/ip firewall address-list find list=SNMP] do={/ip firewall address-list remove $i}")
    lines.append("")
    # Add compliance lists with comments
    for list_name, entries in COMPLIANCE_FIREWALL_ADDRESS_LISTS.items():
        for entry in entries:
            if isinstance(entry, tuple):
                address, comment = entry
                lines.append(f'add list={list_name} address={address} comment="{comment}"')
            else:
                # Legacy plain-string format (should not occur, but handle gracefully)
                lines.append(f"add list={list_name} address={entry}")
    return "\n".join(lines)

# ========================================
# COMPLIANCE: FIREWALL FILTER - INPUT CHAIN
# ========================================
COMPLIANCE_FIREWALL_FILTER_INPUT = """
/ip firewall filter
:foreach i in=[/ip firewall filter find chain=input dynamic=no] do={/ip firewall filter remove $i}
add action=accept chain=input comment="ALLOW EST REL" connection-state=established,related,untracked
add action=accept chain=input comment="ALLOW MT NEIGHBOR" dst-port=5678 protocol=udp
add action=accept chain=input comment="ALLOW MAC TELNET" dst-port=20561 protocol=udp
add action=accept chain=input comment="ALLOW IGMP" protocol=igmp
add action=accept chain=input comment="ALLOW ICMP" protocol=icmp
add action=accept chain=input comment="ALLOW DHCPv4" dst-port=67 protocol=udp
add action=accept chain=input comment="ALLOW DHCPv6" dst-port=547 protocol=udp
add action=accept chain=input comment="ALLOW OSPF" protocol=ospf
add action=accept chain=input comment="ALLOW LDP" dst-port=646 protocol=tcp
add action=accept chain=input comment="ALLOW LDP" dst-port=646 protocol=udp
add action=accept chain=input comment="ALLOW MANAGER IP" src-address-list=managerIP
add action=accept chain=input comment="ALLOW BGP" dst-port=179 protocol=tcp src-address-list=BGP-ALLOW
add action=accept chain=input comment="ALLOW EOIP" protocol=gre src-address-list=EOIP-ALLOW
add action=accept chain=input comment="ALLOW SNMP" dst-port=161 protocol=udp src-address-list=SNMP
add action=drop chain=input comment="DROP INPUT" log=no
"""

# ========================================
# COMPLIANCE: FIREWALL RAW
# ========================================
COMPLIANCE_FIREWALL_RAW = """
/ip firewall raw
:foreach i in=[/ip firewall raw find dynamic=no] do={/ip firewall raw remove $i}
add action=drop chain=prerouting comment="DROP BAD UDP" port=0 protocol=udp
"""

# ========================================
# COMPLIANCE: FIREWALL FORWARD CHAIN
# ========================================
COMPLIANCE_FIREWALL_FORWARD = """
/ip firewall filter
:foreach i in=[/ip firewall filter find chain=forward dynamic=no] do={/ip firewall filter remove $i}
add action=accept chain=forward comment="BGP Accept" dst-address=10.0.0.0/8 dst-port=179 protocol=tcp src-address=10.0.0.0/8
add action=accept chain=forward comment="GRE Accept" dst-address=10.0.0.0/8 protocol=gre src-address=10.0.0.0/8
add action=drop chain=forward comment="unauth drop rule" dst-address-list=!WALLED-GARDEN src-address-list=unauth
add action=fasttrack-connection chain=forward connection-state=established,related,untracked hw-offload=yes
add action=accept chain=forward connection-state=established,related,untracked
"""

# ========================================
# COMPLIANCE: FIREWALL NAT
# ========================================
# NOTE: This does NOT use 'rem [find]' to preserve tab-specific NAT rules (NTP, private NAT)
# These compliance rules are added alongside existing rules
COMPLIANCE_FIREWALL_NAT = """
/ip firewall nat
add action=redirect chain=dstnat dst-port=5022 protocol=tcp to-ports=22
add action=dst-nat chain=dstnat comment="unauth proxy rule" dst-address-list=!WALLED-GARDEN dst-port=80 protocol=tcp src-address-list=unauth to-addresses=107.178.15.27 to-ports=3128
"""

# ========================================
# COMPLIANCE: FIREWALL MANGLE
# ========================================
COMPLIANCE_FIREWALL_MANGLE = """
/ip firewall mangle
:foreach i in=[/ip firewall mangle find dynamic=no] do={/ip firewall mangle remove $i}
"""

# ========================================
# COMPLIANCE: SYSTEM CLOCK & NTP
# ========================================
COMPLIANCE_CLOCK_NTP = """
/system clock
set time-zone-name=America/Chicago

/system ntp client
set enabled=yes

/system ntp client servers
rem [find]
add address=ntp-pool.nxlink.com
"""

# ========================================
# COMPLIANCE: SNMP
# ========================================
COMPLIANCE_SNMP = """
/snmp community
set [find default=yes] read-access=no
rem [find default=no]

/snmp community
add name=FBZ1yYdphf addresses=::/0,132.147.132.26/32,132.147.132.40/32
"""

# ========================================
# COMPLIANCE: SYSTEM SETTINGS
# ========================================
COMPLIANCE_SYSTEM_SETTINGS = """
/system watchdog
set watchdog-timer=yes

/system routerboard settings
set auto-upgrade=yes

/ip firewall connection tracking
set udp-timeout=30s

/ip proxy
set enabled=no

/ip firewall service-port
set sip disabled=yes
"""

# ========================================
# COMPLIANCE: VPLS EDGE PORTS
# ========================================
COMPLIANCE_VPLS_EDGE = """
/interface bridge port
set [find interface~"vpls"] edge=yes
"""

# ========================================
# COMPLIANCE: SYSTEM LOGGING
# ========================================
# Note: syslog server IP is dynamic based on loopback IP
def get_compliance_logging(loopback_ip):
    """Generate compliance logging configuration with dynamic syslog server"""
    loop_ip_clean = loopback_ip.split('/')[0] if '/' in loopback_ip else loopback_ip
    return f"""
/system logging action
rem [find default=no]
set [find name="memory"] memory-lines=1000
set [find name="disk"] disk-lines-per-file=10000 disk-file-count=3
add name=syslog remote=142.147.116.215 src-address={loop_ip_clean} target=remote

/system logging
rem [find default=no]
add action=syslog topics=critical
add action=syslog topics=error
add action=syslog topics=warning
add action=disk topics=critical
add action=disk topics=error
add action=disk topics=warning
add action=memory topics=critical
add action=memory topics=error
add action=memory topics=warning
set 0 action=echo
"""

# ========================================
# COMPLIANCE: USER AAA
# ========================================
COMPLIANCE_USER_AAA = """
/user aaa
set use-radius=no
"""

# ========================================
# COMPLIANCE: USER GROUPS
# ========================================
COMPLIANCE_USER_GROUPS = """
/user group
rem [find where name!="full" and name!="read" and name!="write"]

/user group
set read policy="local,telnet,read,test,winbox,sniff,ssh,!ftp,!reboot,!write,!policy,!password,!web,!sensitive,!api,!romon,!rest-api"
"""

# ========================================
# COMPLIANCE: DHCP OPTIONS
# ========================================
COMPLIANCE_DHCP_OPTIONS = """
/ip dhcp-server option
rem [find]

/ip dhcp-server option
add code=43 name=opt43 value=0x011768747470733a2f2f7573732e6e786c696e6b2e636f6d2f

/ip dhcp-server option sets
rem [find]

/ip dhcp-server option sets
add name=optset options=opt43

/ip dhcp-server network
set [find where address !~ "^10\\\\."] dhcp-option-set=optset
"""

# ========================================
# COMPLIANCE: RADIUS (for DHCP)
# ========================================
# Note: RADIUS servers use loopback IP as source
# SECURITY: RADIUS secret is loaded from environment variable to protect proprietary information
def get_compliance_radius(loopback_ip):
    """Generate compliance RADIUS configuration with dynamic source IP
    
    Uses the engineering default RADIUS secret unless NEXTLINK_RADIUS_SECRET overrides it.
    """
    import os
    
    radius_secret = os.getenv('NEXTLINK_RADIUS_SECRET', 'Nl22021234').strip() or 'Nl22021234'
    
    loop_ip_clean = loopback_ip.split('/')[0] if '/' in loopback_ip else loopback_ip
    return f"""
/radius
rem [find]

/radius
add address=142.147.112.2 secret="{radius_secret}" service=dhcp src-address={loop_ip_clean} timeout=5s
add address=142.147.112.18 secret="{radius_secret}" service=dhcp src-address={loop_ip_clean} timeout=5s
"""

# ========================================
# COMPLIANCE: MPLS LDP FILTERS
# ========================================
# Extensive LDP accept and advertise filters
COMPLIANCE_LDP_DENY_PREFIXES = [
    '10.2.0.14/32',
    '10.2.0.21/32',
    '10.2.0.107/32',
    '10.2.0.108/32',
    '10.17.0.10/32',
    '10.17.0.11/32',
    '10.30.0.9/32',
    '10.240.0.3/32',
    '10.243.0.9/32',
    '10.248.0.220/32',
    '10.249.0.220/32',
    '10.0.0.87/32',
    '10.9.0.88/32',
    '10.254.247.9/32'
]

COMPLIANCE_LDP_ALLOW_PREFIXES = [
    '10.2.0.10/32',
    '10.0.0.0/24',
    '10.0.1.0/24',
    '10.1.0.0/24',
    '10.2.0.0/24',
    '10.3.0.0/24',
    '10.4.0.0/24',
    '10.4.3.0/24',
    '10.5.0.0/24',
    '10.6.0.0/24',
    '10.7.0.0/24',
    '10.7.250.0/24',
    '10.7.254.0/24',
    '10.8.0.0/24',
    '10.9.0.0/24',
    '10.9.1.0/24',
    '10.9.2.0/24',
    '10.10.0.0/24',
    '10.11.0.0/24',
    '10.12.0.0/24',
    '10.13.0.0/24',
    '10.14.0.0/24',
    '10.15.0.0/24',
    '10.16.0.0/24',
    '10.17.0.0/24',
    '10.17.16.0/24',
    '10.17.18.0/24',
    '10.17.31.0/24',
    '10.17.48.0/24',
    '10.18.0.0/24',
    '10.18.2.0/24',
    '10.19.0.0/24',
    '10.21.0.0/24',
    '10.22.0.0/24',
    '10.25.0.0/24',
    '10.26.0.0/24',
    '10.27.0.0/24',
    '10.30.0.0/24',
    '10.32.0.0/24',
    '10.33.0.0/24',
    '10.34.0.0/24',
    '10.35.0.0/24',
    '10.36.0.0/24',
    '10.37.0.0/24',
    '10.39.0.0/24',
    '10.45.252.0/24',
    '10.47.0.0/24',
    '10.53.252.0/22',
    '10.54.0.0/22',
    '10.250.0.0/24',
    '10.250.40.0/22',
    '10.241.0.0/24',
    '10.241.64.0/22',
    '10.254.42.0/24',
    '10.254.243.0/24',
    '10.254.245.0/24',
    '10.254.247.0/24',
    '10.254.248.0/24',
    '10.254.249.0/24',
    '10.42.0.0/24',
    '10.42.12.0/24',
    '10.42.192.0/22',
    '10.243.0.0/24',
    '10.247.0.0/24',
    '10.247.13.0/24',
    '10.247.64.0/22',
    '10.247.72.0/24',
    '10.247.147.0/24',
    '10.247.187.0/24',
    '10.248.0.0/24',
    '10.248.32.0/24',
    '10.248.36.0/24',
    '10.248.86.0/24',
    '10.248.208.0/22',
    '10.249.0.0/24',
    '10.249.7.0/24',
    '10.249.180.0/22'
]

def get_compliance_ldp_filters():
    """Generate compliance MPLS LDP accept and advertise filters"""
    lines = ["/mpls ldp accept-filter"]
    lines.append("rem [find]")
    # Add deny prefixes
    for prefix in COMPLIANCE_LDP_DENY_PREFIXES:
        lines.append(f"add accept=no disabled=no prefix={prefix}")
    # Add allow prefixes
    for prefix in COMPLIANCE_LDP_ALLOW_PREFIXES:
        lines.append(f"add accept=yes disabled=no prefix={prefix}")
    # Default deny
    lines.append("add accept=no disabled=no prefix=0.0.0.0/0")
    lines.append("")
    lines.append("/mpls ldp advertise-filter")
    lines.append("rem [find]")
    # Add deny prefixes
    for prefix in COMPLIANCE_LDP_DENY_PREFIXES:
        lines.append(f"add advertise=no disabled=no prefix={prefix}")
    # Add allow prefixes
    for prefix in COMPLIANCE_LDP_ALLOW_PREFIXES:
        lines.append(f"add advertise=yes disabled=no prefix={prefix}")
    # Default deny
    lines.append("add advertise=no disabled=no prefix=0.0.0.0/0")
    lines.append("")
    lines.append(":foreach i in=[/mpls ldp interface find] do={/mpls ldp interface set $i disabled=yes;/mpls ldp interface set $i disabled=no}")
    return "\n".join(lines)

# ========================================
# GET ALL COMPLIANCE BLOCKS
# ========================================
def _local_reference_compliance_blocks(loopback_ip=None):
    if not loopback_ip:
        loopback_ip = "10.0.0.1/32"
    return {
        "ip_services": COMPLIANCE_IP_SERVICES.strip(),
        "dns": COMPLIANCE_DNS.strip(),
        "firewall_address_lists": get_compliance_address_lists_block().strip(),
        "firewall_filter_input": COMPLIANCE_FIREWALL_FILTER_INPUT.strip(),
        "firewall_raw": COMPLIANCE_FIREWALL_RAW.strip(),
        "firewall_forward": COMPLIANCE_FIREWALL_FORWARD.strip(),
        "firewall_nat": COMPLIANCE_FIREWALL_NAT.strip(),
        "firewall_mangle": COMPLIANCE_FIREWALL_MANGLE.strip(),
        "clock_ntp": COMPLIANCE_CLOCK_NTP.strip(),
        "snmp": COMPLIANCE_SNMP.strip(),
        "system_settings": COMPLIANCE_SYSTEM_SETTINGS.strip(),
        "vpls_edge": COMPLIANCE_VPLS_EDGE.strip(),
        "logging": get_compliance_logging(loopback_ip).strip(),
        "user_aaa": COMPLIANCE_USER_AAA.strip(),
        "user_groups": COMPLIANCE_USER_GROUPS.strip(),
        "dhcp_options": COMPLIANCE_DHCP_OPTIONS.strip(),
        "radius": get_compliance_radius(loopback_ip).strip(),
        "ldp_filters": get_compliance_ldp_filters().strip(),
    }


def get_all_compliance_blocks(loopback_ip=None):
    """
    Get all compliance configuration blocks from GitLab (single source of truth).

    Source: GitLab compliance repo (dynamic, TTL-cached).
    No hardcoded fallback — when GitLab is unavailable, returns empty dict
    with a clear warning so the failure is visible.

    Args:
        loopback_ip: Loopback IP address (with or without /32) for syslog source and RADIUS source

    Returns:
        Dictionary of compliance blocks (empty dict if GitLab unavailable)
    """
    if not loopback_ip:
        loopback_ip = "10.0.0.1/32"  # Default fallback

    # GitLab dynamic compliance — single source of truth
    if _HAS_GITLAB_NCR and _get_gitlab_loader is not None:
        try:
            gitlab_blocks = _get_gitlab_loader().get_compliance_blocks_from_script(
                loopback_ip=loopback_ip
            )
            if gitlab_blocks:
                return gitlab_blocks
            else:
                print("[COMPLIANCE-REF] WARNING: GitLab returned empty compliance blocks")
        except Exception as _exc:
            print(f"[COMPLIANCE-REF] ERROR: GitLab loader failed: {_exc}")
    else:
        print("[COMPLIANCE-REF] WARNING: GitLab compliance module not available")

    print("[COMPLIANCE-REF] WARNING: GitLab unavailable, using bundled local compliance reference blocks")
    return _local_reference_compliance_blocks(loopback_ip)

# ========================================
# COMPLIANCE VALIDATION
# ========================================
def validate_compliance(config_text):
    """
    Validate that a configuration contains all required compliance items.
    
    Args:
        config_text: RouterOS configuration text
        
    Returns:
        Dictionary with validation results:
        {
            'compliant': bool,
            'missing_items': list,
            'warnings': list
        }
    """
    missing = []
    warnings = []
    config_lower = config_text.lower()
    
    # Check IP Services
    if 'telnet disabled=yes port=5023' not in config_lower:
        missing.append('IP Service: telnet disabled on 5023')
    if 'www disabled=yes port=1234' not in config_lower:
        missing.append('IP Service: www disabled on 1234')
    if 'www-ssl disabled=no port=443' not in config_lower and 'www-ssl port=443' not in config_lower:
        missing.append('IP Service: www-ssl enabled on 443')
    if 'winbox port=8291' not in config_lower:
        missing.append('IP Service: winbox on 8291')
    if 'ssh port=22' not in config_lower:
        missing.append('IP Service: ssh on 22')
    
    # Check DNS
    if '142.147.112.3' not in config_text or '142.147.112.19' not in config_text:
        missing.append('DNS: Missing compliance DNS servers (142.147.112.3, 142.147.112.19)')
    
    # Check Firewall Address Lists
    if 'list=eoip-allow' not in config_lower:
        missing.append('Firewall: EOIP-ALLOW address list')
    if 'list=managerip' not in config_lower:
        missing.append('Firewall: managerIP address list')
    if 'list=bgp-allow' not in config_lower:
        missing.append('Firewall: BGP-ALLOW address list')
    if 'list=snmp' not in config_lower:
        missing.append('Firewall: SNMP address list')
    
    # Check Firewall Input Chain
    if 'chain=input comment="allow est rel"' not in config_lower:
        missing.append('Firewall: Input chain EST/REL rule')
    if 'chain=input comment="drop input"' not in config_lower:
        missing.append('Firewall: Input chain final drop rule')
    
    # Check Firewall Raw
    if 'chain=prerouting comment="drop bad udp"' not in config_lower:
        missing.append('Firewall: Raw chain drop bad UDP')
    
    # Check Clock/NTP
    if 'time-zone-name=america/chicago' not in config_lower:
        missing.append('System: Timezone America/Chicago')
    if 'ntp-pool.nxlink.com' not in config_text:
        missing.append('System: NTP server ntp-pool.nxlink.com')
    
    # Check SNMP
    if 'name=fbz1yydphf' not in config_lower:
        missing.append('SNMP: Compliance community FBZ1yYdphf')
    
    # Check System Settings
    if 'watchdog-timer=yes' not in config_lower:
        missing.append('System: Watchdog timer enabled')
    if 'auto-upgrade=yes' not in config_lower:
        missing.append('System: Auto-upgrade enabled')
    if 'udp-timeout=30s' not in config_lower:
        missing.append('Firewall: UDP connection tracking timeout 30s')
    if 'sip disabled=yes' not in config_lower:
        missing.append('Firewall: SIP ALG disabled')
    
    # Check Logging
    if 'remote=142.147.116.215' not in config_text:
        missing.append('Logging: Remote syslog server 142.147.116.215')
    
    # Check User AAA
    if 'use-radius=no' not in config_lower:
        warnings.append('User AAA: Should have use-radius=no (compliance standard)')
    
    # Check DHCP Options
    if 'opt43' not in config_lower or 'uss.nxlink.com' not in config_text:
        warnings.append('DHCP: Option 43 for uss.nxlink.com may be missing')
    
    # Check RADIUS
    if '142.147.112.2' not in config_text or '142.147.112.18' not in config_text:
        warnings.append('RADIUS: DHCP RADIUS servers may be missing')
    
    return {
        'compliant': len(missing) == 0,
        'missing_items': missing,
        'warnings': warnings
    }

