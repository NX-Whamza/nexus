"""
Nextlink-specific network standards and reference data.

NOTE: These constants are Nextlink-internal reference values. In a multi-tenant
deployment, per-tenant equivalents should be configured via the tenant_settings
table. These values serve as documentation and fallback defaults for the Nextlink
tenant only.
"""

# IP Addressing Schemes
NEXTLINK_IP_RANGES = {
    'loopback': {
        'format': '/32',
        'description': 'Loopback addresses for router IDs'
    },
    'uplink': {
        'formats': ['/29', '/30'],
        'description': 'Uplink subnet ranges'
    },
    'management_vlans': {
        'vlan2': '10.10.20.0/24',
        'vlan3': '10.10.30.0/24',
        'vlan4': '10.10.40.0/24'
    },
    'customer_vlans': {
        'range': '1000-4000',
        'description': 'Segregated customer VLANs'
    }
}

# Firewall Rules Template
NEXTLINK_FIREWALL_RULES = {
    'drop_ports': ['telnet', 'ftp', 'high_random'],
    'allow_ports': ['winbox', 'dns', 'snmp'],
    'description': 'Drop telnet, ftp, random high ports; allow Winbox, DNS, SNMP selectively'
}

# RouterOS Version Matrix
NEXTLINK_ROUTEROS_VERSIONS = {
    '6.49.2': {
        'type': 'legacy',
        'ospf_syntax': 'v6',
        'bgp_syntax': 'v6',
        'notes': 'Legacy version, uses older command structure'
    },
    '7.16.2': {
        'type': 'modern',
        'ospf_syntax': 'v7',
        'bgp_syntax': 'template',
        'notes': 'Modern with full OSPFv3/BGP template support'
    },
    '7.19.4': {
        'type': 'modern',
        'ospf_syntax': 'v7',
        'bgp_syntax': 'template',
        'notes': 'Latest modern version with full OSPFv3/BGP template support'
    }
}

# Device Roles
NEXTLINK_DEVICE_ROLES = {
    'rb2011': {
        'role': 'Edge device, light routing',
        'typical_use': 'Customer edge, small sites'
    },
    'ccr1036': {
        'role': 'High-performance core',
        'typical_use': 'Core routing, aggregation'
    },
    'ccr2004': {
        'role': 'Edge or BGP/OSPF aggregator',
        'typical_use': 'Tower aggregation, BGP peering'
    },
    'rb5009': {
        'role': 'Access devices or NID routers',
        'typical_use': 'Network interface devices, access layer'
    }
}

# Naming Conventions
NEXTLINK_NAMING = {
    'device_patterns': {
        'tower': 'TWR-<SITE>-<ID>',
        'core': 'CORE-DC01-01',
        'examples': ['TWR-AUSTIN-01', 'CORE-DC01-01']
    },
    'bridge_patterns': {
        'management': 'br-mgmt',
        'customer': 'br-cust1000'
    },
    'vlan_patterns': {
        'format': 'vlan-<id>-cust',
        'examples': ['vlan-1000-business', 'vlan-2000-residential']
    }
}

# SNMP Configuration
NEXTLINK_SNMP = {
    'communities': {
        'read': 'nextlinkRO',  # Should be customized per deployment
        'write': 'nextlinkRW',  # Should be customized per deployment
        'recommendation': 'Use SNMPv3 with encryption'
    }
}

# DNS & Syslog
NEXTLINK_SERVICES = {
    'dns': {
        'primary': '8.8.8.8',
        'secondary': '8.8.4.4',
        'alternative': 'internal caching resolvers',
        'notes': 'Use Google DNS or internal resolvers'
    },
    'syslog': {
        'config': '/system logging action',
        'notes': 'Remote syslog configured for centralized logging'
    }
}

# Tower Config Workflow
NEXTLINK_TOWER_WORKFLOW = {
    'required_noc_fields': [
        'Site ID',
        'Loopback IP',
        'Uplink IPs',
        'ASN'
    ],
    'ai_populatable': [
        'VLANs',
        'MTU',
        'Common bridge structure',
        'SNMP settings'
    ]
}

# DHCP Standards
NEXTLINK_DHCP = {
    'lease_times': {
        'min': '1h',
        'max': '12h',
        'typical': '1h'
    },
    'pool_template': """
/ip dhcp-server
add address-pool=pool_vlan10 interface=bridge10 lease-time=1h
"""
}

# Tarana Sector Configuration
NEXTLINK_TARANA = {
    'sector_ids': {
        'ALPHA': 0,
        'BETA': 1,
        'GAMMA': 2,
        'DELTA': 3
    },
    'vlan_tagging': 'Consistent with tower conventions',
    'mtu': {
        'default': 1500,
        'with_encapsulation': 1520
    }
}

# VPLS Configuration
NEXTLINK_VPLS = {
    'types': ['/interface vpls', 'Cisco pseudowire style'],
    'template': """
pw-type=raw-ethernet
site-id=100
rd=AS:ID
"""
}

# Enterprise Customer Templates
NEXTLINK_ENTERPRISE = {
    'nat': {
        'use_case': 'Small clients',
        'description': 'NAT for customers without public IPs'
    },
    'routed': {
        'use_case': 'Static/public IPs',
        'description': 'Direct routing for customers with public IPs'
    },
    'bgp': {
        'use_case': 'Multihoming or MPLS',
        'description': 'BGP peering for enterprise customers'
    }
}

# VPN Types
NEXTLINK_VPN_TYPES = {
    'l3vpn': {
        'type': 'MPLS L3VPN',
        'config': 'vrf, route-distinguisher, vpnv4'
    },
    'l2vpn': {
        'type': 'VPLS over LDP/BGP',
        'config': 'VPLS configuration'
    },
    'gre': {
        'type': 'GRE Tunnel',
        'config': 'Simple to deploy'
    }
}

# QoS/Traffic Shaping
NEXTLINK_QOS = {
    'queue_types': [
        'Simple queue with max-limit',
        'HTB with queue tree'
    ],
    'common_tiers': ['100M', '500M', '1G']
}

# Common NOC Errors (for AI validation)
NEXTLINK_COMMON_ERRORS = [
    {
        'error': 'Missing bridge VLAN filtering',
        'severity': 'high',
        'check': 'bridge_vlan_filtering'
    },
    {
        'error': 'Misconfigured BGP route-targets',
        'severity': 'high',
        'check': 'bgp_route_targets'
    },
    {
        'error': 'Incorrect route redistribution',
        'severity': 'medium',
        'check': 'route_redistribution'
    },
    {
        'error': 'Duplicate loopbacks',
        'severity': 'critical',
        'check': 'loopback_duplicates'
    },
    {
        'error': 'IP/mask overlap',
        'severity': 'critical',
        'check': 'ip_overlap'
    },
    {
        'error': 'Missing default route',
        'severity': 'high',
        'check': 'default_route'
    },
    {
        'error': 'Incomplete firewall',
        'severity': 'high',
        'check': 'firewall_completeness'
    }
]

# RouterOS 6.x to 7.x Migration Changes
NEXTLINK_MIGRATION_6X_TO_7X = {
    'ospf': {
        'change': 'network and instance now separate',
        'old': '/routing ospf interface',
        'new': '/routing ospf interface-template'
    },
    'bgp': {
        'change': 'Templates, roles, accept-* filters introduced',
        'old': '/routing bgp peer',
        'new': '/routing bgp connection with templates'
    },
    'interface_naming': {
        'change': 'Interface auto-renaming is more strict',
        'note': 'Bridge VLAN required in v7+'
    },
    'bridge_vlan': {
        'change': '/interface bridge vlan required in v7+',
        'mandatory': True
    },
    'port_roles': {
        'change': 'Port roles may shift (e.g. SFP to Ether)',
        'note': 'Verify port naming after upgrade'
    }
}

# Pre-deployment Testing Commands
NEXTLINK_TESTING_COMMANDS = [
    '/ping',
    '/tool traceroute',
    '/routing ospf neighbor print',
    '/routing bgp session print'
]

# Time-consuming Areas (AI can help)
NEXTLINK_AI_HELP_AREAS = [
    'VLAN tagging and interface mappings',
    'Route reflector and BGP peer definitions',
    'MPLS/VRF config',
    'Generate templates and validate interface-state/bridging'
]

# Extractable from /export (AI parsing capability)
NEXTLINK_EXTRACTABLE_FROM_EXPORT = [
    'Interfaces',
    'IPs, VLANs, bridges',
    'Routes, VRFs',
    'BGP/OSPF neighbors',
    'SNMP/DNS/logging'
]
# AI can parse ~90% automatically

# Auto-detectable Config Errors
NEXTLINK_AUTO_DETECTABLE_ERRORS = [
    'IP conflict',
    'Invalid MTU',
    'Missing BGP router-id',
    'Bridge port not part of VLAN'
]

# Firmware Migration Specifics
NEXTLINK_FIRMWARE_MIGRATION_CHECKS = [
    '/interface bridge vlan required in v7+',
    'OSPF config split into area + instance',
    '/routing/bgp/template must be used for new BGP sessions',
    'Port roles may shift (e.g. SFP to Ether)'
]

