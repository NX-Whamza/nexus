/**
 * Nextlink Configuration Constants
 * Based on Nextscape Navigator standards
 * Include this in nexus.html
 * 
 * IMPORTANT: All infrastructure IPs and secrets should be configured here.
 * These are defaults - in production, load from environment variables or config file.
 */

// Nextlink DNS Servers (configurable - defaults provided)
const NEXTLINK_DNS = {
    primary: '8.8.8.8',  // Configure via environment or override
    secondary: '8.8.4.4',  // Configure via environment or override
    note: 'Configure DNS servers based on your network requirements'
};

// Infrastructure Services (configurable - DO NOT hardcode production values)
const NEXTLINK_INFRASTRUCTURE = {
    // DNS Servers (for DHCP and router configs) - RFC-09-10-25 Compliance
    // Default: NextLink compliance DNS servers (142.147.112.3, 142.147.112.19)
    dnsServers: {
        primary: '142.147.112.3',  // NextLink compliance DNS primary
        secondary: '142.147.112.19',  // NextLink compliance DNS secondary
        // Override these via environment/config: NEXTLINK_DNS_PRIMARY, NEXTLINK_DNS_SECONDARY
        getList: function() { 
            return `${this.primary},${this.secondary}`; 
        }
    },
    
    // Syslog Server - RFC-09-10-25 Compliance
    syslogServer: '142.147.116.215',  // NextLink compliance syslog server (configure via environment: NEXTLINK_SYSLOG_SERVER to override)
    
    // NTP Servers (always include defaults, can add custom)
    ntpServers: {
        default: ['52.128.59.240', '52.128.59.241'],  // Default NTP pool servers (always included)
        custom: ''  // Optional: Add custom NTP server (e.g., 'ntp-pool.yourdomain.com')
    },
    
    // RADIUS Servers (configure via environment)
    radiusServers: {
        dhcp: [],  // Array of {address: 'IP', secret: 'SECRET'}
        login: []  // Array of {address: 'IP', secret: 'SECRET', comment: 'NAME'}
    },
    
    // Backup/FTP Configuration (configure via environment - NEVER hardcode passwords)
    backup: {
        enabled: false,  // Set to true only if backup is configured
        ftpHost: '',  // Configure via environment: NEXTLINK_BACKUP_FTP_HOST
        ftpUser: '',  // Configure via environment: NEXTLINK_BACKUP_FTP_USER
        ftpPassword: '',  // Configure via environment: NEXTLINK_BACKUP_FTP_PASSWORD
        ftpPath: 'backups'  // Configure via environment: NEXTLINK_BACKUP_FTP_PATH
    },
    
    // Email Alerts (configure via environment)
    emailAlerts: {
        enabled: false,  // Set to true only if email alerts are configured
        recipient: '',  // Configure via environment: NEXTLINK_EMAIL_ALERT_RECIPIENT
        from: ''  // Configure via environment: NEXTLINK_EMAIL_ALERT_FROM
    },
    
    // MPLS/VPLS Configuration
    mpls: {
        vplsPeer: '10.254.247.3',  // Default BNG1 peer (configure via environment: NEXTLINK_VPLS_PEER)
        vplsStaticId: 2245  // Default VPLS ID (configurable)
    },
    
    // SNMP Configuration
    snmp: {
        community: 'CHANGE_ME',  // MUST be changed in production
        trapCommunity: 'CHANGE_ME',  // MUST be changed in production
        contact: 'noc@configmaker.local'  // SNMP contact email (configure for production)
    },
    
    // Shared Keys (MUST be configured per deployment)
    sharedKeys: {
        ospfBgpMd5: 'CHANGE_ME',  // MUST be changed from default
        default: 'CHANGE_ME'  // Default shared key (MUST be changed)
    }
};

// Nextlink SNMP Communities (should be customized per deployment)
const NEXTLINK_SNMP = {
    readCommunity: 'nextlinkRO',
    writeCommunity: 'nextlinkRW',
    recommendation: 'Use SNMPv3 with encryption in production'
};

// Management VLAN IP Ranges
const NEXTLINK_MGMT_VLANS = {
    vlan2: '10.10.20.0/24',
    vlan3: '10.10.30.0/24',
    vlan4: '10.10.40.0/24'
};

// Customer VLAN Range
const NEXTLINK_CUSTOMER_VLAN_RANGE = {
    min: 1000,
    max: 4000
};

// DHCP Standards
const NEXTLINK_DHCP = {
    leaseTimeMin: '1h',
    leaseTimeMax: '12h',
    defaultLeaseTime: '1h'
};

// Tarana Sector Configuration
const NEXTLINK_TARANA = {
    sectorIds: {
        ALPHA: 0,
        BETA: 1,
        GAMMA: 2,
        DELTA: 3
    },
    mtu: {
        default: 1500,
        withEncapsulation: 1520
    }
};

// RouterOS Version Information
const NEXTLINK_ROUTEROS_VERSIONS = {
    '6.49.2': {
        type: 'legacy',
        ospfSyntax: 'v6',
        bgpSyntax: 'v6'
    },
    '7.16.2': {
        type: 'modern',
        ospfSyntax: 'v7',
        bgpSyntax: 'template'
    },
    '7.19.4': {
        type: 'modern',
        ospfSyntax: 'v7',
        bgpSyntax: 'template'
    }
};

// Device Naming Patterns
const NEXTLINK_NAMING = {
    towerPattern: 'TWR-<SITE>-<ID>',
    corePattern: 'CORE-DC01-01',
    bridgeManagement: 'br-mgmt',
    bridgeCustomer: 'br-cust1000',
    vlanPattern: 'vlan-<id>-cust',
    examples: {
        tower: 'TWR-AUSTIN-01',
        core: 'CORE-DC01-01',
        vlan: 'vlan-1000-business'
    }
};

// Common NOC Errors to Validate
const NEXTLINK_VALIDATION_CHECKS = [
    'Missing bridge VLAN filtering',
    'Misconfigured BGP route-targets',
    'Incorrect route redistribution',
    'Duplicate loopbacks',
    'IP/mask overlap',
    'Missing default route',
    'Incomplete firewall',
    'IP conflict',
    'Invalid MTU',
    'Missing BGP router-id',
    'Bridge port not part of VLAN'
];

// Pre-deployment Testing Commands
const NEXTLINK_TESTING_COMMANDS = [
    '/ping',
    '/tool traceroute',
    '/routing ospf neighbor print',
    '/routing bgp session print'
];

/**
 * Load Nextlink template defaults into form fields
 * Call this when user clicks "Load Nextlink Template" button
 */
function loadNextlinkTowerTemplate() {
    console.log('Loading Nextlink Tower Template...');
    
    // DNS Settings
    if (document.getElementById('dns1')) {
        document.getElementById('dns1').value = NEXTLINK_DNS.primary;
    }
    if (document.getElementById('dns2')) {
        document.getElementById('dns2').value = NEXTLINK_DNS.secondary;
    }
    
    // SNMP Community (if field exists)
    if (document.getElementById('snmpCommunity')) {
        document.getElementById('snmpCommunity').value = NEXTLINK_SNMP.readCommunity;
    }
    
    // DHCP Lease Time
    if (document.getElementById('dhcpLeaseTime')) {
        document.getElementById('dhcpLeaseTime').value = NEXTLINK_DHCP.defaultLeaseTime;
    }
    
    // Management VLANs (if fields exist)
    if (document.getElementById('vlan2Subnet')) {
        document.getElementById('vlan2Subnet').value = NEXTLINK_MGMT_VLANS.vlan2;
    }
    if (document.getElementById('vlan3Subnet')) {
        document.getElementById('vlan3Subnet').value = NEXTLINK_MGMT_VLANS.vlan3;
    }
    if (document.getElementById('vlan4Subnet')) {
        document.getElementById('vlan4Subnet').value = NEXTLINK_MGMT_VLANS.vlan4;
    }
    
    // Tarana MTU
    if (document.getElementById('tower_tarana_alpha_mtu')) {
        document.getElementById('tower_tarana_alpha_mtu').value = NEXTLINK_TARANA.mtu.default;
        document.getElementById('tower_tarana_beta_mtu').value = NEXTLINK_TARANA.mtu.default;
        document.getElementById('tower_tarana_gamma_mtu').value = NEXTLINK_TARANA.mtu.default;
        document.getElementById('tower_tarana_delta_mtu').value = NEXTLINK_TARANA.mtu.default;
    }
    
    alert('✅ Nextlink template loaded!\n\nDefaults set:\n- DNS: Google (8.8.8.8, 8.8.4.4)\n- SNMP: nextlinkRO\n- DHCP Lease: 1h\n- MTU: 1500\n\nPlease fill in site-specific values (Site Name, IPs, etc.)');
}

/**
 * Validate device name follows Nextlink conventions
 */
function validateNextlinkDeviceName(deviceName) {
    const towerPattern = /^TWR-[A-Z]+-\d+$/;
    const corePattern = /^CORE-[A-Z0-9]+-\d+$/;
    
    if (towerPattern.test(deviceName) || corePattern.test(deviceName)) {
        return { valid: true, message: '✅ Device name follows Nextlink convention' };
    }
    
    return {
        valid: false,
        message: `⚠️ Device name doesn't follow Nextlink convention.\nExpected: ${NEXTLINK_NAMING.towerPattern} or ${NEXTLINK_NAMING.corePattern}\nExamples: ${NEXTLINK_NAMING.examples.tower}, ${NEXTLINK_NAMING.examples.core}`
    };
}

/**
 * Validate VLAN ID is in Nextlink customer range
 */
function validateNextlinkVLAN(vlanId) {
    const id = parseInt(vlanId);
    if (id >= NEXTLINK_CUSTOMER_VLAN_RANGE.min && id <= NEXTLINK_CUSTOMER_VLAN_RANGE.max) {
        return { valid: true, message: '✅ VLAN ID in valid customer range' };
    }
    return {
        valid: false,
        message: `⚠️ VLAN ID ${vlanId} outside Nextlink customer range (${NEXTLINK_CUSTOMER_VLAN_RANGE.min}-${NEXTLINK_CUSTOMER_VLAN_RANGE.max})`
    };
}

/**
 * Get RouterOS version type
 */
function getNextlinkRouterOSInfo(version) {
    return NEXTLINK_ROUTEROS_VERSIONS[version] || { type: 'unknown', ospfSyntax: 'unknown', bgpSyntax: 'unknown' };
}

/**
 * Show Nextlink standards info panel
 */
function showNextlinkStandards() {
    const info = `
🏢 NEXTLINK CONFIGURATION STANDARDS

📋 Device Naming:
  Towers: ${NEXTLINK_NAMING.towerPattern}
  Core: ${NEXTLINK_NAMING.corePattern}
  Examples: ${NEXTLINK_NAMING.examples.tower}, ${NEXTLINK_NAMING.examples.core}

🌐 DNS Servers:
  Primary: ${NEXTLINK_DNS.primary}
  Secondary: ${NEXTLINK_DNS.secondary}

📊 VLAN Ranges:
  Management VLANs:
    - VLAN 2: ${NEXTLINK_MGMT_VLANS.vlan2}
    - VLAN 3: ${NEXTLINK_MGMT_VLANS.vlan3}
    - VLAN 4: ${NEXTLINK_MGMT_VLANS.vlan4}
  Customer VLANs: ${NEXTLINK_CUSTOMER_VLAN_RANGE.min}-${NEXTLINK_CUSTOMER_VLAN_RANGE.max}

📡 Tarana Sectors:
  ALPHA: ID ${NEXTLINK_TARANA.sectorIds.ALPHA}
  BETA: ID ${NEXTLINK_TARANA.sectorIds.BETA}
  GAMMA: ID ${NEXTLINK_TARANA.sectorIds.GAMMA}
  DELTA: ID ${NEXTLINK_TARANA.sectorIds.DELTA}
  MTU: ${NEXTLINK_TARANA.mtu.default} (default), ${NEXTLINK_TARANA.mtu.withEncapsulation} (with encapsulation)

🔍 Pre-deployment Testing:
  ${NEXTLINK_TESTING_COMMANDS.join('\n  ')}

⚠️ Common Errors to Avoid:
  ${NEXTLINK_VALIDATION_CHECKS.slice(0, 5).join('\n  ')}
  ...and ${NEXTLINK_VALIDATION_CHECKS.length - 5} more
`;
    
    alert(info);
}

console.log('✅ Nextlink configuration constants loaded');

