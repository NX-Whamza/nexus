# NEXUS - Complete Documentation

## Table of Contents
1. [Overview](#overview)
2. [Quick Start Guide](#quick-start-guide)
3. [Security & Configuration](#security--configuration)
4. [Configuration Generation Behavior](#configuration-generation-behavior)
5. [Production Readiness](#production-readiness)
6. [RFC-09-10-25 Compliance](#rfc-09-10-25-compliance)
7. [System Architecture](#system-architecture)
8. [Device Upgrade System](#device-upgrade-system)
9. [Tarana Sectors Protection](#tarana-sectors-protection)
10. [AI Training & Integration](#ai-training--integration)
11. [Network Setup](#network-setup)
12. [Enterprise Configuration Improvements](#enterprise-configuration-improvements)

---

## Overview

The NEXUS is a unified MikroTik configuration generator designed for NextLink Internet. It provides automated configuration generation for:
- **Tower Sites**: Full BGP/OSPF/MPLS configurations
- **Non-MPLS Enterprise**: Simplified enterprise customer configurations
- **MPLS Enterprise**: Enterprise configurations with MPLS/OSPF/BGP support
- **6GHz Switch Config**: VLAN-based switch configurations
- **Tarana Sectors**: ALPHA/BETA/GAMMA/DELTA sector configurations

### Key Features
- ✅ **Modern UI**: Dashboard-style interface with real-time metrics and activity tracking
- ✅ **Dynamic Configuration**: No hardcoded proprietary information
- ✅ **AI-Powered**: Intelligent config generation and validation
- ✅ **Device-Agnostic**: Supports all MikroTik devices dynamically
- ✅ **RouterOS Version Support**: v6.x to v7.x with automatic syntax conversion
- ✅ **Security-First**: Passwords hidden by default, configurable infrastructure
- ✅ **Production-Ready**: Centralized configuration system, reference-based architecture

### User Interface (Nov 2024 Update)

The tool features a modern, dashboard-style interface inspired by professional network management tools:

**Header Navigation**:
- Horizontal navigation bar with dropdown menus
- Organized access to all 7 configuration generators
- Integrated dark/light mode toggle
- +21% more screen space (removed 280px sidebar)

**Home Dashboard**:
- **Live Metrics**: Total configs generated, migrations completed, success rate, today's activity
- **Quick Actions**: One-click access to common tasks (New Tower, Enterprise, Migration, View Configs)
- **Recent Activity**: Last 10 configurations with timestamps, device info, and RouterOS versions (refreshes every 30 seconds)

**Security & Configuration**:
- **Feedback**: Stored locally and managed via the **ADMIN** panel (admin users only)
- **API Keys**: All secrets stored in environment variables, never hardcoded
- **VM Safe**: No system modifications, runs in user space
- **Smart Tracking**: Automatic history tracking via localStorage (no placeholders)

**Benefits**:
- Professional appearance matching industry standards
- Progress visibility and activity auditing
- Efficient navigation with dropdown organization
- Real-time metrics calculated from actual usage data

---

## Quick Start Guide

### One-Command Startup (Recommended)

Simply run:
```batch
start_backend_services.bat
```

This single script will:
2. ✅ Start Flask Backend API (port 5000)
3. ✅ Start HTML Frontend Server (port 8000)
4. ✅ Verify all services are running
5. ✅ Display network access URLs

### Installation Requirements

1. **Python 3.8+**
   - Download from: https://www.python.org/downloads/
   - Make sure to check "Add Python to PATH" during installation


3. **Python Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

### Access URLs

**Local Access:**
- Frontend: `http://localhost:8000/nexus.html`
- Backend API: `http://localhost:5000/api`

**Network Access (for coworkers):**
- Frontend: `http://YOUR_IP:8000/nexus.html`
- Backend API: `http://YOUR_IP:5000/api`

### Network Firewall Setup

To allow coworkers to access the tool:

1. **Run as Administrator:**
   ```batch
   setup_network_access.bat
   ```

2. **Or manually configure Windows Firewall:**
   - Allow TCP ports 5000 and 8000
   - Name: "NEXUS Servers"

---

## Security & Configuration

### ✅ Security Best Practices

1. **No Hardcoded Secrets**
   - All passwords, API keys, and secrets use placeholders (`CHANGE_ME`)
   - Infrastructure IPs are configurable via `nextlink_constants.js`
   - Environment variables supported for sensitive data

2. **Centralized Configuration**
   - All infrastructure settings in `nextlink_constants.js`
   - Backend uses `nextlink_enterprise_reference.py` for standard configs
   - No proprietary information in code

3. **Password Protection**
   - Passwords hidden by default in UI
   - "Show Passwords" button to reveal (for verification only)
   - Downloaded `.rsc` files contain actual passwords

4. **Information Leakage Prevention**
   - No hardcoded NextLink IPs in source code
   - All infrastructure values configurable
   - Reference files contain standard configs only (no secrets)

### Configuration Files

1. **`nextlink_constants.js`**
   - DNS servers, syslog, NTP, RADIUS, MPLS, SNMP settings
   - Infrastructure IPs and shared keys
   - All values have fallbacks to public defaults

2. **`nextlink_enterprise_reference.py`**
   - Standard user groups
   - Firewall address lists and rules
   - IP services, system settings
   - Reference data only (no secrets)

### Environment Variables

Configure sensitive data via environment variables:
- `NEXTLINK_DNS_PRIMARY` - Primary DNS server
- `NEXTLINK_DNS_SECONDARY` - Secondary DNS server
- `NEXTLINK_SYSLOG_SERVER` - Syslog server IP
- `NEXTLINK_VPLS_PEER` - VPLS peer IP

---

## Configuration Generation Behavior

### Always Generated (With Defaults)

These sections are **always included** in generated configurations:

1. **DNS Configuration** ✅
   - Default: `8.8.8.8, 8.8.4.4` (Google Public DNS)
   - Configurable via `nextlink_constants.js`
   - Location: `/ip dns` section

2. **Firewall Rules** ✅
   - Standard RFC-compliant baseline firewall rules
   - Always included for security
   - Location: `/ip firewall` sections

3. **NTP Configuration** ✅
   - Default: `52.128.59.240`, `52.128.59.241`
   - Custom NTP server can be added
   - Always includes defaults + custom if configured

4. **System Settings** ✅
   - Clock timezone (America/Chicago)
   - Routerboard auto-upgrade
   - System logging actions

5. **User Groups** ✅
   - Standard groups: ENG, NOC, LTE, DEVOPS, VOIP, STS, etc.
   - Always included for access control

### Conditionally Generated (Only If Configured)

These sections are **only included** if configured:

1. **Remote Syslog** ⚠️
   - Only if `NEXTLINK_SYSLOG_SERVER` is set
   - Location: `/system logging action`

2. **RADIUS Servers** ⚠️
   - Only if configured in `nextlink_constants.js`
   - Location: `/radius` section

3. **Backup Scripts** ⚠️
   - Only if backup is enabled in configuration
   - Location: `/system scheduler`

4. **Email Alerts** ⚠️
   - Only if email alerts are enabled
   - Location: `/system scheduler`

---

## Production Readiness

### ✅ Completed Security Improvements

1. **Removed Hard-Coded Proprietary Information**
   - ✅ Removed hardcoded FTP passwords
   - ✅ Removed hardcoded email addresses
   - ✅ Removed hardcoded internal IP addresses
   - ✅ Removed hardcoded domain names
   - ✅ Removed hardcoded RADIUS server IPs
   - ✅ Removed hardcoded shared keys

2. **Centralized Configuration System**
   - ✅ Created `NEXTLINK_INFRASTRUCTURE` configuration object
   - ✅ Added helper functions for safe config access
   - ✅ All infrastructure IPs use configuration system
   - ✅ Fallbacks to public defaults

3. **Backend API Updates**
   - ✅ Uses environment variables for DNS servers
   - ✅ Uses environment variables for syslog server
   - ✅ Fallback to public DNS when not configured

4. **Dynamic Configuration**
   - ✅ All DNS servers dynamically configured
   - ✅ All syslog servers dynamically configured
   - ✅ All NTP servers dynamically configured
   - ✅ All RADIUS servers dynamically configured

### Production Checklist

- [ ] Configure `nextlink_constants.js` with production values
- [ ] Set environment variables for sensitive data
- [ ] Change all `CHANGE_ME` placeholders
- [ ] Configure syslog server IP
- [ ] Configure RADIUS servers
- [ ] Configure MPLS/VPLS peer IPs
- [ ] Test all configuration tabs
- [ ] Verify dark/light mode functionality
- [ ] Test network access from other machines

---

## System Architecture

### Frontend (`nexus.html`)
- Single-page application with multiple tabs
- Dynamic configuration based on `nextlink_constants.js`
- Dark/light mode support
- AI-powered validation and suggestions

### Backend (`api_server.py`)
- Flask REST API on port 5000
- Config generation endpoints
- Validation and suggestion endpoints

### Reference Files
- **`nextlink_constants.js`**: Infrastructure configuration
- **`nextlink_enterprise_reference.py`**: Standard config blocks
- **`nextlink_standards.py`**: RouterOS standards and rules

### Database
- SQLite database for completed configurations
- Timestamps in Central Standard Time (CST/CDT)
- Stores config metadata and content

---

## RFC-09-10-25 Compliance

### Compliance Standards Integration

All configurations generated by the tool automatically include RFC-09-10-25 compliance standards:

**Compliance Reference File:** `nextlink_compliance_reference.py`

**Automatic Compliance Enforcement:**
- ✅ All new configurations (Non-MPLS, MPLS Enterprise) automatically include compliance
- ✅ All device upgrades automatically include compliance validation
- ✅ Compliance is applied via `/api/apply-compliance` endpoint
- ✅ Compliance blocks are additive and non-destructive
- ✅ Frontend-only tabs (Tarana, 6GHz) are production-ready and skip compliance (self-contained)

### Compliance Sections

**IP Services:**
- Telnet disabled (port 5023)
- FTP disabled (port 5021)
- WWW disabled (port 1234)
- API/API-SSL disabled
- WWW-SSL enabled (port 443)
- Winbox enabled (port 8291)
- SSH enabled (port 22)

**DNS Servers:**
- Primary: `142.147.112.3`
- Secondary: `142.147.112.19`
- Configured via `nextlink_constants.js` or environment variables

**Firewall Rules:**
- Address lists: EOIP-ALLOW, managerIP, BGP-ALLOW, SNMP
- Filter rules: Input chain (EST/REL, MT Neighbor, IGMP, ICMP, DHCP, OSPF, LDP, BGP, SNMP)
- Forward chain: BGP Accept, GRE Accept, unauth drop, fasttrack
- NAT rules: SSH redirect (5022→22), unauth proxy
- Raw rules: DROP BAD UDP

**System Settings:**
- Timezone: America/Chicago
- NTP: ntp-pool.nxlink.com
- Routerboard: Auto-upgrade enabled
- Watchdog: Enabled
- Connection tracking: UDP timeout 30s
- Proxy: Disabled

**Logging:**
- Syslog server: `142.147.116.215`
- Memory lines: 1000
- Disk lines per file: 10000
- Topics: critical, error, warning, info

**SNMP:**
- Community: Configurable (default: CHANGE_ME)
- Contact: Configurable via `nextlink_constants.js`
- Trap community: Configurable

**User Groups:**
- Standard user groups (ENG, NOC, LTE, DEVOPS, etc.)
- Read group policy updated to compliance standards

**RADIUS:**
- DHCP RADIUS servers: `142.147.112.2`, `142.147.112.18`
- Configurable via environment variables

**LDP Filters:**
- Accept/Advertise filters for MPLS networks
- Comprehensive prefix lists for NextLink network

**DHCP Options:**
- Option 43: HTTPS redirect to `https://uss.nxlink.com/`
- Applied to non-10.x networks

### Compliance Validation

The tool automatically validates compliance:
- Checks for required sections
- Validates DNS servers
- Validates syslog configuration
- Reports missing compliance items

**Compliance Status:**
- ✅ All configurations include compliance standards
- ✅ Compliance blocks are validated before generation
- ✅ Non-compliant configs are flagged with warnings

---

## Device Upgrade System

### Universal Device Support

The upgrade system supports **ALL device combinations** dynamically:

**Supported Devices:**
- CCR1036, CCR1072, CCR2004, CCR2116, CCR2216
- RB5009, RB1009, RB2011

**Any device can upgrade to any device** - no restrictions!

### How It Works

1. **Source Device Detection**
   - Automatically detects from config patterns
   - Port patterns, device names, interface types
   - No hardcoding required

2. **Target Device Selection**
   - User selects from dropdown
   - System loads port list dynamically
   - No device-specific code paths

3. **Universal Interface Mapping**
   - Order-based port mapping
   - Management port handling
   - Port name normalization

4. **RouterOS Syntax Translation**
   - RouterOS 6.x → 7.x conversion
   - Speed syntax conversion
   - AI-powered translation

### Key Features

✅ **Fully Dynamic**: No hardcoded device combinations  
✅ **Universal**: Works for any device → any device  
✅ **Intelligent**: AI understands context and device capabilities  
✅ **Preservation**: All IPs, firewall rules, VLANs, bridges preserved  
✅ **Syntax-Aware**: Converts RouterOS syntax based on version  
✅ **Port-Aware**: Maps ports intelligently based on target device  

---

## Tarana Sectors Protection

### Critical Functions Protected

The TARANA SECTORS section is fully protected and isolated:

1. **Event Listener Protection**
   - Function existence checks
   - Multiple initialization points
   - Fallback timeouts
   - Error logging

2. **Port Population Robustness**
   - Primary: Uses `DEVICE_CONFIGS` object
   - Fallback 1: Uses `getDevicePortOptions()` function
   - Fallback 2: Hardcoded port lists for CCR2004/CCR2216
   - Error handling with graceful degradation

3. **Function Isolation**
   - Self-contained functions
   - Try-catch blocks
   - Console logging
   - Validation checks

4. **Device Restrictions**
   - Only CCR2004 and CCR2216 allowed
   - Auto-clears invalid selections
   - User-friendly error messages

### Port Population Logic

**Three-Tier Fallback System:**
1. DEVICE_CONFIGS (Preferred)
2. getDevicePortOptions() (Fallback)
3. Hardcoded Lists (Last Resort)

### Auto-Selection Logic

**CCR2004:**
- ALPHA → `sfp-sfpplus8`
- BETA → `sfp-sfpplus9`
- GAMMA → `sfp-sfpplus10`

**CCR2216:**
- ALPHA → `sfp28-2`
- BETA → `sfp28-7`
- GAMMA → `sfp28-10`

---

## AI Training & Integration

### What the AI Preserves

- All IP addresses/subnets and router-id
- Interface names/assignments (remapped only when target device requires)
- Firewall rules and NAT logic
- VLAN IDs and VPLS identifiers
- User/groups and service settings

### Version/Dialect Normalization (v6 → v7)

**OSPF:**
- `/routing ospf interface` → `/routing ospf interface-template`
- `interface=` → `interfaces=`
- `authentication=` → `auth=`, `authentication-key=` → `auth-key=`
- `network-type=point-to-point` → `type=ptp`

**BGP:**
- `/routing bgp peer` → `/routing bgp connection`
- `remote-address=` → `remote.address=`
- `remote-as=` → `remote.as=`
- `tcp-md5-key=` → `tcp.md5.key=`
- `update-source=` → `update.source=`

### Safety and Gating

- Protocol blocks processed only if present in source
- No injection of new protocols
- Deterministic translation for large configs/timeouts
- Validation and error checking

---

## Network Setup

### Server Configuration

**HTML Server (current options):**
- Local development: `python -m http.server 8000 --directory vm_deployment`
- Packaged/EXE runtime: `vm_deployment/launcher.py`
- Binds to `0.0.0.0` (all network interfaces)
- Port 8000

**API Server (`fastapi_server.py` via uvicorn, or `api_server.py` compatibility shim):**
- Binds to `0.0.0.0` (all network interfaces)
- Port 5000
- CORS enabled

### Firewall Configuration

Windows Firewall may block incoming connections. To allow network access:

1. **Run setup script (as Administrator):**
   ```batch
   setup_network_access.bat
   ```

2. **Or manually configure:**
   - Allow TCP ports 5000 and 8000
   - Name: "NEXUS Servers"

### Troubleshooting

**Can't access from network:**
1. Check if servers are running
2. Check firewall rules
3. Verify servers are listening on all interfaces (`0.0.0.0`)

**Backend API not responding:**
1. Check if `api_server.py` is running
3. Test API: `curl http://localhost:5000/api/health`

**CORS errors:**
- CORS is already enabled in `api_server.py`
- Check browser console for specific errors

---

## Enterprise Configuration Improvements

### Reference File System

Created centralized reference file (`nextlink_enterprise_reference.py`) containing standard configurations:

- **User Groups**: ENG, NOC, LTE, DEVOPS, VOIP, STS, TECHSUPPORT, INFRA, INSTALL, COMENG, INTEGRATIONS, IDO, CALLCENTER-WRITE
- **Firewall Address Lists**: ACS, EOIP-ALLOW, managerIP, BGP-ALLOW, SNMP
- **Firewall Filter Rules**: Comprehensive input chain rules
- **Firewall Raw Rules**: DROP BAD UDP
- **IP Services**: www-ssl, www, ftp, ssh, telnet, api, api-ssl
- **System Settings**: Clock timezone, Routerboard auto-upgrade
- **System Logging**: Comprehensive topic logging
- **NTP Client**: Enabled with ntp-pool.nxlink.com
- **IP Neighbor Discovery**: Interface list configuration
- **User AAA**: RADIUS configuration

### Backend API Enhancements

**Added Missing Configuration Sections:**
- User groups (all 13 standard groups)
- Complete firewall address lists
- Comprehensive firewall filter rules
- Firewall raw rules
- IP services configuration
- System clock settings
- System logging
- NTP client configuration
- IP neighbor discovery settings
- User AAA (RADIUS)

**Improved IP Address Handling:**
- Uses exact IP addresses provided by user
- Properly calculates network addresses from CIDR
- Supports user-provided private CIDR and pool ranges
- Backhaul IP address properly assigned

**Dynamic Port Mapping:**
- Port selection dynamic based on device type
- Uplink interface speed automatically set based on RouterOS version
- Proper interface comments include device identity

### MPLS Enterprise Configuration

MPLS Enterprise configs follow the same reference-based architecture:
- **BASE CONFIG**: Standard sections (IP services, bridges, DNS, firewall, users)
- **SYSTEM SPECIFIC**: Device-specific config (identity, MPLS, VPLS, OSPF, LDP, interfaces)
- **BNG CONFIGS**: BNG configuration templates (MT BNG and Nokia BNG)

All infrastructure values dynamically retrieved from `nextlink_constants.js`.

---

## Best Practices

### Code Organization
- ✅ No hardcoded proprietary information
- ✅ Reference-based architecture
- ✅ Dynamic configuration system
- ✅ Centralized infrastructure settings

### Security
- ✅ Passwords hidden by default
- ✅ Placeholders for secrets (`CHANGE_ME`)
- ✅ Environment variables for sensitive data
- ✅ No information leakage

### Consistency
- ✅ Standard configurations in reference files
- ✅ Consistent output format
- ✅ Device-agnostic logic
- ✅ Version-aware syntax conversion

### Maintainability
- ✅ Single source of truth for configurations
- ✅ Easy to update standard configs
- ✅ Clear separation of concerns
- ✅ Comprehensive documentation

---

## Support & Troubleshooting

### Common Issues

1. **Ports not populating:**
   - Check device selection
   - Verify `DEVICE_CONFIGS` object is loaded
   - Check browser console for errors

2. **Configuration generation fails:**
   - Verify backend API is running
   - Review browser console for errors

3. **Dark/light mode not working:**
   - Check `data-theme` attribute on `<html>` element
   - Verify CSS variables are defined
   - Check for inline styles overriding theme

4. **Network access not working:**
   - Verify firewall rules are configured
   - Check servers are binding to `0.0.0.0`
   - Test with `netstat -an | findstr ":5000 :8000"`

### Getting Help

- Check this documentation first
- Review browser console for errors
- Check backend API logs
- Verify all services are running

---

## Version History

- **v2.0**: Unified configuration system, reference-based architecture
- **v1.5**: Added MPLS Enterprise support
- **v1.0**: Initial release with Tower, Enterprise, Tarana, and 6GHz Switch configs

---

**Last Updated**: 2025  
**Maintained by**: NextLink NOC Team  
**Security Status**: ✅ Production Ready - No Hardcoded Secrets

