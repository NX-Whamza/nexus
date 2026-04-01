# NEXUS UI to API v2 Parity Matrix

This maps current NEXUS UI workflows to `/api/v2` job actions. NEXUS is the canonical product API surface; Omni is a client of that surface.

## How Clients Should Call

## Sidebar Coverage Snapshot

| Sidebar Area | Current UI Coverage | Published `/api/v2/nexus` Contract Coverage | Status |
|-------------|---------------------|--------------------------------------------|--------|
| Home / Dashboard | Health, activity, app defaults, infrastructure | `health.get`, `activity.list`, `configs.list`, `legacy.proxy` | Partial |
| MikroTik Config | Router/generator workflows, enterprise, Tarana | `mt.*`, `enterprise.generate_non_mpls`, `tarana.generate` | Partial |
| Field Config Studio | IDO-backed device interrogation and generation | `ido.*` typed start for ping/generic info, more subflows remain | Partial |
| Devices Firmware Updater | Aviat and Cambium workflows | `aviat.*` typed start, `cambium.run` typed start | Partial |
| FTTH Configurator | Preview/generate BNG plus FTTH site/customer tools | `ftth.preview_bng`, `ftth.generate_bng`, `ftth.fiber_customer`, `ftth.fiber_site`, `ftth.isd_fiber` | Partial |
| Command Vault | Nokia/Cisco/MikroTik references | Not yet promoted as first-class published contract | Gap |
| Cisco Port Setup | Cisco-specific config helper | Not yet promoted as first-class published contract | Gap |
| Power Tools | Diff, bulk ops, maintenance, compliance | `compliance.*` typed start, `bulk.*` typed start, diff still pending | Partial |
| History | Saved configs and log history | `configs.*`, `activity.*` typed start | Partial |
| Feedback / Admin | Feedback submission and review/admin actions | `feedback.submit`, `admin.feedback.*` | Partial |

Status meaning:
- `Typed`: explicit Swagger schema/examples exist for the primary action payloads
- `Partial`: action exists and is callable, but more sub-workflows still need explicit published schemas
- `Gap`: UI exists but the workflow is not yet promoted into the published NEXUS contract

## How Clients Should Call

1. `POST /api/v2/nexus/jobs` with `{"action":"...", "payload":{...}}`
2. Poll `GET /api/v2/nexus/jobs/{job_id}`
3. Poll `GET /api/v2/nexus/jobs/{job_id}/events`

Use API key + HMAC signing + Idempotency-Key for mutating calls.

Compatibility aliases currently exist at `/api/v2/jobs` and `/api/v2/omni/jobs`, but new integrations should prefer `/api/v2/nexus/*`.

---

## Dashboard / Logs

| Action | Description | Payload |
|--------|-------------|---------|
| `health.get` | Health badge | `{}` |
| `app.config.get` | App defaults/config | `{}` |
| `infrastructure.get` | Infra defaults (DNS, RADIUS, shared keys) | `{}` |
| `routerboards.list` | Routerboard device list | `{}` |
| `activity.list` | Activity feed (history) | `{"params": {"limit": 50}}` |
| `activity.log` | Write activity entry | `{"username": "...", "type": "new-config", "device": "...", "siteName": "...", "routeros": "...", "success": true}` |
| `configs.list` | Saved configs list | `{"params": {"search": "", "config_type": "", "limit": 50}}` |

## Completed Configs

| Action | Description | Payload |
|--------|-------------|---------|
| `configs.save` | Save generated config | `{"config_type": "tower-config", "device_name": "...", "device_type": "CCR2004", "loopback_ip": "10.x.x.x", "config_content": "...", "site_name": "...", "metadata": {}}` |
| `configs.get` | Fetch one config by ID | `{"config_id": 42}` |
| `configs.portmap.download` | Download port map by ID | `{"config_id": 42}` |
| `configs.portmap.extract` | Extract port map from text | `{"config_text": "/interface ethernet\nset ..."}` |

## MikroTik Generator

| Action | Description | Payload |
|--------|-------------|---------|
| `mt.render` | Render config + portmap | `{"config_type": "tower", "payload": {"loopback_subnet": "10.x.x.x/32", "site_name": "...", ...}}` |
| `mt.config` | Config text only | `{"config_type": "tower", "payload": {...}}` |
| `mt.portmap` | Port map only | `{"config_type": "tower", "payload": {...}}` |

## Nokia 7250

| Action | Description | Payload |
|--------|-------------|---------|
| `nokia.defaults` | Get Nokia 7250 credentials from env vars | `{}` |
| `nokia.generate_7250` | Generate Nokia 7250 IN-STATE config (legacy builder) | `{"system_name": "RTR-7250-SITE", "system_ip": "10.42.12.88/32", "location": "32.7767,-96.7970", "port1_desc": "Switch", "port2_desc": "Switch", "port2_shutdown": false, "enable_ospf": true, "enable_bgp": true, "enable_fiber": false, "fiber_interface": "FIBERCOMM", "fiber_ip": "", "backhauls": [{"name": "BH-EAST", "ip": "10.42.12.1/30"}]}` |
| `nokia.configurator.generate` | Generate unified Nokia configurator output | `{"model": "7750", "profile": "edge-standard", "system_name": "PE1-WEST-01", "system_ip": "10.10.10.1", "tenant_code": "tenant-a"}` |
| `ido.nokia7250.generate` | Generate Nokia 7250 config via IDO/Jinja2 templates (returns file) | `{"hostname": "RTR-7250-SITE", "system_ip": "10.42.12.88/32", "backhauls": [{"name": "BH-EAST", "ip": "10.42.12.1/30"}], "uplinks": [{"name": "uplink1"}]}` |

**Response for `nokia.generate_7250`:**
```json
{"success": true, "config": "/bof primary-config cf3:/startup-config\n..."}
```

**Response for `nokia.defaults`:**
```json
{"snmp_community": "...", "nlroot_pw": "...", "admin_pw": "...", "bgp_auth_key": "...", "ospf_auth_key": "..."}
```

## Enterprise

| Action | Description | Payload |
|--------|-------------|---------|
| `enterprise.generate_non_mpls` | Generate Enterprise Non-MPLS config | `{"device": "RB5009", "target_version": "7.19.4", "public_cidr": "132.147.x.x/29", "bh_cidr": "10.x.x.x/30", "loopback_ip": "10.x.x.x/32", "uplink_interface": "sfp-sfpplus1", "public_port": "ether7", "nat_port": "ether8", "dns1": "142.147.112.3", "dns2": "142.147.112.19", "snmp_community": "...", "identity": "RTR-RB5009.SITE", "uplink_comment": "BH-EAST"}` |
| `enterprise.generate_mpls` | Generate MPLS enterprise config | `{"routerboard_device": "ccr2004", "routeros_version": "7.19.4", "customer_code": "ACME-537853", "device_name": "RTR-ACME-537853", "loopback_ip": "10.x.x.x/32", "customer_handoff": "sfp-sfpplus7", "uplinks": [{"interface": "sfp-sfpplus1", "ip": "10.x.x.x/29", "comment": "BH-EAST"}], "dns_servers": ["1.1.1.1", "8.8.8.8"], "syslog_server": "10.x.x.x", "shared_key": "...", "snmp_community": "...", "snmp_contact": "noc@example.com", "vpls_static_id": 2245, "vpls_peer": "10.x.x.x", "enable_bgp": true, "bgp_as": 65000, "bgp_peers": [{"ip": "10.x.x.x", "as": 65000}]}` |
| `enterprise.feeding.generate` | Generate Enterprise Feeding port/handoff config | `{"label": "ACME-HANDOFF", "port": "sfp-sfpplus4", "speed": "10G-baseSR-LR", "backhaul_cidr": "10.25.26.48/29", "loopback_ip": "10.25.100.1/32", "public_ip": "132.147.x.x"}` |
| `enterprise.feeding.generate_outstate` | Generate out-of-state BNG snippet | `{"state": "IL", "loopback_ip": "10.247.72.34/32", "username": "ACME-537853"}` |

## 6GHz Switch Port

| Action | Description | Payload |
|--------|-------------|---------|
| `switch.generate_6ghz` | Generate in-state 6GHz switch config | `{"switch_type": "swt_ccr2004", "routeros_version": "7.19.4", "vlan3000_subnet": "10.x.x.x/28", "vlan4000_subnet": "10.x.x.x/28", "pool_offset": 2, "dns_servers": ["1.1.1.1", "8.8.8.8"], "shared_key": "..."}` |
| `switch.generate_6ghz_outstate` | Generate out-of-state 6GHz switch config | `{"switch_type": "swt_mt326", "routeros_version": "7.19.4", "port1": "sfp-sfpplus1", "port2": "sfp-sfpplus2"}` |

## Tarana Sectors

| Action | Description | Payload |
|--------|-------------|---------|
| `tarana.generate` | Validate/correct Tarana sector config | `{"config": "/interface bridge\nadd name=bridge3000...", "device": "ccr2004", "routeros_version": "7.19.4"}` |

## FTTH

| Action | Description | Payload |
|--------|-------------|---------|
| `ftth.preview_bng` | Preview FTTH BNG CIDR details | `{"loopback_ip": "10.x.x.x/32", "cpe_cidr": "10.x.x.0/22", "cgnat_cidr": "100.64.x.0/22", "olt_cidr": "10.x.x.0/29"}` |
| `ftth.generate_bng` | Generate full FTTH BNG config | `{"deployment_type": "outstate", "router_identity": "RTR-MT2216-AR1.SITE", "loopback_ip": "10.x.x.x/32", "cpe_network": "10.x.x.0/22", "cgnat_private": "100.64.x.0/22", "cgnat_public": "132.147.x.x/32", "unauth_network": "10.x.x.0/22", "olt_network": "10.x.x.0/29", "olt_name_primary": "OLT-GW", "routeros_version": "7.19.4"}` |
| `ftth.generate_fiber_customer` | Generate fiber customer handoff config | `{"routerboard": "RB5009", "routeros": "7.19.4", "provider": "ACME Fiber", "port": "sfp-sfpplus1", "address": "10.x.x.2/30", "network": "10.x.x.0/30", "loopback_ip": "10.x.x.x/32", "vlan_mode": "tagged", "vlan_id": "210", "apply_compliance": false}` |
| `ftth.generate_fiber_site` | Generate 1072/1036 paired fiber site configs | `{"tower_name": "ACME-HUB-1", "loopback_1072": "10.x.x.107/32", "loopback_1036": "10.x.x.103/32", "bh1_subnet": "10.x.x.0/30", "link_1072_1036_a": "10.x.x.4/30", "link_1072_1036_b": "10.x.x.8/30", "fiber_port_ip": "10.x.x.1/30", "backhauls": [{"name": "BH-EAST", "port": "sfp-sfpplus1", "subnet": "10.x.x.12/30"}], "apply_compliance": false}` |
| `ftth.generate_isd_fiber` | Generate ISD fiber config + port map | `{"router_type": "CCR2004-1G-12S+2XS", "tower_name": "ACME-ISD-1", "loopback_subnet": "10.x.x.108/32", "private_ip": "10.x.x.1/24", "public_ip": "132.147.x.x/29", "fiber_port_ip": "10.x.x.1/30", "backhauls": [{"name": "CR7", "ip": "10.2.0.107/32"}], "apply_compliance": false}` |
| `ftth.mf2_package` | Generate FTTH MF2 OLT package | `{"olt_name": "OLT-1", "olt_ip": "10.x.x.2", "gateway_ip": "10.x.x.1", "vlan_id": 100}` |
| `ftth.fiber_customer` | Generate FTTH fiber customer handoff config | `{"routerboard": "CCR2004", "routeros": "7.19.4", "provider": "tenant-a", "address": "132.147.10.2/30", "network": "132.147.10.0/30", "port": "sfp-sfpplus1", "vlan_mode": "tagged", "vlan_id": "2100"}` |
| `ftth.fiber_site` | Generate paired FTTH fiber site configs | `{"tower_name": "WEST-HUB", "loopback_1072": "10.249.50.1/32", "loopback_1036": "10.249.50.2/32", "bh1_subnet": "10.249.60.0/30", "link_1072_1036_a": "10.249.61.0/31", "link_1072_1036_b": "10.249.61.2/31", "fiber_port_ip": "10.249.62.1/30"}` |
| `ftth.isd_fiber` | Generate ISD fiber config + port map | `{"router_type": "CCR1036", "tower_name": "WEST-HUB", "loopback_subnet": "10.249.70.1/32", "private_ip": "10.249.71.1/30", "public_ip": "132.147.20.1/30", "fiber_port_ip": "10.249.72.1/30"}` |

## Migration / Translation

| Action | Description | Payload |
|--------|-------------|---------|
| `migration.config` | Generic config migration | `{"source_config": "...", "source_type": "mikrotik", "target_type": "nokia"}` |
| `migration.parse_mikrotik_for_nokia` | Parse MikroTik config for Nokia migration helper | `{"config": "/interface bridge\nadd name=..."}` |
| `migration.mikrotik_to_nokia` | MikroTik -> Nokia migration | `{"source_config": "/interface bridge\nadd name=...", "preserve_ips": true}` |
| `config.validate` | Validate config | `{"config": "...", "device_type": "ccr2004", "routeros_version": "7.19.4"}` |
| `config.suggest` | Suggest config improvements | `{"config": "...", "context": "tower router"}` |
| `config.explain` | Explain config sections | `{"config": "...", "question": "What does this OSPF block do?"}` |
| `config.translate` | Translate config between formats | `{"config": "...", "from_format": "mikrotik", "to_format": "nokia"}` |
| `config.autofill_from_export` | Autofill form from exported config | `{"config_export": "/export\n/ip address\nadd ..."}` |

## SSH Config Fetch

| Action | Description | Payload |
|--------|-------------|---------|
| `device.fetch_config_ssh` | SSH into device and fetch config | `{"host": "10.x.x.x", "port": 22, "username": "admin", "password": "...", "command": "/export"}` |
| `device.push_config_ssh` | Push generated config to device over SSH | `{"host": "10.x.x.x", "port": 22, "username": "admin", "password": "...", "config": "...", "commit": true}` |

## Cisco

| Action | Description | Payload |
|--------|-------------|---------|
| `cisco.generate_interface` | Generate Cisco port + OSPF handoff config | `{"port_description": "BH-TO-SITE-A", "port_type": "TenGigE", "port_number": "0/0/0/1", "interface_ip": "10.x.x.x", "subnet_mask": "255.255.255.252", "ospf_cost": 10, "ospf_process": 1, "ospf_area": "0", "mtu": 9216, "passive": false}` |

## Command Vault

| Action | Description | Payload |
|--------|-------------|---------|
| `command.vault.catalog` | List/search Command Vault families and reference commands for Nokia, Cisco, and MikroTik | `{"family": "nokia", "subsection": "7750-bng", "query": "bgp"}` |

Direct endpoint:

| Endpoint | Description | Payload |
|--------|-------------|---------|
| `POST /api/v2/nexus/tools/command-vault` | Filter command-vault catalog for Omni/native UI rendering | Same payload as `command.vault.catalog` |

## Power Tools

| Action | Description | Payload |
|--------|-------------|---------|
| `config.diff` | Compute side-by-side config diff | `{"config_a": "...", "config_b": "..."}` |
| `bulk.generate` | Bulk-generate configs | `{"sites": [{"site_name": "...", "device": "CCR2004", "loopback_ip": "10.x.x.x/32"}]}` |
| `bulk.fetch_config` | Bulk SSH fetch configs | `{"hosts": ["10.x.x.x"], "ros_version": "7", "ports": [22, 5022]}` |
| `bulk.migration.analyze` | Analyze migration batch | `{"items": [{"site_name": "...", "source_config": "...", "target_device": "CCR2004"}]}` |
| `bulk.migration.execute` | Execute migration batch | `{"items": [{"site_name": "...", "source_config": "...", "target_device": "CCR2004"}]}` |
| `bulk.compliance.scan` | Run bulk compliance scan | `{"items": [{"site_name": "...", "config": "...", "loopback_ip": "10.x.x.x"}]}` |

## Maintenance

Use direct REST endpoints instead of job actions:

| Endpoint | Description | Payload |
|--------|-------------|---------|
| `GET /api/v2/nexus/maintenance/windows` | List maintenance windows | Query: `status`, `limit` |
| `POST /api/v2/nexus/maintenance/windows` | Create maintenance window | `{"name": "ACME firmware window", "scheduled_at": "2026-04-01T02:00:00Z", "duration_minutes": 120, "priority": "normal", "devices": ["10.x.x.x"], "tasks": ["firmware", "testing"], "notes": "...", "ticket_number": "NOC-1234", "ticket_url": "https://..."}` |
| `GET /api/v2/nexus/maintenance/windows/{window_id}` | Read one maintenance window | `{}` |
| `PUT /api/v2/nexus/maintenance/windows/{window_id}` | Update maintenance window | Same payload shape as create |
| `DELETE /api/v2/nexus/maintenance/windows/{window_id}` | Delete maintenance window | `{}` |

## Compliance / Config Policies

| Action | Description | Payload |
|--------|-------------|---------|
| `compliance.apply` | Apply compliance to config | `{"config": "...", "loopback_ip": "10.x.x.x"}` |
| `compliance.status` | Get compliance engine status | `{}` |
| `compliance.blocks` | Get compliance blocks from GitLab | `{}` |
| `compliance.engineering` | Get engineering compliance blocks | `{}` |
| `compliance.policies.list` | List all config policies | `{}` |
| `compliance.policies.get` | Get specific config policy | `{"policy_name": "standard-tower"}` |
| `compliance.policies.bundle` | Get policy bundle (all policies merged) | `{}` |
| `compliance.policies.reload` | Reload config policies from disk | `{}` |
| `compliance.reload` | Reload compliance engine | `{}` |

## Field Config Studio (IDO-backed)

| Action | Description | Payload |
|--------|-------------|---------|
| `ido.capabilities` | List IDO backend capabilities | `{}` |
| `ido.ping` | Ping device via IDO | `{"host": "10.x.x.x"}` |
| `ido.generic.device_info` | Generic device info | `{"host": "10.x.x.x", "username": "admin", "password": "..."}` |

**AP** (Access Point):

| Action | Payload |
|--------|---------|
| `ido.ap.device_info` | `{"host": "10.x.x.x", "username": "admin", "password": "..."}` |
| `ido.ap.running_config` | `{"host": "10.x.x.x", "username": "admin", "password": "..."}` |
| `ido.ap.standard_config` | `{"host": "10.x.x.x", "username": "admin", "password": "..."}` |
| `ido.ap.generate` | `{"host": "10.x.x.x", "username": "admin", "password": "...", "config": {...}}` |

**BH** (Backhaul):

| Action | Payload |
|--------|---------|
| `ido.bh.device_info` | `{"host": "10.x.x.x", "username": "admin", "password": "..."}` |
| `ido.bh.running_config` | `{"host": "10.x.x.x", "username": "admin", "password": "..."}` |
| `ido.bh.standard_config` | `{"host": "10.x.x.x", "username": "admin", "password": "..."}` |
| `ido.bh.generate` | `{"host": "10.x.x.x", "username": "admin", "password": "...", "config": {...}}` |

**Switch**:

| Action | Payload |
|--------|---------|
| `ido.swt.device_info` | `{"host": "10.x.x.x", "username": "admin", "password": "..."}` |
| `ido.swt.running_config` | `{"host": "10.x.x.x", "username": "admin", "password": "..."}` |
| `ido.swt.standard_config` | `{"host": "10.x.x.x", "username": "admin", "password": "..."}` |
| `ido.swt.generate` | `{"host": "10.x.x.x", "username": "admin", "password": "...", "config": {...}}` |

**UPS**:

| Action | Payload |
|--------|---------|
| `ido.ups.device_info` | `{"host": "10.x.x.x", "username": "admin", "password": "..."}` |
| `ido.ups.running_config` | `{"host": "10.x.x.x", "username": "admin", "password": "..."}` |
| `ido.ups.standard_config` | `{"host": "10.x.x.x", "username": "admin", "password": "..."}` |
| `ido.ups.generate` | `{"host": "10.x.x.x", "username": "admin", "password": "...", "config": {...}}` |

**RPC**:

| Action | Payload |
|--------|---------|
| `ido.rpc.device_info` | `{"host": "10.x.x.x", "username": "admin", "password": "..."}` |
| `ido.rpc.running_config` | `{"host": "10.x.x.x", "username": "admin", "password": "..."}` |
| `ido.rpc.standard_config` | `{"host": "10.x.x.x", "username": "admin", "password": "..."}` |
| `ido.rpc.generate` | `{"host": "10.x.x.x", "username": "admin", "password": "...", "config": {...}}` |

**Wave / Nokia 7250**:

| Action | Payload |
|--------|---------|
| `ido.wave.config` | `{"host": "10.x.x.x", "config": {...}}` |
| `ido.nokia7250.generate` | `{"hostname": "...", "system_ip": "...", "backhauls": [...], "uplinks": [...]}` |

## Aviat Backhaul Updater

| Action | Description | Payload |
|--------|-------------|---------|
| `aviat.run` | Run firmware update workflow | `{"devices": [{"ip": "10.x.x.x", "firmware": "v14.1.2"}]}` |
| `aviat.activate_scheduled` | Activate scheduled firmware | `{"devices": [{"ip": "10.x.x.x"}]}` |
| `aviat.check_status` | Check status of batch | `{"devices": [{"ip": "10.x.x.x"}]}` |
| `aviat.status` | Get status of specific task | `{"task_id": "uuid-here"}` |
| `aviat.precheck_recheck` | Re-run prechecks | `{"devices": [{"ip": "10.x.x.x"}]}` |
| `aviat.scheduled.get` | Read scheduled queue | `{}` |
| `aviat.loading.get` | Read loading queue | `{}` |
| `aviat.queue.get` | Read main queue | `{}` |
| `aviat.queue.update` | Update queue entries | `{"entries": [...]}` |
| `aviat.reboot_required.get` | Read reboot-required queue | `{}` |
| `aviat.reboot_required.run` | Run reboot-required queue | `{}` |
| `aviat.scheduled.sync` | Sync scheduled queue | `{}` |
| `aviat.fix_stp` | Fix STP on device | `{"ip": "10.x.x.x"}` |
| `aviat.stream.global` | Stream global log (SSE) | `{}` |
| `aviat.abort` | Abort a running task | `{"task_id": "uuid-here"}` |

## Cambium Radio Updater

| Action | Description | Payload |
|--------|-------------|---------|
| `cambium.run` | Run Cambium queue workflow for backup, firmware, and verify tasks | `{"radios": [{"ip": "10.247.180.66", "username": "admin", "password": "..."}], "tasks": ["backup", "firmware", "verify"], "firmware_version": "5.10.4-13433", "firmware_source": "stable", "requested_by": "omni-automation"}` |

## Bulk Operations Center

| Action | Description | Payload |
|--------|-------------|---------|
| `bulk.generate` | Run bulk config generation | `{"config_type": "tower", "rows": [{"site_name": "WEST-HUB", "loopback_subnet": "10.249.7.137/32"}], "save_completed": true}` |
| `bulk.ssh_fetch` | Fetch configs from many devices over SSH | `{"rows": [{"host": "10.x.x.x", "username": "admin", "password": "..."}], "command": "/export terse"}` |
| `bulk.migration_analyze` | Analyze many migration inputs before generation | `{"rows": [{"site_name": "WEST-HUB", "source_config": "/interface bridge add name=bridge1"}]}` |
| `bulk.migration_execute` | Execute prepared bulk migration rows | `{"rows": [{"site_name": "WEST-HUB", "source_config": "/interface bridge add name=bridge1"}], "save_completed": true}` |
| `bulk.compliance_scan` | Scan many configs for compliance issues | `{"rows": [{"site_name": "WEST-HUB", "config": "/routing ospf instance set default"}]}` |
| `device.ssh_push_config` | Push generated configs to devices over SSH | `{"rows": [{"host": "10.x.x.x", "username": "admin", "password": "...", "config": "/system identity set name=RTR-EDGE-01"}], "dry_run": false}` |

## Feedback

| Action | Description | Payload |
|--------|-------------|---------|
| `feedback.submit` | Submit feedback/bug/feature request | `{"type": "feedback", "rating": 5, "message": "Great tool!", "email": "user@example.com", "tab": "feedback"}` |

## Admin

| Action | Description | Payload |
|--------|-------------|---------|
| `admin.feedback.list` | List all feedback | `{}` |
| `admin.feedback.update_status` | Update feedback status | `{"feedback_id": 1, "status": "reviewed"}` |
| `admin.feedback.export` | Export feedback as CSV | `{}` |
| `admin.users.reset_password` | Reset user password | `{"email": "user@example.com", "new_password": "..."}` |

## Escape hatch

- `legacy.proxy` for endpoints not yet promoted.
- This should be treated as temporary; prefer typed actions above.
