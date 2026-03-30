# UI to API v2 Parity Matrix

This maps current NOC ConfigMaker UI workflows to `/api/v2` job actions for OMNI/Mushu integration.

## Sidebar Coverage Snapshot

| Sidebar Area | Current UI Coverage | Published `/api/v2/omni` Contract Coverage | Status |
|-------------|---------------------|--------------------------------------------|--------|
| Home / Dashboard | Health, activity, app defaults, infrastructure | `health.get`, `activity.list`, `configs.list`, `legacy.proxy` | Partial |
| MikroTik Config | Router/generator workflows, enterprise, Tarana | `mt.*`, `enterprise.generate_non_mpls`, `tarana.generate` | Partial |
| Field Config Studio | IDO-backed device interrogation and generation | `ido.*` actions | Partial |
| Devices Firmware Updater | Aviat and Cambium workflows | `aviat.*` typed start, Cambium not yet promoted into v2 | Partial |
| FTTH Configurator | Preview/generate BNG plus FTTH site/customer tools | `ftth.preview_bng`, `ftth.generate_bng`, `ftth.mf2_package` | Partial |
| Command Vault | Nokia/Cisco/MikroTik references | Not yet promoted as first-class published contract | Gap |
| Cisco Port Setup | Cisco-specific config helper | Not yet promoted as first-class published contract | Gap |
| Power Tools | Diff, bulk ops, maintenance, compliance | `compliance.*` typed start, bulk/diff not yet promoted | Partial |
| History | Saved configs and log history | `configs.*`, `activity.*` typed start | Partial |
| Feedback / Admin | Feedback submission and review/admin actions | `feedback.submit`, `admin.feedback.*` | Partial |

Status meaning:
- `Typed`: explicit Swagger schema/examples exist for the primary action payloads
- `Partial`: action exists and is callable, but more sub-workflows still need explicit published schemas
- `Gap`: UI exists but the workflow is not yet promoted into the OMNI contract

## How OMNI should call

1. `POST /api/v2/omni/jobs` with `{"action":"...", "payload":{...}}`
2. Poll `GET /api/v2/omni/jobs/{job_id}`
3. Poll `GET /api/v2/omni/jobs/{job_id}/events`

Use API key + HMAC signing + Idempotency-Key (for POST).

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

## Tarana Sectors

| Action | Description | Payload |
|--------|-------------|---------|
| `tarana.generate` | Validate/correct Tarana sector config | `{"config": "/interface bridge\nadd name=bridge3000...", "device": "ccr2004", "routeros_version": "7.19.4"}` |

## FTTH

| Action | Description | Payload |
|--------|-------------|---------|
| `ftth.preview_bng` | Preview FTTH BNG CIDR details | `{"loopback_ip": "10.x.x.x/32", "cpe_cidr": "10.x.x.0/22", "cgnat_cidr": "100.64.x.0/22", "olt_cidr": "10.x.x.0/29"}` |
| `ftth.generate_bng` | Generate full FTTH BNG config | `{"deployment_type": "outstate", "router_identity": "RTR-MT2216-AR1.SITE", "loopback_ip": "10.x.x.x/32", "cpe_network": "10.x.x.0/22", "cgnat_private": "100.64.x.0/22", "cgnat_public": "132.147.x.x/32", "unauth_network": "10.x.x.0/22", "olt_network": "10.x.x.0/29", "olt_name_primary": "OLT-GW", "routeros_version": "7.19.4"}` |
| `ftth.mf2_package` | Generate FTTH MF2 OLT package | `{"olt_name": "OLT-1", "olt_ip": "10.x.x.2", "gateway_ip": "10.x.x.1", "vlan_id": 100}` |

## Migration / Translation

| Action | Description | Payload |
|--------|-------------|---------|
| `migration.config` | Generic config migration | `{"source_config": "...", "source_type": "mikrotik", "target_type": "nokia"}` |
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
