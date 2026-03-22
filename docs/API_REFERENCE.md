# NOC ConfigMaker — Full API Reference

> **Auto-maintained** — update this document every time an endpoint is added, removed, or its payload changes.
>
> Live version: `GET /api/docs` returns this file rendered as JSON.

---

## Base URL

| Environment | URL |
|---|---|
| Production | `https://noc-configmaker.nxlink.com` |
| Local dev | `http://localhost:5000` |
| V2 (OMNI) | `https://noc-configmaker.nxlink.com/api/v2` (see `docs/API_V2.md`) |

---

## Authentication

Most endpoints are **open** (internal tool).
Endpoints marked **🔒 Auth** require a JWT token:

```
Authorization: Bearer <jwt_token>
```

Admin endpoints marked **🔒 Admin** additionally require the `admin` role.

---

## Common Response Envelope

```jsonc
// Success
{ "success": true, "config": "...", ... }

// Error
{ "error": "Missing required fields" }   // HTTP 400
{ "success": false, "error": "..." }      // HTTP 500
```

---

## Table of Contents

1. [Health & System](#1-health--system)
2. [Authentication](#2-authentication)
3. [AI Chat](#3-ai-chat)
4. [OpenAI-Compatible API](#4-openai-compatible-api)
5. [Config Translation & Validation](#5-config-translation--validation)
6. [Config Generation — MikroTik](#6-config-generation--mikrotik)
7. [Config Generation — FTTH BNG](#7-config-generation--ftth-bng)
8. [Config Generation — Nokia](#8-config-generation--nokia)
9. [Device Migration](#9-device-migration)
10. [SSH / Remote Device](#10-ssh--remote-device)
11. [Compliance & Policy](#11-compliance--policy)
12. [Completed Configs](#12-completed-configs)
13. [Activity Tracking](#13-activity-tracking)
14. [Feedback](#14-feedback)
15. [Admin](#15-admin)
16. [Aviat Radio Management](#16-aviat-radio-management)
17. [IDO Proxy](#17-ido-proxy)

---

## 1. Health & System

### `GET /api/health`

Health check — server alive + AI provider status.

**Response `200`**
```json
{
  "status": "online",
  "ai_provider": "openai",
  "api_key_configured": true,
  "timestamp": "2026-03-02T01:30:00Z",
  "message": "NOC ConfigMaker API is running"
}
```

---

### `GET /api/app-config`

Runtime config for the frontend (BNG peers, defaults).

**Response `200`**
```json
{
  "bng_peers": {
    "NE": { "ip": "10.2.0.107", "name": "CR7" },
    "IL": { "ip": "10.2.0.108", "name": "CR8" }
  },
  "default_bng_peer": "NE"
}
```

---

### `GET /api/infrastructure` 🔒 Auth

Authenticated infrastructure defaults (DNS, RADIUS, SNMP).

**Headers:** `Authorization: Bearer <token>`

**Response `200`**
```json
{
  "dns_servers": ["142.147.112.3", "142.147.112.19"],
  "shared_key": "...",
  "snmp": { "community": "..." },
  "radius": { "servers": [...] }
}
```

---

### `POST /api/reload-training`

Hot-reload AI training rules from disk.

**Request**
```json
{ "dir": "/path/to/training" }
```

**Response `200`**
```json
{ "success": true, "loaded": ["rule1.md", "rule2.md"], "dir": "/path" }
```

---

### `GET /api/docs`

Returns this API reference as JSON (self-documenting endpoint).

**Response `200`**
```json
{
  "success": true,
  "version": "1.0.0",
  "total_endpoints": 84,
  "categories": [...],
  "endpoints": [...]
}
```

---

## 2. Authentication

### `POST /api/auth/login`

Email/password login. Creates user on first login.
Domain restricted to `@team.nxlink.com`.

**Request**
```json
{
  "email": "user@team.nxlink.com",
  "password": "secretpassword"
}
```

**Response `200`**
```json
{
  "success": true,
  "token": "eyJ...",
  "user": {
    "id": "abc123",
    "email": "user@team.nxlink.com",
    "displayName": "User Name",
    "firstLogin": false
  }
}
```

---

### `POST /api/auth/microsoft`

Microsoft SSO — returns OAuth redirect URL.

**Response `200`**
```json
{ "success": true, "authUrl": "https://login.microsoftonline.com/..." }
```

---

### `POST /api/auth/change-password` 🔒 Auth

**Request**
```json
{
  "currentPassword": "oldpass",
  "newPassword": "newpass"
}
```

**Response `200`**
```json
{ "success": true, "message": "Password changed successfully" }
```

---

### `POST /api/auth/forgot-password`

**Request**
```json
{ "email": "user@team.nxlink.com" }
```

**Response `200`**
```json
{ "success": true, "message": "Reset token generated", "resetToken": "abc123" }
```

---

### `POST /api/auth/reset-password`

**Request**
```json
{
  "email": "user@team.nxlink.com",
  "resetToken": "abc123",
  "newPassword": "newpassword"
}
```

**Response `200`**
```json
{ "success": true, "message": "Password reset successfully" }
```

---

### `POST /api/auth/verify`

Verify JWT token validity.

**Request**
```json
{ "token": "eyJ..." }
```

**Response `200`**
```json
{
  "success": true,
  "authenticated": true,
  "user": { "id": "abc123", "email": "user@team.nxlink.com", "displayName": "User", "firstLogin": false }
}
```

---

## 3. AI Chat

### `POST /api/chat`

AI chat for RouterOS / network engineering Q&A.

**Request**
```json
{
  "message": "How do I configure OSPF on ROS7?",
  "session_id": "optional-session-id"
}
```

_Or multi-turn:_
```json
{
  "messages": [
    { "role": "user", "content": "Configure OSPF..." },
    { "role": "assistant", "content": "Here's how..." },
    { "role": "user", "content": "Now add BGP" }
  ],
  "session_id": "sess-123"
}
```

**Response `200`**
```json
{
  "success": true,
  "reply": "To configure OSPF on RouterOS 7...",
  "session_id": "sess-123"
}
```

---

### `GET /api/chat/history/<session_id>`

**Query:** `?limit=20` (default 20)

**Response `200`**
```json
{
  "success": true,
  "history": [
    { "role": "user", "content": "...", "timestamp": "..." },
    { "role": "assistant", "content": "...", "timestamp": "..." }
  ]
}
```

---

### `GET /api/chat/context/<session_id>`

**Response `200`**
```json
{ "success": true, "context": { "preferred_model": "gpt-4", "context_memory": {} } }
```

---

### `POST /api/chat/context/<session_id>`

**Request**
```json
{ "preferred_model": "gpt-4", "context_memory": { "key": "value" } }
```

**Response `200`**
```json
{ "success": true, "message": "Context updated" }
```

---

### `GET /api/chat/export/<session_id>`

**Response `200`**
```json
{
  "session_id": "sess-123",
  "export_timestamp": "2026-03-02T01:30:00Z",
  "total_messages": 10,
  "conversations": [...]
}
```

---

## 4. OpenAI-Compatible API

For external UIs like Open WebUI.

### `GET /v1/models`

**Response `200`**
```json
{
  "object": "list",
  "data": [
    { "id": "noc-configmaker", "object": "model", "created": 1709337600, "owned_by": "nextlink" }
  ]
}
```

---

### `POST /v1/chat/completions`

**Request**
```json
{
  "model": "noc-configmaker",
  "messages": [{ "role": "user", "content": "Configure BGP..." }],
  "temperature": 0.7,
  "max_tokens": 4096
}
```

**Response `200`**
```json
{
  "id": "chatcmpl-abc123",
  "object": "chat.completion",
  "created": 1709337600,
  "model": "noc-configmaker",
  "choices": [{ "index": 0, "message": { "role": "assistant", "content": "..." }, "finish_reason": "stop" }],
  "usage": { "prompt_tokens": 50, "completion_tokens": 200, "total_tokens": 250 }
}
```

---

## 5. Config Translation & Validation

### `POST /api/translate-config`

Translate RouterOS config between firmware versions (ROS6→ROS7) and/or between device models (CCR1072→CCR2216).

**Request**
```json
{
  "source_config": "# 2023-10-01 by RouterOS 6.49.17\n/ip address add ...",
  "target_device": "CCR2216-1G-12XS-2XQ",
  "target_version": "7.19.4",
  "strict_preserve": true,
  "apply_compliance": true
}
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `source_config` | string | ✅ | — | Full RouterOS export text |
| `target_device` | string | ✅ | — | Target RouterBoard model |
| `target_version` | string | ✅ | — | Target RouterOS version (e.g. `7.19.4`) |
| `strict_preserve` | bool | ❌ | `true` | Preserve source structure; only apply syntax + interface mapping |
| `apply_compliance` | bool | ❌ | `false` | Append RFC-09-10-25 compliance blocks |

**Response `200`**
```json
{
  "success": true,
  "config": "# 2026-03-02 by RouterOS 7.19.4\n...",
  "interface_mapping": { "ether1": "ether1", "sfp1": "sfp28-1" },
  "source_version": "6.49.17",
  "target_version": "7.19.4"
}
```

---

### `POST /api/validate-config`

Validate a RouterOS config for syntax errors, missing fields, RFC compliance.

**Request**
```json
{
  "config": "/ip address add address=10.0.0.1 interface=loop0\n...",
  "type": "tower"
}
```

| Field | Type | Required | Default | Options |
|---|---|---|---|---|
| `config` | string | ✅ | — | Full config text |
| `type` | string | ❌ | `tower` | `tower`, `enterprise`, `mpls`, `enterprise-feeding` |

**Response `200`**
```json
{
  "success": true,
  "validation": {
    "valid": false,
    "issues": [
      { "severity": "error", "message": "Missing /system identity" },
      { "severity": "warning", "message": "No SNMP community configured" }
    ],
    "summary": "Validation found 1 error(s) and 1 warning(s)"
  }
}
```

---

### `POST /api/apply-compliance`

Apply RFC-09-10-25 compliance standards (additive, non-destructive).

**Request**
```json
{
  "config": "# RouterOS 7.19.4\n/ip address add ...",
  "loopback_ip": "10.33.0.95"
}
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `config` | string | ✅ | — | Full RouterOS config text |
| `loopback_ip` | string | ❌ | auto-detect from config | Loopback IP (without `/32`) |

**Response `200`**
```json
{
  "success": true,
  "config": "... with compliance appended ...",
  "compliance": {
    "compliant": true,
    "missing_items": [],
    "warnings": []
  }
}
```

---

### `POST /api/suggest-config`

AI suggests config values (autocomplete) from partial input.

**Request**
```json
{
  "device": "CCR2216-1G-12XS-2XQ",
  "target_version": "7.19.4",
  "loopback_ip": "10.33.0.95",
  "public_cidr": "132.147.181.176/30",
  "bh_cidr": "10.33.1.152/30"
}
```

**Response `200`**
```json
{
  "success": true,
  "public_port": "sfp28-1",
  "nat_port": "sfp28-2",
  "uplink_interface": "sfp28-3",
  "public_pool": "132.147.181.177-132.147.181.178",
  "gateway": "132.147.181.177"
}
```

---

### `POST /api/explain-config`

AI explains what a config section does.

**Request**
```json
{
  "config": "/ip firewall filter add action=drop chain=input comment=\"DROP INPUT\""
}
```

**Response `200`**
```json
{
  "success": true,
  "explanation": "This firewall rule drops all traffic on the input chain that hasn't been explicitly accepted by earlier rules..."
}
```

---

### `POST /api/autofill-from-export`

Parse exported config and auto-fill form fields.

**Request**
```json
{
  "exported_config": "# 2026-03-02 by RouterOS 7.19.4\n...",
  "target_form": "tower"
}
```

**Response `200`**
```json
{
  "success": true,
  "fields": {
    "site_name": "TX-HEMPSTEAD-FC-1",
    "router_id": "10.33.0.95",
    "loopback_ip": "10.33.0.95",
    "device_model": "CCR2216-1G-12XS-2XQ"
  }
}
```

---

## 6. Config Generation — MikroTik

### `POST /api/gen-enterprise-non-mpls`

Generate Non-MPLS Enterprise RouterOS config.

**Request**
```json
{
  "device": "CCR2216-1G-12XS-2XQ",
  "target_version": "7.19.4",
  "public_cidr": "132.147.181.176/30",
  "bh_cidr": "10.33.1.152/30",
  "loopback_ip": "10.33.0.95",
  "uplink_interface": "sfp28-1",
  "public_port": "sfp28-7",
  "nat_port": "sfp28-8",
  "dns1": "142.147.112.3",
  "dns2": "142.147.112.19",
  "snmp_community": "FBZ1yYdphf",
  "syslog_ip": "142.147.116.215",
  "coords": "32.1234,-97.5678",
  "identity": "RTR-MT2216-AR1.TX-HEMPSTEAD-FC-1",
  "uplink_comment": "SPARKLIGHT"
}
```

**Response `200`**
```json
{
  "success": true,
  "config": "# RouterOS 7.19.4\n...",
  "device": "CCR2216",
  "version": "7.19.4",
  "profile": {
    "public_port": "sfp28-7",
    "nat_port": "sfp28-8",
    "uplink_interface": "sfp28-1"
  }
}
```

**Response `400`**
```json
{
  "success": false,
  "error": "Enterprise interface roles must be unique. Conflicts: ether7: customer handoff, nat"
}
```

---

### `POST /api/gen-tarana-config`

Generate/validate Tarana sector config.

**Request**
```json
{
  "config": "sector configuration text...",
  "device": "CCR2004-16G-2S+",
  "routeros_version": "7.19.4"
}
```

**Response `200`**
```json
{
  "success": true,
  "config": "validated config...",
  "warnings": [],
  "device": "CCR2004-16G-2S+",
  "version": "7.19.4"
}
```

---

### `POST /api/mt/<config_type>/config`

Generate MikroTik config (Netlaunch-compatible).

| URL Param | Values |
|---|---|
| `config_type` | `tower`, `bng2` |

**Request:** Form payload with device fields + `apply_compliance: true/false`

**Response `200`:** JSON string of config text.

---

### `POST /api/mt/<config_type>/portmap`

Generate MikroTik port map (Netlaunch-compatible).

**Request:** Form payload with device fields.

**Response `200`:** JSON string of portmap text.

---

## 7. Config Generation — FTTH BNG

### `POST /api/generate-ftth-bng`

Generate complete FTTH BNG config from strict template.

**Request**
```json
{
  "deployment_type": "ftth",
  "loopback_ip": "10.33.0.95",
  "cpe_network": "10.17.108.0/22",
  "cgnat_private": "100.70.224.0/22",
  "cgnat_public": "132.147.184.147",
  "unauth_network": "10.117.108.0/22",
  "olt_network": "10.25.250.120/29",
  "uplink_ports": ["sfp28-1", "sfp28-2"],
  "olt_ports": ["sfp28-4", "sfp28-5", "sfp28-6", "sfp28-7"]
}
```

**Response `200`**
```json
{ "success": true, "config": "# FTTH BNG Config\n..." }
```

---

### `POST /api/gen-ftth-bng` _(deprecated)_

Alternate FTTH endpoint. Supports both payload shapes during the transition to the unified FTTH configurator.

**Legacy Request**
```json
{
  "loopback_ip": "10.33.0.95",
  "cpe_cidr": "10.17.108.0/22",
  "cgnat_cidr": "100.70.224.0/22",
  "olt_cidr": "10.25.250.120/29"
}
```

---

### `POST /api/preview-ftth-bng`

Returns parsed FTTH CIDR details for preview (no config generated).

**Request**
```json
{
  "loopback_ip": "10.33.0.95",
  "cpe_cidr": "10.17.108.0/22",
  "cgnat_cidr": "100.70.224.0/22",
  "olt_cidr": "10.25.250.120/29"
}
```

**Response `200`**
```json
{
  "success": true,
  "preview": {
    "olt": { "network": "10.25.250.120/29", "gateway": "10.25.250.121", "usable": 6 },
    "cpe": { "network": "10.17.108.0/22", "gateway": "10.17.108.1", "pool": "10.17.108.50-10.17.111.254" },
    "cgnat": { "network": "100.70.224.0/22", "gateway": "100.70.224.1", "pool": "100.70.224.3-100.70.227.254" }
  }
}
```

---

### `POST /api/generate-ftth-fiber-customer`

Generate the FTTH Fiber Customer handoff block for MikroTik, with optional Nextlink compliance injection.

**Request**
```json
{
  "routerboard": "ccr2004",
  "routeros": "7.19.4",
  "provider": "ATT",
  "port": "sfp-sfpplus1",
  "address": "10.42.10.2/30",
  "network": "10.42.10.0/30",
  "loopback_ip": "10.26.0.7/32",
  "vlan_mode": "tagged",
  "vlan_id": "300",
  "apply_compliance": true
}
```

**Response `200`**
```json
{
  "success": true,
  "config": "# FIBER SITE SETTINGS\n...",
  "base_config": "# FIBER SITE SETTINGS\n...",
  "selected_port": "sfp-sfpplus1",
  "compliance_source": "bundled-local",
  "metadata": {
    "routerboard": "ccr2004",
    "routeros": "7.19.4",
    "provider": "ATT",
    "port": "sfp-sfpplus1",
    "address": "10.42.10.2/30",
    "network": "10.42.10.0/30",
    "loopback_ip": "10.26.0.7/32",
    "router_id": "10.26.0.7",
    "vlan_mode": "tagged",
    "vlan_id": "300"
  },
  "compliance": {
    "compliant": true,
    "missing_items": []
  },
  "warnings": []
}
```

**Notes**
- `loopback_ip` is required when `apply_compliance=true`.
- The response `config` is the final rendered output shown in the FTTH Home Fiber Customer UI.
- `base_config` is the pre-compliance handoff block, useful for debugging or future Swagger examples.

---

### `POST /api/generate-ftth-fiber-site`

Generate the paired MikroTik `1072` and `1036` FTTH fiber-site configs and the backhaul IP / port map.

**Request**
```json
{
  "tower_name": "TX-MARLIN-W-FC-2",
  "tower_gps": "30.1,-96.1",
  "asn": "26077",
  "routeros_1072": "7.19.4",
  "loopback_1072": "10.26.0.7/32",
  "loopback_1036": "10.26.0.8/32",
  "bh1_subnet": "10.25.10.0/29",
  "link_1072_1036_a": "10.25.10.8/30",
  "link_1072_1036_b": "10.25.10.12/30",
  "cpe_subnet": "10.40.0.0/22",
  "unauth_subnet": "10.130.0.0/22",
  "cgn_priv_subnet": "100.64.0.0/22",
  "cgn_pub_ip": "132.147.184.147/32",
  "fiber_provider": "ATT",
  "fiber_port": "sfp-sfpplus8",
  "fiber_port_ip": "10.42.10.2/30",
  "fiber_vlan_mode": "tagged",
  "fiber_vlan_id": "300",
  "backhauls": [
    { "port": "3", "name": "BH-TO-SITE-A", "subnet": "10.25.10.16/29", "master": "yes", "bandwidth": "1G" }
  ],
  "apply_compliance": true
}
```

**Response `200`**
```json
{
  "success": true,
  "router_1072_config": "# 1072 FIBER SITE CONFIG ...",
  "router_1036_config": "# 1036 FIBER SITE CONFIG ...",
  "port_map": "===================================================================",
  "compliance_source": "bundled-local",
  "warnings": []
}
```

---

### `POST /api/generate-ftth-isd-fiber`

Generate the MikroTik ISD fiber config and the backhaul IP / port map.

**Request**
```json
{
  "router_type": "2004",
  "routeros": "7.19.4",
  "tower_name": "TX-MARLIN-W-FC-2",
  "tower_gps": "30.1,-96.1",
  "loopback_subnet": "10.26.0.7/32",
  "bh1_subnet": "10.25.10.0/29",
  "private_ip": "10.50.0.0/24",
  "public_ip": "198.51.100.0/29",
  "fiber_provider": "ATT",
  "fiber_port": "sfp-sfpplus1",
  "fiber_port_ip": "10.42.10.2/30",
  "has_vlan": true,
  "fiber_vlan_num": "300",
  "backhauls": [
    { "port": "4", "name": "BH-TO-SITE-B", "subnet": "10.25.10.24/29", "master": "no", "bandwidth": "1G" }
  ],
  "apply_compliance": true
}
```

**Response `200`**
```json
{
  "success": true,
  "config": "# ISD FIBER CONFIG ...",
  "port_map": "===================================================================",
  "compliance_source": "bundled-local",
  "warnings": []
}
```

---

### `POST /api/ftth-home/mf2-package`

Generate MF2 ZIP package with updated gateway/primary IP in startup XML.

**Request**
```json
{
  "gateway_ip": "10.25.250.121",
  "primary_ip": "10.25.250.122",
  "olt_name": "OLT-HEMPSTEAD-1"
}
```

**Response `200`:** ZIP file download (`application/zip`).

---

## 8. Config Generation — Nokia

### `GET /api/nokia7250-defaults`

Return Nokia 7250 credentials/secrets from environment variables.

**Response `200`**
```json
{
  "snmp_community": "...",
  "nlroot_pw": "...",
  "admin_pw": "...",
  "bgp_auth_key": "..."
}
```

---

### `GET /api/nokia-configurator-defaults`

Alias for the unified Nokia Configurator to load credentials/secrets from the backend.

**Response `200`**
```json
{
  "snmp_community": "...",
  "nlroot_pw": "...",
  "admin_pw": "...",
  "bgp_auth_key": "..."
}
```

---

### `POST /api/generate-nokia7250`

Generate Nokia 7250 (SR OS) configuration.

**Request**
```json
{
  "system_name": "NK-7250-AR1.TX-HEMPSTEAD",
  "system_ip": "10.33.0.100/32",
  "location": "TX-HEMPSTEAD-FC-1",
  "port1_desc": "SPARKLIGHT",
  "port2_desc": "HEMPSTEADISD",
  "port2_shutdown": false,
  "enable_ospf": true,
  "enable_bgp": true,
  "enable_fiber": true,
  "fiber_interface": "1/1/c1",
  "fiber_ip": "10.33.1.185/29",
  "backhauls": [
    { "port": "1/1/c2", "description": "SPARKLIGHT", "ip": "10.33.1.154/30" }
  ]
}
```

**Response `200`**
```json
{ "success": true, "config": "# Nokia 7250 SR OS\nconfigure\n..." }
```

---

### `POST /api/generate-nokia-configurator`

Generate unified Nokia Configurator output for `7210` and `7750` profiles from the same workspace.

**Request**
```json
{
  "model": "7210",
  "profile": "isd",
  "system_name": "RTR-NK7210-TEST",
  "system_ip": "10.25.0.46/32",
  "latitude": "29.1",
  "longitude": "-96.1",
  "timezone": "CST",
  "static_hop": "10.25.1.1",
  "isd_public": "172.16.10.1/24",
  "isd_private": "192.168.10.1/24",
  "uplinks": [
    { "port": "1/1/1", "desc": "BH-1", "ip": "10.45.248.105/30", "speed": "10000" }
  ]
}
```

**Response `200`**
```json
{
  "success": true,
  "config": "##################################\n# NOKIA 7210 ISD CONFIG\n...",
  "device_type": "Nokia 7210 ISD",
  "config_type": "nokia-7210-isd",
  "model": "7210",
  "profile": "isd"
}
```

**Response `400`**
```json
{
  "success": false,
  "error": "System name and system IP are required"
}
```

---

## 9. Device Migration

### `POST /api/migrate-config`

Intelligent device-aware migration (auto-detect source, interface mapping, ROS6→ROS7).

**Request**
```json
{
  "config": "# 2023 by RouterOS 6.49.17\n# model = CCR1072-1G-8S+\n...",
  "target_device": "CCR2216-1G-12XS-2XQ",
  "target_version": "7.19.4",
  "source_device": "CCR1072-1G-8S+",
  "apply_compliance": true
}
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `config` | string | ✅ | — | Source config text |
| `target_device` | string | ✅ | — | Target model |
| `target_version` | string | ✅ | — | Target ROS version |
| `source_device` | string | ❌ | auto-detect | Source model (auto-detected from config) |
| `apply_compliance` | bool | ❌ | `false` | Append compliance |

**Response `200`**
```json
{
  "success": true,
  "config": "# 2026-03-02 by RouterOS 7.19.4\n...",
  "interface_mapping": { "sfp1": "sfp28-1", "sfp2": "sfp28-2" }
}
```

---

### `POST /api/migrate-mikrotik-to-nokia`

Convert MikroTik RouterOS config to Nokia SR OS syntax.

**Request**
```json
{
  "source_config": "# MikroTik config...",
  "preserve_ips": true
}
```

**Response `200`**
```json
{
  "success": true,
  "config": "# Nokia SR OS\nconfigure\n...",
  "warnings": ["OSPF area format may need manual review"]
}
```

---

### `GET /api/get-routerboards`

Get all supported RouterBoard models with specs.

**Response `200`**
```json
{
  "success": true,
  "devices": [
    {
      "model": "CCR2216-1G-12XS-2XQ",
      "ethernet_ports": 1,
      "sfp_ports": 12,
      "qsfp_ports": 2,
      "port_prefix": "sfp28",
      "default_speed": "10G-baseSR-LR"
    }
  ],
  "total_models": 11
}
```

---

### `GET /api/toolbox-inventory`

Return the normalized refinement inventory used when folding proven toolbox behavior into the unified app.

**Response `200`**
```json
{
  "success": true,
  "inventory": {
    "mikrotik": ["mt_tower.py", "mt_enterprise.py", "mt_mpls_enterprise.py"],
    "nokia": ["nokia7210.py", "nokia7250.py", "BNG_7750_VPLS_Gen.py"],
    "templates": ["MT_BNG2_Univ_Base.py", "MT_BNG2_Univ_Tarana.py"]
  },
  "role_patterns": {
    "switch": ["netonix", "cnmatrix", "switch uplink"],
    "backhaul": ["backhaul", "uplink", "transport"],
    "tarana": ["tarana", "alpha", "beta", "gamma", "delta"],
    "lte": ["lte", "bbu", "vlan 75", "vlan 444"],
    "6ghz": ["6ghz", "al60", "wave", "cnep3k"]
  }
}
```

---

## 10. SSH / Remote Device

### `POST /api/fetch-config-ssh`

SSH into a MikroTik device and fetch config via `/export`.

**Request**
```json
{
  "host": "10.33.0.95",
  "ros_version": "7",
  "command": "/export",
  "username": "root",
  "password": "secret",
  "port": 22
}
```

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `host` | string | ✅ | — | Device IP address |
| `ros_version` | string | ❌ | `7` | `6` or `7` |
| `command` | string | ❌ | `/export` | SSH command to run |
| `username` | string | ❌ | from env | SSH username |
| `password` | string | ❌ | from env | SSH password |
| `port` | int | ❌ | `22` | SSH port |

**Response `200`**
```json
{ "success": true, "config": "# 2026-03-02 by RouterOS 7.19.4\n..." }
```

---

## 11. Compliance & Policy

### `GET /api/compliance-status`

Report active compliance source, GitLab health, cache state.

**Response `200`**
```json
{
  "gitlab_configured": true,
  "gitlab_available": true,
  "active_source": "gitlab",
  "cache_info": { "ttl": 600, "entries": 3, "hits": 15, "misses": 2 },
  "stats": { "total_fetches": 17, "errors": 0 },
  "recent_log": ["[COMPLIANCE] Using GitLab dynamic compliance blocks (23 blocks)"]
}
```

---

### `POST /api/reload-compliance`

Clear GitLab compliance TTL cache for immediate re-fetch.

**Response `200`**
```json
{ "success": true, "message": "Compliance cache cleared" }
```

---

### `GET /api/compliance/blocks`

Return compliance blocks as JSON (for client-side generators).

**Query:** `?loopback_ip=10.33.0.95`

**Response `200`**
```json
{
  "success": true,
  "source": "gitlab",
  "loopback_ip": "10.33.0.95",
  "blocks": {
    "variables": ":global LoopIP ...",
    "ip_services": "/ip service set telnet disabled=yes...",
    "dns": "/ip dns set servers=...",
    "firewall_address_lists": "...",
    "firewall_filter_input": "...",
    "firewall_raw": "...",
    "snmp": "...",
    "logging": "..."
  },
  "raw_compliance_text": "full verbatim TX-ARv2.rsc text..."
}
```

---

### `GET /api/compliance/engineering`

Return engineering compliance policy text.

**Query:** `?loopback_ip=10.33.0.95`

**Response `200`**
```json
{ "compliance": "# Engineering compliance script...\n/ip service set telnet disabled=yes..." }
```

---

### `GET /api/get-config-policies`

List available config policies with optional category filter.

**Query:** `?category=compliance&reload=true`

**Response `200`**
```json
{
  "success": true,
  "policies": [
    { "name": "compliance-mikrotik-rfc", "category": "compliance", "filename": "mikrotik-rfc.md" }
  ],
  "count": 5,
  "total_policies": 12,
  "categories": ["compliance", "enterprise", "tower", "nextlink"]
}
```

---

### `GET /api/get-config-policy/<policy_name>`

Get a specific policy by name.

**Response `200`**
```json
{
  "success": true,
  "policy_name": "compliance-mikrotik-rfc",
  "content": "# MikroTik RFC Policy\n...",
  "path": "config_policies/compliance/mikrotik-rfc.md"
}
```

---

### `GET /api/get-config-policy-bundle`

Return merged policy text for selected keys.

**Query:** `?keys=compliance-mikrotik-rfc,enterprise-standard&include=compliance`

**Response `200`**
```json
{
  "success": true,
  "keys": ["compliance-mikrotik-rfc"],
  "include": ["compliance"],
  "content": "merged policy text..."
}
```

---

### `POST /api/reload-config-policies`

Reload policies from disk.

**Response `200`**
```json
{ "success": true, "message": "Policies reloaded", "policies": [...] }
```

---

## 12. Completed Configs

### `POST /api/save-completed-config`

Save a completed config to the database with auto-extracted port mapping.

**Request**
```json
{
  "config_type": "tower",
  "device_name": "RTR-MT2216-AR1.TX-HEMPSTEAD-FC-1",
  "device_type": "CCR2216-1G-12XS-2XQ",
  "customer_code": "HEMPSTEAD",
  "loopback_ip": "10.33.0.95",
  "routeros_version": "7.19.4",
  "config_content": "# Full config text...",
  "created_by": "user@team.nxlink.com",
  "site_name": "TX-HEMPSTEAD-FC-1",
  "metadata": { "notes": "Initial deployment" }
}
```

**Response `200`**
```json
{ "success": true, "config_id": 42, "message": "Config saved" }
```

**Common frontend payload variants**
```json
{
  "config_type": "cisco-interface",
  "device_name": "TenGigE 0/0/0/1",
  "device_type": "Cisco",
  "customer_code": "",
  "loopback_ip": "10.42.10.1",
  "config_content": "configure terminal\ninterface TenGigE 0/0/0/1\n...",
  "site_name": "BH-TO-SITE-A",
  "metadata": {
    "port_description": "BH-TO-SITE-A",
    "port_type": "TenGigE",
    "port_number": "0/0/0/1",
    "interface_ip": "10.42.10.1",
    "subnet_mask": "255.255.255.252",
    "ospf_cost": "10",
    "passive": "No"
  }
}
```

```json
{
  "config_type": "ftth-fiber-customer",
  "device_name": "FIBERCOMM",
  "device_type": "MikroTik Fiber Customer",
  "customer_code": "FIBERCOMM",
  "loopback_ip": "",
  "config_content": "# FIBER SITE SETTINGS\n/interface ethernet\n...",
  "site_name": "FIBERCOMM",
  "metadata": {
    "provider": "FIBERCOMM",
    "port": "sfp-sfpplus8",
    "address": "10.42.10.2/30",
    "network": "10.42.10.0/30",
    "vlan_mode": "tagged",
    "vlan_id": "300"
  }
}
```

---

### `GET /api/get-completed-configs`

Get all saved configs with filtering.

**Query:** `?search=HEMPSTEAD&year=2026&type=tower`

**Response `200`**
```json
{
  "configs": [
    {
      "id": 42,
      "config_type": "tower",
      "device_name": "RTR-MT2216-AR1.TX-HEMPSTEAD-FC-1",
      "created_at": "2026-03-02T01:30:00Z",
      "created_by": "user@team.nxlink.com"
    }
  ],
  "years": [2025, 2026]
}
```

---

### `GET /api/get-completed-config/<config_id>`

Get a specific config with port mapping.

**Response `200`**
```json
{
  "id": 42,
  "config_type": "tower",
  "config_content": "# Full config...",
  "port_mapping": { "sfp28-1": "SPARKLIGHT", "sfp28-2": "HEMPSTEADISD" },
  "port_mapping_text": "sfp28-1: SPARKLIGHT\nsfp28-2: HEMPSTEADISD",
  "metadata": {}
}
```

---

### `GET /api/download-port-map/<config_id>`

Download port map as `.txt` file.

**Response `200`:** Text file download.

---

### `POST /api/extract-port-map`

Extract port map from raw config (without saving).

**Request**
```json
{
  "config_content": "# Full config...",
  "device_name": "RTR-MT2216-AR1.TX-HEMPSTEAD-FC-1",
  "customer_code": "HEMPSTEAD"
}
```

**Response `200`**
```json
{
  "port_mapping": { "sfp28-1": "SPARKLIGHT" },
  "port_map_text": "sfp28-1: SPARKLIGHT"
}
```

---

## 13. Activity Tracking

### `POST /api/log-activity`

Log user activity to database.

**Request**
```json
{
  "token": "eyJ...",
  "username": "user@team.nxlink.com",
  "type": "translate-config",
  "device": "CCR2216-1G-12XS-2XQ",
  "siteName": "TX-HEMPSTEAD-FC-1",
  "routeros": "7.19.4",
  "success": true
}
```

**Response `200`**
```json
{ "success": true }
```

**Common frontend payload variants**
```json
{
  "username": "user@team.nxlink.com",
  "type": "new-config",
  "device": "Cisco",
  "siteName": "BH-TO-SITE-A",
  "routeros": "",
  "success": true
}
```

```json
{
  "username": "user@team.nxlink.com",
  "type": "new-config",
  "device": "MikroTik Fiber Customer",
  "siteName": "FIBERCOMM",
  "routeros": "7",
  "success": true
}
```

---

### `GET /api/get-activity`

Get recent activities from database.

**Query:** `?limit=50&all=false`

**Response `200`**
```json
{
  "activities": [
    {
      "id": 1,
      "username": "user@team.nxlink.com",
      "type": "translate-config",
      "device": "CCR2216-1G-12XS-2XQ",
      "siteName": "TX-HEMPSTEAD-FC-1",
      "timestamp": "2026-03-02T01:30:00Z",
      "success": true
    }
  ],
  "total": 150
}
```

---

### `GET /api/activity` | `POST /api/activity`

In-memory live activity feed (last 50).

**POST Request**
```json
{
  "timestamp": "2026-03-02T01:30:00Z",
  "username": "user@team.nxlink.com",
  "type": "translate-config",
  "siteName": "TX-HEMPSTEAD-FC-1"
}
```

**GET Response `200`:** Array of activity objects.

---

## 14. Feedback

### `POST /api/feedback`

Submit feedback / bug report / feature request.

**Request**
```json
{
  "type": "bug",
  "subject": "Translation issue",
  "category": "config-translation",
  "experience": "negative",
  "details": "When translating from CCR1072...",
  "name": "User Name",
  "email": "user@team.nxlink.com"
}
```

**Response `200`**
```json
{ "success": true, "message": "Feedback submitted", "feedback_id": "fb-abc123" }
```

---

## 15. Admin

### `GET /api/admin/feedback` 🔒 Admin

Get all feedback with filtering.

**Query:** `?status=open&type=bug&limit=20&offset=0`

**Response `200`**
```json
{ "success": true, "feedback": [...], "total": 45 }
```

---

### `PUT /api/admin/feedback/<feedback_id>/status` 🔒 Admin

Update feedback status.

**Request**
```json
{ "status": "resolved", "admin_notes": "Fixed in commit abc123" }
```

**Response `200`**
```json
{ "success": true, "message": "Status updated" }
```

---

### `GET /api/admin/feedback/export` 🔒 Admin

Export all feedback to Excel.

**Response `200`:** `.xlsx` file download.

---

### `POST /api/admin/users/reset-password` 🔒 Admin

Reset or create user password.

**Request**
```json
{
  "email": "user@team.nxlink.com",
  "newPassword": "optional-new-pw",
  "requirePasswordChange": true
}
```

**Response `200`**
```json
{
  "success": true,
  "message": "Password reset",
  "temporaryPassword": "auto-generated-if-no-newPassword",
  "requirePasswordChange": true
}
```

---

## 16. Aviat Radio Management

### `POST /api/aviat/run`

Run maintenance tasks on Aviat radios (background).

**Request**
```json
{
  "ips": ["10.1.0.1", "10.1.0.2"],
  "tasks": ["firmware_upload", "activate"],
  "maintenance_params": { "firmware_file": "path/to/file" },
  "username": "user@team.nxlink.com"
}
```

**Response `200`**
```json
{ "task_id": "aviat-abc123" }
```

---

### `POST /api/aviat/activate-scheduled`

Activate scheduled firmware (time-window enforced unless `force`).

**Request**
```json
{
  "ips": ["10.1.0.1"],
  "force": false,
  "remaining_tasks": [],
  "maintenance_params": {},
  "activation_at": "2026-03-02T03:00:00Z",
  "client_hour": 3,
  "client_minute": 0,
  "username": "user@team.nxlink.com"
}
```

**Response `200`**
```json
{ "task_id": "aviat-def456" }
```

---

### `GET /api/aviat/scheduled`

**Response `200`**
```json
{ "scheduled": ["10.1.0.1", "10.1.0.2"] }
```

---

### `GET /api/aviat/loading`

**Response `200`**
```json
{ "loading": ["10.1.0.3"] }
```

---

### `GET /api/aviat/reboot-required`

**Response `200`**
```json
{ "reboot_required": [{ "ip": "10.1.0.1", "reason": "firmware_activated" }] }
```

---

### `POST /api/aviat/reboot-required/run`

Reboot devices that require it.

**Request**
```json
{ "ips": ["10.1.0.1"], "username": "user@team.nxlink.com" }
```

**Response `200`**
```json
{ "status": "rebooting", "count": 1 }
```

---

### `POST /api/aviat/scheduled/sync`

Sync/replace the scheduled device queue.

**Request**
```json
{
  "ips": ["10.1.0.1", "10.1.0.2"],
  "remaining_tasks": ["activate"],
  "maintenance_params": {},
  "username": "user@team.nxlink.com",
  "activation_at": "2026-03-02T03:00:00Z"
}
```

**Response `200`**
```json
{ "scheduled": ["10.1.0.1", "10.1.0.2"] }
```

---

### `GET /api/aviat/queue` | `POST /api/aviat/queue`

**GET:** Get shared radio queue.
**POST:** Modify queue.

**POST Request**
```json
{
  "mode": "replace",
  "radios": [{ "ip": "10.1.0.1", "status": "pending" }],
  "username": "user@team.nxlink.com"
}
```

| mode | Description |
|---|---|
| `replace` | Replace entire queue |
| `add` | Add radios to queue |
| `remove` | Remove radios from queue |

**Response `200`**
```json
{ "radios": [{ "ip": "10.1.0.1", "status": "pending" }] }
```

---

### `POST /api/aviat/check-status`

Check firmware/SNMP/STP/license status.

**Request**
```json
{ "ips": ["10.1.0.1", "10.1.0.2"] }
```

**Response `200`**
```json
{
  "results": [
    { "ip": "10.1.0.1", "reachable": true, "firmware": "8.2.0", "snmp": true, "stp": false, "license": "valid" }
  ]
}
```

---

### `POST /api/aviat/precheck/recheck`

Re-run precheck on a single radio.

**Request**
```json
{ "ip": "10.1.0.1" }
```

**Response `200`**
```json
{
  "ip": "10.1.0.1",
  "reachable": true,
  "result": { "firmware": "8.2.0", "snmp": true, "stp": false },
  "updates": { "stp_disabled": true },
  "precheck_clear": true
}
```

---

### `POST /api/aviat/fix-stp`

SSH into radio and disable STP.

**Request**
```json
{ "ip": "10.1.0.1" }
```

**Response `200`**
```json
{ "status": "ok" }
```

---

### `POST /api/aviat/abort/<task_id>`

Abort a running background task.

**Response `200`**
```json
{ "status": "aborting" }
```

---

### `GET /api/aviat/stream/<task_id>` (SSE)

Server-Sent Events stream for task logs.

**Response:** `text/event-stream` — continuous log events:
```
data: {"type": "log", "message": "Connecting to 10.1.0.1...", "timestamp": "..."}

data: {"type": "progress", "ip": "10.1.0.1", "status": "uploading", "percent": 45}

data: {"type": "complete", "ip": "10.1.0.1", "success": true}
```

---

### `GET /api/aviat/stream/global` (SSE)

Global SSE stream for all Aviat activity (with backlog replay).

---

### `GET /api/aviat/status/<task_id>`

Get task status/results.

**Response `200`**
```json
{
  "status": "running",
  "abort": false,
  "ips": ["10.1.0.1"],
  "tasks": ["firmware_upload"],
  "results": { "10.1.0.1": { "status": "uploading", "progress": 45 } }
}
```

---

## 17. IDO Proxy

### `GET /api/ido/capabilities`

Report IDO backend configuration and health.

**Response `200`**
```json
{
  "configured": true,
  "backend_url": "http://ido-backend:8080",
  "backend_health": true,
  "fallback_mode": false,
  "embedded_endpoints": ["/api/ping", "/api/generic/device_info"],
  "allowed_prefixes": ["/api/"]
}
```

---

### `GET|POST /api/ido/proxy/<path>`

Proxy requests to external IDO backend. Embedded fallback for `/api/ping` and `/api/generic/device_info`.

**Example:** `POST /api/ido/proxy/api/ping`

**Request** (proxied to IDO backend):
```json
{ "host": "10.33.0.95" }
```

**Response:** Proxied upstream response.

---

## Changelog

| Date | Change |
|---|---|
| 2026-03-02 | Initial full API reference — 84 endpoints across 17 categories |
