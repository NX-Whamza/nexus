# MikroTik Backend Migration Plan

## Goal
Unify new-device MikroTik config generation behind backend APIs compatible with Netlaunch, while keeping `Upgrade Existing` workflow unchanged.

## Current State
- UI has strong existing UX in `vm_deployment/nexus.html`.
- New-device tower generation is mostly JS-side generation logic.
- Added backend-compatible endpoints:
  - `POST /api/mt/tower/config`
  - `POST /api/mt/tower/portmap`
  - `POST /api/mt/bng2/config`
  - `POST /api/mt/bng2/portmap`
- Runtime now supports FastAPI hosting via `vm_deployment/fastapi_server.py` (Flask mounted for compatibility).

## Required Data Paths
- Netlaunch-compatible templates must exist under `BASE_CONFIG_PATH`:
  - `Router/Tower/config`
  - `Router/Tower/port_map`
  - `Router/BNG2/config`
  - `Router/BNG2/port_map`
- UI CSV/JSON templates are served from:
  - `vm_deployment/config-templates/mikrotik`

## API Contract (Netlaunch-compatible)
- `tower` payload keys:
  - `tower_name`, `router_type`, `loopback_subnet`, `asn`
  - `peer_1_name`, `peer_1_address`, `peer_2_name`, `peer_2_address`
  - `cpe_subnet`, `unauth_subnet`, `cgn_priv`, `cgn_pub`
  - feature flags: `is_326`, `is_6ghz`, `is_tachyon`, `is_tarana`, `enable_contractor_login`
  - optionals: `326_mgmt_subnet`, `6ghz_subnet`, `tarana_subnet`, `tarana_sector_count`, `tarana_sector_start`
  - `backhauls` list with `name`, `subnet`, `port`, `bandwidth`, `master`
- `bng2` payload keys:
  - `tower_name`, `router_type`, `loop_ip`, `gateway`
  - `bng_1_ip`, `bng_2_ip`, `ospf_area`
  - `vlan_1000_cisco`, `vlan_2000_cisco`, `vlan_3000_cisco`, `vlan_4000_cisco`
  - `mpls_mtu`, `vpls_l2_mtu`, `switch_ip`
  - feature flags: `is_switchless`, `is_lte`, `is_tarana`, `is_326`, `is_6ghz`, `enable_contractor_login`
  - optionals: `bbu_s1_subnet`, `bbu_mgmt_subnet`, `tarana_subnet`, `tarana_sector_count`, `tarana_sector_start`
  - `backhauls` list with `name`, `subnet`, `port`, `master`

## Migration Phases
1. Backend-first integration
   - Keep UI design and forms.
   - Replace JS local generation path for new-device MikroTik with calls to `/api/mt/*`.
   - Preserve download UX and history logging.
2. Validation hardening
   - Server-side payload validation with typed schemas.
   - Return field-level validation errors.
3. Native FastAPI migration
   - Move Flask routes module-by-module into FastAPI routers.
   - Keep old paths and response shapes to avoid UI regression.
4. Decommission compatibility layer
   - Remove Flask mount when all routes are native FastAPI.

## Non-Goals
- No change to Aviat upgrade flow and scheduled activation behavior.
- No forced redesign of current UI look/feel.

## Risks
- Missing `BASE_CONFIG_PATH` templates blocks config rendering.
- UI and backend field-name drift can cause silent misgeneration.
- Running without strict backend validation can produce incorrect config output.
