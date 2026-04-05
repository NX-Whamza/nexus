# Tenant Hardening Audit

This audit tracks which NEXUS tabs and payloads are still carrying provider-specific assumptions and which backend surfaces have been hardened into tenant-neutral defaults.

## Canonical Defaults Direction

NEXUS should prefer explicit tenant payload values first, then neutral tenant defaults from backend configuration, and only use legacy `NEXTLINK_*` environment variables as compatibility fallback.

New shared backend source of truth:

- `vm_deployment/tenant_defaults.py`
- `GET /api/tenant/defaults`
- `GET /api/v2/nexus/tenant/defaults`

These sources now centralize:

- tenant code/name
- default ASN
- route-reflector peers
- BNG peers
- DNS/NTP/syslog defaults
- SNMP contact/community
- policy/compliance profile metadata
- audit hint indicating whether legacy `NEXTLINK_*` envs are still being used

## High-Risk Tabs

These tabs still need deeper hardening because their generated output or frontend defaults contain embedded provider assumptions:

1. MikroTik Config Generator
   Current risks:
   - default ASN `26077`
   - default BGP peers `10.2.0.107/32`, `10.2.0.108/32`
   - compliance and address-list assumptions tied to RFC-09-10-25 / Nextlink

2. Non-MPLS Enterprise
   Current risks:
   - backend still falls back to legacy DNS environment names
   - generated output can still inherit provider-specific compliance overlays

3. MPLS Enterprise
   Current risks:
   - frontend defaults still carry provider-oriented addressing examples
   - generated output needs audit against tenant ASN, BGP, and VPLS assumptions

4. Nokia Configurator / Nokia Migration
   Current risks:
   - UI defaults still expose ASN `26077` and fixed peer IPs
   - generated output still contains provider-specific group/profile assumptions in some modes

5. FTTH Configurator
   Current risks:
   - several subtabs still expose fixed ASN and peer defaults in the UI
   - generated output still needs audit for provider-specific routing and compliance assumptions

6. Compliance Scanner / Compliance Apply
   Current risks:
   - compliance reference is still strongly tied to the Nextlink RFC/profile set
   - needs tenant-selectable policy bundles rather than one baked-in baseline

7. Device Config Studio
   Current risks:
   - wording is now neutral, but payloads still flow through legacy `/api/ido/*` compatibility routes
   - should eventually publish a cleaner NEXUS-native device-access contract

## Medium-Risk Tabs

These are operationally aligned but still need payload/output review:

- MikroTik Switch Maker
- Tarana Sectors
- Enterprise Feeding
- Cisco Port Setup
- Command Vault
- Bulk Operations Center
- Scheduled Maintenance

## Next Refactor Steps

1. Replace hardcoded UI defaults for ASN, peers, DNS, and policy references with values from `tenant/defaults`.
2. Add typed backend payload models for the remaining frontend-heavy generators.
3. Split compliance into tenant-selectable policy bundles instead of one provider policy.
4. Add regression tests asserting that neutral defaults are used when tenant-specific values are not configured.
