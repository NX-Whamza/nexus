# Configuration Policy Directory

This directory contains **all** configuration policies, standards, and references for the NEXUS backend. The backend automatically loads every Markdown file in this tree and exposes them through the policy APIs.

## Directory Structure

```
config_policies/
├── README.md (this file)
├── USAGE.md (policy usage guide)
├── nextlink/
│   ├── texas-in-statepolicy.md (Texas non-MPLS towers)
│   ├── illinois-out-of-state-mpls-config-policy.md (Illinois MPLS aggregation)
│   ├── kansas-out-of-state-mpls-config-policy.md (Kansas MPLS aggregation)
│   └── nextlink-internet-policy.md (global standards)
├── compliance/
│   └── README.md (compliance references, RFC-09-10-25 script notes)
└── examples/
    ├── TX-LIPAN-CONFIG-POLICY-CN-1.rsc
    ├── IL-HUMBOLDT-NE-1-CONFIG-POLICY.rsc
    └── KS-BENTON-CONFIG-POLICY.rsc
```

## Policy Categories

### Nextlink Policies (`nextlink/`)
- **texas-in-statepolicy.md** – Texas non-MPLS tower baseline driven by the LIPAN template.
- **illinois-out-of-state-mpls-config-policy.md** – Illinois MPLS aggregation routers (bridge9990 + VPLS domains).
- **kansas-out-of-state-mpls-config-policy.md** – Kansas MPLS aggregation routers with vendor bridges 600/800.
- **nextlink-internet-policy.md** – Global standards for port roles, naming, MPLS vs non-MPLS expectations, security.

### Compliance References (`compliance/`)
- Python modules in the repository (`nextlink_compliance_reference.py`, `nextlink_enterprise_reference.py`, `nextlink_standards.py`) provide reusable blocks and constants; these are automatically available alongside the Markdown policies.

### Examples (`examples/`)
- Contains sanitized RouterOS exports used to derive the policies. Helpful for context and comparison but not loaded by the policy service.

## Backend Integration

The backend (`api_server.py`) automatically:
1. Loads all Markdown policies on startup.
2. Loads compliance/reference modules.
3. Makes policies queryable via `/api/get-config-policies` and `/api/get-config-policy/<name>`.
4. Supports bundling policies plus compliance blocks via `/api/get-config-policy-bundle`.

## Usage Summary

- Call `GET /api/get-config-policies` to discover available policy keys.
- Call `GET /api/get-config-policy/<name>` to retrieve a specific Markdown policy.
- Call `POST /api/reload-config-policies` after editing Markdown files to refresh the in-memory cache.
- See `USAGE.md` for detailed examples on wiring policies into prompts and the LLM backend.