# NOC Operations Config Suite SOP

## Status
- Environment: Production URL currently used for testing.
- Current production URL: `https://nexus.nxlink.com`
- Dev URL: Pending URL and approval.
- Current phase: Testing/Beta for selected modules.

## Purpose
This SOP defines how to safely use the NOC Operations Config Suite for configuration generation, upgrade workflows, and operational command lookup while the platform is in testing.

## Audience
- NOC
- Engineering
- Field support
- DevOps (deployment and release operations)

## Access and Safety Rules
- Always validate generated config before deployment.
- Do not assume a generated output is production-ready unless the module is marked production-ready.
- Use maintenance windows for upgrade/activation operations.
- Keep rollback options available before applying live changes.

## Tool Overview
### Home
- Shows announcements, activity, and high-level usage metrics.
- Use as the launch page and status check.

### MikroTik Config
- Generates Tower, BNG/BNG2, Enterprise, 6GHz, and related RouterOS configs.
- Pulls engineering compliance policy dynamically from GitLab (when token and URL are configured).

### Field Config Studio
- Device utility workspace for operational tasks and config helpers.

### IDO Tools
- Operational helper utilities and integrations migrated into dedicated tab.

### Aviat Backhaul Updater
- Multi-step upgrade flow with prechecks, firmware upload/activation, and recheck.
- Supports scheduled and immediate activation modes.

### FTTH Home
- FTTH configuration workflows and outputs.

### Command Vault
- Searchable command cards for Nokia, Cisco, and MikroTik references.

## Standard Workflow (Config Generation)
1. Select the module/tab for the target device type.
2. Enter required site/device fields.
3. Confirm auto-generated identity format is correct.
4. Generate config.
5. Review output for:
   - Router identity
   - Interface mapping
   - OSPF/BGP sections
   - State-specific policy content
   - Compliance block inclusion
6. Save and peer-review before deployment.

## Aviat Backhaul Upgrade Workflow
1. Add radio IPs.
2. Select required tasks (firmware, credentials, SNMP, buffer script, recheck).
3. Set activation mode:
   - `Scheduled`: command queued to activation window.
   - `Activate Now`: execute activation immediately after safety checks.
4. Run queue and monitor per-device row states.
5. Use `Check Status` during and after activation window.
6. Confirm post-check status before closing job.

## Dynamic Compliance Source (GitLab)
The platform is expected to fetch compliance content from GitLab and inject it into generated outputs.

Required runtime inputs:
- GitLab API token
- GitLab raw file URL (recommended)
- Optional project/file fallback identifiers

Validation checklist:
1. Generate a MikroTik config.
2. Confirm compliance block exists in output.
3. Confirm current expected lines appear (example: firewall lists, OSPF auth, logging, LDP filter lines).
4. If mismatch occurs, check token validity and URL path first.

## Known Guardrails While in Testing
- Some modules contain testing notices and may still evolve.
- Use production URL with testing discipline until UAT URL is available.
- Treat all outputs as “review required.”

## Troubleshooting Quick Checks
### Missing compliance section
- Verify GitLab token.
- Verify raw file URL path and branch.
- Re-run generation and compare output.

### Unexpected fields/sections in output
- Confirm selected config type and state profile.
- Confirm module version includes latest backend templates.
- Rebuild/redeploy backend container if stale.

### Upgrade queue not progressing
- Check maintenance window/time settings.
- Check device reachability and credentials.
- Use `Check Status` and inspect activity log entries.

## Release and Change Control
- All changes must be committed and pushed through GitHub.
- Rebuild Docker services after backend/frontend/template changes.
- Validate with at least one known-good sample per affected module.

## SOP Image Appendix (Placeholders)
Use these images in the final published SOP/PDF build:
- Home dashboard (testing/beta announcement).
- Recent activity panel.
- Policy reference modal.
- MikroTik main generator page.
- BNG2 parameter section/state selector.
- Non-MPLS Enterprise page.
- Tarana page.
- 6GHz generator page.
- Aviat Backhaul updater queue/status page.
- FTTH page with IP allocations.
- Command Vault page.

## Suggested Intro Text (Short Form)
Welcome to the NOC Operations Config Suite. This platform centralizes MikroTik configuration generation, Aviat firmware operations, FTTH workflows, and command references in one operational interface. The current environment is actively tested with production discipline: validate outputs, follow maintenance windows, and use the policy references in-tool for consistency.
