# Toolbox Refinement Plan

This app no longer uses the old CSV upload workflow, but the earlier toolbox
still contains proven generator logic and naming conventions worth preserving.

## Current strategy

- Keep the current UI and JSON APIs.
- Reuse proven naming, port-role, and template conventions in backend modules.
- Port generators into clean backend services before adding or renaming tabs.

## Source inventory

### MikroTik

- `mt_tower.py`
- `mt_enterprise.py`
- `mt_mpls_enterprise.py`
- `mt_fiber_site_1072.py`
- `mt_isd_fiber.py`
- `mt_lte_site.py`
- `mt_lte_site_2004.py`
- `mt_switch.py`
- `mt_switch_crs326.py`
- `mt_bng_v2.py`
- `universal_mpls.py`

### Nokia

- `nokia7210.py`
- `nokia7210isd.py`
- `nokia7210_BNG2.0.py`
- `nokia7250.py`
- `nokia7250_bng2.py`
- `BNG_7750_VPLS_Gen.py`
- `BNG_7750_Existing_VPLS_Tunnel_Gen.py`

### Templates and reference blocks

- `MT_BNG2_Univ_Base.py`
- `MT_BNG2_Univ_System_ro7.py`
- `MT_BNG2_Univ_ENT_Pmap.py`
- `MT_BNG2_Univ_Pmap.py`
- `MT_BNG2_Univ_Tarana.py`
- `MT_BNG2_Univ_LTE.py`
- `MT_Switch_Config_File.py`
- `MT_LTE_Site_2004_Config_File.py`
- `Nokia_Universal_Config.py`
- `Nokia_Universal_Config_BNG2.0.py`

## Conventions already folded into backend analysis

- Netonix/cnMatrix/switch uplinks map to switch slots.
- Tarana Alpha/Beta/Gamma/Delta and Unicorn naming map to radio slots.
- LTE/BBU/S1/VLAN 75/VLAN 444 naming maps to LTE-aware radio slots.
- AL60/Wave/Cambium/CNEP3K/AP-style naming maps to 6 GHz radio slots.
- UPS/ICT/WPS/infra naming is flagged as infrastructure/manual-review traffic.

## Porting order

1. Strengthen shared backend reference data and tests.
2. Port MikroTik specialty generators into JSON-driven services.
3. Unify Nokia makers behind one backend contract with model/profile dropdowns.
4. Add or rename UI tabs only after backend endpoints are stable.
