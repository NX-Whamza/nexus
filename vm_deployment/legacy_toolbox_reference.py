"""Legacy toolbox reference data used to strengthen current backend behavior.

This file intentionally stores only normalized reference data. It does not
depend on the old toolbox path or its CSV workflows.
"""

from __future__ import annotations

LEGACY_ROLE_PATTERNS = {
    "management": [
        "management",
        "mgmt",
        "reserved_management_port",
    ],
    "switch": [
        "netonix",
        "cnmatrix",
        "cmm",
        "matrix",
        "edgecore",
        "switch",
        "switch uplink",
        "customer uplink",
    ],
    "backhaul": [
        "backhaul",
        "uplink",
        "transport",
        "tower router",
        "core fiber",
        "fiber",
        "bh to",
    ],
    "tarana": [
        "tarana",
        "unicorn",
        "alpha",
        "beta",
        "gamma",
        "delta",
    ],
    "lte": [
        "lte",
        "bbu",
        "nokia bbu",
        "nokia bbu uplink",
        "bbu s1",
        "bbu mgmt",
        "vlan 75",
        "vlan 444",
        "s1",
        "cell",
        "verizon",
        "t-mobile",
        "tmobile",
        "att",
    ],
    "6ghz": [
        "6ghz",
        "6 ghz",
        "6-ghz",
        "cambium",
        "pmp450",
        "af60",
        "wave",
        "al60",
        "cnep3k",
        "ap1",
        "ap2",
        "ap3",
        "ap4",
        "ap5",
        "ap6",
    ],
    "infrastructure": [
        "ups",
        "ict",
        "power",
        "wps",
        "infra",
    ],
    "olt": [
        "olt",
        "gpon",
        "xgs",
        "nokia",
    ],
}


LEGACY_GENERATOR_INVENTORY = {
    "mikrotik": [
        "mt_tower.py",
        "mt_enterprise.py",
        "mt_mpls_enterprise.py",
        "mt_fiber_site_1072.py",
        "mt_isd_fiber.py",
        "mt_lte_site.py",
        "mt_lte_site_2004.py",
        "mt_switch.py",
        "mt_switch_crs326.py",
        "mt_bng_v2.py",
        "universal_mpls.py",
    ],
    "nokia": [
        "nokia7210.py",
        "nokia7210isd.py",
        "nokia7210_BNG2.0.py",
        "nokia7250.py",
        "nokia7250_bng2.py",
        "BNG_7750_VPLS_Gen.py",
        "BNG_7750_Existing_VPLS_Tunnel_Gen.py",
    ],
    "templates": [
        "MT_BNG2_Univ_Base.py",
        "MT_BNG2_Univ_System_ro7.py",
        "MT_BNG2_Univ_ENT_Pmap.py",
        "MT_BNG2_Univ_Pmap.py",
        "MT_BNG2_Univ_Tarana.py",
        "MT_BNG2_Univ_LTE.py",
        "MT_Switch_Config_File.py",
        "MT_LTE_Site_2004_Config_File.py",
        "Nokia_Universal_Config.py",
        "Nokia_Universal_Config_BNG2.0.py",
    ],
}
