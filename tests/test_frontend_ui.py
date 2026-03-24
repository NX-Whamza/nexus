#!/usr/bin/env python3
"""Simple tests to verify presence of FTTH modal UI in the built frontend file."""

from __future__ import annotations

import os
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))

UI_FILE = repo_root / 'vm_deployment' / 'NOC-configMaker.html'


def test_ftth_modal_exists():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'FTTH BNG CONFIG' in content, 'Missing menu label "FTTH BNG CONFIG" in Mikrotik dropdown in NOC-configMaker.html'
    assert 'data-tab="ftth-home"' in content, 'Missing FTTH HOME navigation entry in NOC-configMaker.html'
    assert 'id="ftth-home-pane"' in content, 'Missing FTTH HOME content pane id="ftth-home-pane" in NOC-configMaker.html'
    assert 'id="ftth-pane"' in content, 'Missing ftth content pane id="ftth-pane" in NOC-configMaker.html'
    assert 'id="ftthPreviewBtn"' in content, 'Missing Preview button id="ftthPreviewBtn" in NOC-configMaker.html'
    assert ('generateFtthBng' in content) or ('ftthGenerate' in content), 'Missing generator hook: generateFtthBng() or element id="ftthGenerate"'
    assert 'id="ftth_instate_btn"' in content, 'Missing FTTH sub-tab button id="ftth_instate_btn" in NOC-configMaker.html'
    assert 'id="ftth_outstate_btn"' in content, 'Missing FTTH sub-tab button id="ftth_outstate_btn" in NOC-configMaker.html'
    assert 'id="ftth-instate-section"' in content and 'id="ftth-outstate-section"' in content, 'Missing FTTH sub-tab sections in NOC-configMaker.html'
    assert 'id="ftth_add_olt_port_btn"' in content, 'Missing OLT add button id="ftth_add_olt_port_btn" in NOC-configMaker.html'
    assert 'id="ftth_add_backhaul_btn"' in content, 'Missing backhaul add button id="ftth_add_backhaul_btn" in NOC-configMaker.html'
    assert 'id="ftth_open_portconfigs_btn"' in content, 'Missing Open Port & Uplink button id="ftth_open_portconfigs_btn" in NOC-configMaker.html'
    assert 'id="ftth_olt_port_in"' in content, 'Missing OLT port select id="ftth_olt_port_in" in NOC-configMaker.html'
    assert 'id="ftth_olt_speed_in"' in content, 'Missing OLT port speed select id="ftth_olt_speed_in" in NOC-configMaker.html'
    assert 'id="ftth_olt_port_out"' in content, 'Missing OLT port select id="ftth_olt_port_out" in NOC-configMaker.html'
    assert 'id="ftth_olt_speed_out"' in content, 'Missing OLT port speed select id="ftth_olt_speed_out" in NOC-configMaker.html'
    assert 'id="ftth_preset_select"' in content, 'Missing preset select id="ftth_preset_select" in NOC-configMaker.html'
    assert 'id="ftth_preset_save"' in content, 'Missing preset save button id="ftth_preset_save" in NOC-configMaker.html'
    assert 'id="ftth_preset_delete"' in content, 'Missing preset delete button id="ftth_preset_delete" in NOC-configMaker.html'
    assert 'id="ftth_preset_name"' in content, 'Missing preset name input id="ftth_preset_name" in NOC-configMaker.html'
    assert 'id="ftthValidateBtn"' in content, 'Missing Validate button id="ftthValidateBtn" in NOC-configMaker.html'
    assert 'id="ftthGenerate"' in content, 'Missing Generate button id="ftthGenerate" in NOC-configMaker.html'
    assert 'id="ftthReset"' in content, 'Missing Reset button id="ftthReset" in NOC-configMaker.html'
    assert 'id="ftthPreview"' in content, 'Missing FTTH preview container id="ftthPreview" in NOC-configMaker.html'
    assert '<option value="25G-baseSR-LR">25G-baseSR-LR</option>' in content, 'Missing 25G-baseSR-LR option for FTTH speed selectors in NOC-configMaker.html'


def test_ftth_speed_controls_and_backend_payload_hooks_exist():
    content = UI_FILE.read_text(encoding='utf-8')
    assert '25G-baseSR-LR' in content, 'Missing 25G-baseSR-LR FTTH speed option in NOC-configMaker.html'
    assert "auto_negotiation: row.querySelector('.ftth-uplink-autoneg')?.checked || false" in content, \
        'Missing FTTH uplink auto-negotiation payload mapping in NOC-configMaker.html'
    assert "speed: speedSelect.value" in content, 'Missing FTTH OLT speed payload mapping in NOC-configMaker.html'
    assert 'BGP Peer Configuration' in content, 'Missing FTTH BGP peer display section in NOC-configMaker.html'
    assert '10.2.0.107/32' in content, 'Missing FTTH CR7 peer display in NOC-configMaker.html'
    assert '10.2.0.108/32' in content, 'Missing FTTH CR8 peer display in NOC-configMaker.html'
    assert "const targetUrl = `${apiBase.replace(/\\/+$/, '')}/preview-ftth-bng`;" in content, \
        'Missing resolved API base wiring for FTTH preview in NOC-configMaker.html'
    assert "apiBase + '/save-completed-config'" in content, \
        'Missing completed-config endpoint wiring for bulk SSH save in NOC-configMaker.html'
    assert "apiBase + '/save-config'" not in content, \
        'Found stale /save-config endpoint reference in NOC-configMaker.html'


def test_ftth_fiber_customer_and_cisco_generator_exist():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'data-ftth-home-tab="fiber"' in content, 'Missing FTTH Fiber Customer subtab in NOC-configMaker.html'
    assert 'data-ftth-home-tab="fiber-site"' in content, 'Missing FTTH Fiber Site subtab in NOC-configMaker.html'
    assert 'data-ftth-home-tab="isd-fiber"' in content, 'Missing FTTH ISD Fiber subtab in NOC-configMaker.html'
    assert 'id="ftth-home-fiber-section"' in content, 'Missing FTTH Fiber Customer section in NOC-configMaker.html'
    assert 'id="ftth-home-fiber-site-section"' in content, 'Missing FTTH Fiber Site section in NOC-configMaker.html'
    assert 'id="ftth-home-isd-fiber-section"' in content, 'Missing FTTH ISD Fiber section in NOC-configMaker.html'
    assert 'id="ftthFiberRouterboard"' in content, 'Missing FTTH Fiber Customer RouterBoard selector in NOC-configMaker.html'
    assert 'id="ftthFiberRouteros"' in content, 'Missing FTTH Fiber Customer RouterOS selector in NOC-configMaker.html'
    assert 'id="ftthFiberLoopback"' in content, 'Missing FTTH Fiber Customer loopback field in NOC-configMaker.html'
    assert 'id="ftthFiberApplyCompliance"' in content, 'Missing FTTH Fiber Customer compliance toggle in NOC-configMaker.html'
    assert 'updateFtthFiberPortOptions' in content, 'Missing FTTH Fiber Customer dynamic port helper in NOC-configMaker.html'
    assert 'generateFtthFiberCustomerConfig' in content, 'Missing FTTH Fiber Customer generator hook in NOC-configMaker.html'
    assert '/generate-ftth-fiber-customer' in content, 'Missing FTTH Fiber Customer backend endpoint wiring in NOC-configMaker.html'
    assert 'generateFtthFiberSiteConfig' in content, 'Missing FTTH Fiber Site generator hook in NOC-configMaker.html'
    assert '/generate-ftth-fiber-site' in content, 'Missing FTTH Fiber Site backend endpoint wiring in NOC-configMaker.html'
    assert 'generateFtthIsdFiberConfig' in content, 'Missing FTTH ISD Fiber generator hook in NOC-configMaker.html'
    assert '/generate-ftth-isd-fiber' in content, 'Missing FTTH ISD Fiber backend endpoint wiring in NOC-configMaker.html'
    assert 'addFtthFiberBackhaulRow' in content, 'Missing shared FTTH fiber backhaul row helper in NOC-configMaker.html'
    assert '<select class="ftth-fiber-bh-port"></select>' in content, 'Missing FTTH Home routerboard-driven backhaul port dropdown in NOC-configMaker.html'
    assert 'refreshFtthFiberBackhaulPortOptions' in content, 'Missing FTTH Home backhaul port refresh helper in NOC-configMaker.html'
    assert 'confirmFtthComplianceBypass' in content, 'Missing FTTH Home compliance bypass confirmation helper in NOC-configMaker.html'
    assert 'GitLab compliance script' in content, 'Missing FTTH Home compliance bypass confirmation text in NOC-configMaker.html'
    assert 'id="cisco-config-pane"' in content, 'Missing Cisco Config pane in NOC-configMaker.html'
    assert 'Cisco Port Configuration Generator' in content, 'Missing Cisco Port Configuration Generator title in NOC-configMaker.html'
    assert 'id="ciscoHostname"' not in content, 'Cisco hostname field should not be present in NOC-configMaker.html'
    assert 'id="ciscoOspfProcess"' in content, 'Missing Cisco OSPF process field in NOC-configMaker.html'
    assert 'id="ciscoOspfArea"' in content, 'Missing Cisco OSPF area field in NOC-configMaker.html'
    assert 'id="ciscoMtu"' in content, 'Missing Cisco MTU field in NOC-configMaker.html'
    assert 'id="ciscoOspfKey"' not in content, 'Cisco OSPF MD5 key should not be exposed in the UI in NOC-configMaker.html'
    assert 'OSPF MD5 authentication uses the standard internal template key' in content, 'Missing Cisco internal OSPF key guidance in NOC-configMaker.html'
    assert "const ospfKey = '0456532B5A0B5B580D2028'" in content, 'Missing fixed Cisco OSPF MD5 key constant in NOC-configMaker.html'
    assert 'router ospf ${ospfProcess} area ${ospfArea}' in content, 'Missing Cisco OSPF process/area block in NOC-configMaker.html'
    assert 'no passive' in content, 'Missing Cisco explicit no-passive output in NOC-configMaker.html'
    assert 'commit' in content, 'Missing Cisco commit output in NOC-configMaker.html'
    assert 'generateCiscoConfig' in content, 'Missing Cisco Config generator hook in NOC-configMaker.html'
    assert "config_type: 'ftth-fiber-customer'" in content, 'Missing FTTH Fiber Customer completed-config save wiring in NOC-configMaker.html'
    assert "device: 'MikroTik Fiber Customer'" in content, 'Missing FTTH Fiber Customer activity wiring in NOC-configMaker.html'
    assert "config_type: 'cisco-interface'" in content, 'Missing Cisco completed-config save wiring in NOC-configMaker.html'
    assert "device: 'Cisco'" in content, 'Missing Cisco activity wiring in NOC-configMaker.html'
    assert 'Cisco Port Setup' in content, 'Missing Cisco Port Setup naming in NOC-configMaker.html'


def test_switch_maker_uses_backend_profile_generator():
    content = UI_FILE.read_text(encoding='utf-8')
    assert '<h1> MikroTik Switch Config Maker</h1>' in content, 'Missing Switch Maker heading in NOC-configMaker.html'
    assert 'id="switch_maker_profile"' in content, 'Missing in-state switch deployment profile selector in NOC-configMaker.html'
    assert 'id="switch_outstate_profile"' in content, 'Missing out-of-state switch deployment profile selector in NOC-configMaker.html'
    assert 'id="switch_maker_apply_compliance"' in content, 'Missing in-state switch compliance toggle in NOC-configMaker.html'
    assert 'id="switch_outstate_apply_compliance"' in content, 'Missing out-of-state switch compliance toggle in NOC-configMaker.html'
    assert 'const SWITCH_MAKER_DEVICE_PROFILES =' in content, 'Missing switch device profile inventory in NOC-configMaker.html'
    assert 'updateSwitchProfileDefaults(state)' in content, 'Missing switch profile default helper in NOC-configMaker.html'
    assert '/generate-mt-switch-config' in content, 'Missing backend switch generator endpoint wiring in NOC-configMaker.html'
    assert 'sfp28-1' in content, 'Missing CCR2004 SFP28 uplink family in switch UI wiring'
    assert 'sfp-sfpplus23' in content, 'Missing CRS326 bonded uplink default in switch UI wiring'


def test_routerboard_identity_prefixes_are_normalized():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'function getMikroTikIdentityPrefix(modelValue, options = {})' in content, 'Missing shared MikroTik identity prefix helper in NOC-configMaker.html'
    assert 'placeholder="RTR-MT2004.HALLETTSVILLE-NW-1"' in content, 'Missing MT-prefixed tower identity placeholder in NOC-configMaker.html'
    assert 'RTR-${getMikroTikIdentityPrefix(deviceConfig.name, { style: \'family\' })}-1.${siteName}' in content, 'Missing RouterBOARD system identity auto-fill normalization in NOC-configMaker.html'
    assert 'RTR-${getMikroTikIdentityPrefix(deviceConfig.name, { style: \'family\' })}-1.${this.value}' in content, 'Missing site-change RouterBOARD identity normalization in NOC-configMaker.html'
    assert 'RTR-MTCCR-2004' not in content, 'Found stale malformed CCR2004 identity prefix in NOC-configMaker.html'
    assert 'RTR-MTRB-5009' not in content, 'Found stale malformed RB5009 identity prefix in NOC-configMaker.html'
    assert 'placeholder="RTR-2004.HALLETTSVILLE-NW-1"' not in content, 'Found stale tower identity placeholder without MT prefix in NOC-configMaker.html'


def test_enterprise_uses_single_routerboard_source_of_truth():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'const ENTERPRISE_DEVICE_PROFILES =' in content, 'Missing shared enterprise device profile map in NOC-configMaker.html'
    assert 'getEnterpriseDeviceProfile(deviceKey)' in content, 'Missing enterprise device profile helper in NOC-configMaker.html'
    assert 'getMPLSEnterpriseDefaults(deviceKey)' in content, 'Missing MPLS enterprise device profile helper in NOC-configMaker.html'
    assert 'validateDistinctEnterpriseInterfaces(roleMap)' in content, 'Missing shared enterprise interface collision validator in NOC-configMaker.html'
    assert 'Enterprise generation uses this single device selector as the source of truth' in content, 'Missing enterprise single-selector guidance in NOC-configMaker.html'
    assert '<label for="targetDevice">Target Device:</label>' not in content, 'Found duplicated Target Device selector inside enterprise UI in NOC-configMaker.html'
    assert 'id="ent_mpls_profile_hint"' in content, 'Missing MPLS profile hint element in NOC-configMaker.html'
    assert 'Please add at least one uplink interface and uplink IP/network.' in content, 'Missing MPLS uplink validation guard in NOC-configMaker.html'
    assert '# PORT MAP SUMMARY' in content, 'Missing MPLS port map summary block in NOC-configMaker.html'
    assert "type: 'generated enterprise config'" in content, 'Missing Non-MPLS enterprise activity logging in NOC-configMaker.html'
    assert "type: 'generated mpls enterprise config'" in content, 'Missing MPLS enterprise activity logging in NOC-configMaker.html'


def test_nokia_configurator_is_truly_unified():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'id="nokiaPlatformModel"' in content, 'Missing Nokia platform model selector in NOC-configMaker.html'
    assert 'id="nokiaPlatformProfile"' in content, 'Missing Nokia platform profile selector in NOC-configMaker.html'
    assert 'id="nokiaProfileHost"' in content, 'Missing Nokia profile host container in NOC-configMaker.html'
    assert 'id="nokia7210ProfileSection"' in content, 'Missing Nokia 7210 profile section in NOC-configMaker.html'
    assert 'id="nokia7210IsdSection"' in content, 'Missing Nokia 7210 ISD profile section in NOC-configMaker.html'
    assert 'id="nokia7750TunnelSection"' in content, 'Missing Nokia 7750 tunnel section in NOC-configMaker.html'
    assert 'renderNokia7210ProfileConfig' in content, 'Missing Nokia 7210 renderer in NOC-configMaker.html'
    assert 'renderNokia7750ProfileConfig' in content, 'Missing Nokia 7750 renderer in NOC-configMaker.html'
    assert 'finalizeNokiaConfiguratorOutput' in content, 'Missing shared Nokia output finalizer in NOC-configMaker.html'
    assert 'configType: `nokia-7210-${selection.profile}`' in content, 'Missing Nokia 7210 profile-specific save type in NOC-configMaker.html'
    assert 'configType: `nokia-7750-${selection.profile}`' in content, 'Missing Nokia 7750 profile-specific save type in NOC-configMaker.html'
    assert '/generate-nokia-configurator' in content, 'Missing backend Nokia configurator endpoint wiring in NOC-configMaker.html'

def test_sidebar_and_nokia_7250_layout_updates_exist():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'IDO Tools Space' not in content, 'Standalone IDO Tools pane should be removed from NOC-configMaker.html'
    assert 'data-sb-tab="ido-tools"' not in content, 'Sidebar should not include the removed IDO Tools entry'
    assert 'data-tab="ido-tools"' not in content, 'Top navigation should not include the removed IDO Tools tab'
    assert 'data-tool="nokia-7250"' not in content, 'Field Config Studio should not include the Nokia 7250 subtab'
    assert '> Nokia Configurator<' in content or '>Nokia Configurator<' in content, 'Missing unified Nokia Configurator page title'
    assert 'IN-STATE Nokia 7250 Configuration Maker' not in content, 'Old Nokia 7250 in-state-only title should be removed'
    assert 'id="nokia7250_siteSuffix"' in content, 'Missing Nokia 7250 short site-name input'
    assert 'id="nokia7250_output_format"' in content, 'Missing Nokia 7250 output format selector'
    assert 'Classic Hierarchy' in content, 'Missing Nokia 7250 classic hierarchy option'
    assert 'Cisco configuration (coming soon)' not in content, 'Cisco quick navigation should not still be marked as coming soon'
    assert 'Command Lines' in content, 'Missing Nokia 7250 command-line option'
    assert 'buildNokia7250CommandLineOutput' in content, 'Missing Nokia 7250 command-line conversion helper'
    assert 'buildNokia7250SystemName' in content, 'Missing Nokia 7250 system-name auto-fill helper'
    assert 'syncNokia7250SystemName' in content, 'Missing Nokia 7250 system-name sync helper'
    assert 'setNokia7250OutputFormat' in content, 'Missing Nokia 7250 output format switcher'
    assert 'validateNokia7250Inputs' in content, 'Missing Nokia 7250 input validation helper'
    assert 'Uplink ${index + 1} IP/CIDR is invalid' in content, 'Missing Nokia 7250 uplink CIDR validation message'



if __name__ == '__main__':
    try:
        test_ftth_modal_exists()
        test_ftth_speed_controls_and_backend_payload_hooks_exist()
        test_ftth_fiber_customer_and_cisco_generator_exist()
        test_routerboard_identity_prefixes_are_normalized()
        test_enterprise_uses_single_routerboard_source_of_truth()
        test_nokia_configurator_is_truly_unified()
        test_sidebar_and_nokia_7250_layout_updates_exist()
        print('[OK] test_ftth_modal_exists')
        raise SystemExit(0)
    except AssertionError as e:
        print('[FAIL] test_ftth_modal_exists:', e)
        raise SystemExit(1)
