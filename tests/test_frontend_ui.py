#!/usr/bin/env python3
"""Simple tests to verify presence of FTTH modal UI in the built frontend file."""

from __future__ import annotations

import os
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))

UI_FILE = repo_root / 'vm_deployment' / 'nexus.html'
CAMBIUM_UI_FILE = repo_root / 'vm_deployment' / 'cambium-firmware-updater.js'


def test_ftth_modal_exists():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'FTTH BNG CONFIG' in content, 'Missing menu label "FTTH BNG CONFIG" in Mikrotik dropdown in nexus.html'
    assert 'data-tab="ftth-home"' in content, 'Missing FTTH HOME navigation entry in nexus.html'
    assert 'id="ftth-home-pane"' in content, 'Missing FTTH HOME content pane id="ftth-home-pane" in nexus.html'
    assert 'id="ftth-pane"' in content, 'Missing ftth content pane id="ftth-pane" in nexus.html'
    assert 'id="ftthPreviewBtn"' in content, 'Missing Preview button id="ftthPreviewBtn" in nexus.html'
    assert ('generateFtthBng' in content) or ('ftthGenerate' in content), 'Missing generator hook: generateFtthBng() or element id="ftthGenerate"'
    assert 'id="ftth_instate_btn"' in content, 'Missing FTTH sub-tab button id="ftth_instate_btn" in nexus.html'
    assert 'id="ftth_outstate_btn"' in content, 'Missing FTTH sub-tab button id="ftth_outstate_btn" in nexus.html'
    assert 'id="ftth-instate-section"' in content and 'id="ftth-outstate-section"' in content, 'Missing FTTH sub-tab sections in nexus.html'
    assert 'id="ftth_add_olt_port_btn"' in content, 'Missing OLT add button id="ftth_add_olt_port_btn" in nexus.html'
    assert 'id="ftth_add_backhaul_btn"' in content, 'Missing backhaul add button id="ftth_add_backhaul_btn" in nexus.html'
    assert 'id="ftth_open_portconfigs_btn"' in content, 'Missing Open Port & Uplink button id="ftth_open_portconfigs_btn" in nexus.html'
    assert 'id="ftth_olt_port_in"' in content, 'Missing OLT port select id="ftth_olt_port_in" in nexus.html'
    assert 'id="ftth_olt_speed_in"' in content, 'Missing OLT port speed select id="ftth_olt_speed_in" in nexus.html'
    assert 'id="ftth_olt_port_out"' in content, 'Missing OLT port select id="ftth_olt_port_out" in nexus.html'
    assert 'id="ftth_olt_speed_out"' in content, 'Missing OLT port speed select id="ftth_olt_speed_out" in nexus.html'
    assert 'id="ftth_preset_select"' in content, 'Missing preset select id="ftth_preset_select" in nexus.html'
    assert 'id="ftth_preset_save"' in content, 'Missing preset save button id="ftth_preset_save" in nexus.html'
    assert 'id="ftth_preset_delete"' in content, 'Missing preset delete button id="ftth_preset_delete" in nexus.html'
    assert 'id="ftth_preset_name"' in content, 'Missing preset name input id="ftth_preset_name" in nexus.html'
    assert 'id="ftthValidateBtn"' in content, 'Missing Validate button id="ftthValidateBtn" in nexus.html'
    assert 'id="ftthGenerate"' in content, 'Missing Generate button id="ftthGenerate" in nexus.html'
    assert 'id="ftthReset"' in content, 'Missing Reset button id="ftthReset" in nexus.html'
    assert 'id="ftthPreview"' in content, 'Missing FTTH preview container id="ftthPreview" in nexus.html'
    assert '<option value="25G-baseSR-LR">25G-baseSR-LR</option>' in content, 'Missing 25G-baseSR-LR option for FTTH speed selectors in nexus.html'


def test_ftth_speed_controls_and_backend_payload_hooks_exist():
    content = UI_FILE.read_text(encoding='utf-8')
    assert '25G-baseSR-LR' in content, 'Missing 25G-baseSR-LR FTTH speed option in nexus.html'
    assert "auto_negotiation: row.querySelector('.ftth-uplink-autoneg')?.checked || false" in content, \
        'Missing FTTH uplink auto-negotiation payload mapping in nexus.html'
    assert "speed: speedSelect.value" in content, 'Missing FTTH OLT speed payload mapping in nexus.html'
    assert 'BGP Peer Configuration' in content, 'Missing FTTH BGP peer display section in nexus.html'
    assert "fetch(`${apiBase}/tenant/defaults`)" in content, 'Missing tenant-defaults bootstrap fetch in nexus.html'
    assert 'getTenantRouteReflectorPeers' in content, 'Missing tenant route-reflector peer helper in nexus.html'
    assert 'getTenantDefaultAsn' in content, 'Missing tenant ASN helper in nexus.html'
    assert "const targetUrl = `${apiBase.replace(/\\/+$/, '')}/preview-ftth-bng`;" in content, \
        'Missing resolved API base wiring for FTTH preview in nexus.html'
    assert "apiBase + '/save-completed-config'" in content, \
        'Missing completed-config endpoint wiring for bulk SSH save in nexus.html'
    assert "apiBase + '/save-config'" not in content, \
        'Found stale /save-config endpoint reference in nexus.html'


def test_ftth_fiber_customer_and_cisco_generator_exist():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'data-ftth-home-tab="fiber"' in content, 'Missing FTTH Fiber Customer subtab in nexus.html'
    assert 'data-ftth-home-tab="fiber-site"' in content, 'Missing FTTH Fiber Site subtab in nexus.html'
    assert 'data-ftth-home-tab="isd-fiber"' in content, 'Missing FTTH ISD Fiber subtab in nexus.html'
    assert 'id="ftth-home-fiber-section"' in content, 'Missing FTTH Fiber Customer section in nexus.html'
    assert 'id="ftth-home-fiber-site-section"' in content, 'Missing FTTH Fiber Site section in nexus.html'
    assert 'id="ftth-home-isd-fiber-section"' in content, 'Missing FTTH ISD Fiber section in nexus.html'
    assert 'id="ftthFiberRouterboard"' in content, 'Missing FTTH Fiber Customer RouterBoard selector in nexus.html'
    assert 'id="ftthFiberRouteros"' in content, 'Missing FTTH Fiber Customer RouterOS selector in nexus.html'
    assert 'id="ftthFiberLoopback"' in content, 'Missing FTTH Fiber Customer loopback field in nexus.html'
    assert 'id="ftthFiberApplyCompliance"' in content, 'Missing FTTH Fiber Customer compliance toggle in nexus.html'
    assert 'updateFtthFiberPortOptions' in content, 'Missing FTTH Fiber Customer dynamic port helper in nexus.html'
    assert 'generateFtthFiberCustomerConfig' in content, 'Missing FTTH Fiber Customer generator hook in nexus.html'
    assert '/generate-ftth-fiber-customer' in content, 'Missing FTTH Fiber Customer backend endpoint wiring in nexus.html'
    assert 'generateFtthFiberSiteConfig' in content, 'Missing FTTH Fiber Site generator hook in nexus.html'
    assert '/generate-ftth-fiber-site' in content, 'Missing FTTH Fiber Site backend endpoint wiring in nexus.html'
    assert 'generateFtthIsdFiberConfig' in content, 'Missing FTTH ISD Fiber generator hook in nexus.html'
    assert '/generate-ftth-isd-fiber' in content, 'Missing FTTH ISD Fiber backend endpoint wiring in nexus.html'
    assert 'addFtthFiberBackhaulRow' in content, 'Missing shared FTTH fiber backhaul row helper in nexus.html'
    assert '<select class="ftth-fiber-bh-port"></select>' in content, 'Missing FTTH Home routerboard-driven backhaul port dropdown in nexus.html'
    assert 'refreshFtthFiberBackhaulPortOptions' in content, 'Missing FTTH Home backhaul port refresh helper in nexus.html'
    assert 'confirmFtthComplianceBypass' in content, 'Missing FTTH Home compliance bypass confirmation helper in nexus.html'
    assert 'GitLab compliance script' in content, 'Missing FTTH Home compliance bypass confirmation text in nexus.html'
    assert 'id="cisco-config-pane"' in content, 'Missing Cisco Config pane in nexus.html'
    assert 'Cisco Port Configuration Generator' in content, 'Missing Cisco Port Configuration Generator title in nexus.html'
    assert 'id="ciscoHostname"' not in content, 'Cisco hostname field should not be present in nexus.html'
    assert 'id="ciscoOspfProcess"' in content, 'Missing Cisco OSPF process field in nexus.html'
    assert 'id="ciscoOspfArea"' in content, 'Missing Cisco OSPF area field in nexus.html'
    assert 'id="ciscoMtu"' in content, 'Missing Cisco MTU field in nexus.html'
    assert 'id="ciscoOspfKey"' not in content, 'Cisco OSPF MD5 key should not be exposed in the UI in nexus.html'
    assert 'OSPF MD5 authentication uses the standard internal template key' in content, 'Missing Cisco internal OSPF key guidance in nexus.html'
    assert "const ospfKey = '0456532B5A0B5B580D2028'" in content, 'Missing fixed Cisco OSPF MD5 key constant in nexus.html'
    assert 'router ospf ${ospfProcess} area ${ospfArea}' in content, 'Missing Cisco OSPF process/area block in nexus.html'
    assert 'no passive' in content, 'Missing Cisco explicit no-passive output in nexus.html'
    assert 'commit' in content, 'Missing Cisco commit output in nexus.html'
    assert 'generateCiscoConfig' in content, 'Missing Cisco Config generator hook in nexus.html'
    assert "config_type: 'ftth-fiber-customer'" in content, 'Missing FTTH Fiber Customer completed-config save wiring in nexus.html'
    assert "device: 'MikroTik Fiber Customer'" in content, 'Missing FTTH Fiber Customer activity wiring in nexus.html'
    assert "config_type: 'cisco-interface'" in content, 'Missing Cisco completed-config save wiring in nexus.html'
    assert "device: 'Cisco'" in content, 'Missing Cisco activity wiring in nexus.html'
    assert 'Cisco Port Setup' in content, 'Missing Cisco Port Setup naming in nexus.html'


def test_switch_maker_uses_backend_profile_generator():
    content = UI_FILE.read_text(encoding='utf-8')
    assert '<h1> MikroTik Switch Config Maker</h1>' in content, 'Missing Switch Maker heading in nexus.html'
    assert 'id="switch_maker_profile"' in content, 'Missing in-state switch deployment profile selector in nexus.html'
    assert 'id="switch_outstate_profile"' in content, 'Missing out-of-state switch deployment profile selector in nexus.html'
    assert 'id="switch_maker_apply_compliance"' in content, 'Missing in-state switch compliance toggle in nexus.html'
    assert 'id="switch_outstate_apply_compliance"' in content, 'Missing out-of-state switch compliance toggle in nexus.html'
    assert 'const SWITCH_MAKER_DEVICE_PROFILES =' in content, 'Missing switch device profile inventory in nexus.html'
    assert 'updateSwitchProfileDefaults(state)' in content, 'Missing switch profile default helper in nexus.html'
    assert '/generate-mt-switch-config' in content, 'Missing backend switch generator endpoint wiring in nexus.html'
    assert 'sfp28-1' in content, 'Missing CCR2004 SFP28 uplink family in switch UI wiring'
    assert 'sfp-sfpplus23' in content, 'Missing CRS326 bonded uplink default in switch UI wiring'


def test_routerboard_identity_prefixes_are_normalized():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'function getMikroTikIdentityPrefix(modelValue, options = {})' in content, 'Missing shared MikroTik identity prefix helper in nexus.html'
    assert 'placeholder="RTR-MT2004.HALLETTSVILLE-NW-1"' in content, 'Missing MT-prefixed tower identity placeholder in nexus.html'
    assert 'RTR-${getMikroTikIdentityPrefix(deviceConfig.name, { style: \'family\' })}-1.${siteName}' in content, 'Missing RouterBOARD system identity auto-fill normalization in nexus.html'
    assert 'RTR-${getMikroTikIdentityPrefix(deviceConfig.name, { style: \'family\' })}-1.${this.value}' in content, 'Missing site-change RouterBOARD identity normalization in nexus.html'
    assert 'RTR-MTCCR-2004' not in content, 'Found stale malformed CCR2004 identity prefix in nexus.html'
    assert 'RTR-MTRB-5009' not in content, 'Found stale malformed RB5009 identity prefix in nexus.html'
    assert 'placeholder="RTR-2004.HALLETTSVILLE-NW-1"' not in content, 'Found stale tower identity placeholder without MT prefix in nexus.html'


def test_enterprise_uses_single_routerboard_source_of_truth():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'const ENTERPRISE_DEVICE_PROFILES =' in content, 'Missing shared enterprise device profile map in nexus.html'
    assert 'getEnterpriseDeviceProfile(deviceKey)' in content, 'Missing enterprise device profile helper in nexus.html'
    assert 'getMPLSEnterpriseDefaults(deviceKey)' in content, 'Missing MPLS enterprise device profile helper in nexus.html'
    assert 'validateDistinctEnterpriseInterfaces(roleMap)' in content, 'Missing shared enterprise interface collision validator in nexus.html'
    assert 'Enterprise generation uses this single device selector as the source of truth' in content, 'Missing enterprise single-selector guidance in nexus.html'
    assert '<label for="targetDevice">Target Device:</label>' not in content, 'Found duplicated Target Device selector inside enterprise UI in nexus.html'
    assert 'id="ent_mpls_profile_hint"' in content, 'Missing MPLS profile hint element in nexus.html'
    assert 'Please add at least one uplink interface and uplink IP/network.' in content, 'Missing MPLS uplink validation guard in nexus.html'
    assert '# PORT MAP SUMMARY' in content, 'Missing MPLS port map summary block in nexus.html'
    assert "type: 'generated enterprise config'" in content, 'Missing Non-MPLS enterprise activity logging in nexus.html'
    assert "type: 'generated mpls enterprise config'" in content, 'Missing MPLS enterprise activity logging in nexus.html'


def test_tarana_tab_uses_shared_port_population_and_validates_bng1_inputs():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'function normalizeTaranaDeviceKey(deviceKey, fallbackKey = \'\')' in content, 'Missing Tarana-local device normalization helper in nexus.html'
    assert 'function getTaranaRecommendedPorts(deviceValue)' in content, 'Missing Tarana-local recommended port helper in nexus.html'
    assert 'function getTaranaPortOptions(deviceKey)' in content, 'Missing shared Tarana port inventory helper in nexus.html'
    assert 'function populateTaranaPortSelects(options)' in content, 'Missing shared Tarana port select population helper in nexus.html'
    assert 'function resolveTaranaMgmtCidr(cidrInput)' in content, 'Missing Tarana BNG1 CIDR normalization helper in nexus.html'
    assert 'function getTaranaSpeedSyntax(routerosVersion)' in content, 'Missing Tarana RouterOS speed helper in nexus.html'
    assert 'Gateway or Network (CIDR)' in content, 'Missing Tarana BNG1 gateway/network guidance in nexus.html'
    assert 'You can enter the /29 network or the first usable router IP.' in content, 'Missing Tarana BNG1 CIDR hint in nexus.html'
    assert "preserveSelection: true" in content, 'Tarana port dropdowns should preserve user selections during repopulation'
    assert 'Each Tarana sector must use a different port.' in content, 'Missing Tarana duplicate-port validation in nexus.html'
    assert 'const speedSyntax = getTaranaSpeedSyntax(routerosVersion);' in content, 'Missing Tarana RouterOS-aware speed syntax wiring in nexus.html'
    assert 'Tarana BNG1 supports only CCR2004 and CCR2216.' in content, 'Missing explicit Tarana BNG1 device guard in nexus.html'
    assert "const selectedDeviceKey = normalizeTaranaDeviceKey(selectedDevice, '');" in content, 'Tarana handlers should use the local device normalization fallback'


def test_nokia_configurator_is_truly_unified():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'id="nokiaPlatformModel"' in content, 'Missing Nokia platform model selector in nexus.html'
    assert 'id="nokiaPlatformProfile"' in content, 'Missing Nokia platform profile selector in nexus.html'
    assert 'id="nokiaProfileHost"' in content, 'Missing Nokia profile host container in nexus.html'
    assert 'id="nokia7210ProfileSection"' in content, 'Missing Nokia 7210 profile section in nexus.html'
    assert 'id="nokia7210IsdSection"' in content, 'Missing Nokia 7210 ISD profile section in nexus.html'
    assert 'id="nokia7750TunnelSection"' in content, 'Missing Nokia 7750 tunnel section in nexus.html'
    assert 'renderNokia7210ProfileConfig' in content, 'Missing Nokia 7210 renderer in nexus.html'
    assert 'renderNokia7750ProfileConfig' in content, 'Missing Nokia 7750 renderer in nexus.html'
    assert 'finalizeNokiaConfiguratorOutput' in content, 'Missing shared Nokia output finalizer in nexus.html'
    assert 'configType: `nokia-7210-${selection.profile}`' in content, 'Missing Nokia 7210 profile-specific save type in nexus.html'
    assert 'configType: `nokia-7750-${selection.profile}`' in content, 'Missing Nokia 7750 profile-specific save type in nexus.html'
    assert '/generate-nokia-configurator' in content, 'Missing backend Nokia configurator endpoint wiring in nexus.html'

def test_sidebar_and_nokia_7250_layout_updates_exist():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'IDO Tools Space' not in content, 'Standalone IDO Tools pane should be removed from nexus.html'
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


def test_command_vault_and_maintenance_tabs_use_backend_contracts():
    content = UI_FILE.read_text(encoding='utf-8')
    assert "fetch(`${getCommandVaultApiBase()}/command-vault/catalog`" in content, 'Command Vault should sync from the backend catalog endpoint'
    assert 'function syncCommandVaultCatalog()' in content, 'Missing Command Vault backend sync helper in nexus.html'
    assert 'id="nokiaVault7750Grid"' in content, 'Missing Nokia Command Vault backend target grid in nexus.html'
    assert 'id="ciscoVaultGrid"' in content, 'Missing Cisco Command Vault backend target grid in nexus.html'
    assert 'id="mikrotikVaultGrid"' in content, 'Missing MikroTik Command Vault backend target grid in nexus.html'
    assert "fetch(`${apiBase}/maintenance/windows?status=all&limit=250`)" in content, 'Scheduled Maintenance should load from the backend endpoint'
    assert "const MAINT_KEY = 'nexus_maintenance_windows_cache';" in content, 'Scheduled Maintenance should use the NEXUS cache key'
    assert "fetch(`${apiBase}/tenant/defaults`)" in content, 'Shared tools should hydrate tenant defaults from backend discovery'


def test_frontend_copy_is_tenant_neutral_for_shared_tools():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'Uses IDO proxy backends.' not in content, 'Field Config Studio copy should not expose legacy IDO wording'
    assert 'IDO status check failed:' not in content, 'Field Config Studio status copy should use tenant-neutral wording'
    assert 'IDO backend is not configured' not in content, 'Field Config Studio error copy should use tenant-neutral wording'
    assert 'Unified device configurator workspace for shared device-access backends' in content, 'Field Config Studio should describe the shared device-access backend'
    assert 'device-access backend not configured' in content, 'Field Config Studio should reference the shared device-access backend'


def test_nokia_7250_port_setup_uses_safe_field_reader_and_clean_labels():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'function getCellFieldValue(tr, cellIndex, selector, options = {})' in content, 'Missing shared Nokia 7250 port-table field reader helper'
    assert "ospfKey = creds.ospf_auth_key || creds.bgp_auth_key || '';" in content, 'Missing Nokia 7250 OSPF key fallback wiring'
    assert 'Please enter an OSPF MD5 Auth Key, or configure NOKIA7250_OSPF_AUTH_KEY on the server.' in content, 'Missing Nokia 7250 OSPF env guidance'
    assert 'Port ${duplicatePort.port} is selected more than once. Each Nokia port can only be configured once.' in content, 'Missing duplicate Nokia 7250 port guard'
    assert 'Interface description "${duplicateDesc.desc}" is duplicated. Use a unique interface name per port.' in content, 'Missing duplicate Nokia 7250 interface-name guard'
    assert '`<option value="1/1/${i}">1/1/${i}</option>`' in content, 'Missing clean Nokia 7250 SFP+ port label'
    assert '`<option value="1/1/c${i}/1">1/1/c${i}/1</option>`' in content, 'Missing clean Nokia 7250 breakout port label'
    assert '`<option value="1/1/${i}">1/1/${i} (SFP+)</option>`' not in content, 'Found stale Nokia 7250 SFP+ bracket label'
    assert '`<option value="1/1/c${i}/1">1/1/c${i}/1 (QSFP28)</option>`' not in content, 'Found stale Nokia 7250 QSFP28 bracket label'
    assert '`/configure port ${p.port} no shutdown`' in content, 'Missing normalized Nokia 7250 port command prefix'
    assert '`/configure router ospf 1 area "${ospfArea}" interface "${p.desc}" no shutdown`' in content, 'Missing normalized Nokia 7250 OSPF shutdown command'


def test_mikrotik_migration_target_device_change_handler_exists():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'onchange="updateInterfacesForMigration()"' in content, 'Missing MikroTik migration target-device onchange hook'
    assert 'window.updateInterfacesForMigration = function () {' in content, 'Missing MikroTik migration onchange handler implementation'
    assert 'updateDevicePorts();' in content, 'Missing MikroTik migration device-port refresh delegation'
    assert "const escapeHtml = (typeof window !== 'undefined' && typeof window.escHtml === 'function')" in content, 'Missing local HTML escaping fallback for Upgrade Existing migration preview'
    assert '${escapeHtml(analysis.migration_type || \'config-audit\')}' in content, 'Migration preview should use the local escapeHtml fallback instead of raw escHtml'


def test_device_firmware_updater_wraps_aviat_and_cambium():
    content = UI_FILE.read_text(encoding='utf-8')
    cambium_js = CAMBIUM_UI_FILE.read_text(encoding='utf-8')
    assert 'DEVICES FIRMWARE UPDATER' in content, 'Missing top-level Devices Firmware Updater navigation label'
    assert 'id="device-firmware-updater-pane"' in content, 'Missing shared device firmware content pane'
    assert 'data-device-firmware-tab="aviat"' in content, 'Missing Aviat firmware subtab button/dropdown wiring'
    assert 'data-device-firmware-tab="cambium"' in content, 'Missing Cambium firmware subtab button/dropdown wiring'
    assert 'window.showDeviceFirmwareUpdaterSubTab = function (tabKey)' in content, 'Missing device firmware subtab controller'
    assert 'id="device-firmware-cambium-section"' in content, 'Missing Cambium firmware section in shared pane'
    assert '<script src="cambium-firmware-updater.js"></script>' in content, 'Missing external Cambium firmware updater bundle'
    assert 'function getCambiumApiBase()' in cambium_js, 'Missing Cambium API base helper'
    assert "return `${getApiRoot()}/cambium`;" in cambium_js, 'Cambium updater should point at the dedicated /api/cambium namespace'
    assert "/firmware-updater/providers" in cambium_js, 'Cambium updater should load shared firmware providers'
    assert "cambiumFetch('/catalog')" in cambium_js, 'Cambium updater should load the Cambium catalog'
    assert "cambiumFetch('/device-info'" in cambium_js, 'Cambium updater should query Cambium device info'
    assert "cambiumFetch('/queue'" in cambium_js, 'Cambium updater should queue Cambium radios through the backend'
    assert "cambiumFetch('/run'" in cambium_js, 'Cambium updater should start Cambium runs through the backend'
    assert "cambiumFetch(`/status/${taskId}`)" in cambium_js, 'Cambium updater should poll Cambium task status'
    assert "new EventSource(getCambiumStreamUrl(`/stream/${encodeURIComponent(taskId)}`))" in cambium_js, 'Cambium updater should open per-task Cambium SSE streams via getCambiumStreamUrl'
    assert "new EventSource(getCambiumStreamUrl('/stream/global'))" in cambium_js, 'Cambium updater should open the Cambium global SSE stream via getCambiumStreamUrl'
    assert "cambiumFetch('/check-status'" not in cambium_js, 'Cambium updater should not call the removed check-status endpoint'
    assert "cambiumFetch(`/abort/${encodeURIComponent(cambiumState.taskId)}`" in cambium_js, 'Cambium updater should request abort through the Cambium backend'
    assert "requested_by: cambiumGetUsername()" in cambium_js, 'Cambium updater should send the operator as requested_by, not as the radio login username'
    assert "body: JSON.stringify({ ip, device_type: deviceType, username: cambiumGetUsername(), password: selectedProfile().password || '' })" not in cambium_js, 'Cambium device-info requests should not send the signed-in app user as the device username'
    assert "function syncInteractiveState()" in cambium_js, 'Cambium updater should centralize UI lockout while a run is active'
    assert "if (cambiumState.isProcessing) return;" in cambium_js, 'Cambium updater row actions should no-op while a run is active'
    assert "syncInteractiveState();" in cambium_js and "updateUI();" in cambium_js, 'Cambium updater should refresh disabled button state when processing starts or ends'
    assert "backupPath: radio.backupPath || radio.backup_path || ''" in cambium_js, 'Cambium updater should preserve backup paths from backend results'
    assert "onclick=\"cambiumDownloadBackup(" in cambium_js, 'Cambium updater should expose a per-row backup download action'
    assert "window.cambiumDownloadBackup = async function (ip)" in cambium_js, 'Cambium updater should define a backup download handler'
    assert "abortBtn.disabled = !cambiumState.isProcessing;" in cambium_js, 'Cambium abort button should be clickable whenever a Cambium task is active'
    assert "const backupAvailable = backupStatus === 'success' || !!radio.backupPath;" in cambium_js, 'Cambium backup button should enable from successful backup status even if the path is stale in UI state'
    assert "const query = radio.backupPath" in cambium_js, 'Cambium backup download should fall back to IP-based lookup when only backup status is available'
    assert "function clearPersistedRadios()" in cambium_js, 'Cambium updater should clear stale browser-side queue state on reload'
    assert "await loadQueueState({ quiet: true });" in cambium_js, 'Cambium updater should reload queue state from the backend during initialization'
    assert "localStorage.setItem(CAMBIUM_STORAGE_KEY" not in cambium_js, 'Cambium updater should not repopulate stale local queue state from browser storage'
    assert "'cambium-upgrade': TOOL_ROUTE_DEFINITIONS['device-firmware-updater:cambium']" in content, 'Missing activity-route mapping for Cambium upgrades'


def test_vpls_helpers_are_not_shadowed_by_duplicate_definitions():
    content = UI_FILE.read_text(encoding='utf-8')
    assert content.count('function addVpls(') == 1, 'Found duplicate addVpls() definitions shadowing VPLS preset support'
    assert content.count('function updateVplsCount(') == 1, 'Found duplicate updateVplsCount() definitions shadowing VPLS count handling'


def test_routeros_ui_baseline_is_7194_or_newer():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'option value="7.11.2"' not in content, 'Found stale RouterOS 7.11.2 option in nexus.html'
    assert 'option value="7.16.2"' not in content, 'Found stale RouterOS 7.16.2 option in nexus.html'
    assert 'option value="7.18.2"' not in content, 'Found stale RouterOS 7.18.2 option in nexus.html'
    assert 'option value="6.49.2"' not in content, 'Found stale RouterOS 6.49.2 option in nexus.html'
    assert 'option value="6.45.2"' not in content, 'Found stale RouterOS 6.45.2 option in nexus.html'
    assert 'RouterOS generation baseline: 7.19.4 or newer' in content, 'Missing updated RouterOS baseline guidance in nexus.html'


def test_mikrotik_device_lookup_and_tarana_defaults_are_normalized():
    content = UI_FILE.read_text(encoding='utf-8')
    assert "function getDeviceConfig(deviceValue, fallbackKey = 'ccr2004')" in content, 'Missing shared normalized device-config helper in nexus.html'
    assert "const selectedDevice = getNormalizedDeviceKey(targetDevice || currentDevice, '');" in content, 'Missing normalized migration device key selection in nexus.html'
    assert "const targetDeviceConfig = getDeviceConfig(targetDevice, '');" in content, 'Missing normalized migration target-device config lookup in nexus.html'
    assert "function getTaranaRecommendedPortsForDevice(deviceValue)" in content, 'Missing shared Tarana default-port helper in nexus.html'
    assert "alpha: 'sfp28-8'" in content and "delta: 'sfp28-11'" in content, 'Missing consistent CCR2216 Tarana default ports in nexus.html'



if __name__ == '__main__':
    try:
        test_ftth_modal_exists()
        test_ftth_speed_controls_and_backend_payload_hooks_exist()
        test_ftth_fiber_customer_and_cisco_generator_exist()
        test_routerboard_identity_prefixes_are_normalized()
        test_enterprise_uses_single_routerboard_source_of_truth()
        test_tarana_tab_uses_shared_port_population_and_validates_bng1_inputs()
        test_nokia_configurator_is_truly_unified()
        test_sidebar_and_nokia_7250_layout_updates_exist()
        print('[OK] test_ftth_modal_exists')
        raise SystemExit(0)
    except AssertionError as e:
        print('[FAIL] test_ftth_modal_exists:', e)
        raise SystemExit(1)
