#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
UI_FILE = REPO_ROOT / "vm_deployment" / "nexus.html"


def test_ui_route_registry_and_dynamic_palette_cover_newer_tools():
    content = UI_FILE.read_text(encoding="utf-8")
    assert "const TOOL_ROUTE_DEFINITIONS =" in content
    assert "'ftth-home:fiber': { tabId: 'ftth-home', subtab: 'fiber'" in content
    assert "'ftth-home:fiber-site': { tabId: 'ftth-home', subtab: 'fiber-site'" in content
    assert "'ftth-home:isd-fiber': { tabId: 'ftth-home', subtab: 'isd-fiber'" in content
    assert "function getCommandPaletteItems()" in content
    assert "document.querySelectorAll('#appSidebar .sb-item[data-sb-tab]')" in content
    assert "navigateToToolRoute(route)" in content


def test_saved_config_and_log_history_filters_are_dynamic_and_routable():
    content = UI_FILE.read_text(encoding="utf-8")
    assert "function populateConfigTypeFilter(configs)" in content
    assert "function populateLogTypeFilterOptions(activities)" in content
    assert "function openConfigRouteByType(configType)" in content
    assert "'bng2': TOOL_ROUTE_DEFINITIONS['tower']" in content
    assert "if (normalized.startsWith('nokia-')) return TOOL_ROUTE_DEFINITIONS['nokia7250-maker'];" in content
    assert 'Open Tool' in content
    assert "const route = getConfigRoute(data.config_type);" in content
    assert "const route = getActivityRoute(type) || TOOL_ROUTE_DEFINITIONS['log-history'];" in content


def test_startup_defaults_do_not_force_sidebar_into_nested_tools():
    content = UI_FILE.read_text(encoding="utf-8")
    assert "const LAST_ROUTE_KEY = 'nexusLastRoute';" in content
    assert "setCommandVaultSubTabState('nokia');" in content
    assert "setFtthHomeSubTabState('olt');" in content
    assert "storeLastRoute('home');" in content
    init_command_vault = content.split("function initCommandVaultTabs() {", 1)[1].split("function initNokiaVaultDropdown()", 1)[0]
    init_ftth_home = content.split("function initFtthHomeTabs() {", 1)[1].split("window.generateFtthHomeZip", 1)[0]
    assert "window.showCommandVaultSubTab('nokia');" not in init_command_vault
    assert "window.showFtthHomeSubTab('olt');" not in init_ftth_home


def test_deploy_scripts_generate_version_env_before_rebuild():
    repo_root = Path(__file__).resolve().parents[1]
    for rel_path in (
        "vm_deployment/update_dev.sh",
        "vm_deployment/update_prod.sh",
        "vm_deployment/setup_dev.sh",
    ):
        content = (repo_root / rel_path).read_text(encoding="utf-8")
        assert "generate_version_env()" in content
        assert "generate_version_env.py" in content
