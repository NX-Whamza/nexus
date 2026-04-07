from __future__ import annotations

import sys
from pathlib import Path


repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))

UI_FILE = repo_root / "vm_deployment" / "nexus.html"


def test_tenant_badge_and_switcher_are_present():
    content = UI_FILE.read_text(encoding="utf-8")
    assert 'id="roleBadge"' in content
    assert 'id="tenantBadge"' in content
    assert 'id="tenantSwitcher"' in content
    assert 'function getCurrentRoleLabel()' in content
    assert 'function renderTenantContext()' in content
    assert 'function switchActiveTenant(tenantId)' in content
    assert "/session/switch-tenant" in content
    assert 'id="adminFeedbackSection"' in content
    assert 'id="adminPlatformSection"' in content
    assert 'function applyAdminPanelRoles(' in content
    assert 'function loadAdminTenants(' in content
    assert 'function loadAdminUsers(' in content
