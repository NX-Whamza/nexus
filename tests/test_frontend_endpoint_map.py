#!/usr/bin/env python3
"""Regression checks for frontend-to-backend endpoint wiring."""

from __future__ import annotations

import re
import sys
from pathlib import Path


repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))


def _backend_routes() -> set[str]:
    files = [
        repo_root / 'vm_deployment' / 'api_server.py',
        repo_root / 'vm_deployment' / 'fastapi_server.py',
        repo_root / 'vm_deployment' / 'api_v2.py',
        repo_root / 'vm_deployment' / 'routes' / 'ftth.py',
        repo_root / 'vm_deployment' / 'routes' / 'runtime.py',
    ]
    route_re = re.compile(r"""@(?:app|bp)\.(?:route|get|post|put|delete|patch)\((?:'|")([^'"]+)""")
    routes: set[str] = set()
    for path in files:
        text = path.read_text(encoding='utf-8', errors='ignore')
        routes.update(route_re.findall(text))
    return routes


def _normalize_route(route: str) -> str:
    route = re.sub(r'<[^>]+>', 'X', route)
    route = re.sub(r'\{[^}]+\}', 'X', route)
    return route


def test_frontend_endpoint_wiring_has_backend_routes():
    routes = {_normalize_route(route) for route in _backend_routes()}
    frontend_endpoints = {
        '/api/auth/verify',
        '/api/session/bootstrap',
        '/api/session/switch-tenant',
        '/api/health',
        '/api/version',
        '/api/app-config',
        '/api/preview-ftth-bng',
        '/api/generate-ftth-bng',
        '/api/generate-ftth-fiber-customer',
        '/api/generate-ftth-fiber-site',
        '/api/generate-ftth-isd-fiber',
        '/api/ftth-home/mf2-package',
        '/api/compliance/blocks',
        '/api/apply-compliance',
        '/api/infrastructure',
        '/api/log-activity',
        '/api/get-activity',
        '/api/admin/feedback',
        '/api/admin/users/reset-password',
        '/api/admin/feedback/X/status',
        '/api/admin/feedback/export',
        '/api/chat',
        '/api/ido/capabilities',
        '/api/ido/compliance',
        '/api/mt/X/config',
        '/api/mt/X/portmap',
        '/api/suggest-config',
        '/api/gen-enterprise-non-mpls',
        '/api/generate-mt-switch-config',
        '/api/validate-config',
        '/api/autofill-from-export',
        '/api/fetch-config-ssh',
        '/api/translate-config',
        '/api/save-completed-config',
        '/api/get-completed-configs',
        '/api/get-completed-config/X',
        '/api/nokia7250-defaults',
        '/api/parse-mikrotik-for-nokia',
        '/api/migrate-mikrotik-to-nokia',
        '/api/feedback',
        '/api/feedback/my-status',
        '/api/bulk-generate',
        '/api/bulk-ssh-fetch',
        '/api/bulk-migration-analyze',
        '/api/bulk-migration-execute',
        '/api/bulk-compliance-scan',
        '/api/ssh-push-config',
        '/api/admin/tenants',
        '/api/admin/users',
    }
    missing = sorted(ep for ep in frontend_endpoints if ep not in routes)
    assert not missing, f"Frontend endpoints missing backend routes: {missing}"
