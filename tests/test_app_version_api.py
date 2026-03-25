from __future__ import annotations

import importlib
import sys
from pathlib import Path


def _load_api_server():
    repo_root = Path(__file__).resolve().parents[1]
    vm_dep = repo_root / "vm_deployment"
    for p in (str(repo_root), str(vm_dep)):
        if p not in sys.path:
            sys.path.insert(0, p)
    return importlib.import_module("vm_deployment.api_server")


def test_version_endpoint_and_health_expose_app_metadata(monkeypatch):
    api_server = _load_api_server()
    monkeypatch.setenv("NEXUS_APP_PRODUCT", "NEXUS")
    monkeypatch.setenv("NEXUS_APP_VERSION", "v2.6.7")
    monkeypatch.setenv("NEXUS_APP_VERSION_BASE", "2.6")
    monkeypatch.setenv("NEXUS_APP_BUILD_NUMBER", "7")
    monkeypatch.setenv("NEXUS_APP_RELEASE_DATE", "Mar 2026")
    monkeypatch.setenv("NEXUS_APP_GIT_SHA", "abc1234")
    monkeypatch.setenv("NOC_ENVIRONMENT", "dev")
    monkeypatch.setattr(api_server, "_health_check_secure_data", lambda: {"name": "secure_data", "ok": True})
    monkeypatch.setattr(api_server, "_health_check_ido_backend", lambda: {"name": "ido_backend", "ok": True})

    client = api_server.app.test_client()

    version_payload = client.get("/api/version").get_json()
    assert version_payload["success"] is True
    assert version_payload["product"] == "NEXUS"
    assert version_payload["version"] == "v2.6.7"
    assert version_payload["build_number"] == 7
    assert version_payload["git_sha"] == "abc1234"
    assert version_payload["environment"] == "dev"

    health_payload = client.get("/api/health").get_json()
    assert health_payload["status"] == "online"
    assert health_payload["app"]["version"] == "v2.6.7"
    assert health_payload["app"]["environment"] == "dev"
