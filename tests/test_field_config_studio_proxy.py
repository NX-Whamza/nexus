#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi.testclient import TestClient


repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root / "vm_deployment"))

from fastapi_server import app  # noqa: E402
import fastapi_server as fastapi_server_module  # noqa: E402


client = TestClient(app)


class _FakeResponse:
    def __init__(self, status_code: int = 200, payload=None, content_type: str = "application/json"):
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.headers = {"content-type": content_type}
        if content_type.startswith("application/json"):
            self.text = json.dumps(self._payload)
        else:
            self.text = str(self._payload)

    def json(self):
        return self._payload


def test_ido_capabilities_reports_inprocess_backend():
    resp = client.get("/api/ido/capabilities")
    assert resp.status_code == 200
    body = resp.json()
    assert body["configured"] is True
    assert body["backend_url"] == "inprocess://ido-local"
    assert body["backend_health"]["ok"] is True
    assert body["backend_health"]["missing_required_modules"] == []


def test_ido_proxy_forwards_ap_standard_query_with_device_fields(monkeypatch):
    captured = {}

    def fake_get(url, params=None, timeout=None):
        captured["url"] = url
        captured["params"] = dict(params or {})
        captured["timeout"] = timeout
        return _FakeResponse(payload={"ok": True, "kind": "standard"})

    monkeypatch.setattr(fastapi_server_module, "_ido_backend_url", lambda: "http://ido-backend.local")
    monkeypatch.setattr(fastapi_server_module.requests, "get", fake_get)

    resp = client.get(
        "/api/ido/proxy/api/ap/standard_config",
        params={
            "ip_address": "10.0.0.10",
            "device_type": "CNEP3K",
            "site_name": "TX-TEST-CN-1",
            "azimuth": "90",
            "device_number": "1",
            "frequency": "5600",
            "antenna": "CN090",
            "cnm_url": "https://cnm-tx1.nxlink.com/",
            "latitude": "32.100000",
            "longitude": "-97.100000",
        },
    )

    assert resp.status_code == 200
    assert captured["url"] == "http://ido-backend.local/api/ap/standard_config"
    assert captured["params"]["frequency"] == "5600"
    assert captured["params"]["antenna"] == "CN090"
    assert captured["params"]["site_name"] == "TX-TEST-CN-1"


def test_ido_proxy_forwards_post_configure_payload(monkeypatch):
    captured = {}

    def fake_post(url, params=None, timeout=None, data=None, headers=None):
        captured["url"] = url
        captured["params"] = dict(params or {})
        captured["timeout"] = timeout
        captured["headers"] = dict(headers or {})
        captured["data"] = json.loads(data.decode("utf-8") if isinstance(data, bytes) else data)
        return _FakeResponse(payload={"success": True, "mode": "configure"})

    monkeypatch.setattr(fastapi_server_module, "_ido_backend_url", lambda: "http://ido-backend.local")
    monkeypatch.setattr(fastapi_server_module.requests, "post", fake_post)

    payload = {
        "ip_address": "10.0.0.20",
        "device_type": "NXWS12",
        "site_name": "TX-TEST-SWT-1",
        "device_number": "1",
        "latitude": "32.100000",
        "longitude": "-97.100000",
        "ap_count": "6",
        "ap_voltage": "48V",
    }
    resp = client.post("/api/ido/proxy/api/swt/configure", json=payload)

    assert resp.status_code == 200
    assert captured["url"] == "http://ido-backend.local/api/swt/configure"
    assert captured["headers"]["content-type"].startswith("application/json")
    assert captured["data"]["device_type"] == "NXWS12"
    assert captured["data"]["ap_voltage"] == "48V"


def test_ido_proxy_rejects_configure_when_backend_missing(monkeypatch):
    monkeypatch.setattr(fastapi_server_module, "_ido_backend_url", lambda: "")
    monkeypatch.setattr(fastapi_server_module, "_ido_inprocess_module", lambda: None)
    resp = client.post("/api/ido/proxy/api/ap/configure", json={"device_type": "CNEP3K"})
    assert resp.status_code == 503
    assert "Embedded fallback supports only /api/ping and /api/generic/device_info" in resp.json()["detail"]
