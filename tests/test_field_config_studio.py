#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path


repo_root = Path(__file__).resolve().parents[1]
UI_FILE = repo_root / "vm_deployment" / "NOC-configMaker.html"
AP_FILE = repo_root / "vm_deployment" / "ido_modules" / "rest" / "ap.py"
SWITCH_FILE = repo_root / "vm_deployment" / "ido_modules" / "rest" / "switch.py"
UPS_FILE = repo_root / "vm_deployment" / "ido_modules" / "rest" / "ups.py"
RPC_FILE = repo_root / "vm_deployment" / "ido_modules" / "rest" / "rpc.py"
LOCAL_BACKEND_FILE = repo_root / "vm_deployment" / "ido_local_backend.py"


def test_field_config_studio_ui_has_dynamic_device_forms_and_no_aviat():
    content = UI_FILE.read_text(encoding="utf-8")
    assert 'data-tool="aviat-bh"' not in content
    assert 'id="fieldConfigDynamicFields"' in content
    assert "FIELD_CONFIG_DEVICE_PROFILES" in content
    assert "renderFieldConfigDynamicFields" in content
    assert "buildFieldConfigBasePayload" in content
    assert "api/ap/configure" in content
    assert "api/swt/configure" in content
    assert "api/ups/configure" in content
    assert "api/rpc/configure" in content
    assert "CNEP3KL" in content
    assert "F4600C" in content
    assert "ICTMPS" in content


def test_field_config_studio_backend_routes_and_aliases_exist():
    ap_text = AP_FILE.read_text(encoding="utf-8")
    switch_text = SWITCH_FILE.read_text(encoding="utf-8")
    ups_text = UPS_FILE.read_text(encoding="utf-8")
    rpc_text = RPC_FILE.read_text(encoding="utf-8")
    local_backend_text = LOCAL_BACKEND_FILE.read_text(encoding="utf-8")

    assert '@app.post("/api/ap/configure")' in ap_text
    assert 'DEVICE_TYPE_ALIASES' in ap_text
    assert '"CNF300-13": "F300-13"' in ap_text
    assert '"CNEP3KL": "CN"' in ap_text
    assert '"F4600C": "CN"' in ap_text
    assert '@app.post("/api/swt/configure")' in switch_text
    assert '@app.post("/api/ups/configure")' in ups_text
    assert '"ICTMPS": "ICT"' in ups_text
    assert 'elif oem == "ICT":' in ups_text
    assert '@app.post("/api/rpc/configure")' in rpc_text
    assert '"ICT200DB12": "ICT"' in rpc_text
    assert '/api/ap/configure' in local_backend_text
    assert '/api/swt/configure' in local_backend_text
    assert '/api/ups/configure' in local_backend_text
    assert '/api/rpc/configure' in local_backend_text
