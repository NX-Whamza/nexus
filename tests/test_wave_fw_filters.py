import importlib
import sys
from pathlib import Path


def _load_module():
    repo_root = Path(__file__).resolve().parents[1]
    vm_dep = repo_root / "vm_deployment"
    for p in (str(repo_root), str(vm_dep)):
        if p not in sys.path:
            sys.path.insert(0, p)
    return importlib.import_module("vm_deployment.api_server")


def test_wave_fw_classify_role_maps_backhaul_prefix():
    api_server = _load_module()
    assert api_server._wave_fw_classify_role({"name": "BH-TOWER-LINK", "role": "station"}) == "backhaul"


def test_wave_fw_classify_role_prefers_ap_name_prefix_over_uisp_station_role():
    api_server = _load_module()
    assert api_server._wave_fw_classify_role({"name": "AP-Sector-01", "role": "station"}) == "ap"


def test_wave_fw_classify_role_treats_non_ap_non_bh_named_devices_as_station():
    api_server = _load_module()
    assert api_server._wave_fw_classify_role({"name": "Customer-SM-01", "role": ""}) == "station"


def test_wave_fw_model_family_keeps_long_range_with_nano_family():
    api_server = _load_module()
    assert api_server._wave_fw_model_family("Wave Long Range") == "nano"
