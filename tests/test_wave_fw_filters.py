import importlib
import sys
from pathlib import Path
import tempfile


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


def test_wave_fw_model_family_keeps_wave_pro_with_ap_family():
    api_server = _load_module()
    assert api_server._wave_fw_model_family("Wave Pro") == "ap"


def test_wave_fw_model_family_keeps_wave_ap_micro_with_ap_family():
    api_server = _load_module()
    assert api_server._wave_fw_model_family("Wave-AP-Micro") == "ap"


def test_wave_fw_model_family_keeps_wave_ap_without_spaces_with_ap_family():
    api_server = _load_module()
    assert api_server._wave_fw_model_family("WaveAP") == "ap"


def test_wave_fw_select_firmware_uses_ap_family_file_for_wave_pro():
    api_server = _load_module()
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "wave-ap-micro-pro-v4.1.0.bin").write_bytes(b"ap")
        (root / "wave-nano-lr-pico-v4.1.0.bin").write_bytes(b"nano")
        chosen = api_server._wave_fw_select_firmware("Wave Pro", root)
        assert chosen is not None
        assert chosen.name == "wave-ap-micro-pro-v4.1.0.bin"


def test_wave_fw_select_firmware_uses_nano_family_file_for_wave_lr():
    api_server = _load_module()
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        (root / "wave-ap-micro-pro-v4.1.0.bin").write_bytes(b"ap")
        (root / "wave-nano-lr-pico-v4.1.0.bin").write_bytes(b"nano")
        chosen = api_server._wave_fw_select_firmware("Wave-LR", root)
        assert chosen is not None
        assert chosen.name == "wave-nano-lr-pico-v4.1.0.bin"
