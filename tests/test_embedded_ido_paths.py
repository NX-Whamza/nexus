#!/usr/bin/env python3
from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import MethodType


repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root / "vm_deployment"))


def test_embedded_ido_backend_uses_vm_deployment_base_configs(monkeypatch):
    monkeypatch.delenv("BASE_CONFIG_PATH", raising=False)
    monkeypatch.delenv("NEXTLINK_BASE_CONFIG_PATH", raising=False)

    import ido_local_backend

    module = importlib.reload(ido_local_backend)
    assert Path(module.BASE_CONFIG_ROOT) == repo_root / "vm_deployment" / "base_configs"


def test_cn4600_standard_config_falls_back_to_embedded_standard_config(monkeypatch):
    from ido_modules.device_io import epmp_config

    monkeypatch.setattr(
        epmp_config,
        "CONF_TEMPLATE_PATH",
        str(repo_root / "vm_deployment" / "base_configs" / "Cambium"),
    )
    device = epmp_config.EPMPConfig(
        ip_address="10.0.0.1",
        device_type="CN4600",
        password="dummy",
        site_name="KS-GREENSBURG-WE-1",
        azimuth="0",
        device_number="1",
        frequency="6605",
        antenna="AL060",
        cnm_url="https://cnm4.nxlink.com/",
        latitude="37.6081",
        longitude="-99.3194",
    )

    config = device.get_standard_config()
    assert isinstance(config, dict)
    assert "device_props" in config


def test_epmp_send_configuration_accepts_empty_success_response(monkeypatch):
    from ido_modules.device_io import epmp_config

    monkeypatch.setattr(
        epmp_config,
        "CONF_TEMPLATE_PATH",
        str(repo_root / "vm_deployment" / "base_configs" / "Cambium"),
    )
    device = epmp_config.EPMPConfig(
        ip_address="10.0.0.1",
        device_type="CN4600",
        password="dummy",
        site_name="KS-GREENSBURG-WE-1",
        azimuth="0",
        device_number="1",
        frequency="6605",
        antenna="AL060",
        cnm_url="https://cnm4.nxlink.com/",
        latitude="37.6081",
        longitude="-99.3194",
    )

    class _Resp:
        status_code = 200
        text = ""
        content = b""
        headers = {"content-type": ""}

    class _Session:
        def post(self, *args, **kwargs):
            return _Resp()

    device.session = _Session()
    device.stok = "stok"
    device.mgmt_url = "https://10.0.0.1"
    device.is_logged_in = MethodType(lambda self: True, device)
    device.get_device_params = MethodType(
        lambda self, full=False, apply_status=False, **kwargs: {"template_props": {"applyFinished": 1}},
        device,
    )
    device.init_session = MethodType(lambda self, **kwargs: None, device)
    device.logout = MethodType(lambda self, **kwargs: None, device)
    device.reboot = MethodType(lambda self: None, device)

    device.send_configuration({"device_props": {"centerFrequency": "6605"}})


def test_epmp_init_and_configure_returns_pending_reboot_when_relogin_blocked(monkeypatch):
    from ido_modules.device_io import epmp_config

    monkeypatch.setattr(
        epmp_config,
        "CONF_TEMPLATE_PATH",
        str(repo_root / "vm_deployment" / "base_configs" / "Cambium"),
    )
    monkeypatch.setattr(epmp_config.time, "sleep", lambda *_args, **_kwargs: None)
    device = epmp_config.EPMPConfig(
        ip_address="10.0.0.1",
        device_type="CN4600",
        password="dummy",
        site_name="KS-GREENSBURG-WE-1",
        azimuth="0",
        device_number="1",
        frequency="6605",
        antenna="AL060",
        cnm_url="https://cnm4.nxlink.com/",
        latitude="37.6081",
        longitude="-99.3194",
    )

    device.is_logged_in = MethodType(lambda self: True, device)
    device._verify_configuration_valid = MethodType(lambda self: None, device)
    device.get_standard_config = MethodType(lambda self: {"device_props": {}}, device)
    device._configure_device_params = MethodType(lambda self, config: config["device_props"].update({"centerFrequency": "6605"}), device)
    device.send_configuration = MethodType(lambda self, config: None, device)
    device.logout = MethodType(lambda self, **kwargs: None, device)
    device.init_session = MethodType(
        lambda self, **kwargs: (_ for _ in ()).throw(self.ConfigurationInProgressError("Device configuration import is in progress.")),
        device,
    )
    device.reboot = MethodType(lambda self: None, device)

    result = device.init_and_configure()
    assert result["configuration_sent"] is True
    assert result["pending_reboot"] is True
    assert result["reboot_required"] is True
    assert result["reboot_requested"] is False


def test_ups_merge_preserves_device_specific_failure():
    from vm_deployment.ido_modules.rest.ups import _merge_generic_device_info

    merged = _merge_generic_device_info(
        {"success": False, "message": "Invalid IP address or host down."},
        {"success": True, "message": {}, "test_results": [{"name": "Ping", "pass": False}]},
    )

    assert merged["success"] is False
    assert merged["message"] == "Invalid IP address or host down."
    assert merged["test_results"] == [{"name": "Ping", "pass": False}]


def test_smartsys_device_info_extracts_sc501_fields(monkeypatch):
    from ido_modules.device_io import smart_sys_config

    monkeypatch.setattr(
        smart_sys_config.SmartSysConfig,
        "login",
        lambda self: setattr(self, "logged_in", True),
    )
    monkeypatch.setattr(
        smart_sys_config.SmartSysConfig,
        "pre_check",
        lambda self: [("SC501 Firmware", "V201", "V201", True)],
    )

    def fake_get_xml_values(self, path, params=None):
        payloads = {
            "/data/about.xml": (
                "homepage",
                {
                    "siteName": "SC501 Controller",
                    "siteID": "SITE-1",
                    "siteAddr": "123 Main",
                    "Lati": "1",
                    "LatiDegree": "39",
                    "LatiMinu": "49",
                    "LatiSec": "54",
                    "Long": "0",
                    "LongDegree": "116",
                    "LongMinu": "16",
                    "LongSec": "35",
                    "altitude": "12.0",
                },
            ),
            "/data/equipment.xml": ("EquipmentInfo", {"model": "SC501", "swVer": "V201"}),
            "/data/battbasicconfig.xml": ("BattBasicConfig", {"Batt1TotCap": "2000.0"}),
            "/data/sysconfig.xml": ("SysConfig", {"BattTyp": "0"}),
            "/data/SNMPconfig.xml": (
                "CommConfig",
                {"TrapAddr1": "132.147.132.40", "Community1": "FBZ1yYdphf", "TrapEn": "1"},
            ),
        }
        return payloads[path]

    monkeypatch.setattr(
        smart_sys_config.SmartSysConfig,
        "_get_xml_values",
        fake_get_xml_values,
    )

    result = smart_sys_config.SmartSysConfig.get_device_info(
        "10.247.199.82", "SS", password="170313", run_tests=True
    )

    assert result["success"] is True
    assert result["model"] == "SC501"
    assert result["firmware"] == "V201"
    assert result["site_name"] == "SC501 Controller"
    assert result["site_id"] == "SITE-1"
    assert result["site_address"] == "123 Main"
    assert result["battery_capacity"] == 2000.0
    assert result["battery_type"] == "lead_acid"
    assert result["trap_addr"] == "132.147.132.40"
    assert result["snmp_community"] == "FBZ1yYdphf"
    assert round(result["latitude"], 4) == 39.8317
    assert round(result["longitude"], 4) == 116.2764
    assert result["test_results"] == [
        {"name": "SC501 Firmware", "expected": "V201", "actual": "V201", "pass": True}
    ]


def test_smartsys_config_posts_live_sc501_cgi_payloads(monkeypatch):
    from ido_modules.device_io import smart_sys_config

    posted = []

    monkeypatch.setattr(
        smart_sys_config.SmartSysConfig,
        "login",
        lambda self: (
            setattr(self, "logged_in", True),
            setattr(self, "session", object()),
        ),
    )

    def fake_get_xml_values(self, path, params=None):
        payloads = {
            "/data/about.xml": (
                "homepage",
                {
                    "siteName": "OLD-SITE",
                    "siteID": "",
                    "siteAddr": "",
                    "Long": "0",
                    "LongDegree": "116",
                    "LongMinu": "16",
                    "LongSec": "35",
                    "Lati": "1",
                    "LatiDegree": "39",
                    "LatiMinu": "49",
                    "LatiSec": "54",
                    "altitude": "0.0",
                },
            ),
            "/data/battbasicconfig.xml": (
                "BattBasicConfig",
                {
                    "Batt1SulCap": "100.0",
                    "Batt1TotCap": "2000.0",
                    "Batt8TotCap": "2000.0",
                },
            ),
            "/data/SNMPconfig.xml": (
                "CommConfig",
                {
                    "TrapEn": "1",
                    "TrapAddr1": "132.147.132.40",
                    "Community1": "FBZ1yYdphf",
                },
            ),
        }
        return payloads[path]

    def fake_post_xml(self, path, data):
        posted.append((path, data.decode("iso-8859-1")))

    monkeypatch.setattr(
        smart_sys_config.SmartSysConfig,
        "_get_xml_values",
        fake_get_xml_values,
    )
    monkeypatch.setattr(
        smart_sys_config.SmartSysConfig,
        "_post_xml",
        fake_post_xml,
    )

    device = smart_sys_config.SmartSysConfig(
        ip_address="10.247.199.82",
        device_type="SS",
        password="170313",
        site_name="KS-GREENSBURG-WE-1",
        device_number="1",
        latitude="37.6081",
        longitude="-99.3194",
        battery_capacity="2000",
        trap_addr="132.147.132.40",
    )

    device.init_and_configure()

    assert device.device_name == "UPS-SS1.KS-GREENSBURG-WE-1"
    assert [path for path, _ in posted] == [
        "/data/about.cgi",
        "/data/battbasicconfig.cgi",
        "/data/commconfig.cgi",
    ]
    assert 'siteName val="KS-GREENSBURG-WE-1"' in posted[0][1]
    assert 'Long val="1"' in posted[0][1]
    assert 'Lati val="1"' in posted[0][1]
    assert 'Batt1TotCap val="2000.0"' in posted[1][1]
    assert 'Batt8TotCap val="2000.0"' in posted[1][1]
    assert 'TrapAddr1 val="132.147.132.40"' in posted[2][1]
