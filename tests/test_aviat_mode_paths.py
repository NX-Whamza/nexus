from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import SimpleNamespace


def _load_modules():
    repo_root = Path(__file__).resolve().parents[1]
    vm_dep = repo_root / "vm_deployment"
    for p in (str(repo_root), str(vm_dep)):
        if p not in sys.path:
            sys.path.insert(0, p)
    aviat_config = importlib.import_module("vm_deployment.aviat_config")
    api_server = importlib.import_module("vm_deployment.api_server")
    return aviat_config, api_server


def test_immediate_upgrade_waits_for_baseline_before_final(monkeypatch):
    aviat_config, _ = _load_modules()
    events = []
    version_reads = iter(["2.10.0", "2.11.11", "6.1.0", "6.1.0", "6.1.0", "6.1.0"])

    class FakeClient:
        def __init__(self, ip, username, password, port=22):
            self.ip = ip
            self.output_buffer = []

        def connect(self):
            events.append("connect")
            return True

        def close(self):
            events.append("close")

    monkeypatch.setattr(aviat_config, "AviatSSHClient", FakeClient)
    monkeypatch.setattr(aviat_config, "check_subnet_mask", lambda client: (True, "255.255.255.248"))
    monkeypatch.setattr(aviat_config, "check_license_bundles", lambda client: (True, "licensed"))
    monkeypatch.setattr(aviat_config, "check_stp_disabled", lambda client: (True, "disabled"))
    monkeypatch.setattr(aviat_config, "get_inactive_firmware_version", lambda client, callback=None: None)
    monkeypatch.setattr(aviat_config, "get_uptime_days", lambda client, callback=None: 10)
    monkeypatch.setattr(
        aviat_config,
        "get_firmware_version",
        lambda client, callback=None: next(version_reads),
    )

    def fake_trigger(client, uri, activation_time, activate_now, activation_mode, callback=None):
        if uri == aviat_config.CONFIG.firmware_baseline_uri:
            events.append("trigger_baseline")
        elif uri == aviat_config.CONFIG.firmware_final_uri:
            events.append("trigger_final")
        else:
            events.append(f"trigger:{uri}")
        return True, "Firmware download started"

    monkeypatch.setattr(aviat_config, "trigger_firmware_download", fake_trigger)

    def fake_wait(ip, username, password, fallback_password=None, callback=None, initial_delay=0, **kwargs):
        events.append("wait")
        return FakeClient(ip, username, password)

    monkeypatch.setattr(aviat_config, "wait_for_device_ready_and_reconnect", fake_wait)

    result = aviat_config.process_radio(
        "10.0.0.10",
        ["firmware"],
        maintenance_params={
            "activation_mode": "immediate",
            "activate_now": True,
            "firmware_target": "final",
        },
    )

    assert result.success is True
    assert result.error is None
    assert result.firmware_version_after == "6.1.0"
    assert events.index("trigger_baseline") < events.index("wait") < events.index("trigger_final")
    assert events.count("wait") == 2


def test_check_status_uses_queue_target_version_for_downgrade(monkeypatch):
    _, api_server = _load_modules()
    client = api_server.app.test_client()

    monkeypatch.setattr(
        api_server,
        "aviat_check_device_status",
        lambda ip: {
            "ip": ip,
            "reachable": True,
            "firmware": "2.11.11",
            "snmp_ok": True,
            "buffer_ok": True,
            "license_ok": True,
            "license_detail": "licensed",
            "stp_ok": True,
            "stp_detail": "disabled",
            "subnet_ok": True,
            "subnet_actual": "255.255.255.248",
            "error": None,
        },
    )

    api_server.aviat_shared_queue.clear()
    api_server.aviat_shared_queue.append(
        {"ip": "10.0.0.20", "status": "pending", "targetVersion": "2.11.11"}
    )

    response = client.post("/api/aviat/check-status", json={"ips": ["10.0.0.20"]})
    assert response.status_code == 200
    updated = api_server._aviat_queue_find("10.0.0.20")
    assert updated["status"] == "success"
    assert updated["firmwareStatus"] == "success"
    assert updated["targetVersion"] == "2.11.11"


def test_immediate_upgrade_exits_early_when_firmware_already_loading(monkeypatch):
    aviat_config, _ = _load_modules()

    class FakeClient:
        def __init__(self, ip, username, password, port=22):
            self.ip = ip
            self.output_buffer = []

        def connect(self):
            return True

        def close(self):
            return True

    monkeypatch.setattr(aviat_config, "AviatSSHClient", FakeClient)
    monkeypatch.setattr(aviat_config, "check_subnet_mask", lambda client: (True, "255.255.255.248"))
    monkeypatch.setattr(aviat_config, "check_license_bundles", lambda client: (True, "licensed"))
    monkeypatch.setattr(aviat_config, "check_stp_disabled", lambda client: (True, "disabled"))
    monkeypatch.setattr(aviat_config, "get_inactive_firmware_version", lambda client, callback=None: "2.11.10")
    monkeypatch.setattr(aviat_config, "get_uptime_days", lambda client, callback=None: 10)
    monkeypatch.setattr(aviat_config, "get_firmware_version", lambda client, callback=None: "2.11.11")

    def fake_trigger(client, uri, activation_time, activate_now, activation_mode, callback=None):
        return False, "Firmware download failed: resp Software operation already in progress.  Load not started."

    monkeypatch.setattr(aviat_config, "trigger_firmware_download", fake_trigger)
    monkeypatch.setattr(
        aviat_config,
        "configure_snmp",
        lambda client, callback=None: (_ for _ in ()).throw(AssertionError("snmp should not run")),
    )
    monkeypatch.setattr(
        aviat_config,
        "configure_buffer",
        lambda client, callback=None: (_ for _ in ()).throw(AssertionError("buffer should not run")),
    )

    result = aviat_config.process_radio(
        "10.0.0.30",
        ["firmware", "snmp", "buffer", "sop"],
        maintenance_params={
            "activation_mode": "immediate",
            "activate_now": True,
            "firmware_target": "final",
        },
    )

    assert result.success is True
    assert result.status == "loading"


def test_immediate_downgrade_activates_inactive_baseline(monkeypatch):
    aviat_config, _ = _load_modules()
    events = []
    version_reads = iter(["6.1.0", "2.11.11", "2.11.11"])

    class FakeClient:
        def __init__(self, ip, username, password, port=22):
            self.ip = ip
            self.output_buffer = []

        def connect(self):
            return True

        def close(self):
            events.append("close")
            return True

    monkeypatch.setattr(aviat_config, "AviatSSHClient", FakeClient)
    monkeypatch.setattr(aviat_config, "check_subnet_mask", lambda client: (True, "255.255.255.248"))
    monkeypatch.setattr(aviat_config, "check_license_bundles", lambda client: (True, "licensed"))
    monkeypatch.setattr(aviat_config, "check_stp_disabled", lambda client: (True, "disabled"))
    monkeypatch.setattr(aviat_config, "get_uptime_days", lambda client, callback=None: 10)
    monkeypatch.setattr(aviat_config, "get_inactive_firmware_version", lambda client, callback=None: "2.11.11")
    monkeypatch.setattr(
        aviat_config,
        "get_firmware_version",
        lambda client, callback=None: next(version_reads),
    )
    def fake_wait(ip, username, password, fallback_password=None, callback=None, initial_delay=0, **kwargs):
        events.append("wait")
        return FakeClient(ip, username, password)

    monkeypatch.setattr(aviat_config, "wait_for_device_ready_and_reconnect", fake_wait)
    def fake_trigger(client, uri, activation_time, activate_now, activation_mode, callback=None):
        events.append(("trigger", uri, activate_now, activation_mode))
        return True, "Firmware download started"

    monkeypatch.setattr(aviat_config, "trigger_firmware_download", fake_trigger)

    result = aviat_config.process_radio(
        "10.0.0.40",
        ["firmware"],
        maintenance_params={
            "activation_mode": "immediate",
            "activate_now": True,
            "firmware_target": "baseline",
        },
    )

    assert result.success is True
    assert result.firmware_version_after == "2.11.11"
    assert any(event[0] == "trigger" and event[1] == aviat_config.CONFIG.firmware_baseline_uri for event in events if isinstance(event, tuple))
    assert "wait" in events


def test_activate_firmware_enters_config_mode(monkeypatch):
    aviat_config, _ = _load_modules()
    commands = []

    class FakeClient:
        ip = "10.0.0.50"

        def send_command(self, command, wait_for=None, timeout=5.0):
            commands.append(command)
            if command == "config terminal":
                return "Entering configuration mode terminal\nhost(config)#"
            if command == "software activate":
                return "Resp activating new software now"
            if command == "exit":
                return "host#"
            if command == "restart":
                return "Restarting"
            if command == "show software-status status":
                return "software-status status activate"
            return ""

    result = aviat_config.activate_firmware(FakeClient())

    assert result[0] is True
    assert commands[:2] == ["config terminal", "software activate"]


def test_rollback_firmware_uses_rollback_and_status(monkeypatch):
    aviat_config, _ = _load_modules()
    commands = []

    class FakeClient:
        ip = "10.0.0.51"

        def send_command(self, command, wait_for=None, timeout=5.0):
            commands.append(command)
            if command == "config terminal":
                return "Entering configuration mode terminal\nhost(config)#"
            if command == "software rollback":
                return "resp ok"
            if command == "exit":
                return "host#"
            if command == "show software-status status":
                return "software-status status rollback"
            return ""

    result = aviat_config.rollback_firmware(FakeClient())

    assert result[0] is True
    assert commands[:2] == ["config terminal", "software rollback"]


def test_trigger_firmware_download_falls_back_to_config_mode_and_clears_error(monkeypatch):
    aviat_config, _ = _load_modules()
    commands = []

    class FakeClient:
        ip = "10.0.0.52"

        def send_command(self, command, wait_for=None, timeout=5.0):
            commands.append(command)
            if command == "show software-status status":
                if commands.count("show software-status status") == 1:
                    return "software-status status rollbackError"
                return "software-status status prepareLoad"
            if command == "config terminal":
                return "Entering configuration mode terminal\nhost(config)#"
            if command == "software abort":
                return "resp Software load aborted."
            if command.startswith("software load uri "):
                if commands.count(command) == 1:
                    return "syntax error: expecting"
                return "resp Loading started with automatic activation."
            if command == "exit":
                return "host#"
            return ""

    ok, msg = aviat_config.trigger_firmware_download(
        FakeClient(),
        aviat_config.CONFIG.firmware_baseline_uri,
        activation_time=None,
        activate_now=True,
        activation_mode="immediate",
    )

    assert ok is True
    assert msg == "Firmware download started"
    assert commands[:3] == ["show software-status status", "config terminal", "software abort"]
    assert commands.count("config terminal") >= 2


def test_resume_remaining_tasks_runs_deferred_steps(monkeypatch):
    _, api_server = _load_modules()
    events = []

    monkeypatch.setattr(
        api_server,
        "aviat_process_radio",
        lambda ip, tasks, callback=None, maintenance_params=None: (
            events.append((ip, tuple(tasks), maintenance_params.get("activation_mode")))
            or SimpleNamespace(
                ip=ip,
                success=True,
                status="success",
                firmware_downloaded=False,
                firmware_downloaded_version=None,
                firmware_scheduled=False,
                firmware_activated=False,
                password_changed=False,
                snmp_configured=True,
                buffer_configured=True,
                sop_checked=True,
                sop_passed=True,
                sop_results=[],
                subnet_ok=True,
                subnet_actual="255.255.255.248",
                license_ok=True,
                license_detail="licensed",
                stp_ok=True,
                stp_detail="disabled",
                target_version="6.1.0",
                firmware_version_before="6.1.0",
                firmware_version_after="6.1.0",
                error=None,
                output=[],
                duration=0.0,
            )
        ),
    )

    entry = {
        "ip": "10.0.0.60",
        "remaining_tasks": ["snmp", "buffer", "sop"],
        "maintenance_params": {"activation_mode": "immediate", "firmware_target": "final"},
        "username": "tester",
    }

    result = api_server._aviat_resume_remaining_tasks(entry)

    assert result is not None
    assert result.success is True
    assert events == [("10.0.0.60", ("snmp", "buffer", "sop"), "immediate")]
