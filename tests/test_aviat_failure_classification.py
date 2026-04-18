from types import SimpleNamespace
import sys
from pathlib import Path
import pytest


def _load_module():
    import importlib
    repo_root = Path(__file__).resolve().parents[1]
    vm_dep = repo_root / "vm_deployment"
    for p in (str(repo_root), str(vm_dep)):
        if p not in sys.path:
            sys.path.insert(0, p)
    return importlib.import_module("vm_deployment.api_server")


def test_transient_upgrade_error_maps_to_pending_verify_and_not_logged():
    api_server = _load_module()
    result = {
        "ip": "10.0.0.1",
        "success": False,
        "status": None,
        "error": "Socket is closed",
        "firmware_version_before": "2.11.11",
        "firmware_version_after": None,
    }
    assert api_server._aviat_status_from_result(result) == "pending_verify"
    assert api_server._aviat_should_log(result) is False


def test_terminal_non_transient_error_is_logged():
    api_server = _load_module()
    result = {
        "ip": "10.0.0.2",
        "success": False,
        "status": None,
        "error": "unsupported command sequence",
        "firmware_version_before": "2.11.11",
        "firmware_version_after": None,
    }
    assert api_server._aviat_status_from_result(result) == "error"
    assert api_server._aviat_should_log(result) is True


def test_result_dict_normalizes_transitional_status_to_non_failure():
    api_server = _load_module()
    res = SimpleNamespace(
        ip="10.0.0.3",
        success=False,
        status=None,
        firmware_downloaded=False,
        firmware_downloaded_version=None,
        firmware_scheduled=False,
        firmware_activated=False,
        password_changed=False,
        snmp_configured=False,
        buffer_configured=False,
        sop_checked=False,
        sop_passed=False,
        sop_results=[],
        subnet_ok=None,
        subnet_actual=None,
        license_ok=None,
        license_detail=None,
        stp_ok=None,
        stp_detail=None,
        firmware_version_before="2.11.11",
        firmware_version_after=None,
        error="Unable to connect to port 22",
    )
    payload = api_server._aviat_result_dict(res, username="tester")
    assert payload["status"] == "pending_verify"
    assert payload["success"] is True
    assert payload["raw_status"] is None


def test_firmware_final_check_uses_version_tuple_not_major_prefix():
    api_server = _load_module()
    assert api_server._aviat_firmware_is_final("6.2.4") is True
    assert api_server._aviat_firmware_is_final("6.3.0") is True
    assert api_server._aviat_firmware_is_final("6.1.0") is False
    assert api_server._aviat_firmware_is_final("2.11.11") is False


def test_target_version_check_handles_baseline_downgrade_exactly():
    api_server = _load_module()
    assert api_server._aviat_version_meets_target("2.11.11", "2.11.11") is True
    assert api_server._aviat_version_meets_target("6.1.0", "2.11.11") is False


def test_baseline_target_result_maps_to_success():
    api_server = _load_module()
    result = {
        "ip": "10.0.0.4",
        "success": True,
        "status": None,
        "target_version": "2.11.11",
        "firmware_version_before": "6.1.0",
        "firmware_version_after": "2.11.11",
        "password_changed": True,
        "snmp_configured": True,
        "buffer_configured": True,
        "license_ok": True,
        "stp_ok": True,
    }
    assert api_server._aviat_status_from_result(result) == "success"


def test_precheck_failure_keeps_overall_status_pending():
    api_server = _load_module()
    result = {
        "ip": "10.0.0.5",
        "success": True,
        "status": None,
        "target_version": "6.1.0",
        "firmware_version_after": "6.1.0",
        "password_changed": True,
        "snmp_configured": True,
        "buffer_configured": True,
        "license_ok": True,
        "stp_ok": True,
        "subnet_ok": False,
    }
    assert api_server._aviat_status_from_result(result) == "pending"


@pytest.mark.parametrize(
    ("result", "expected_status", "expected_firmware_status"),
    [
        (
            {
                "ip": "10.0.0.6",
                "success": True,
                "status": "loading",
                "firmware_version_before": "2.11.11",
                "firmware_version_after": None,
            },
            "loading",
            "loading",
        ),
        (
            {
                "ip": "10.0.0.7",
                "success": True,
                "status": "pending_verify",
                "firmware_version_before": "6.1.0",
                "firmware_version_after": None,
                "error": "firmware version not ready",
            },
            "pending_verify",
            "pending_verify",
        ),
        (
            {
                "ip": "10.0.0.8",
                "success": True,
                "status": "scheduled",
                "firmware_scheduled": True,
                "target_version": "6.1.0",
                "firmware_version_before": "2.11.11",
                "firmware_version_after": None,
            },
            "scheduled",
            "scheduled",
        ),
        (
            {
                "ip": "10.0.0.9",
                "success": True,
                "status": "reboot_required",
                "target_version": "6.1.0",
                "firmware_version_before": "2.11.11",
                "firmware_version_after": None,
            },
            "reboot_required",
            "pending",
        ),
        (
            {
                "ip": "10.0.0.10",
                "success": True,
                "status": None,
                "target_version": "6.1.0",
                "firmware_version_after": "6.1.0",
                "password_changed": True,
                "snmp_configured": True,
                "buffer_configured": True,
                "license_ok": True,
                "stp_ok": True,
                "subnet_ok": True,
            },
            "success",
            "success",
        ),
        (
            {
                "ip": "10.0.0.11",
                "success": True,
                "status": "precheck_failed",
                "target_version": "6.1.0",
                "firmware_version_after": "6.1.0",
                "password_changed": True,
                "snmp_configured": True,
                "buffer_configured": True,
                "license_ok": True,
                "stp_ok": True,
                "subnet_ok": False,
            },
            "pending",
            "success",
        ),
    ],
)
def test_status_matrix_maps_correctly(result, expected_status, expected_firmware_status):
    api_server = _load_module()
    api_server.aviat_shared_queue.clear()
    api_server.aviat_shared_queue.append({"ip": result["ip"], "status": "pending"})
    api_server._aviat_queue_update_from_result(result, username="tester")
    updated = api_server._aviat_queue_find(result["ip"])
    assert updated["status"] == expected_status
    assert updated["firmwareStatus"] == expected_firmware_status
