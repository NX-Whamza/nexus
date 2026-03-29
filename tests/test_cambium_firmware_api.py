#!/usr/bin/env python3
"""Regression tests for Cambium firmware updater backend APIs."""

from __future__ import annotations

import os
import shutil
import sys
import time
from pathlib import Path

from fastapi.testclient import TestClient
import pytest


repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root / "vm_deployment"))

os.environ.setdefault("NEXTLINK_RADIUS_SECRET", "TEST_RADIUS_SECRET")

from fastapi_server import app  # noqa: E402
import api_server  # noqa: E402
from cambium_firmware import list_firmware_catalog, resolve_firmware_image, resolve_device_type  # noqa: E402


client = TestClient(app)


def test_cambium_catalog_scans_images_and_picks_latest(monkeypatch):
    artifacts_root = repo_root / "tests_artifacts"
    artifacts_root.mkdir(exist_ok=True)
    firmware_root = artifacts_root / "cambium-firmware-catalog"
    if firmware_root.exists():
        shutil.rmtree(firmware_root)
    try:
        ep3k_dir = firmware_root / "Cambium" / "EP3K"
        ep3k_dir.mkdir(parents=True)
        (ep3k_dir / "ePMP-AC-v5.10.1.img").write_bytes(b"old")
        (ep3k_dir / "ePMP-AC-v5.10.4.img").write_bytes(b"new")

        monkeypatch.setenv("FIRMWARE_PATH", str(firmware_root))

        catalog = list_firmware_catalog()
        assert catalog["devices"]["CNEP3K"]["default_version"] == "5.10.4"
        assert catalog["devices"]["CNEP3K"]["available_versions"] == ["5.10.4", "5.10.1"]

        selected = resolve_firmware_image("CNEP3K")
        assert selected["version"] == "5.10.4"
        pinned = resolve_firmware_image("CNEP3K", "5.10.1")
        assert pinned["filename"] == "ePMP-AC-v5.10.1.img"
    finally:
        if firmware_root.exists():
            shutil.rmtree(firmware_root)


def test_cambium_device_info_updates_queue(monkeypatch):
    monkeypatch.setattr(api_server, "HAS_CAMBIUM", True)
    api_server.cambium_shared_queue.clear()

    def fake_device_info(ip, device_type, password=None, run_tests=True):
        return {
            "success": True,
            "test_results": [
                {"name": "Firmware Version", "actual": "5.10.4", "expected": "5.10.4", "pass": True}
            ],
            "running_config": "ok",
            "standard_config": "{}",
        }

    monkeypatch.setattr(api_server, "cambium_get_device_info", fake_device_info)
    monkeypatch.setattr(api_server, "cambium_resolve_device_type", lambda value: "CNEP3K")

    r = client.post(
        "/api/cambium/device-info",
        json={"ip": "10.10.10.10", "device_type": "CNEP3K", "password": "secret"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    assert body["firmware_version"] == "5.10.4"

    queue_body = client.get("/api/cambium/queue").json()
    assert queue_body["radios"][0]["firmwareVersion"] == "5.10.4"
    assert queue_body["radios"][0]["deviceType"] == "CNEP3K"


def test_cambium_run_completes_and_updates_status(monkeypatch):
    monkeypatch.setattr(api_server, "HAS_CAMBIUM", True)
    api_server.cambium_shared_queue.clear()
    api_server.cambium_tasks.clear()
    api_server.cambium_log_queues.clear()
    captured = {}

    def fake_device_info(ip, device_type, password=None, run_tests=True):
        return {
            "success": True,
            "test_results": [
                {"name": "Firmware Version", "actual": "5.10.1", "expected": "5.10.4", "pass": False}
            ],
        }

    def fake_update_device(ip, device_type, username=None, password=None, update_version=None, callback=None):
        captured["username"] = username
        captured["password"] = password
        if callback:
            callback(f"[{ip}] Firmware uploaded.")
            callback(f"[{ip}] Device updated.")
        return {
            "success": True,
            "ip": ip,
            "device_type": device_type,
            "target_version": update_version or "5.10.4",
            "selected_image": "ePMP-AC-v5.10.4.img",
        }

    monkeypatch.setattr(api_server, "cambium_get_device_info", fake_device_info)
    monkeypatch.setattr(api_server, "cambium_update_device", fake_update_device)
    monkeypatch.setattr(api_server, "cambium_resolve_device_type", lambda value: "CNEP3K")

    r = client.post(
        "/api/cambium/run",
        json={
            "ips": ["10.20.30.40"],
            "device_type": "CNEP3K",
            "update_version": "5.10.4",
            "password": "secret",
            "username": "tester",
            "requested_by": "frontend-user",
        },
    )
    assert r.status_code == 200
    task_id = r.json()["task_id"]

    deadline = time.time() + 3
    final_status = None
    while time.time() < deadline:
        status_resp = client.get(f"/api/cambium/status/{task_id}")
        assert status_resp.status_code == 200
        final_status = status_resp.json()
        if final_status["status"] == "completed":
            break
        time.sleep(0.05)

    assert final_status is not None
    assert final_status["status"] == "completed"
    assert final_status["username"] == "frontend-user"
    assert final_status["results"][0]["status"] == "success"
    assert final_status["results"][0]["selected_image"] == "ePMP-AC-v5.10.4.img"
    assert captured == {"username": "tester", "password": "secret"}

    queue_body = client.get("/api/cambium/queue").json()
    assert queue_body["radios"][0]["status"] == "success"
    assert queue_body["radios"][0]["targetVersion"] == "5.10.4"
    assert queue_body["radios"][0]["username"] == "frontend-user"


def test_cambium_run_requested_by_does_not_override_device_login_username(monkeypatch):
    monkeypatch.setattr(api_server, "HAS_CAMBIUM", True)
    api_server.cambium_shared_queue.clear()
    api_server.cambium_tasks.clear()
    api_server.cambium_log_queues.clear()
    captured = {}

    def fake_device_info(ip, device_type, password=None, run_tests=True):
        return {"success": True, "test_results": []}

    def fake_update_device(ip, device_type, username=None, password=None, update_version=None, callback=None):
        captured["username"] = username
        captured["password"] = password
        return {
            "success": True,
            "ip": ip,
            "device_type": device_type,
            "target_version": update_version or "5.10.4",
            "selected_image": "ePMP-AC-v5.10.4.img",
        }

    monkeypatch.setattr(api_server, "cambium_get_device_info", fake_device_info)
    monkeypatch.setattr(api_server, "cambium_update_device", fake_update_device)
    monkeypatch.setattr(api_server, "cambium_resolve_device_type", lambda value: "CNEP3K")

    r = client.post(
        "/api/cambium/run",
        json={
            "ips": ["10.20.30.41"],
            "device_type": "CNEP3K",
            "update_version": "5.10.4",
            "password": "secret",
            "requested_by": "frontend-user",
        },
    )
    assert r.status_code == 200
    task_id = r.json()["task_id"]

    deadline = time.time() + 3
    final_status = None
    while time.time() < deadline:
        status_resp = client.get(f"/api/cambium/status/{task_id}")
        assert status_resp.status_code == 200
        final_status = status_resp.json()
        if final_status["status"] == "completed":
            break
        time.sleep(0.05)

    assert final_status is not None
    assert final_status["status"] == "completed"
    assert final_status["username"] == "frontend-user"
    assert captured == {"username": None, "password": "secret"}


def test_cambium_resolve_device_type_aliases():
    # Only AP types — canonical names pass through unchanged
    assert resolve_device_type("CNEP3K") == "CNEP3K"
    assert resolve_device_type("CNEP3KL") == "CNEP3KL"
    assert resolve_device_type("CN4600") == "CN4600"
    # removed device types now raise
    with pytest.raises(ValueError, match="Unsupported Cambium device_type"):
        resolve_device_type("F4600C")
    with pytest.raises(ValueError, match="Unsupported Cambium device_type"):
        resolve_device_type("F300-13")
    with pytest.raises(ValueError, match="Unsupported Cambium device_type"):
        resolve_device_type("BOGUS")
    with pytest.raises(ValueError, match="device_type is required"):
        resolve_device_type("")


def test_cambium_catalog_endpoint(monkeypatch):
    monkeypatch.setattr(api_server, "HAS_CAMBIUM", True)
    monkeypatch.setattr(
        api_server,
        "cambium_list_firmware_catalog",
        lambda: {
            "firmware_root": "/fake",
            "default_username": "admin",
            "default_password_configured": True,
            "devices": {
                "CNEP3K": {
                    "device_type": "CNEP3K", "family": "EP3K",
                    "label": "Cambium ePMP 3000",
                    "default_version": "5.10.4",
                    "available_versions": ["5.10.4"], "images": [],
                },
                "CNEP3KL": {
                    "device_type": "CNEP3KL", "family": "EP3K",
                    "label": "Cambium ePMP 3000 Lite",
                    "default_version": "5.10.4",
                    "available_versions": ["5.10.4"], "images": [],
                },
                "CN4600": {
                    "device_type": "CN4600", "family": "4600",
                    "label": "Cambium ePMP 4600",
                    "default_version": "5.10.4",
                    "available_versions": ["5.10.4"], "images": [],
                },
            },
        },
    )
    r = client.get("/api/cambium/catalog")
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    assert set(body["devices"].keys()) == {"CNEP3K", "CNEP3KL", "CN4600"}
    assert body["devices"]["CNEP3K"]["default_version"] == "5.10.4"


def test_cambium_check_status_updates_queue(monkeypatch):
    monkeypatch.setattr(api_server, "HAS_CAMBIUM", True)
    api_server.cambium_shared_queue.clear()

    def fake_device_info(ip, device_type, password=None, run_tests=True):
        return {
            "success": True,
            "test_results": [
                {"name": "Firmware Version", "actual": "5.10.1", "expected": "5.10.4", "pass": False}
            ],
        }

    monkeypatch.setattr(api_server, "cambium_get_device_info", fake_device_info)
    monkeypatch.setattr(api_server, "cambium_resolve_device_type", lambda value: "CNEP3K")

    r = client.post(
        "/api/cambium/check-status",
        json={"ips": ["10.1.1.1", "10.1.1.2"], "device_type": "CNEP3K", "password": "secret"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    assert len(body["results"]) == 2
    ips_returned = {res["ip"] for res in body["results"]}
    assert ips_returned == {"10.1.1.1", "10.1.1.2"}

    # Both IPs should appear in the shared queue
    queue_ips = {entry["ip"] for entry in api_server.cambium_shared_queue}
    assert "10.1.1.1" in queue_ips
    assert "10.1.1.2" in queue_ips


def test_cambium_check_status_rejects_empty(monkeypatch):
    monkeypatch.setattr(api_server, "HAS_CAMBIUM", True)
    r = client.post("/api/cambium/check-status", json={})
    assert r.status_code == 400


def test_cambium_queue_post_replace_add_remove(monkeypatch):
    monkeypatch.setattr(api_server, "HAS_CAMBIUM", True)
    monkeypatch.setattr(api_server, "cambium_resolve_device_type", lambda value: "CNEP3K")
    api_server.cambium_shared_queue.clear()

    # replace mode — clears and rebuilds
    r = client.post(
        "/api/cambium/queue",
        json={
            "mode": "replace",
            "ips": ["10.0.0.1", "10.0.0.2"],
            "device_type": "CNEP3K",
            "update_version": "5.10.4",
            "requested_by": "test-user",
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body["radios"]) == 2
    assert all(e["deviceType"] == "CNEP3K" for e in body["radios"])

    # add mode — preserves existing and appends new
    r = client.post(
        "/api/cambium/queue",
        json={
            "mode": "add",
            "ips": ["10.0.0.3"],
            "device_type": "CNEP3K",
            "update_version": "5.10.4",
            "requested_by": "test-user",
        },
    )
    assert r.status_code == 200
    queue_ips = {e["ip"] for e in r.json()["radios"]}
    assert {"10.0.0.1", "10.0.0.2", "10.0.0.3"} == queue_ips

    # remove mode — deletes specific IP
    r = client.post(
        "/api/cambium/queue",
        json={
            "mode": "remove",
            "ips": ["10.0.0.2"],
            "device_type": "CNEP3K",
        },
    )
    assert r.status_code == 200
    queue_ips = {e["ip"] for e in r.json()["radios"]}
    assert "10.0.0.2" not in queue_ips
    assert "10.0.0.1" in queue_ips
    assert "10.0.0.3" in queue_ips


def test_cambium_run_rejects_missing_radios(monkeypatch):
    monkeypatch.setattr(api_server, "HAS_CAMBIUM", True)
    r = client.post("/api/cambium/run", json={"device_type": "CNEP3K"})
    assert r.status_code == 400
