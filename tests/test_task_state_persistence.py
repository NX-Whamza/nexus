from __future__ import annotations

import importlib
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
import shutil


def _load_api_server():
    repo_root = Path(__file__).resolve().parents[1]
    vm_dep = repo_root / "vm_deployment"
    for p in (str(repo_root), str(vm_dep)):
        if p not in sys.path:
            sys.path.insert(0, p)
    return importlib.import_module("vm_deployment.api_server")


def test_aviat_status_abort_and_stream_work_from_persisted_store(monkeypatch):
    api_server = _load_api_server()
    task_root = Path(__file__).resolve().parents[1] / "tests_artifacts" / "task_store_aviat"
    shutil.rmtree(task_root, ignore_errors=True)
    task_root.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(api_server, "HAS_AVIAT", True)
    monkeypatch.setattr(api_server, "ensure_secure_data_dir", lambda: task_root)
    monkeypatch.setattr(api_server, "verify_token", lambda token: {"user_id": "user-a", "email": "a@example.com", "tenant_id": None, "tenantId": None} if token == "test-token" else None)
    api_server._BACKGROUND_TASK_STORE_DIR = None
    api_server.aviat_tasks.clear()
    api_server.aviat_log_queues.clear()

    task_id = "aviat-persisted"
    api_server._background_task_persist(
        "aviat",
        task_id,
        {
            "task_id": task_id,
            "status": "running",
            "ips": ["10.0.0.1"],
            "results": [],
            "abort": False,
        },
    )
    api_server._background_task_append_log(
        "aviat",
        task_id,
        {"message": "persisted log line", "level": "info", "task_id": task_id},
    )

    client = api_server.app.test_client()

    headers = {"Authorization": "Bearer test-token"}

    status_resp = client.get(f"/api/aviat/status/{task_id}", headers=headers)
    assert status_resp.status_code == 200
    assert status_resp.get_json()["status"] == "running"

    abort_resp = client.post(f"/api/aviat/abort/{task_id}", headers=headers)
    assert abort_resp.status_code == 200
    assert api_server._background_task_has_abort("aviat", task_id) is True

    stream_resp = client.get(f"/api/aviat/stream/{task_id}?token=test-token")
    assert stream_resp.status_code == 200
    body = stream_resp.get_data(as_text=True)
    assert "persisted log line" in body


def test_cambium_status_and_abort_work_from_persisted_store(monkeypatch):
    api_server = _load_api_server()
    task_root = Path(__file__).resolve().parents[1] / "tests_artifacts" / "task_store_cambium"
    shutil.rmtree(task_root, ignore_errors=True)
    task_root.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(api_server, "HAS_CAMBIUM", True)
    monkeypatch.setattr(api_server, "ensure_secure_data_dir", lambda: task_root)
    monkeypatch.setattr(api_server, "verify_token", lambda token: {"user_id": "user-a", "email": "a@example.com", "tenant_id": None, "tenantId": None} if token == "test-token" else None)
    api_server._BACKGROUND_TASK_STORE_DIR = None
    api_server.cambium_tasks.clear()
    api_server.cambium_log_queues.clear()

    task_id = "cambium-persisted"
    api_server._background_task_persist(
        "cambium",
        task_id,
        {
            "task_id": task_id,
            "status": "running",
            "radios": [{"ip": "10.0.0.2"}],
            "results": [],
            "abort": False,
        },
    )

    client = api_server.app.test_client()

    headers = {"Authorization": "Bearer test-token"}

    status_resp = client.get(f"/api/cambium/status/{task_id}", headers=headers)
    assert status_resp.status_code == 200
    assert status_resp.get_json()["status"] == "running"

    abort_resp = client.post(f"/api/cambium/abort/{task_id}", headers=headers)
    assert abort_resp.status_code == 200
    assert api_server._background_task_has_abort("cambium", task_id) is True


def test_background_task_helpers_list_tasks_and_recent_logs(monkeypatch):
    api_server = _load_api_server()
    task_root = Path(__file__).resolve().parents[1] / "tests_artifacts" / "task_store_helpers"
    shutil.rmtree(task_root, ignore_errors=True)
    task_root.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(api_server, "ensure_secure_data_dir", lambda: task_root)
    api_server._BACKGROUND_TASK_STORE_DIR = None
    api_server._BACKGROUND_TASK_DB_PATH = None

    api_server._background_task_persist(
        "wave_fw",
        "task-1",
        {"task_id": "task-1", "status": "completed", "created_at": "2026-01-01T00:00:00Z"},
    )
    api_server._background_task_persist(
        "wave_fw",
        "task-2",
        {"task_id": "task-2", "status": "running", "created_at": "2026-01-02T00:00:00Z"},
    )
    api_server._background_task_append_log(
        "aviat",
        "task-a",
        {"message": "first", "level": "info", "ts": "2026-01-01T00:00:00Z"},
    )
    api_server._background_task_append_log(
        "aviat",
        "task-b",
        {"message": "second", "level": "warning", "ts": "2026-01-02T00:00:00Z"},
    )

    listed = api_server._background_task_list("wave_fw", limit=10)
    assert [item["task_id"] for item in listed[:2]] == ["task-2", "task-1"]

    logs = api_server._background_task_recent_logs("aviat", limit=10)
    assert [entry["message"] for entry in logs] == ["first", "second"]

    db_path = task_root / "background_tasks.db"
    assert db_path.exists()


def test_background_task_cleanup_stale_removes_completed_records(monkeypatch):
    api_server = _load_api_server()
    task_root = Path(__file__).resolve().parents[1] / "tests_artifacts" / "task_store_cleanup"
    shutil.rmtree(task_root, ignore_errors=True)
    task_root.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(api_server, "ensure_secure_data_dir", lambda: task_root)
    api_server._BACKGROUND_TASK_STORE_DIR = None
    api_server._BACKGROUND_TASK_DB_PATH = None

    api_server._background_task_persist(
        "wave_fw",
        "old-task",
        {
            "task_id": "old-task",
            "status": "completed",
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
            "completed_at": "2026-01-01T00:00:00Z",
        },
    )
    api_server._background_task_append_log(
        "wave_fw",
        "old-task",
        {"message": "old log", "timestamp": "2026-01-01T00:00:00Z"},
    )

    future_now = datetime.now(timezone.utc) + timedelta(days=2)
    monkeypatch.setattr(api_server, "get_utc_now", lambda: future_now)

    api_server._background_task_cleanup_stale(ttl_seconds=3600)

    assert api_server._background_task_load("wave_fw", "old-task") is None
    assert api_server._background_task_recent_logs("wave_fw", limit=10) == []


def test_aviat_queue_is_tenant_scoped(monkeypatch):
    api_server = _load_api_server()
    monkeypatch.setattr(api_server, "HAS_AVIAT", True)

    def _verify_token(token):
        if token == "tenant-a":
            return {"user_id": "user-a", "email": "a@example.com", "tenant_id": "tenant-a", "tenantId": "tenant-a"}
        if token == "tenant-b":
            return {"user_id": "user-b", "email": "b@example.com", "tenant_id": "tenant-b", "tenantId": "tenant-b"}
        return None

    monkeypatch.setattr(api_server, "verify_token", _verify_token)
    monkeypatch.setattr(
        api_server,
        "_get_request_tenant_context",
        lambda: {
            "user": None,
            "tenant": {
                "id": (getattr(api_server.request, "current_user", {}) or {}).get("tenant_id"),
                "slug": f"slug-{(getattr(api_server.request, 'current_user', {}) or {}).get('tenant_id')}",
            },
        },
    )
    api_server.aviat_shared_queue.clear()

    client = api_server.app.test_client()
    headers_a = {"Authorization": "Bearer tenant-a"}
    headers_b = {"Authorization": "Bearer tenant-b"}

    resp = client.post("/api/aviat/queue", json={"mode": "add", "radios": [{"ip": "10.0.0.1"}]}, headers=headers_a)
    assert resp.status_code == 200
    resp = client.post("/api/aviat/queue", json={"mode": "add", "radios": [{"ip": "10.0.0.2"}]}, headers=headers_b)
    assert resp.status_code == 200

    radios_a = client.get("/api/aviat/queue", headers=headers_a).get_json()["radios"]
    radios_b = client.get("/api/aviat/queue", headers=headers_b).get_json()["radios"]

    assert [radio["ip"] for radio in radios_a] == ["10.0.0.1"]
    assert [radio["ip"] for radio in radios_b] == ["10.0.0.2"]


def test_cambium_status_and_stream_enforce_tenant_access(monkeypatch):
    api_server = _load_api_server()
    task_root = Path(__file__).resolve().parents[1] / "tests_artifacts" / "task_store_cambium_auth"
    shutil.rmtree(task_root, ignore_errors=True)
    task_root.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(api_server, "HAS_CAMBIUM", True)
    monkeypatch.setattr(api_server, "ensure_secure_data_dir", lambda: task_root)
    api_server._BACKGROUND_TASK_STORE_DIR = None
    api_server._BACKGROUND_TASK_DB_PATH = None
    api_server.cambium_tasks.clear()
    api_server.cambium_log_queues.clear()

    def _verify_token(token):
        if token == "tenant-a":
            return {"user_id": "user-a", "email": "a@example.com", "tenant_id": "tenant-a", "tenantId": "tenant-a"}
        if token == "tenant-b":
            return {"user_id": "user-b", "email": "b@example.com", "tenant_id": "tenant-b", "tenantId": "tenant-b"}
        return None

    monkeypatch.setattr(api_server, "verify_token", _verify_token)

    task_id = "cambium-tenant-task"
    api_server._background_task_persist(
        "cambium",
        task_id,
        {
            "task_id": task_id,
            "status": "running",
            "radios": [{"ip": "10.0.0.2"}],
            "results": [],
            "abort": False,
            "_tenant_id": "tenant-a",
        },
    )
    api_server._background_task_append_log(
        "cambium",
        task_id,
        {"message": "tenant scoped log", "level": "info", "task_id": task_id},
    )

    client = api_server.app.test_client()

    ok_status = client.get(f"/api/cambium/status/{task_id}", headers={"Authorization": "Bearer tenant-a"})
    denied_status = client.get(f"/api/cambium/status/{task_id}", headers={"Authorization": "Bearer tenant-b"})
    ok_stream = client.get(f"/api/cambium/stream/{task_id}?token=tenant-a")
    denied_stream = client.get(f"/api/cambium/stream/{task_id}?token=tenant-b")

    assert ok_status.status_code == 200
    assert denied_status.status_code == 404
    assert ok_stream.status_code == 200
    assert "tenant scoped log" in ok_stream.get_data(as_text=True)
    assert denied_stream.status_code == 404


def test_wave_status_stream_and_abort_enforce_tenant_access(monkeypatch):
    api_server = _load_api_server()
    task_root = Path(__file__).resolve().parents[1] / "tests_artifacts" / "task_store_wave_auth"
    shutil.rmtree(task_root, ignore_errors=True)
    task_root.mkdir(parents=True, exist_ok=True)

    monkeypatch.setattr(api_server, "HAS_WAVE_FW", True)
    monkeypatch.setattr(api_server, "ensure_secure_data_dir", lambda: task_root)
    api_server._BACKGROUND_TASK_STORE_DIR = None
    api_server._BACKGROUND_TASK_DB_PATH = None
    api_server.wave_fw_tasks.clear()
    api_server.wave_fw_log_queues.clear()

    def _verify_token(token):
        if token == "tenant-a":
            return {"user_id": "user-a", "email": "a@example.com", "tenant_id": "tenant-a", "tenantId": "tenant-a"}
        if token == "tenant-b":
            return {"user_id": "user-b", "email": "b@example.com", "tenant_id": "tenant-b", "tenantId": "tenant-b"}
        return None

    monkeypatch.setattr(api_server, "verify_token", _verify_token)

    task_id = "wave-tenant-task"
    api_server._background_task_persist(
        "wave_fw",
        task_id,
        {
            "task_id": task_id,
            "status": "running",
            "created_at": "2026-04-07T12:00:00Z",
            "results": [],
            "_tenant_id": "tenant-a",
        },
    )
    api_server._background_task_append_log(
        "wave_fw",
        task_id,
        {"message": "wave tenant log", "level": "info", "task_id": task_id},
    )

    client = api_server.app.test_client()

    ok_status = client.get(f"/api/wave-fw/status/{task_id}", headers={"Authorization": "Bearer tenant-a"})
    denied_status = client.get(f"/api/wave-fw/status/{task_id}", headers={"Authorization": "Bearer tenant-b"})
    ok_stream = client.get(f"/api/wave-fw/stream/{task_id}?token=tenant-a")
    denied_stream = client.get(f"/api/wave-fw/stream/{task_id}?token=tenant-b")
    ok_abort = client.post(f"/api/wave-fw/abort/{task_id}", headers={"Authorization": "Bearer tenant-a"})
    denied_abort = client.post(f"/api/wave-fw/abort/{task_id}", headers={"Authorization": "Bearer tenant-b"})

    assert ok_status.status_code == 200
    assert ok_status.get_json()["task"]["status"] == "running"
    assert denied_status.status_code == 404
    assert ok_stream.status_code == 200
    assert "wave tenant log" in ok_stream.get_data(as_text=True)
    assert denied_stream.status_code == 404
    assert ok_abort.status_code == 200
    assert denied_abort.status_code == 404
    assert api_server._wave_fw_check_abort_signal(task_id) is True
