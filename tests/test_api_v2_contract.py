import hashlib
import hmac
import importlib
import json
import sys
import time
import uuid
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _load_api_v2(monkeypatch, *, require_signature="true", require_idempotency="true"):
    repo_root = Path(__file__).resolve().parents[1]
    vm_dep = repo_root / "vm_deployment"
    for p in (str(repo_root), str(vm_dep)):
        if p not in sys.path:
            sys.path.insert(0, p)

    monkeypatch.setenv("NOC_API_KEYS_JSON", '{"test-key":["admin"]}')
    monkeypatch.setenv("NOC_API_SIGNING_KEYS_JSON", '{"sig-1":"secret123"}')
    monkeypatch.setenv("NOC_API_V2_REQUIRE_SIGNATURE", require_signature)
    monkeypatch.setenv("NOC_API_V2_REQUIRE_IDEMPOTENCY", require_idempotency)
    monkeypatch.setenv("NOC_API_V2_SIGNATURE_SKEW_SECONDS", "300")
    monkeypatch.setenv("NOC_API_V2_NONCE_TTL_SECONDS", "900")

    module_name = "vm_deployment.api_v2"
    if module_name in sys.modules:
        api_v2 = importlib.reload(sys.modules[module_name])
    else:
        api_v2 = importlib.import_module(module_name)

    app = FastAPI()
    app.include_router(api_v2.router)
    return api_v2, TestClient(app)


def _sign(method: str, path: str, body: str, *, secret: str = "secret123", key_id: str = "sig-1", api_key: str = "test-key", idem: str | None = None):
    ts = str(int(time.time()))
    nonce = uuid.uuid4().hex
    body_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    canonical = "\n".join([method.upper(), path, ts, nonce, body_hash])
    sig = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    headers = {
        "X-API-Key": api_key,
        "X-Key-Id": key_id,
        "X-Timestamp": ts,
        "X-Nonce": nonce,
        "X-Signature": sig,
        "Content-Type": "application/json",
    }
    if idem:
        headers["Idempotency-Key"] = idem
    return headers


def test_missing_api_key_returns_401(monkeypatch):
    _, client = _load_api_v2(monkeypatch, require_signature="false")
    r = client.get("/api/v2/nexus/whoami")
    assert r.status_code == 401
    assert r.json()["detail"] == "Missing API key"


def test_signature_required_missing_signature_headers_returns_401(monkeypatch):
    _, client = _load_api_v2(monkeypatch, require_signature="true")
    r = client.get("/api/v2/nexus/whoami", headers={"X-API-Key": "test-key"})
    assert r.status_code == 401
    assert "Missing signature headers" in r.json()["detail"]


def test_api_key_only_mode_works_when_signature_disabled(monkeypatch):
    _, client = _load_api_v2(monkeypatch, require_signature="false")
    r = client.get("/api/v2/nexus/whoami", headers={"X-API-Key": "test-key"})
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok"
    assert body["data"]["api_key"] == "test-key"


def test_submit_requires_idempotency_key_when_enabled(monkeypatch):
    _, client = _load_api_v2(monkeypatch, require_signature="false", require_idempotency="true")
    payload = {"action": "health.get", "payload": {}}
    r = client.post("/api/v2/nexus/jobs", headers={"X-API-Key": "test-key"}, json=payload)
    assert r.status_code == 400
    assert r.json()["detail"] == "Missing Idempotency-Key"


def test_submit_job_and_poll_detail_events_with_hmac(monkeypatch):
    _, client = _load_api_v2(monkeypatch, require_signature="true", require_idempotency="true")

    path_submit = "/api/v2/nexus/jobs"
    submit_body = json.dumps({"action": "health.get", "payload": {}}, separators=(",", ":"))
    headers_submit = _sign("POST", path_submit, submit_body, idem="idem-1")
    r_submit = client.post(path_submit, headers=headers_submit, data=submit_body)
    assert r_submit.status_code == 202

    submit_json = r_submit.json()
    assert submit_json["status"] == "accepted"
    job_id = submit_json["data"]["job_id"]
    assert job_id

    path_job = f"/api/v2/nexus/jobs/{job_id}"
    headers_job = _sign("GET", path_job, "")
    r_job = client.get(path_job, headers=headers_job)
    assert r_job.status_code == 200
    job_data = r_job.json()["data"]
    assert job_data["job_id"] == job_id
    assert "status" in job_data
    assert "payload" in job_data

    path_events = f"/api/v2/nexus/jobs/{job_id}/events"
    headers_events = _sign("GET", path_events, "")
    r_events = client.get(path_events, headers=headers_events)
    assert r_events.status_code == 200
    events_data = r_events.json()["data"]
    assert events_data["job_id"] == job_id
    assert isinstance(events_data["events"], list)
    if events_data["events"]:
        evt = events_data["events"][0]
        assert set(evt.keys()) == {"ts", "level", "message"}


def test_nexus_catalog_exposes_action_metadata_and_frontend_only_flags(monkeypatch):
    _, client = _load_api_v2(monkeypatch, require_signature="false", require_idempotency="false")
    r = client.get("/api/v2/nexus/catalog/actions", headers={"X-API-Key": "test-key"})
    assert r.status_code == 200
    body = r.json()
    actions = body["data"]["actions"]
    assert "switch.generate_mikrotik" in actions
    assert "ftth.generate_fiber_customer" in actions
    assert "command.vault.catalog" in actions
    assert actions["switch.generate_mikrotik"]["backend_path"] == "/api/generate-mt-switch-config"

    r_workflows = client.get("/api/v2/nexus/workflows", headers={"X-API-Key": "test-key"})
    assert r_workflows.status_code == 200
    workflows = r_workflows.json()["data"]["workflows"]
    assert workflows["cisco_port_setup"]["delivery"] == "api"
    assert workflows["ftth_configurator"]["delivery"] == "api"
    assert workflows["command_vault"]["delivery"] == "api"


def test_openapi_contains_nexus_job_examples(monkeypatch):
    _, client = _load_api_v2(monkeypatch, require_signature="false", require_idempotency="false")
    schema = client.get("/openapi.json").json()
    assert "/api/v2/nexus/jobs" in schema["paths"]
    req = schema["paths"]["/api/v2/nexus/jobs"]["post"]["requestBody"]["content"]["application/json"]["schema"]
    examples = schema["paths"]["/api/v2/nexus/jobs"]["post"]["requestBody"]["content"]["application/json"]["examples"]
    assert req["type"] == "object"
    assert "switch_generate_mikrotik" in examples
    assert "nokia_configurator_generate" in examples
    assert "enterprise_generate_mpls" in examples
    assert "command_vault_catalog" in examples


def test_nexus_direct_tool_endpoints_work(monkeypatch):
    _, client = _load_api_v2(monkeypatch, require_signature="false", require_idempotency="false")
    headers = {"X-API-Key": "test-key"}

    cisco = client.post(
        "/api/v2/nexus/tools/cisco/interface",
        headers=headers,
        json={
            "port_description": "BH-TO-SITE-A",
            "port_type": "TenGigE",
            "port_number": "0/0/0/1",
            "interface_ip": "10.42.10.1",
            "subnet_mask": "255.255.255.252",
        },
    )
    assert cisco.status_code == 200
    assert "router ospf" in cisco.json()["data"]["config"]

    feeding = client.post(
        "/api/v2/nexus/tools/enterprise-feeding/generate",
        headers=headers,
        json={
            "label": "ACME-HANDOFF",
            "port": "sfp-sfpplus4",
            "backhaul_cidr": "10.25.26.48/29",
            "loopback_ip": "10.25.100.1/32",
        },
    )
    assert feeding.status_code == 200
    assert "routing ospf interface-template" in feeding.json()["data"]["config"]

    diff = client.post(
        "/api/v2/nexus/tools/config-diff",
        headers=headers,
        json={"config_a": "/interface bridge\nadd name=bridge1", "config_b": "/interface bridge\nadd name=bridge2"},
    )
    assert diff.status_code == 200
    assert diff.json()["data"]["summary"]["changed"] >= 1

    command_vault = client.post(
        "/api/v2/nexus/tools/command-vault",
        headers=headers,
        json={"family": "nokia", "subsection": "7750-bng", "query": "bgp"},
    )
    assert command_vault.status_code == 200
    assert command_vault.json()["data"]["count"] >= 1
    assert command_vault.json()["data"]["results"][0]["family"] == "nokia"

    sixghz = client.post(
        "/api/v2/nexus/tools/6ghz/instate",
        headers=headers,
        json={
            "switch_type": "swt_ccr2004",
            "routeros_version": "7.19.4",
            "vlan3000_subnet": "10.246.22.224/28",
            "vlan4000_subnet": "10.246.22.240/28",
            "dns_servers": ["1.1.1.1", "8.8.8.8"],
        },
    )
    assert sixghz.status_code == 200
    assert "interface bonding" in sixghz.json()["data"]["config"]

    mpls = client.post(
        "/api/v2/nexus/tools/enterprise/mpls",
        headers=headers,
        json={
            "routerboard_device": "ccr2004",
            "routeros_version": "7.19.4",
            "customer_code": "ACME-537853",
            "device_name": "RTR-ACME-537853",
            "loopback_ip": "10.247.72.34/32",
            "customer_handoff": "sfp-sfpplus7",
            "uplinks": [{"interface": "sfp-sfpplus1", "ip": "10.247.57.4/29", "comment": "IL-CARMI-CN-1"}],
            "dns_servers": ["1.1.1.1", "8.8.8.8"],
            "vpls_peer": "10.254.247.3",
            "enable_bgp": True,
            "bgp_as": 65000,
            "bgp_peers": [{"ip": "10.4.0.1", "as": 65000}],
        },
    )
    assert mpls.status_code == 200
    assert "/routing ospf instance" in mpls.json()["data"]["config"]
    assert "/routing bgp connection" in mpls.json()["data"]["config"]


def test_nexus_maintenance_crud(monkeypatch):
    _, client = _load_api_v2(monkeypatch, require_signature="false", require_idempotency="false")
    headers = {"X-API-Key": "test-key"}
    payload = {
        "name": "ACME firmware window",
        "scheduled_at": "2026-04-01T02:00:00Z",
        "duration_minutes": 120,
        "priority": "normal",
        "devices": ["10.0.0.1", "10.0.0.2"],
        "tasks": ["firmware", "testing"],
        "notes": "Upgrade and validate",
    }
    created = client.post("/api/v2/nexus/maintenance/windows", headers=headers, json=payload)
    assert created.status_code == 201
    window = created.json()["data"]
    assert window["name"] == payload["name"]
    window_id = window["window_id"]

    fetched = client.get(f"/api/v2/nexus/maintenance/windows/{window_id}", headers=headers)
    assert fetched.status_code == 200
    assert fetched.json()["data"]["window_id"] == window_id

    updated = client.put(
        f"/api/v2/nexus/maintenance/windows/{window_id}",
        headers=headers,
        json={**payload, "status": "running"},
    )
    assert updated.status_code == 200
    assert updated.json()["data"]["status"] == "running"

    listed = client.get("/api/v2/nexus/maintenance/windows", headers=headers)
    assert listed.status_code == 200
    assert listed.json()["data"]["count"] >= 1

    deleted = client.delete(f"/api/v2/nexus/maintenance/windows/{window_id}", headers=headers)
    assert deleted.status_code == 200
