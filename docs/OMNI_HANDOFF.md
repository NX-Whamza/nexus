# OMNI Handoff - API Key Contract (NEXUS v2)

This document is the strict OMNI integration contract for NEXUS.
Authentication model: API key only.

## Base URLs

- API base: `https://nexus.nxlink.com/api/v2`
- UI base: `https://nexus.nxlink.com/l`

## Required headers

All requests:

```http
X-API-Key: <OMNI_API_KEY>
Content-Type: application/json
```

Mutating requests (`POST`, `PUT`, `PATCH`) should include:

```http
Idempotency-Key: <unique-per-request>
```

Recommended environment configuration:

- `NOC_API_V2_REQUIRE_SIGNATURE=false`
- `NOC_API_V2_REQUIRE_IDEMPOTENCY=true`
- `NOC_API_KEYS_JSON` or `NOC_API_KEYS` or `NOC_API_KEY` configured

## Full OMNI endpoint URLs and purpose

- `GET https://nexus.nxlink.com/api/v2/omni/health` -> health check
- `GET https://nexus.nxlink.com/api/v2/omni/whoami` -> key identity and scopes
- `GET https://nexus.nxlink.com/api/v2/omni/actions` -> available action IDs
- `GET https://nexus.nxlink.com/api/v2/omni/bootstrap` -> integration contract metadata
- `GET https://nexus.nxlink.com/api/v2/omni/workflows` -> workflow to action mapping
- `POST https://nexus.nxlink.com/api/v2/omni/jobs` -> submit async job
- `GET https://nexus.nxlink.com/api/v2/omni/jobs` -> list jobs
- `GET https://nexus.nxlink.com/api/v2/omni/jobs/{job_id}` -> job detail
- `GET https://nexus.nxlink.com/api/v2/omni/jobs/{job_id}/events` -> job events
- `POST https://nexus.nxlink.com/api/v2/omni/jobs/{job_id}/cancel` -> cancel job
- `PUT https://nexus.nxlink.com/api/v2/omni/jobs/{job_id}/cancel` -> cancel job
- `PATCH https://nexus.nxlink.com/api/v2/omni/jobs/{job_id}` -> cancel job using patch op

## Common response envelope

Successful endpoint responses use this envelope:

```json
{
  "request_id": "3c28e595-f636-4c2a-ab13-546ac0a5d07a",
  "status": "ok",
  "message": "",
  "data": {},
  "errors": [],
  "timestamp": "2026-02-18T05:10:00Z"
}
```

Error responses use FastAPI detail shape:

```json
{
  "detail": "Missing API key"
}
```

## Endpoint request/response contract

## 1) Health

### Request

- Method: `GET`
- URL: `https://nexus.nxlink.com/api/v2/omni/health`
- Body: none

### Success response (`200`)

```json
{
  "request_id": "de34edce-f608-4f1c-a4d6-c76c113cd4e4",
  "status": "degraded",
  "message": "v2 health",
  "data": {
    "legacy_api_base": "http://127.0.0.1:5000",
    "legacy_health": {
      "ok": false,
      "error": "HTTPConnectionPool(host='127.0.0.1', port=5000): Max retries exceeded"
    },
    "ido_caps": {
      "ok": false,
      "error": "HTTPConnectionPool(host='127.0.0.1', port=5000): Max retries exceeded"
    }
  },
  "errors": [],
  "timestamp": "2026-02-18T05:10:00Z"
}
```

## 2) Whoami

### Request

- Method: `GET`
- URL: `https://nexus.nxlink.com/api/v2/omni/whoami`
- Body: none

### Success response (`200`)

```json
{
  "request_id": "8ddf1092-21e5-4edf-a5f4-f4f53f8f0ec0",
  "status": "ok",
  "message": "",
  "data": {
    "api_key": "admin-key",
    "scopes": [
      "admin"
    ]
  },
  "errors": [],
  "timestamp": "2026-02-18T05:10:01Z"
}
```

## 3) Actions

### Request

- Method: `GET`
- URL: `https://nexus.nxlink.com/api/v2/omni/actions`
- Body: none

### Success response (`200`) with full action list

```json
{
  "request_id": "b5f8c93f-0c66-4764-a651-c3a4302fcad8",
  "status": "ok",
  "message": "",
  "data": {
    "actions": [
      "activity.list",
      "activity.log",
      "app.config.get",
      "aviat.abort",
      "aviat.activate_scheduled",
      "aviat.check_status",
      "aviat.fix_stp",
      "aviat.loading.get",
      "aviat.queue.get",
      "aviat.queue.update",
      "aviat.reboot_required.get",
      "aviat.reboot_required.run",
      "aviat.run",
      "aviat.scheduled.get",
      "aviat.scheduled.sync",
      "aviat.stream.global",
      "compliance.apply",
      "config.autofill_from_export",
      "config.explain",
      "config.suggest",
      "config.translate",
      "config.validate",
      "configs.get",
      "configs.list",
      "configs.portmap.download",
      "configs.portmap.extract",
      "configs.save",
      "ftth.generate_bng",
      "ftth.mf2_package",
      "ftth.preview_bng",
      "health.get",
      "ido.ap.device_info",
      "ido.ap.generate",
      "ido.ap.running_config",
      "ido.ap.standard_config",
      "ido.bh.device_info",
      "ido.bh.generate",
      "ido.bh.running_config",
      "ido.bh.standard_config",
      "ido.capabilities",
      "ido.generic.device_info",
      "ido.nokia7250.generate",
      "ido.ping",
      "ido.rpc.device_info",
      "ido.rpc.generate",
      "ido.rpc.running_config",
      "ido.rpc.standard_config",
      "ido.swt.device_info",
      "ido.swt.generate",
      "ido.swt.running_config",
      "ido.swt.standard_config",
      "ido.ups.device_info",
      "ido.ups.generate",
      "ido.ups.running_config",
      "ido.ups.standard_config",
      "ido.wave.config",
      "infrastructure.get",
      "legacy.proxy",
      "migration.config",
      "migration.mikrotik_to_nokia",
      "mt.config",
      "mt.portmap",
      "mt.render",
      "nokia.generate_7250",
      "routerboards.list"
    ],
    "notes": {
      "mt.*": "Native renderer actions",
      "legacy.proxy": "Whitelisted generic proxy to legacy /api/* endpoint",
      "activity.list/configs.list": "Convenience wrappers for common list endpoints"
    }
  },
  "errors": [],
  "timestamp": "2026-02-18T05:10:02Z"
}
```

## 4) Bootstrap

### Request

- Method: `GET`
- URL: `https://nexus.nxlink.com/api/v2/omni/bootstrap`
- Body: none

### Success response (`200`)

```json
{
  "request_id": "f913489f-97c8-4d5e-9ec7-4c6f5a4f1de5",
  "status": "ok",
  "message": "OMNI bootstrap contract",
  "data": {
    "api_version": "v2",
    "service": "nexus",
    "base_url_hint": "/api/v2",
    "methods_supported": [
      "GET",
      "POST",
      "PUT",
      "PATCH"
    ],
    "resources": {
      "health": {"method": "GET", "path": "/api/v2/health"},
      "identity": {"method": "GET", "path": "/api/v2/whoami"},
      "actions": {"method": "GET", "path": "/api/v2/actions"},
      "job_submit": {"method": "POST", "path": "/api/v2/jobs"},
      "job_list": {"method": "GET", "path": "/api/v2/jobs"},
      "job_get": {"method": "GET", "path": "/api/v2/jobs/{job_id}"},
      "job_events": {"method": "GET", "path": "/api/v2/jobs/{job_id}/events"},
      "job_cancel_patch": {"method": "PATCH", "path": "/api/v2/jobs/{job_id}"},
      "job_cancel_put": {"method": "PUT", "path": "/api/v2/jobs/{job_id}/cancel"}
    },
    "notes": {
      "read_method": "READ maps to GET in HTTP semantics",
      "auth": "X-API-Key",
      "idempotency": "Mutating endpoints require Idempotency-Key"
    }
  },
  "errors": [],
  "timestamp": "2026-02-18T05:10:03Z"
}
```

## 5) Workflows

### Request

- Method: `GET`
- URL: `https://nexus.nxlink.com/api/v2/omni/workflows`
- Body: none

### Success response (`200`) with full workflow mapping

```json
{
  "request_id": "86d57fe9-a32e-44a3-bf33-eae2e8ff0f26",
  "status": "ok",
  "message": "OMNI workflow/action mappings",
  "data": {
    "workflows": {
      "dashboard": {
        "health": "health.get",
        "activity_list": "activity.list",
        "configs_list": "configs.list"
      },
      "mikrotik": {
        "render": {"action": "mt.render", "required": ["config_type", "payload"]},
        "config_only": {"action": "mt.config", "required": ["config_type", "payload"]},
        "portmap_only": {"action": "mt.portmap", "required": ["config_type", "payload"]}
      },
      "field_config_studio": {
        "ap": ["ido.ap.device_info", "ido.ap.running_config", "ido.ap.standard_config", "ido.ap.generate"],
        "bh": ["ido.bh.device_info", "ido.bh.running_config", "ido.bh.standard_config", "ido.bh.generate"],
        "switch": ["ido.swt.device_info", "ido.swt.running_config", "ido.swt.standard_config", "ido.swt.generate"],
        "ups": ["ido.ups.device_info", "ido.ups.running_config", "ido.ups.standard_config", "ido.ups.generate"],
        "rpc": ["ido.rpc.device_info", "ido.rpc.running_config", "ido.rpc.standard_config", "ido.rpc.generate"]
      },
      "aviat": {
        "run": "aviat.run",
        "check_status": "aviat.check_status",
        "activate_scheduled": "aviat.activate_scheduled",
        "queue_get": "aviat.queue.get",
        "queue_update": "aviat.queue.update"
      },
      "ftth": {
        "preview_bng": "ftth.preview_bng",
        "generate_bng": "ftth.generate_bng",
        "mf2_package": "ftth.mf2_package"
      }
    },
    "parity_doc": "/docs/UI_API_PARITY.md",
    "actions_count": 65
  },
  "errors": [],
  "timestamp": "2026-02-18T05:10:04Z"
}
```

## 6) Submit job

### Request

- Method: `POST`
- URL: `https://nexus.nxlink.com/api/v2/omni/jobs`

Request JSON:

```json
{
  "action": "health.get",
  "payload": {}
}
```

### Success response (`202`)

```json
{
  "request_id": "9fcb9791-198c-43e3-8e5a-5f6aa7f15a03",
  "status": "accepted",
  "message": "Job accepted",
  "data": {
    "job_id": "089d0977-cec4-4cd8-9961-5c2dc9bbb34f",
    "request_id": "9fcb9791-198c-43e3-8e5a-5f6aa7f15a03",
    "action": "health.get",
    "status": "running"
  },
  "errors": [],
  "timestamp": "2026-02-18T05:10:05Z"
}
```

## 7) List jobs

### Request

- Method: `GET`
- URL: `https://nexus.nxlink.com/api/v2/omni/jobs?limit=100`

### Success response (`200`)

```json
{
  "request_id": "f8966fcb-98e2-44f8-8740-9ad2400c4bf7",
  "status": "ok",
  "message": "",
  "data": {
    "jobs": [
      {
        "job_id": "089d0977-cec4-4cd8-9961-5c2dc9bbb34f",
        "request_id": "9fcb9791-198c-43e3-8e5a-5f6aa7f15a03",
        "action": "health.get",
        "submitted_by": "admin-key",
        "status": "success",
        "created_at": "2026-02-18T05:10:05Z",
        "started_at": "2026-02-18T05:10:05Z",
        "finished_at": "2026-02-18T05:10:06Z",
        "cancel_requested": false,
        "result": {
          "http_status": 200,
          "ok": true,
          "path": "/api/health",
          "method": "GET",
          "response": {
            "status": "online"
          }
        },
        "error": null
      }
    ],
    "count": 1
  },
  "errors": [],
  "timestamp": "2026-02-18T05:10:06Z"
}
```

## 8) Get job detail

### Request

- Method: `GET`
- URL: `https://nexus.nxlink.com/api/v2/omni/jobs/089d0977-cec4-4cd8-9961-5c2dc9bbb34f`

### Success response (`200`)

```json
{
  "request_id": "15a4df1c-3f32-483b-ab59-2874521ca2f5",
  "status": "ok",
  "message": "",
  "data": {
    "job_id": "089d0977-cec4-4cd8-9961-5c2dc9bbb34f",
    "request_id": "9fcb9791-198c-43e3-8e5a-5f6aa7f15a03",
    "action": "health.get",
    "submitted_by": "admin-key",
    "status": "running",
    "created_at": "2026-02-18T05:10:05Z",
    "started_at": "2026-02-18T05:10:05Z",
    "finished_at": null,
    "cancel_requested": false,
    "result": null,
    "error": null,
    "payload": {}
  },
  "errors": [],
  "timestamp": "2026-02-18T05:10:06Z"
}
```

## 9) Get job events

### Request

- Method: `GET`
- URL: `https://nexus.nxlink.com/api/v2/omni/jobs/089d0977-cec4-4cd8-9961-5c2dc9bbb34f/events`

### Success response (`200`)

```json
{
  "request_id": "5a5e5db4-4ed6-4f26-ac87-d48eb7efc9f8",
  "status": "ok",
  "message": "",
  "data": {
    "job_id": "089d0977-cec4-4cd8-9961-5c2dc9bbb34f",
    "status": "running",
    "events": [
      {
        "ts": "2026-02-18T05:10:05Z",
        "level": "info",
        "message": "Started action 'health.get'"
      }
    ]
  },
  "errors": [],
  "timestamp": "2026-02-18T05:10:06Z"
}
```

## 10) Cancel job

### POST cancel request

- Method: `POST`
- URL: `https://nexus.nxlink.com/api/v2/omni/jobs/089d0977-cec4-4cd8-9961-5c2dc9bbb34f/cancel`
- Body:

```json
{}
```

### PUT cancel request

- Method: `PUT`
- URL: `https://nexus.nxlink.com/api/v2/omni/jobs/089d0977-cec4-4cd8-9961-5c2dc9bbb34f/cancel`
- Body:

```json
{}
```

### PATCH cancel request

- Method: `PATCH`
- URL: `https://nexus.nxlink.com/api/v2/omni/jobs/089d0977-cec4-4cd8-9961-5c2dc9bbb34f`
- Body:

```json
{
  "op": "cancel"
}
```

### Success response (`200`)

```json
{
  "request_id": "7dc6cb40-fc08-4e53-ad4d-8afeb1fdf0e0",
  "status": "ok",
  "message": "Cancel request accepted",
  "data": {
    "job_id": "089d0977-cec4-4cd8-9961-5c2dc9bbb34f",
    "status": "running",
    "cancel_requested": true
  },
  "errors": [],
  "timestamp": "2026-02-18T05:10:07Z"
}
```

## Job statuses and fields

Job status values:

- `queued`
- `running`
- `success`
- `error`
- `cancelled`

Job detail fields:

- `job_id`
- `request_id`
- `action`
- `submitted_by`
- `status`
- `created_at`
- `started_at`
- `finished_at`
- `cancel_requested`
- `result`
- `error`
- `payload`

Job event fields:

- `ts`
- `level` (`info`, `warning`, `success`, `error`)
- `message`

## Error catalog

Authentication and authorization:

```json
{ "detail": "Missing API key" }
```

```json
{ "detail": "Invalid API key" }
```

```json
{ "detail": "Insufficient scope; need 'job.submit'" }
```

Idempotency:

```json
{ "detail": "Missing Idempotency-Key" }
```

```json
{ "detail": "Idempotency-Key reused with different payload" }
```

Validation and resource:

```json
{ "detail": "Missing 'action'" }
```

```json
{ "detail": "Supported PATCH ops: cancel" }
```

```json
{ "detail": "Job not found" }
```

Server configuration:

```json
{ "detail": "API keys are not configured for /api/v2 (set NOC_API_KEYS_JSON or NOC_API_KEYS)" }
```

## Copy/paste curl examples

```bash
export BASE_URL="https://nexus.nxlink.com"
export API_KEY="<OMNI_API_KEY>"
```

Whoami:

```bash
curl -sS "${BASE_URL}/api/v2/omni/whoami" \
  -H "X-API-Key: ${API_KEY}"
```

Submit:

```bash
curl -sS "${BASE_URL}/api/v2/omni/jobs" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -H "Idempotency-Key: idem-$(date +%s)" \
  --data-raw '{"action":"health.get","payload":{}}'
```

Detail:

```bash
curl -sS "${BASE_URL}/api/v2/omni/jobs/089d0977-cec4-4cd8-9961-5c2dc9bbb34f" \
  -H "X-API-Key: ${API_KEY}"
```

Events:

```bash
curl -sS "${BASE_URL}/api/v2/omni/jobs/089d0977-cec4-4cd8-9961-5c2dc9bbb34f/events" \
  -H "X-API-Key: ${API_KEY}"
```

Cancel:

```bash
curl -sS "${BASE_URL}/api/v2/omni/jobs/089d0977-cec4-4cd8-9961-5c2dc9bbb34f/cancel" \
  -X POST \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -H "Idempotency-Key: idem-cancel-$(date +%s)" \
  --data-raw '{}'
```

## Verified test status

Executed in this repo:

- `python -m pytest -q tests/test_api_v2_contract.py`
- `python -m pytest -q tests/test_ftth_ui_backend_contract.py`

Latest result summary:

- `tests/test_api_v2_contract.py`: 5 passed
- `tests/test_ftth_ui_backend_contract.py`: 3 passed