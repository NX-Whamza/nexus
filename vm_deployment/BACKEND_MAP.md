# Backend Map

## Active Runtime

- `vm_deployment/fastapi_server.py`
  - Primary ASGI entrypoint.
  - Hosts native FastAPI routes.
  - Mounts the legacy Flask app for compatibility.

## Legacy Compatibility Layer

- `vm_deployment/api_server.py`
  - Large legacy Flask application.
  - Still provides many routes used by the UI and tests.
  - FTTH generation route lives here and delegates to `ftth_renderer.py`.

## Native FastAPI Surface

- `vm_deployment/api_v2.py`
  - Incremental FastAPI router for newer endpoints.
  - Included into `fastapi_server.py`.

## FTTH Generation Path

1. Frontend submits FTTH payload from `vm_deployment/NOC-configMaker.html`.
2. Request reaches `/api/generate-ftth-bng`.
3. Legacy Flask route in `vm_deployment/api_server.py` handles the request.
4. Renderer logic lives in `vm_deployment/ftth_renderer.py`.

## Compliance / Defaults

- `vm_deployment/nextlink_compliance_reference.py`
  - Bundled compliance blocks and operational defaults.
- `vm_deployment/gitlab_compliance.py`
  - Optional GitLab-backed compliance loader.
- `vm_deployment/ido_adapter.py`
  - Shared default values used by backend features.

## Practical Rule

- Add new backend routes in `api_v2.py` when possible.
- Keep `api_server.py` for legacy compatibility and gradual extraction.
- Keep rendering logic in focused modules like `ftth_renderer.py`, not inside route files.
