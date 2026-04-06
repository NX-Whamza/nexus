# NOC ConfigMaker — Claude Project Rules

## What This Project Is
AI-powered network configuration automation for Nextlink Internet. Generates production-ready
configs for MikroTik, Nokia, Cambium, and Aviat devices. Bad output reaches live routers.
Accuracy and safety matter more than cleverness.

## Architecture Constraints

### Dual Runtime — Read Before Touching Routes
- Flask (`vm_deployment/api_server.py`) and FastAPI (`vm_deployment/fastapi_server.py`) coexist via a2wsgi
- New endpoints go in FastAPI (`api_v2.py` or `routes/`)
- Legacy Flask routes stay unless explicitly migrating
- Changes visible to the UI must work in both runtimes

### Large Files — Always Grep First
These files are too large to read whole. Use Grep to locate the exact section, then read ±50 lines:
- `vm_deployment/api_server.py` — 815 KB Flask backend
- `vm_deployment/NOC-configMaker.html` — 30k+ lines monolithic SPA
- `vm_deployment/aviat_config.py` — 121 KB Aviat provisioning engine

### Device Type Isolation
Each device type has its own generator. Don't create cross-device abstractions:
- MikroTik tower: `mt_config_gen/mt_tower.py`
- MikroTik BNG2: `mt_config_gen/mt_bng2.py`
- Aviat microwave: `aviat_config.py`
- FTTH/BNG: `ftth_renderer.py`
- Nokia, Cambium: handled in `api_server.py` + `base_configs/`

### Compliance Is Layered — Don't Inline Validation
- `engineering_compliance.py` — local validation rules
- `gitlab_compliance.py` — dynamic RFC checks via GitLab
- `nextlink_compliance_reference.py` — Nextlink standards reference
Changes to any compliance file affect all device types. Flag for extra review.

## Never Touch These Files
- `.env`, `ENV_TEMPLATE.txt`, `ENV_DEV_TEMPLATE.txt` — secrets
- `docker-compose.yml`, `Dockerfile`, `docker/` — deployment infra
- `.github/workflows/` — CI/CD
- `build_exe.py`, `NOC-ConfigMaker.spec` — EXE build system
- `secure_data/` — runtime SQLite databases (config history, feedback)

## Code Standards

### Python (Backend)
- Match existing function and variable naming conventions per file
- Flask routes return `jsonify({"success": True/False, ...})`
- FastAPI routes use Pydantic models for request/response bodies
- Error handling is mandatory — never let exceptions surface as 500s without logging
- Use existing utilities in `nextlink_standards.py` before writing new validation logic

### JavaScript (Frontend — NOC-configMaker.html)
- Vanilla JS only — no frameworks, no imports
- API calls: `fetch('/api/endpoint', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({...}) })`
- Find the existing section for a device type and follow its pattern exactly
- Never duplicate UI patterns that already exist for another device type

### Generated Configs
- Must never contain default SNMP community strings (`public`, `private`)
- Must never contain hardcoded credentials or placeholder passwords
- Must follow standards in `config_policies/nextlink/` for the relevant state/device

## Agent Workflow

**Quick fix (single file, clear scope):**
Builder → Tester

**Feature or multi-file change:**
Planner → Architect → Builder → Tester → Reviewer

**Anything touching auth, network ops, SSH, SNMP, or compliance:**
Planner → Architect → Builder → Security + Tester → Reviewer

**Multi-layer change (frontend + backend + tests):**
Agent Team with domain-specific teammates

Use the agents in `.claude/agents/` — they know this codebase.

## Testing
```bash
# Run full test suite
python -m pytest tests/ -v --tb=short

# Device-specific
python -m pytest tests/test_aviat_mode_paths.py -v
python -m pytest tests/test_mt_fastapi.py -v
python -m pytest tests/test_ftth_ui_backend_contract.py -v

# Smoke tests (requires running server on port 5000)
python tests/smoke_api.py
```
Always run tests after changes. Smoke tests require the server running — note this, don't fail silently.

## Context Management
- `/compact` at 50% context usage
- `/clear` when switching to a different device type or unrelated task
- When compacting, preserve: list of modified files, failing tests, current device type in scope
