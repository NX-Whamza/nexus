#!/usr/bin/env python3
"""
FastAPI runtime wrapper for the existing NOC backend.

This mounts the current Flask app so we can switch the server runtime to FastAPI/uvicorn
without breaking existing routes while we continue native FastAPI migration incrementally.
"""

import os
import sys
import socket
import subprocess
import threading
import time
import sqlite3
import shutil
import importlib
from contextlib import asynccontextmanager
from datetime import datetime
from urllib.parse import urljoin
import httpx
import requests
from pathlib import Path
from typing import Any, Dict, Type
from fastapi.openapi.utils import get_openapi

from a2wsgi import WSGIMiddleware
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

# Ensure local imports resolve when launched from repo root or service wrappers.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from api_server import app as flask_app
try:
    from mt_config_gen.mt_tower import MTTowerConfig
    from mt_config_gen.mt_bng2 import MTBNG2Config
except Exception:
    from vm_deployment.mt_config_gen.mt_tower import MTTowerConfig
    from vm_deployment.mt_config_gen.mt_bng2 import MTBNG2Config
from ido_adapter import (
    apply_compliance as ido_apply_compliance,
    get_compliance as ido_get_compliance,
    get_defaults as ido_get_defaults,
    get_device_profiles as ido_get_device_profiles,
    get_templates as ido_get_templates,
    merge_defaults as ido_merge_defaults,
)
from api_v2 import router as api_v2_router


@asynccontextmanager
async def lifespan(_: FastAPI):
    _schedule_startup_maintenance()
    yield


API_DESCRIPTION = """
API-first contract for OMNI and future tenant-facing integrations.

Use the `/api/v2/omni/*` routes documented here as the stable external surface.
Legacy Flask routes remain mounted for backward compatibility, but they are not the primary integration contract.
""".strip()

OPENAPI_TAGS = [
    {
        "name": "OMNI Health",
        "description": "Availability and health endpoints for OMNI and external integrations.",
    },
    {
        "name": "OMNI Discovery",
        "description": "Identity, actions, bootstrap, and workflow discovery endpoints.",
    },
    {
        "name": "OMNI Jobs",
        "description": "Async job submission, job inspection, events, and cancellation endpoints.",
    },
]


app = FastAPI(
    title="NEXUS API",
    version="2.6.0",
    description=API_DESCRIPTION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url=None,
    openapi_url="/docs/openapi.json",
    openapi_tags=OPENAPI_TAGS,
    swagger_ui_parameters={
        "persistAuthorization": True,
        "displayRequestDuration": True,
        "docExpansion": "list",
    },
)

# Match current permissive CORS behavior from Flask setup.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(api_v2_router)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=OPENAPI_TAGS,
    )
    schema.setdefault("components", {}).setdefault("securitySchemes", {})
    schema["components"]["securitySchemes"]["ApiKeyAuth"] = {
        "type": "apiKey",
        "in": "header",
        "name": "X-API-Key",
        "description": "Primary API key header for OMNI and tenant integrations.",
    }
    schema["components"]["securitySchemes"]["BearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "API key",
        "description": "Bearer token alternative. Use the same API key value as X-API-Key.",
    }
    for path, methods in schema.get("paths", {}).items():
        if not path.startswith("/api/v2/omni/"):
            continue
        for method, operation in methods.items():
            if method.lower() not in {"get", "post", "put", "patch"}:
                continue
            operation.setdefault("security", [{"ApiKeyAuth": []}, {"BearerAuth": []}])
    app.openapi_schema = schema
    return schema


app.openapi = custom_openapi


def _str_to_bool(value: str) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _startup_maintenance_delay_seconds(default: float = 2.0) -> float:
    raw = (os.getenv("STARTUP_MAINTENANCE_DELAY_SECONDS") or "").strip()
    if not raw:
        return default
    try:
        return max(0.0, float(raw))
    except ValueError:
        print(f"[STARTUP] Invalid STARTUP_MAINTENANCE_DELAY_SECONDS={raw!r}; using {default}s")
        return default


def _maybe_purge_bad_aviat_logs_on_startup() -> None:
    """
    Optional one-shot cleanup for known bad Aviat log entries.
    Enabled only when AUTO_PURGE_BAD_AVIAT_LOGS=true.
    """
    if not _str_to_bool(os.getenv("AUTO_PURGE_BAD_AVIAT_LOGS", "false")):
        return

    db_path = Path("secure_data") / "activity_log.db"
    if not db_path.exists():
        print(f"[ACTIVITY] Auto-purge skipped: DB not found at {db_path}")
        return

    ts_from = (os.getenv("AUTO_PURGE_BAD_AVIAT_LOGS_FROM") or "").strip()
    ts_to = (os.getenv("AUTO_PURGE_BAD_AVIAT_LOGS_TO") or "").strip()
    username = (os.getenv("AUTO_PURGE_BAD_AVIAT_LOGS_USERNAME") or "").strip()
    fw_value = (os.getenv("AUTO_PURGE_BAD_AVIAT_LOGS_FW") or "0.0.0").strip()

    where = [
        "activity_type = ?",
        "success = 0",
        "routeros_version = ?",
    ]
    params = ["aviat-upgrade", fw_value]

    if ts_from:
        where.append("timestamp >= ?")
        params.append(ts_from)
    if ts_to:
        where.append("timestamp < ?")
        params.append(ts_to)
    if username:
        where.append("username = ?")
        params.append(username)

    where_sql = " AND ".join(where)

    try:
        backup_name = f"activity_log.db.bak_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        backup_path = db_path.parent / backup_name
        shutil.copy2(db_path, backup_path)
        print(f"[ACTIVITY] Auto-purge backup created: {backup_path}")

        conn = sqlite3.connect(str(db_path))
        cur = conn.cursor()
        count_sql = f"SELECT COUNT(*) FROM activities WHERE {where_sql}"
        cur.execute(count_sql, params)
        match_count = int(cur.fetchone()[0] or 0)
        if match_count <= 0:
            print("[ACTIVITY] Auto-purge: no matching bad Aviat rows found.")
            conn.close()
            return

        delete_sql = f"DELETE FROM activities WHERE {where_sql}"
        cur.execute(delete_sql, params)
        deleted = cur.rowcount
        conn.commit()
        conn.close()
        print(f"[ACTIVITY] Auto-purge complete: deleted {deleted} bad Aviat rows.")
    except Exception as exc:
        print(f"[ACTIVITY] Auto-purge failed: {exc}")


def _run_startup_maintenance() -> None:
    delay_seconds = _startup_maintenance_delay_seconds()
    if delay_seconds > 0:
        time.sleep(delay_seconds)
    _maybe_purge_bad_aviat_logs_on_startup()


def _schedule_startup_maintenance() -> None:
    mode = (os.getenv("STARTUP_MAINTENANCE_MODE") or "background").strip().lower()
    if mode == "blocking":
        print("[STARTUP] Running startup maintenance in blocking mode")
        _run_startup_maintenance()
        return

    print("[STARTUP] Scheduling startup maintenance in background mode")
    threading.Thread(
        target=_run_startup_maintenance,
        name="startup-maintenance",
        daemon=True,
    ).start()
@app.get("/api/runtime")
def runtime_info():
    return JSONResponse(
        {
            "runtime": "fastapi",
            "mounted_backend": "flask",
            "note": "Incremental migration mode",
        }
    )


IDO_PROXY_ALLOWED_PREFIXES = (
    "/api/bh/",
    "/api/ap/",
    "/api/ups/",
    "/api/rpc/",
    "/api/swt/",
    "/api/generic/",
    "/api/ping",
    "/api/waveconfig/",
    "/api/7250config/",
    "/generate",
)


def _ido_backend_url() -> str:
    def _ido_local_backend_path() -> str:
        candidates = [
            str(Path(__file__).resolve().parent / "ido_modules"),
            (os.getenv("IDO_BACKEND_PATH") or "").strip(),
            (os.getenv("IDO_TOOLS_BACKEND_PATH") or "").strip(),
            (os.getenv("NETLAUNCH_IDO_BACKEND_PATH") or "").strip(),
            (os.getenv("NETLAUNCH_TOOLS_BACKEND_PATH") or "").strip(),
            "/opt/ido-backend",
            "/opt/ido-backend/ido-backend-main",
            "/opt/netlaunch-tools-backend",
            "/opt/netlaunch-tools-backend/netlaunch-tools-backend-main",
            "/app/external/netlaunch-tools-backend-main",
            "/app/external/netlaunch-tools-backend-main/netlaunch-tools-backend-main",
            "/app/external/ido-backend-main",
            "/app/external/ido-backend-main/ido-backend-main",
            str(Path(__file__).resolve().parents[2] / "ido-backend-main" / "ido-backend-main"),
            str(Path(__file__).resolve().parents[2] / "netlaunch-tools-backend-main" / "netlaunch-tools-backend-main"),
            r"C:\Users\WalihlahHamza\Downloads\ido-backend-main\ido-backend-main",
            r"C:\Users\WalihlahHamza\Downloads\netlaunch-tools-backend-main\netlaunch-tools-backend-main",
        ]
        for candidate in candidates:
            if not candidate:
                continue
            p = Path(candidate)
            if (p / "rest" / "rest_server.py").exists():
                return str(p)
        return ""

    def _ido_local_base_config_path() -> str:
        candidates = [
            (os.getenv("BASE_CONFIG_PATH") or "").strip(),
            (os.getenv("NEXTLINK_BASE_CONFIG_PATH") or "").strip(),
            str(Path(__file__).resolve().parent / "base_configs"),
        ]
        for candidate in candidates:
            if not candidate:
                continue
            p = Path(candidate)
            if (p / "Cambium").is_dir():
                return str(p)
        return ""

    local_proc = getattr(_ido_backend_url, "_local_proc", None)
    local_lock = getattr(_ido_backend_url, "_local_lock", None)
    if local_lock is None:
        local_lock = threading.Lock()
        setattr(_ido_backend_url, "_local_lock", local_lock)

    def _ensure_local_ido_backend() -> str:
        nonlocal local_proc
        if str(os.getenv("ENABLE_LOCAL_IDO_BACKEND_AUTOSTART", "true")).strip().lower() in {"0", "false", "no"}:
            return ""

        backend_path = _ido_local_backend_path()
        if not backend_path:
            return ""
        base_config_path = _ido_local_base_config_path() or backend_path

        host = (os.getenv("LOCAL_IDO_BACKEND_HOST") or "127.0.0.1").strip()
        port = int((os.getenv("LOCAL_IDO_BACKEND_PORT") or "18081").strip())
        url = f"http://{host}:{port}"

        try:
            health = requests.get(f"{url}/openapi.json", timeout=1.5)
            if health.status_code < 500:
                return url
        except Exception:
            pass

        with local_lock:
            local_proc = getattr(_ido_backend_url, "_local_proc", None)
            if local_proc is not None and local_proc.poll() is None:
                return url

            cmd = [
                sys.executable,
                "-m",
                "uvicorn",
                "vm_deployment.ido_local_backend:app",
                "--host",
                host,
                "--port",
                str(port),
                "--log-level",
                "warning",
            ]
            try:
                env = os.environ.copy()
                env.setdefault("BASE_CONFIG_PATH", base_config_path)
                env.setdefault("FIRMWARE_PATH", base_config_path)
                # Field Config Studio device defaults (netlaunch backend modules use these env vars).
                # If explicit module vars are not set, fall back to NEXTLINK_SSH_PASSWORD.
                ssh_pw = (env.get("NEXTLINK_SSH_PASSWORD") or "").strip()
                if ssh_pw:
                    env.setdefault("AP_STANDARD_PW", ssh_pw)
                    env.setdefault("SM_STANDARD_PW", ssh_pw)
                    env.setdefault("BH_STANDARD_PW", ssh_pw)
                    env.setdefault("SWT_STANDARD_PW", ssh_pw)
                    env.setdefault("RPC_STANDARD_PW", ssh_pw)
                    env.setdefault("CNMATRIX_STANDARD_PW", ssh_pw)
                    env.setdefault("WAVE_AP_PASS", ssh_pw)
                configured_stub = (env.get("BNG_SSH_SERVER_CONFIG") or "").strip()
                if configured_stub:
                    env.setdefault("BNG_SSH_SERVER_CONFIG", configured_stub)
                else:
                    backend_stub = Path(backend_path) / ".bng_ssh_servers.json"
                    if backend_stub.exists():
                        env.setdefault("BNG_SSH_SERVER_CONFIG", str(backend_stub))
                    else:
                        runtime_dir = Path(env.get("NOC_RUNTIME_DIR") or "/tmp")
                        runtime_dir.mkdir(parents=True, exist_ok=True)
                        runtime_stub = runtime_dir / "bng_ssh_servers.json"
                        if not runtime_stub.exists():
                            runtime_stub.write_text("[]", encoding="utf-8")
                        env.setdefault("BNG_SSH_SERVER_CONFIG", str(runtime_stub))
                local_proc = subprocess.Popen(
                    cmd,
                    cwd=str(Path(__file__).resolve().parents[1]),
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                setattr(_ido_backend_url, "_local_proc", local_proc)
            except Exception:
                return ""

        for _ in range(20):
            time.sleep(0.25)
            try:
                health = requests.get(f"{url}/openapi.json", timeout=1.5)
                if health.status_code < 500:
                    return url
            except Exception:
                continue
        return ""

    candidates = (
        "IDO_BACKEND_URL",
        "IDO_TOOLS_BACKEND_URL",
        "NETLAUNCH_IDO_BACKEND_URL",
        "NEXTLINK_IDO_BACKEND_URL",
        "NETLAUNCH_TOOLS_BACKEND_URL",
    )
    for key in candidates:
        value = (os.getenv(key) or "").strip()
        if value:
            if not value.startswith(("http://", "https://")):
                value = f"http://{value}"
            return value.rstrip("/")
    return _ensure_local_ido_backend()


def _ido_inprocess_module():
    try:
        return importlib.import_module("ido_local_backend")
    except Exception:
        try:
            return importlib.import_module("vm_deployment.ido_local_backend")
        except Exception:
            return None


def _ido_inprocess_health(module) -> Dict[str, Any]:
    if not module:
        return {"ok": False, "checked": False, "error": "in-process backend unavailable"}
    return {
        "ok": not bool(getattr(module, "_MISSING_REQUIRED", [])),
        "checked": True,
        "mode": "inprocess",
        "backend_path": getattr(module, "BACKEND_PATH", ""),
        "loaded_modules": getattr(module, "_LOADED", {}),
        "required_modules": list(getattr(module, "_REQUIRED_MODULE_KEYS", [])),
        "missing_required_modules": getattr(module, "_MISSING_REQUIRED", []),
    }


def _ido_target_allowed(target_path: str) -> bool:
    path = "/" + target_path.lstrip("/")
    if path.startswith("/api/sites"):
        return False
    return any(path.startswith(prefix) for prefix in IDO_PROXY_ALLOWED_PREFIXES)


def _ido_to_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _ido_local_ping(ip_address: str, ping_count: int = 4) -> Dict[str, Any]:
    try:
        from ping3 import ping as ping3_ping
    except Exception:
        ping3_ping = None
    count = max(1, min(int(ping_count or 4), 10))
    samples = []
    if ping3_ping:
        for _ in range(count):
            try:
                samples.append(ping3_ping(ip_address, unit="ms", timeout=1.5))
            except Exception:
                samples.append(None)
    ok = [x for x in samples if isinstance(x, (int, float))]
    return {
        "success": True,
        "ip_address": ip_address,
        "ping_count": count,
        "successful": len(ok),
        "loss_percent": round((1 - (len(ok) / count)) * 100, 2),
        "avg_ms": round(sum(ok) / len(ok), 2) if ok else None,
        "max_ms": round(max(ok), 2) if ok else None,
        "samples_ms": samples,
    }


def _ido_local_generic(ip_address: str, run_tests: bool = False) -> Dict[str, Any]:
    try:
        name = socket.getfqdn(ip_address) or ip_address
    except Exception:
        name = ip_address
    out: Dict[str, Any] = {"success": True, "ip_address": ip_address, "name": name, "test_results": []}
    if run_tests:
        p = _ido_local_ping(ip_address, 4)
        out["test_results"].append({
            "name": "Ping",
            "actual": f"{p.get('successful')}/{p.get('ping_count')} successful",
            "expected": None,
            "pass": p.get("successful", 0) > 0,
        })
    return out


@app.get("/api/ido/capabilities")
def ido_capabilities():
    backend = _ido_backend_url()
    inprocess_module = None if backend else _ido_inprocess_module()
    backend_health: Dict[str, Any] = {"ok": False, "checked": False, "error": None}
    if backend:
        try:
            r = requests.get(urljoin(backend.rstrip("/") + "/", "health/full"), timeout=3)
            backend_health["checked"] = True
            if r.headers.get("content-type", "").lower().startswith("application/json"):
                data = r.json()
                backend_health.update(data if isinstance(data, dict) else {})
                backend_health["ok"] = bool(data.get("ok")) if isinstance(data, dict) else (r.status_code == 200)
            else:
                backend_health["ok"] = r.status_code == 200
            backend_health["status_code"] = r.status_code
        except Exception as exc:
            backend_health["checked"] = True
            backend_health["error"] = str(exc)
    elif inprocess_module:
        backend = "inprocess://ido-local"
        backend_health = _ido_inprocess_health(inprocess_module)
    return JSONResponse(
        content={
            "configured": bool(backend),
            "backend_url": backend,
            "backend_health": backend_health,
            "fallback_mode": ("embedded-partial" if not backend else ("inprocess-local" if backend.startswith("inprocess://") else "external")),
            "embedded_endpoints": ["/api/ping", "/api/generic/device_info"],
            "excluded": ["/api/sites"],
            "allowed_prefixes": list(IDO_PROXY_ALLOWED_PREFIXES),
        }
    )


@app.api_route("/api/ido/proxy/{target_path:path}", methods=["GET", "POST"], include_in_schema=False)
async def ido_proxy(target_path: str, request: Request):
    backend_url = _ido_backend_url()
    inprocess_module = None if backend_url else _ido_inprocess_module()
    if not _ido_target_allowed(target_path):
        raise HTTPException(
            status_code=403,
            detail=f"Target path '/{target_path.lstrip('/')}' is not allowed",
        )
    if not backend_url and inprocess_module:
        rel = "/" + target_path.lstrip("/")
        try:
            transport = httpx.ASGITransport(app=inprocess_module.app)
            async with httpx.AsyncClient(transport=transport, base_url="http://ido-local") as client:
                if request.method.upper() == "GET":
                    upstream = await client.get(rel, params=dict(request.query_params))
                else:
                    raw_body = await request.body()
                    headers = {}
                    content_type = request.headers.get("content-type", "")
                    if content_type:
                        headers["content-type"] = content_type
                    upstream = await client.post(rel, params=dict(request.query_params), content=raw_body or None, headers=headers or None)
                if upstream.status_code == 404 and target_path.startswith("api/"):
                    fallback_rel = "/" + target_path[4:].lstrip("/")
                    if request.method.upper() == "GET":
                        upstream = await client.get(fallback_rel, params=dict(request.query_params))
                    else:
                        raw_body = await request.body()
                        headers = {}
                        content_type = request.headers.get("content-type", "")
                        if content_type:
                            headers["content-type"] = content_type
                        upstream = await client.post(fallback_rel, params=dict(request.query_params), content=raw_body or None, headers=headers or None)
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"IDO in-process request failed: {exc}") from exc

        content_type = (upstream.headers.get("content-type") or "").lower()
        if "application/json" in content_type:
            try:
                return JSONResponse(content=upstream.json(), status_code=upstream.status_code)
            except Exception:
                return PlainTextResponse(content=upstream.text, status_code=upstream.status_code)
        return PlainTextResponse(content=upstream.text, status_code=upstream.status_code)
    if not backend_url:
        rel = "/" + target_path.lstrip("/")
        qp = dict(request.query_params)
        if request.method.upper() == "GET" and rel == "/api/ping":
            ip = (qp.get("ip_address") or "").strip()
            if not ip:
                raise HTTPException(status_code=422, detail="Missing query param: ip_address")
            return JSONResponse(content=_ido_local_ping(ip, qp.get("ping_count", 4)))
        if request.method.upper() == "GET" and rel == "/api/generic/device_info":
            ip = (qp.get("ip_address") or "").strip()
            if not ip:
                raise HTTPException(status_code=422, detail="Missing query param: ip_address")
            return JSONResponse(content=_ido_local_generic(ip, _ido_to_bool(qp.get("run_tests"), False)))
        raise HTTPException(
            status_code=503,
            detail=f"IDO backend URL is not configured. Embedded fallback supports only /api/ping and /api/generic/device_info (requested: {rel})",
        )

    url = urljoin(backend_url.rstrip("/") + "/", target_path.lstrip("/"))
    try:
        if request.method.upper() == "GET":
            upstream = requests.get(url, params=dict(request.query_params), timeout=60)
        else:
            raw_body = await request.body()
            content_type = request.headers.get("content-type", "")
            post_kwargs: Dict[str, Any] = {
                "params": dict(request.query_params),
                "timeout": 60,
            }
            if raw_body:
                post_kwargs["data"] = raw_body
                if content_type:
                    post_kwargs["headers"] = {"content-type": content_type}
            upstream = requests.post(url, **post_kwargs)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"IDO upstream request failed: {exc}") from exc

    # Compatibility fallback: some IDO backends expose endpoints without `/api/` prefix.
    if upstream.status_code == 404 and target_path.startswith("api/"):
        fallback_url = urljoin(backend_url.rstrip("/") + "/", target_path[4:].lstrip("/"))
        try:
            if request.method.upper() == "GET":
                upstream = requests.get(fallback_url, params=dict(request.query_params), timeout=60)
            else:
                raw_body = await request.body()
                content_type = request.headers.get("content-type", "")
                post_kwargs: Dict[str, Any] = {
                    "params": dict(request.query_params),
                    "timeout": 60,
                }
                if raw_body:
                    post_kwargs["data"] = raw_body
                    if content_type:
                        post_kwargs["headers"] = {"content-type": content_type}
                upstream = requests.post(fallback_url, **post_kwargs)
        except Exception:
            pass

    content_type = (upstream.headers.get("content-type") or "").lower()
    if "application/json" in content_type:
        try:
            return JSONResponse(content=upstream.json(), status_code=upstream.status_code)
        except Exception:
            return PlainTextResponse(content=upstream.text, status_code=upstream.status_code)
    return PlainTextResponse(content=upstream.text, status_code=upstream.status_code)


def _mt_config_class(config_type: str) -> Type[Any]:
    config_map = {
        "tower": MTTowerConfig,
        "bng2": MTBNG2Config,
    }
    config_cls = config_map.get(config_type)
    if not config_cls:
        raise HTTPException(status_code=400, detail=f"Invalid config type: {config_type}")
    return config_cls


def _require_base_config_path() -> str:
    base_path = os.getenv("BASE_CONFIG_PATH") or os.getenv("NEXTLINK_BASE_CONFIG_PATH")
    fallback = os.path.join(os.path.dirname(__file__), "base_configs")

    def _required_dirs(path: str):
        return [
            os.path.join(path, "Router", "Tower", "config"),
            os.path.join(path, "Router", "Tower", "port_map"),
            os.path.join(path, "Router", "BNG2", "config"),
            os.path.join(path, "Router", "BNG2", "port_map"),
        ]

    if base_path:
        missing = [d for d in _required_dirs(base_path) if not os.path.isdir(d)]
        if not missing:
            return base_path

    missing_fallback = [d for d in _required_dirs(fallback) if not os.path.isdir(d)]
    if not missing_fallback:
        return fallback

    raise HTTPException(
        status_code=500,
        detail={
            "error": "No valid MikroTik base config template path found",
            "configured_base_config_path": base_path,
            "missing_in_configured_path": _required_dirs(base_path) if base_path else [],
            "fallback_path": fallback,
            "missing_in_fallback_path": missing_fallback,
        },
    )


@app.post("/api/mt/{config_type}/config")
def mt_generate_config(config_type: str, payload: Dict[str, Any] = Body(default_factory=dict)):
    _require_base_config_path()
    config_cls = _mt_config_class(config_type)
    try:
        local_payload = ido_merge_defaults(config_type, dict(payload or {}))
        apply_compliance = _ido_to_bool(local_payload.pop("apply_compliance", True), True)
        payload_loopback = local_payload.get("loopback_subnet") or local_payload.get("loop_ip")
        cfg = config_cls(**local_payload)
        # Keep response shape compatible: frontend expects response.json() -> string
        config_text = cfg.generate_config()
        if apply_compliance:
            config_text = ido_apply_compliance(config_text, payload_loopback)
        if config_type == "bng2":
            config_text = MTBNG2Config._sanitize_transport_only_output(config_text)
        return JSONResponse(content=config_text)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.post("/api/mt/{config_type}/portmap")
def mt_generate_portmap(config_type: str, payload: Dict[str, Any] = Body(default_factory=dict)):
    _require_base_config_path()
    config_cls = _mt_config_class(config_type)
    try:
        cfg = config_cls(**ido_merge_defaults(config_type, dict(payload or {})))
        # Keep response shape compatible: frontend expects response.json() -> string
        return JSONResponse(content=cfg.generate_port_map())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@app.get("/api/ido/defaults")
def ido_defaults(config_type: str | None = None):
    return JSONResponse(content=ido_get_defaults(config_type))


@app.get("/api/ido/templates")
def ido_templates(config_type: str | None = None):
    return JSONResponse(content=ido_get_templates(config_type))


@app.get("/api/ido/device-profiles")
def ido_device_profiles():
    return JSONResponse(content=ido_get_device_profiles())


@app.get("/api/ido/compliance")
def ido_compliance(loopback_ip: str = "10.0.0.1"):
    return JSONResponse(content={"compliance": ido_get_compliance(loopback_ip)})


@app.get("/api/ido/compliance/status")
def ido_compliance_status():
    """Diagnostic: check GitLab compliance configuration and cache state."""
    try:
        from gitlab_compliance import get_loader as _gl
    except ImportError:
        try:
            from vm_deployment.gitlab_compliance import get_loader as _gl
        except ImportError:
            return JSONResponse(content={"configured": False, "detail": "gitlab_compliance module not available"})
    loader = _gl()
    configured = loader.is_configured()
    info = loader.diagnostics()
    info["configured"] = configured
    if configured:
        info["available"] = loader.is_available()
    return JSONResponse(content=info)


@app.post("/api/ido/compliance/refresh")
def ido_compliance_refresh():
    """Clear GitLab compliance cache — next request will re-fetch from GitLab."""
    try:
        from gitlab_compliance import get_loader as _gl
    except ImportError:
        try:
            from vm_deployment.gitlab_compliance import get_loader as _gl
        except ImportError:
            return JSONResponse(content={"status": "error", "detail": "gitlab_compliance module not available"}, status_code=500)
    loader = _gl()
    if not loader.is_configured():
        return JSONResponse(content={
            "status": "warning",
            "detail": "GitLab compliance not configured (GITLAB_COMPLIANCE_TOKEN / GITLAB_COMPLIANCE_PROJECT_ID not set)"
        })
    loader.refresh()
    cache = loader.cache_info()
    return JSONResponse(content={"status": "ok", "detail": "Compliance cache cleared", "cache": cache})


@app.post("/api/ido/render")
def ido_render(config_type: str, payload: Dict[str, Any] = Body(default_factory=dict)):
    _require_base_config_path()
    config_cls = _mt_config_class(config_type)
    try:
        local_payload = ido_merge_defaults(config_type, dict(payload or {}))
        apply_compliance = _ido_to_bool(local_payload.pop("apply_compliance", True), True)
        payload_loopback = local_payload.get("loopback_subnet") or local_payload.get("loop_ip")
        cfg = config_cls(**local_payload)
        config_text = cfg.generate_config()
        if apply_compliance:
            config_text = ido_apply_compliance(config_text, payload_loopback)
        if config_type == "bng2":
            config_text = MTBNG2Config._sanitize_transport_only_output(config_text)
        return JSONResponse(
            content={
                "config": config_text,
                "portmap": cfg.generate_port_map(),
                "config_type": config_type,
            }
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc


# Mount all existing Flask routes at root
app.mount("/", WSGIMiddleware(flask_app))
