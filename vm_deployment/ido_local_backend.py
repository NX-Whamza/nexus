from __future__ import annotations

import os
import socket
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException, Response


def _discover_backend_path() -> str:
    candidates = [
        (os.getenv("IDO_BACKEND_PATH") or "").strip(),
        (os.getenv("IDO_TOOLS_BACKEND_PATH") or "").strip(),
        (os.getenv("NETLAUNCH_IDO_BACKEND_PATH") or "").strip(),
        (os.getenv("NETLAUNCH_TOOLS_BACKEND_PATH") or "").strip(),
        str(Path(__file__).resolve().parent / "ido_modules"),
        "/opt/netlaunch-tools-backend",
        "/opt/netlaunch-tools-backend/netlaunch-tools-backend-main",
        "/opt/ido-backend",
        "/opt/ido-backend/ido-backend-main",
        "/app/external/netlaunch-tools-backend-main",
        "/app/external/netlaunch-tools-backend-main/netlaunch-tools-backend-main",
        "/app/external/ido-backend-main",
        "/app/external/ido-backend-main/ido-backend-main",
        str(Path(__file__).resolve().parents[2] / "netlaunch-tools-backend-main" / "netlaunch-tools-backend-main"),
        str(Path(__file__).resolve().parents[2] / "ido-backend-main" / "ido-backend-main"),
        r"C:\Users\WalihlahHamza\Downloads\netlaunch-tools-backend-main\netlaunch-tools-backend-main",
        r"C:\Users\WalihlahHamza\Downloads\ido-backend-main\ido-backend-main",
    ]
    for candidate in candidates:
        if not candidate:
            continue
        p = Path(candidate)
        if (p / "rest").is_dir():
            return str(p)
    return ""


BACKEND_PATH = _discover_backend_path()
if BACKEND_PATH and BACKEND_PATH not in sys.path:
    sys.path.insert(0, BACKEND_PATH)

if BACKEND_PATH:
    os.environ.setdefault("BASE_CONFIG_PATH", BACKEND_PATH)
    os.environ.setdefault("FIRMWARE_PATH", BACKEND_PATH)
    # Field Config Studio device defaults for netlaunch modules.
    # Most modules use username "admin" and password from these env keys.
    _ssh_pw = (os.getenv("NEXTLINK_SSH_PASSWORD") or "").strip()
    if _ssh_pw:
        os.environ.setdefault("AP_STANDARD_PW", _ssh_pw)
        os.environ.setdefault("SM_STANDARD_PW", _ssh_pw)
        os.environ.setdefault("BH_STANDARD_PW", _ssh_pw)
        os.environ.setdefault("SWT_STANDARD_PW", _ssh_pw)
        os.environ.setdefault("RPC_STANDARD_PW", _ssh_pw)
        os.environ.setdefault("CNMATRIX_STANDARD_PW", _ssh_pw)
        os.environ.setdefault("WAVE_AP_PASS", _ssh_pw)
    # BNG_SSH_SERVER_CONFIG may point into a read-only bind mount in Docker.
    # Prefer existing file in backend path, otherwise create a writable runtime stub.
    try:
        configured_stub = (os.getenv("BNG_SSH_SERVER_CONFIG") or "").strip()
        if configured_stub:
            os.environ.setdefault("BNG_SSH_SERVER_CONFIG", configured_stub)
        else:
            backend_stub = Path(BACKEND_PATH) / ".bng_ssh_servers.json"
            if backend_stub.exists():
                os.environ.setdefault("BNG_SSH_SERVER_CONFIG", str(backend_stub))
            else:
                runtime_dir = Path(os.getenv("NOC_RUNTIME_DIR", "/tmp"))
                runtime_dir.mkdir(parents=True, exist_ok=True)
                runtime_stub = runtime_dir / "bng_ssh_servers.json"
                if not runtime_stub.exists():
                    runtime_stub.write_text("[]", encoding="utf-8")
                os.environ.setdefault("BNG_SSH_SERVER_CONFIG", str(runtime_stub))
    except Exception:
        # Keep startup resilient; downstream modules can handle missing file.
        pass

app = FastAPI(title="IDO Local Backend", version="1.0")


@app.get("/health")
def health():
    return {"ok": True, "backend_path": BACKEND_PATH or ""}


@app.get("/health/full")
def health_full(response: Response):
    ok = bool(BACKEND_PATH) and not _MISSING_REQUIRED
    if not ok:
        response.status_code = 503
    return {
        "ok": ok,
        "backend_path": BACKEND_PATH or "",
        "loaded_modules": _LOADED,
        "required_modules": list(_REQUIRED_MODULE_KEYS),
        "missing_required_modules": _MISSING_REQUIRED,
    }


def _safe_include(import_path: str, attr: str = "app") -> bool:
    try:
        module = __import__(import_path, fromlist=[attr])
        router = getattr(module, attr)
        app.include_router(router)
        return True
    except Exception:
        return False


_LOADED = {
    "ping": _safe_include("rest.ping"),
    "generic": _safe_include("rest.device_info"),
    "ap": _safe_include("rest.ap"),
    "bh": _safe_include("rest.backhaul"),
    "ups": _safe_include("rest.ups"),
    "rpc": _safe_include("rest.rpc"),
    "swt": _safe_include("rest.switch"),
    "waveconfig": _safe_include("rest.waveconfig"),
    "config7250": _safe_include("rest.config7250"),
}


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    val = str(raw).strip().lower()
    if val in {"1", "true", "yes", "y", "on"}:
        return True
    if val in {"0", "false", "no", "n", "off"}:
        return False
    return default


_REQUIRED_MODULE_KEYS = (
    "ping",
    "generic",
    "ap",
    "bh",
    "rpc",
    "swt",
    "waveconfig",
    "config7250",
)
_MISSING_REQUIRED = [k for k in _REQUIRED_MODULE_KEYS if not _LOADED.get(k)]

if _env_bool("IDO_REQUIRE_FULL_MODULES", False) and _MISSING_REQUIRED:
    raise RuntimeError(
        "IDO local backend started without required modules: "
        + ", ".join(_MISSING_REQUIRED)
        + f" | backend_path={BACKEND_PATH or '<not-found>'}"
    )


def _to_bool(v, default=False):
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in {"1", "true", "yes", "y", "on"}:
        return True
    if s in {"0", "false", "no", "n", "off"}:
        return False
    return default


def _local_ping(ip_address: str, ping_count: int = 4):
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


def _local_generic(ip_address: str, run_tests: bool = False):
    try:
        name = socket.getfqdn(ip_address) or ip_address
    except Exception:
        name = ip_address
    out = {"success": True, "ip_address": ip_address, "name": name, "test_results": []}
    if run_tests:
        p = _local_ping(ip_address, 4)
        out["test_results"].append({
            "name": "Ping",
            "actual": f"{p.get('successful')}/{p.get('ping_count')} successful",
            "expected": None,
            "pass": p.get("successful", 0) > 0,
        })
    return out


def _unavailable(detail: str):
    raise HTTPException(status_code=501, detail=detail)


if not _LOADED.get("rpc"):
    @app.get("/api/rpc/device_info")
    def rpc_device_info_unavailable():
        raise HTTPException(status_code=501, detail="RPC module unavailable in local IDO backend")

    @app.post("/api/rpc/configure")
    def rpc_configure_unavailable():
        raise HTTPException(status_code=501, detail="RPC configure module unavailable in local IDO backend")


if not _LOADED.get("swt"):
    @app.get("/api/swt/device_info")
    def swt_device_info_unavailable():
        raise HTTPException(status_code=501, detail="Switch module unavailable in local IDO backend")

    @app.post("/api/swt/configure")
    def swt_configure_unavailable():
        raise HTTPException(status_code=501, detail="Switch configure module unavailable in local IDO backend")


if not _LOADED.get("ups"):
    @app.get("/api/ups/device_info")
    def ups_device_info_unavailable():
        _unavailable("UPS module unavailable in local IDO backend")

    @app.post("/api/ups/configure")
    def ups_configure_unavailable():
        _unavailable("UPS configure module unavailable in local IDO backend")


if not _LOADED.get("ping"):
    @app.get("/api/ping")
    def ping_fallback(ip_address: str, ping_count: int = 4):
        return _local_ping(ip_address, ping_count)


if not _LOADED.get("generic"):
    @app.get("/api/generic/device_info")
    def generic_fallback(ip_address: str, run_tests: bool = False):
        return _local_generic(ip_address, run_tests=_to_bool(run_tests, False))


if not _LOADED.get("ap"):
    @app.get("/api/ap/device_info")
    def ap_info_unavailable():
        _unavailable("AP module unavailable in local IDO backend")

    @app.get("/api/ap/running_config")
    def ap_running_unavailable():
        _unavailable("AP running-config module unavailable in local IDO backend")

    @app.get("/api/ap/standard_config")
    def ap_standard_unavailable():
        _unavailable("AP standard-config module unavailable in local IDO backend")

    @app.post("/api/ap/configure")
    def ap_configure_unavailable():
        _unavailable("AP configure module unavailable in local IDO backend")


if not _LOADED.get("bh"):
    @app.get("/api/bh/device_info")
    def bh_info_unavailable():
        _unavailable("Backhaul module unavailable in local IDO backend")

    @app.get("/api/bh/running_config")
    def bh_running_unavailable():
        _unavailable("Backhaul running-config module unavailable in local IDO backend")

    @app.get("/api/bh/standard_config")
    def bh_standard_unavailable():
        _unavailable("Backhaul standard-config module unavailable in local IDO backend")


if not _LOADED.get("waveconfig"):
    @app.post("/api/waveconfig/full_config")
    def waveconfig_unavailable():
        _unavailable("Waveconfig module unavailable in local IDO backend")


if not _LOADED.get("config7250"):
    @app.post("/api/7250config/generate")
    def nokia7250_unavailable():
        _unavailable("7250 config module unavailable in local IDO backend")
