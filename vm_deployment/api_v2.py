#!/usr/bin/env python3
"""
API v2 (contract-first layer) for NOC ConfigMaker.

This module adds:
- API key + scope auth for /api/v2
- Async job model (submit/status/events/cancel)
- Stable action registry so external UIs (OMNI/Mushu/etc.) can drive backend safely
"""

from __future__ import annotations

import json
import os
import hashlib
import hmac
import secrets
import sqlite3
import threading
import uuid
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin

import requests
from fastapi import APIRouter, Body, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse

try:
    from mt_config_gen.mt_tower import MTTowerConfig
    from mt_config_gen.mt_bng2 import MTBNG2Config
except Exception:
    from vm_deployment.mt_config_gen.mt_tower import MTTowerConfig
    from vm_deployment.mt_config_gen.mt_bng2 import MTBNG2Config

from ido_adapter import apply_compliance as ido_apply_compliance
from ido_adapter import merge_defaults as ido_merge_defaults


router = APIRouter(prefix="/api/v2", tags=["NOC API v2"])


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_now() -> str:
    return _utc_now().isoformat().replace("+00:00", "Z")


def _request_id() -> str:
    return str(uuid.uuid4())


def _secure_data_dir() -> Path:
    base = (os.getenv("NOC_RUNTIME_DIR") or "").strip()
    if base:
        p = Path(base)
    else:
        p = Path(__file__).resolve().parents[1] / "secure_data"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _db_path() -> Path:
    return _secure_data_dir() / "api_v2.db"


def _db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_db_path()), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _json_dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, sort_keys=True)


def _body_hash(body_bytes: bytes) -> str:
    return hashlib.sha256(body_bytes).hexdigest()


def _request_body_bytes(request: Request) -> bytes:
    cached = getattr(request.state, "_cached_body", None)
    if cached is None:
        cached = b""
        setattr(request.state, "_cached_body", cached)
    return cached


def _canonical_signing_message(request: Request, body_bytes: bytes, ts: str, nonce: str) -> str:
    return "\n".join(
        [
            request.method.upper(),
            request.url.path,
            ts,
            nonce,
            _body_hash(body_bytes),
        ]
    )


def _parse_signing_keys() -> Dict[str, str]:
    records: Dict[str, str] = {}
    raw_json = (os.getenv("NOC_API_SIGNING_KEYS_JSON") or "").strip()
    if raw_json:
        try:
            parsed = json.loads(raw_json)
            if isinstance(parsed, dict):
                for kid, secret in parsed.items():
                    if str(kid).strip() and str(secret).strip():
                        records[str(kid).strip()] = str(secret).strip()
        except Exception:
            pass
    raw_compact = (os.getenv("NOC_API_SIGNING_KEYS") or "").strip()
    if raw_compact:
        for entry in raw_compact.split(";"):
            entry = entry.strip()
            if not entry or ":" not in entry:
                continue
            kid, secret = entry.split(":", 1)
            kid = kid.strip()
            secret = secret.strip()
            if kid and secret:
                records[kid] = secret
    return records


_SIGNING_KEYS = _parse_signing_keys()
_SIGNATURE_REQUIRED = (os.getenv("NOC_API_V2_REQUIRE_SIGNATURE", "true").strip().lower() not in {"0", "false", "no"})
_IDEMPOTENCY_REQUIRED = (os.getenv("NOC_API_V2_REQUIRE_IDEMPOTENCY", "true").strip().lower() not in {"0", "false", "no"})
_SIGNATURE_SKEW_SECONDS = int((os.getenv("NOC_API_V2_SIGNATURE_SKEW_SECONDS") or "300").strip())
_NONCE_TTL_SECONDS = int((os.getenv("NOC_API_V2_NONCE_TTL_SECONDS") or "900").strip())
_IDEMPOTENCY_TTL_SECONDS = int((os.getenv("NOC_API_V2_IDEMPOTENCY_TTL_SECONDS") or "86400").strip())


def _envelope(
    *,
    status: str,
    data: Any = None,
    message: str = "",
    errors: Optional[List[str]] = None,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "request_id": request_id or _request_id(),
        "status": status,
        "message": message,
        "data": data,
        "errors": errors or [],
        "timestamp": _iso_now(),
    }


def _parse_api_keys() -> Dict[str, Set[str]]:
    """
    Supports:
    - NOC_API_KEYS_JSON='{"key1":["admin"],"key2":["config.read","job.submit"]}'
    - NOC_API_KEYS='key1:admin,config.read;key2:config.read'
    - NOC_API_KEY='single-key' (grants admin)
    """
    records: Dict[str, Set[str]] = {}

    raw_json = (os.getenv("NOC_API_KEYS_JSON") or "").strip()
    if raw_json:
        try:
            parsed = json.loads(raw_json)
            if isinstance(parsed, dict):
                for key, scopes in parsed.items():
                    if not key:
                        continue
                    if isinstance(scopes, (list, tuple)):
                        records[str(key)] = {str(s).strip() for s in scopes if str(s).strip()}
                    elif isinstance(scopes, str):
                        records[str(key)] = {s.strip() for s in scopes.split(",") if s.strip()}
        except Exception:
            pass

    raw_compact = (os.getenv("NOC_API_KEYS") or "").strip()
    if raw_compact:
        for entry in raw_compact.split(";"):
            entry = entry.strip()
            if not entry:
                continue
            if ":" in entry:
                key, scope_csv = entry.split(":", 1)
                scopes = {s.strip() for s in scope_csv.split(",") if s.strip()}
            else:
                key, scopes = entry, {"admin"}
            key = key.strip()
            if key:
                records[key] = scopes or {"admin"}

    single = (os.getenv("NOC_API_KEY") or "").strip()
    if single:
        records.setdefault(single, {"admin"})

    return records


_API_KEYS = _parse_api_keys()


def _init_db() -> None:
    conn = _db_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS v2_jobs (
                job_id TEXT PRIMARY KEY,
                request_id TEXT,
                action TEXT NOT NULL,
                submitted_by TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                result_json TEXT,
                error_text TEXT,
                cancel_requested INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_v2_jobs_created_at ON v2_jobs(created_at DESC)")
        # Additive migration: add tenant_id column if missing
        cur.execute("PRAGMA table_info(v2_jobs)")
        existing_cols = {r[1] for r in cur.fetchall()}
        if 'tenant_id' not in existing_cols:
            cur.execute("ALTER TABLE v2_jobs ADD COLUMN tenant_id INTEGER")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_v2_jobs_tenant_id ON v2_jobs(tenant_id)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS v2_job_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                ts TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_v2_job_events_job_id ON v2_job_events(job_id, id)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS v2_nonces (
                nonce TEXT PRIMARY KEY,
                key_id TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_v2_nonces_created_at ON v2_nonces(created_at)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS v2_idempotency (
                idem_key TEXT NOT NULL,
                api_key TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                request_hash TEXT NOT NULL,
                response_json TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY (idem_key, api_key, method, path)
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_v2_idempotency_expires_at ON v2_idempotency(expires_at)")
        conn.commit()
    finally:
        conn.close()


def _prune_nonce_store(conn: sqlite3.Connection) -> None:
    cutoff = int(datetime.now(timezone.utc).timestamp()) - _NONCE_TTL_SECONDS
    conn.execute("DELETE FROM v2_nonces WHERE created_at < ?", (cutoff,))


def _reserve_nonce(key_id: str, nonce: str) -> None:
    now_ts = int(datetime.now(timezone.utc).timestamp())
    conn = _db_conn()
    try:
        _prune_nonce_store(conn)
        conn.execute(
            "INSERT INTO v2_nonces(nonce, key_id, created_at) VALUES(?,?,?)",
            (nonce, key_id, now_ts),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Replay detected: nonce already used")
    finally:
        conn.close()


def _load_idempotency(
    *,
    idem_key: str,
    api_key: str,
    method: str,
    path: str,
    request_hash: str,
) -> Optional[Tuple[int, Dict[str, Any]]]:
    now_ts = int(datetime.now(timezone.utc).timestamp())
    conn = _db_conn()
    try:
        conn.execute("DELETE FROM v2_idempotency WHERE expires_at < ?", (now_ts,))
        row = conn.execute(
            """
            SELECT request_hash, response_json, status_code
            FROM v2_idempotency
            WHERE idem_key=? AND api_key=? AND method=? AND path=? AND expires_at>=?
            """,
            (idem_key, api_key, method, path, now_ts),
        ).fetchone()
        conn.commit()
        if not row:
            return None
        if row["request_hash"] != request_hash:
            raise HTTPException(status_code=409, detail="Idempotency-Key reused with different payload")
        return int(row["status_code"]), json.loads(row["response_json"])
    finally:
        conn.close()


def _save_idempotency(
    *,
    idem_key: str,
    api_key: str,
    method: str,
    path: str,
    request_hash: str,
    status_code: int,
    response_json: Dict[str, Any],
) -> None:
    now_ts = int(datetime.now(timezone.utc).timestamp())
    exp_ts = now_ts + _IDEMPOTENCY_TTL_SECONDS
    conn = _db_conn()
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO v2_idempotency(
                idem_key, api_key, method, path, request_hash, response_json, status_code, created_at, expires_at
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                idem_key,
                api_key,
                method,
                path,
                request_hash,
                _json_dumps(response_json),
                status_code,
                now_ts,
                exp_ts,
            ),
        )
        conn.commit()
    finally:
        conn.close()


_init_db()


def _require_scope(required: str) -> Callable[..., Dict[str, Any]]:
    async def _dep(
        request: Request,
        x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
        authorization: Optional[str] = Header(default=None, alias="Authorization"),
        x_key_id: Optional[str] = Header(default=None, alias="X-Key-Id"),
        x_timestamp: Optional[str] = Header(default=None, alias="X-Timestamp"),
        x_nonce: Optional[str] = Header(default=None, alias="X-Nonce"),
        x_signature: Optional[str] = Header(default=None, alias="X-Signature"),
    ) -> Dict[str, Any]:
        if not _API_KEYS:
            raise HTTPException(
                status_code=503,
                detail="API keys are not configured for /api/v2 (set NOC_API_KEYS_JSON or NOC_API_KEYS)",
            )
        token = (x_api_key or "").strip()
        if not token and authorization and authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1].strip()
        if not token:
            raise HTTPException(status_code=401, detail="Missing API key")
        scopes = _API_KEYS.get(token)
        if scopes is None:
            raise HTTPException(status_code=403, detail="Invalid API key")
        if "admin" not in scopes and required not in scopes:
            raise HTTPException(status_code=403, detail=f"Insufficient scope; need '{required}'")

        body_bytes = await request.body()
        setattr(request.state, "_cached_body", body_bytes)

        if _SIGNATURE_REQUIRED:
            if not _SIGNING_KEYS:
                raise HTTPException(status_code=503, detail="Request-signing is required but no signing keys are configured")
            key_id = (x_key_id or "").strip()
            ts_raw = (x_timestamp or "").strip()
            nonce = (x_nonce or "").strip()
            signature = (x_signature or "").strip()
            if not key_id or not ts_raw or not nonce or not signature:
                raise HTTPException(status_code=401, detail="Missing signature headers (X-Key-Id, X-Timestamp, X-Nonce, X-Signature)")

            signing_secret = _SIGNING_KEYS.get(key_id)
            if not signing_secret:
                raise HTTPException(status_code=403, detail="Unknown signing key id")

            try:
                ts_val = int(ts_raw)
            except ValueError:
                raise HTTPException(status_code=401, detail="Invalid X-Timestamp")
            now_ts = int(datetime.now(timezone.utc).timestamp())
            if abs(now_ts - ts_val) > _SIGNATURE_SKEW_SECONDS:
                raise HTTPException(status_code=401, detail="Request timestamp out of allowed window")

            canonical = _canonical_signing_message(request, body_bytes, ts_raw, nonce)
            expected = hmac.new(signing_secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                raise HTTPException(status_code=401, detail="Invalid request signature")

            _reserve_nonce(key_id, nonce)

        return {"api_key": token, "scopes": sorted(scopes)}

    return _dep


def _legacy_api_base() -> str:
    return (os.getenv("NOC_LEGACY_API_BASE") or "http://127.0.0.1:5000").rstrip("/")


def _mt_config_class(config_type: str):
    mapping = {
        "tower": MTTowerConfig,
        "bng2": MTBNG2Config,
    }
    cls = mapping.get((config_type or "").strip().lower())
    if not cls:
        raise ValueError(f"Unsupported config_type '{config_type}'")
    return cls


def _render_mt(action: str, payload: Dict[str, Any]) -> Any:
    config_type = (payload.get("config_type") or payload.get("type") or "").strip().lower()
    if not config_type:
        raise ValueError("Missing config_type")
    config_cls = _mt_config_class(config_type)
    local_payload = ido_merge_defaults(config_type, dict(payload.get("payload") or payload.get("data") or payload))
    apply_compliance = bool(local_payload.pop("apply_compliance", True))
    payload_loopback = local_payload.get("loopback_subnet") or local_payload.get("loop_ip")
    cfg = config_cls(**local_payload)
    if action == "mt.portmap":
        return cfg.generate_port_map()
    config_text = cfg.generate_config()
    if apply_compliance:
        config_text = ido_apply_compliance(config_text, payload_loopback)
    if config_type == "bng2":
        # Compliance blocks are shared across profiles; sanitize transport-only BNG2 output after compliance merge.
        config_text = MTBNG2Config._sanitize_transport_only_output(config_text)
    if action == "mt.config":
        return config_text
    return {"config": config_text, "portmap": cfg.generate_port_map(), "config_type": config_type}


def _legacy_call(payload: Dict[str, Any]) -> Any:
    method = str(payload.get("method") or "GET").upper()
    path = str(payload.get("path") or "").strip()
    if not path.startswith("/api/"):
        raise ValueError("legacy path must start with /api/")
    if path.startswith("/api/v2/"):
        raise ValueError("legacy path cannot target /api/v2/")

    timeout = int(payload.get("timeout") or 120)
    url = urljoin(_legacy_api_base() + "/", path.lstrip("/"))
    params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
    headers = payload.get("headers") if isinstance(payload.get("headers"), dict) else {}
    body = payload.get("body")

    if method == "GET":
        resp = requests.get(url, params=params, headers=headers, timeout=timeout)
    elif method == "POST":
        resp = requests.post(url, params=params, headers=headers, json=body, timeout=timeout)
    elif method == "PUT":
        resp = requests.put(url, params=params, headers=headers, json=body, timeout=timeout)
    elif method == "PATCH":
        resp = requests.patch(url, params=params, headers=headers, json=body, timeout=timeout)
    elif method == "DELETE":
        resp = requests.delete(url, params=params, headers=headers, timeout=timeout)
    else:
        raise ValueError(f"Unsupported method '{method}'")

    content_type = (resp.headers.get("content-type") or "").lower()
    data: Any
    if "application/json" in content_type:
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text}
    else:
        data = {"raw": resp.text}

    return {
        "http_status": resp.status_code,
        "ok": 200 <= resp.status_code < 300,
        "path": path,
        "method": method,
        "response": data,
    }


def _legacy_get(path: str) -> Callable[[Dict[str, Any]], Any]:
    def _handler(payload: Dict[str, Any]) -> Any:
        params = payload.get("params") if isinstance(payload.get("params"), dict) else payload
        return _legacy_call({"method": "GET", "path": path, "params": params})
    return _handler


def _legacy_post(path: str) -> Callable[[Dict[str, Any]], Any]:
    def _handler(payload: Dict[str, Any]) -> Any:
        body = payload.get("body") if isinstance(payload.get("body"), dict) else payload
        return _legacy_call({"method": "POST", "path": path, "body": body})
    return _handler


def _legacy_put(path: str) -> Callable[[Dict[str, Any]], Any]:
    def _handler(payload: Dict[str, Any]) -> Any:
        body = payload.get("body") if isinstance(payload.get("body"), dict) else payload
        return _legacy_call({"method": "PUT", "path": path, "body": body})
    return _handler


def _ido_proxy_call(target_path: str, payload: Dict[str, Any]) -> Any:
    method = str(payload.get("method") or "POST").upper()
    body = payload.get("body") if isinstance(payload.get("body"), dict) else payload
    params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
    proxy_path = f"/api/ido/proxy/{target_path.lstrip('/')}"
    return _legacy_call({"method": method, "path": proxy_path, "params": params, "body": body})


def _require_int(payload: Dict[str, Any], key: str) -> int:
    try:
        return int(payload.get(key))
    except Exception:
        raise ValueError(f"Missing or invalid '{key}'")


def _configs_get(payload: Dict[str, Any]) -> Any:
    config_id = _require_int(payload, "config_id")
    return _legacy_call({"method": "GET", "path": f"/api/get-completed-config/{config_id}"})


def _configs_portmap_download(payload: Dict[str, Any]) -> Any:
    config_id = _require_int(payload, "config_id")
    return _legacy_call({"method": "GET", "path": f"/api/download-port-map/{config_id}"})


def _aviat_abort(payload: Dict[str, Any]) -> Any:
    task_id = str(payload.get("task_id") or "").strip()
    if not task_id:
        raise ValueError("Missing 'task_id'")
    body = payload.get("body") if isinstance(payload.get("body"), dict) else {}
    return _legacy_call({"method": "POST", "path": f"/api/aviat/abort/{task_id}", "body": body})


def _aviat_status(payload: Dict[str, Any]) -> Any:
    task_id = str(payload.get("task_id") or "").strip()
    if not task_id:
        raise ValueError("Missing 'task_id'")
    return _legacy_call({"method": "GET", "path": f"/api/aviat/status/{task_id}"})


def _admin_feedback_update_status(payload: Dict[str, Any]) -> Any:
    feedback_id = _require_int(payload, "feedback_id")
    body = {k: v for k, v in payload.items() if k != "feedback_id"}
    return _legacy_call({"method": "PUT", "path": f"/api/admin/feedback/{feedback_id}/status", "body": body})


def _compliance_policy_get(payload: Dict[str, Any]) -> Any:
    policy_name = str(payload.get("policy_name") or "").strip()
    if not policy_name:
        raise ValueError("Missing 'policy_name'")
    return _legacy_call({"method": "GET", "path": f"/api/get-config-policy/{policy_name}"})


@dataclass
class JobEvent:
    ts: str
    level: str
    message: str


@dataclass
class JobRecord:
    job_id: str
    action: str
    submitted_by: str
    request_id: str
    payload: Dict[str, Any] = field(default_factory=dict)
    status: str = "queued"  # queued|running|success|error|cancelled
    created_at: str = field(default_factory=_iso_now)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    result: Any = None
    error: Optional[str] = None
    cancel_requested: bool = False
    events: List[JobEvent] = field(default_factory=list)
    tenant_id: Optional[int] = None


class JobManager:
    def __init__(self):
        self._jobs: Dict[str, JobRecord] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=int(os.getenv("NOC_API_V2_JOB_WORKERS", "8")))
        self._hydrate_from_db()

    def _hydrate_from_db(self) -> None:
        conn = _db_conn()
        try:
            rows = conn.execute(
                """
                SELECT job_id, request_id, action, submitted_by, payload_json, status, created_at,
                       started_at, finished_at, result_json, error_text, cancel_requested
                FROM v2_jobs
                ORDER BY created_at DESC
                LIMIT 2000
                """
            ).fetchall()
            for row in rows:
                payload = json.loads(row["payload_json"] or "{}")
                result = json.loads(row["result_json"]) if row["result_json"] else None
                job = JobRecord(
                    job_id=row["job_id"],
                    action=row["action"],
                    submitted_by=row["submitted_by"],
                    request_id=row["request_id"] or "",
                    payload=payload,
                    status=row["status"],
                    created_at=row["created_at"],
                    started_at=row["started_at"],
                    finished_at=row["finished_at"],
                    result=result,
                    error=row["error_text"],
                    cancel_requested=bool(row["cancel_requested"]),
                )
                if job.status in {"queued", "running"}:
                    job.status = "error"
                    job.error = "Job interrupted by service restart"
                    if not job.finished_at:
                        job.finished_at = _iso_now()
                    conn.execute(
                        "UPDATE v2_jobs SET status=?, error_text=?, finished_at=? WHERE job_id=?",
                        (job.status, job.error, job.finished_at, job.job_id),
                    )
                ev_rows = conn.execute(
                    "SELECT ts, level, message FROM v2_job_events WHERE job_id=? ORDER BY id ASC",
                    (job.job_id,),
                ).fetchall()
                job.events = [JobEvent(ts=e["ts"], level=e["level"], message=e["message"]) for e in ev_rows]
                self._jobs[job.job_id] = job
            conn.commit()
        finally:
            conn.close()

    def _persist_job(self, job: JobRecord) -> None:
        conn = _db_conn()
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO v2_jobs(
                    job_id, request_id, action, submitted_by, payload_json, status, created_at, started_at, finished_at,
                    result_json, error_text, cancel_requested, tenant_id
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    job.job_id,
                    job.request_id,
                    job.action,
                    job.submitted_by,
                    _json_dumps(job.payload),
                    job.status,
                    job.created_at,
                    job.started_at,
                    job.finished_at,
                    _json_dumps(job.result) if job.result is not None else None,
                    job.error,
                    1 if job.cancel_requested else 0,
                    job.tenant_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def add_event(self, job: JobRecord, level: str, message: str) -> None:
        evt = JobEvent(ts=_iso_now(), level=level, message=message)
        with self._lock:
            job.events.append(evt)
            if len(job.events) > 500:
                job.events = job.events[-500:]
        conn = _db_conn()
        try:
            conn.execute(
                "INSERT INTO v2_job_events(job_id, ts, level, message) VALUES(?,?,?,?)",
                (job.job_id, evt.ts, evt.level, evt.message),
            )
            conn.execute(
                """
                DELETE FROM v2_job_events
                WHERE job_id=?
                  AND id NOT IN (
                      SELECT id FROM v2_job_events
                      WHERE job_id=?
                      ORDER BY id DESC
                      LIMIT 500
                  )
                """,
                (job.job_id, job.job_id),
            )
            conn.commit()
        finally:
            conn.close()

    def submit(self, action: str, payload: Dict[str, Any], submitted_by: str, request_id: str) -> JobRecord:
        job = JobRecord(
            job_id=str(uuid.uuid4()),
            action=action,
            submitted_by=submitted_by,
            request_id=request_id,
            payload=payload or {},
        )
        with self._lock:
            self._jobs[job.job_id] = job
        self._persist_job(job)
        self._executor.submit(self._run, job.job_id)
        return job

    def _run(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
        if not job:
            return
        if job.cancel_requested:
            job.status = "cancelled"
            job.finished_at = _iso_now()
            self._persist_job(job)
            return
        job.status = "running"
        job.started_at = _iso_now()
        self._persist_job(job)
        self.add_event(job, "info", f"Started action '{job.action}'")
        try:
            handler = _ACTION_HANDLERS.get(job.action)
            if not handler:
                raise ValueError(f"Unsupported action '{job.action}'")
            if job.cancel_requested:
                job.status = "cancelled"
                job.finished_at = _iso_now()
                return
            job.result = handler(job.payload)
            if job.cancel_requested:
                job.status = "cancelled"
            else:
                job.status = "success"
                self.add_event(job, "success", "Action completed")
        except Exception as exc:
            job.status = "error"
            job.error = str(exc)
            self.add_event(job, "error", str(exc))
        finally:
            job.finished_at = _iso_now()
            self._persist_job(job)

    def get(self, job_id: str) -> Optional[JobRecord]:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self, limit: int = 100) -> List[JobRecord]:
        with self._lock:
            jobs = list(self._jobs.values())
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return jobs[: max(1, min(limit, 1000))]

    def cancel(self, job_id: str) -> Optional[JobRecord]:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            job.cancel_requested = True
            if job.status == "queued":
                job.status = "cancelled"
                job.finished_at = _iso_now()
        if job:
            self.add_event(job, "warning", "Cancel requested")
            self._persist_job(job)
        return job


_JOBS = JobManager()


def _get_tenant_id_for_api_key(api_key, conn):
    """Get the default tenant_id for an API key owner. Returns None if not resolvable."""
    try:
        # V2 API keys are not directly tied to users in the current model
        # Default to the platform default tenant for backward compatibility
        from vm_deployment.api_server import _get_default_tenant_id
        return _get_default_tenant_id(conn)
    except Exception:
        return None


_ACTION_HANDLERS: Dict[str, Callable[[Dict[str, Any]], Any]] = {
    # Native MikroTik generators
    "mt.render": lambda payload: _render_mt("mt.render", payload),
    "mt.config": lambda payload: _render_mt("mt.config", payload),
    "mt.portmap": lambda payload: _render_mt("mt.portmap", payload),

    # Generic legacy proxy (escape hatch, still whitelisted by backend)
    "legacy.proxy": _legacy_call,

    # Dashboard / shared reads
    "health.get": _legacy_get("/api/health"),
    "app.config.get": _legacy_get("/api/app-config"),
    "infrastructure.get": _legacy_get("/api/infrastructure"),
    "routerboards.list": _legacy_get("/api/get-routerboards"),

    # Activity / history
    "activity.list": lambda payload: _legacy_call(
        {
            "method": "GET",
            "path": "/api/get-activity",
            "params": payload.get("params") if isinstance(payload.get("params"), dict) else payload,
        }
    ),
    "activity.log": _legacy_post("/api/log-activity"),

    # Completed config store
    "configs.list": lambda payload: _legacy_call(
        {
            "method": "GET",
            "path": "/api/get-completed-configs",
            "params": payload.get("params") if isinstance(payload.get("params"), dict) else payload,
        }
    ),
    "configs.save": _legacy_post("/api/save-completed-config"),
    "configs.get": _configs_get,
    "configs.portmap.download": _configs_portmap_download,
    "configs.portmap.extract": _legacy_post("/api/extract-port-map"),

    # Migration / translation
    "migration.mikrotik_to_nokia": _legacy_post("/api/migrate-mikrotik-to-nokia"),
    "migration.config": _legacy_post("/api/migrate-config"),
    "compliance.apply": _legacy_post("/api/apply-compliance"),
    "config.validate": _legacy_post("/api/validate-config"),
    "config.suggest": _legacy_post("/api/suggest-config"),
    "config.explain": _legacy_post("/api/explain-config"),
    "config.translate": _legacy_post("/api/translate-config"),
    "config.autofill_from_export": _legacy_post("/api/autofill-from-export"),

    # FTTH
    "ftth.preview_bng": _legacy_post("/api/preview-ftth-bng"),
    "ftth.generate_bng": _legacy_post("/api/generate-ftth-bng"),
    "ftth.mf2_package": _legacy_post("/api/ftth-home/mf2-package"),

    # Nokia
    "nokia.generate_7250": _legacy_post("/api/generate-nokia7250"),
    "nokia.defaults": _legacy_get("/api/nokia7250-defaults"),

    # Enterprise
    "enterprise.generate_non_mpls": _legacy_post("/api/gen-enterprise-non-mpls"),

    # Tarana
    "tarana.generate": _legacy_post("/api/gen-tarana-config"),

    # SSH Config Fetch
    "device.fetch_config_ssh": _legacy_post("/api/fetch-config-ssh"),

    # Feedback
    "feedback.submit": _legacy_post("/api/feedback"),

    # Admin
    "admin.feedback.list": _legacy_get("/api/admin/feedback"),
    "admin.feedback.update_status": _admin_feedback_update_status,
    "admin.feedback.export": _legacy_get("/api/admin/feedback/export"),
    "admin.users.reset_password": _legacy_post("/api/admin/users/reset-password"),

    # Compliance / Config Policies
    "compliance.policies.list": _legacy_get("/api/get-config-policies"),
    "compliance.policies.get": _compliance_policy_get,
    "compliance.policies.bundle": _legacy_get("/api/get-config-policy-bundle"),
    "compliance.policies.reload": _legacy_post("/api/reload-config-policies"),
    "compliance.reload": _legacy_post("/api/reload-compliance"),
    "compliance.status": _legacy_get("/api/compliance-status"),
    "compliance.blocks": _legacy_get("/api/compliance/blocks"),
    "compliance.engineering": _legacy_get("/api/compliance/engineering"),

    # IDO / Field Config Studio capabilities + proxy actions
    "ido.capabilities": _legacy_get("/api/ido/capabilities"),
    "ido.ping": lambda payload: _ido_proxy_call("/api/ping", payload),
    "ido.generic.device_info": lambda payload: _ido_proxy_call("/api/generic/device_info", payload),
    "ido.ap.device_info": lambda payload: _ido_proxy_call("/api/ap/device_info", payload),
    "ido.ap.running_config": lambda payload: _ido_proxy_call("/api/ap/running_config", payload),
    "ido.ap.standard_config": lambda payload: _ido_proxy_call("/api/ap/standard_config", payload),
    "ido.ap.generate": lambda payload: _ido_proxy_call("/api/ap/generate", payload),
    "ido.bh.device_info": lambda payload: _ido_proxy_call("/api/bh/device_info", payload),
    "ido.bh.running_config": lambda payload: _ido_proxy_call("/api/bh/running_config", payload),
    "ido.bh.standard_config": lambda payload: _ido_proxy_call("/api/bh/standard_config", payload),
    "ido.bh.generate": lambda payload: _ido_proxy_call("/api/bh/generate", payload),
    "ido.swt.device_info": lambda payload: _ido_proxy_call("/api/swt/device_info", payload),
    "ido.swt.running_config": lambda payload: _ido_proxy_call("/api/swt/running_config", payload),
    "ido.swt.standard_config": lambda payload: _ido_proxy_call("/api/swt/standard_config", payload),
    "ido.swt.generate": lambda payload: _ido_proxy_call("/api/swt/generate", payload),
    "ido.ups.device_info": lambda payload: _ido_proxy_call("/api/ups/device_info", payload),
    "ido.ups.running_config": lambda payload: _ido_proxy_call("/api/ups/running_config", payload),
    "ido.ups.standard_config": lambda payload: _ido_proxy_call("/api/ups/standard_config", payload),
    "ido.ups.generate": lambda payload: _ido_proxy_call("/api/ups/generate", payload),
    "ido.rpc.device_info": lambda payload: _ido_proxy_call("/api/rpc/device_info", payload),
    "ido.rpc.running_config": lambda payload: _ido_proxy_call("/api/rpc/running_config", payload),
    "ido.rpc.standard_config": lambda payload: _ido_proxy_call("/api/rpc/standard_config", payload),
    "ido.rpc.generate": lambda payload: _ido_proxy_call("/api/rpc/generate", payload),
    "ido.wave.config": lambda payload: _ido_proxy_call("/api/waveconfig/generate", payload),
    "ido.nokia7250.generate": lambda payload: _ido_proxy_call("/api/7250config/generate", payload),

    # Aviat
    "aviat.run": _legacy_post("/api/aviat/run"),
    "aviat.activate_scheduled": lambda payload: _legacy_call(
        {"method": "POST", "path": "/api/aviat/activate-scheduled", "body": payload}
    ),
    "aviat.check_status": lambda payload: _legacy_call(
        {"method": "POST", "path": "/api/aviat/check-status", "body": payload}
    ),
    "aviat.scheduled.get": _legacy_get("/api/aviat/scheduled"),
    "aviat.loading.get": _legacy_get("/api/aviat/loading"),
    "aviat.queue.get": _legacy_get("/api/aviat/queue"),
    "aviat.queue.update": _legacy_post("/api/aviat/queue"),
    "aviat.reboot_required.get": _legacy_get("/api/aviat/reboot-required"),
    "aviat.reboot_required.run": _legacy_post("/api/aviat/reboot-required/run"),
    "aviat.scheduled.sync": _legacy_post("/api/aviat/scheduled/sync"),
    "aviat.fix_stp": _legacy_post("/api/aviat/fix-stp"),
    "aviat.stream.global": _legacy_get("/api/aviat/stream/global"),
    "aviat.abort": _aviat_abort,
    "aviat.status": _aviat_status,
    "aviat.precheck_recheck": _legacy_post("/api/aviat/precheck/recheck"),
}


_OMNI_WORKFLOWS: Dict[str, Any] = {
    "dashboard": {
        "health": "health.get",
        "activity_list": "activity.list",
        "configs_list": "configs.list",
        "infrastructure": "infrastructure.get",
    },
    "mikrotik": {
        "render": {"action": "mt.render", "required": ["config_type", "payload"]},
        "config_only": {"action": "mt.config", "required": ["config_type", "payload"]},
        "portmap_only": {"action": "mt.portmap", "required": ["config_type", "payload"]},
    },
    "nokia_7250": {
        "defaults": "nokia.defaults",
        "generate": "nokia.generate_7250",
        "generate_ido": "ido.nokia7250.generate",
        "migrate_from_mikrotik": "migration.mikrotik_to_nokia",
    },
    "enterprise": {
        "generate_non_mpls": "enterprise.generate_non_mpls",
    },
    "tarana": {
        "generate": "tarana.generate",
    },
    "field_config_studio": {
        "capabilities": "ido.capabilities",
        "ap": ["ido.ap.device_info", "ido.ap.running_config", "ido.ap.standard_config", "ido.ap.generate"],
        "bh": ["ido.bh.device_info", "ido.bh.running_config", "ido.bh.standard_config", "ido.bh.generate"],
        "switch": ["ido.swt.device_info", "ido.swt.running_config", "ido.swt.standard_config", "ido.swt.generate"],
        "ups": ["ido.ups.device_info", "ido.ups.running_config", "ido.ups.standard_config", "ido.ups.generate"],
        "rpc": ["ido.rpc.device_info", "ido.rpc.running_config", "ido.rpc.standard_config", "ido.rpc.generate"],
        "wave": "ido.wave.config",
    },
    "aviat": {
        "run": "aviat.run",
        "check_status": "aviat.check_status",
        "activate_scheduled": "aviat.activate_scheduled",
        "queue_get": "aviat.queue.get",
        "queue_update": "aviat.queue.update",
        "status": "aviat.status",
        "precheck_recheck": "aviat.precheck_recheck",
        "scheduled_get": "aviat.scheduled.get",
        "loading_get": "aviat.loading.get",
        "reboot_required_get": "aviat.reboot_required.get",
        "reboot_required_run": "aviat.reboot_required.run",
        "scheduled_sync": "aviat.scheduled.sync",
        "fix_stp": "aviat.fix_stp",
        "abort": "aviat.abort",
    },
    "ftth": {
        "preview_bng": "ftth.preview_bng",
        "generate_bng": "ftth.generate_bng",
        "mf2_package": "ftth.mf2_package",
    },
    "compliance": {
        "apply": "compliance.apply",
        "status": "compliance.status",
        "blocks": "compliance.blocks",
        "engineering": "compliance.engineering",
        "policies_list": "compliance.policies.list",
        "policies_get": "compliance.policies.get",
        "policies_bundle": "compliance.policies.bundle",
        "policies_reload": "compliance.policies.reload",
        "reload": "compliance.reload",
    },
    "device_ops": {
        "fetch_config_ssh": "device.fetch_config_ssh",
        "ping": "ido.ping",
        "generic_device_info": "ido.generic.device_info",
    },
    "feedback": {
        "submit": "feedback.submit",
    },
    "admin": {
        "feedback_list": "admin.feedback.list",
        "feedback_update_status": "admin.feedback.update_status",
        "feedback_export": "admin.feedback.export",
        "users_reset_password": "admin.users.reset_password",
    },
}


def _job_to_dict(job: JobRecord, include_payload: bool = False, include_events: bool = False) -> Dict[str, Any]:
    out = {
        "job_id": job.job_id,
        "request_id": job.request_id,
        "action": job.action,
        "submitted_by": job.submitted_by,
        "status": job.status,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "cancel_requested": job.cancel_requested,
        "result": job.result,
        "error": job.error,
    }
    if include_payload:
        out["payload"] = job.payload
    if include_events:
        out["events"] = [{"ts": e.ts, "level": e.level, "message": e.message} for e in job.events]
    return out


def _normalize_idempotency_key(value: Optional[str]) -> str:
    return (value or "").strip()


@router.get("/health")
def v2_health(_: Dict[str, Any] = Depends(_require_scope("health.read"))):
    checks: Dict[str, Any] = {"legacy_api_base": _legacy_api_base(), "legacy_health": {"ok": False}, "ido_caps": {"ok": False}}
    try:
        r = requests.get(urljoin(_legacy_api_base() + "/", "api/health"), timeout=5)
        checks["legacy_health"] = {"ok": r.ok, "status_code": r.status_code}
    except Exception as exc:
        checks["legacy_health"] = {"ok": False, "error": str(exc)}

    try:
        r = requests.get(urljoin(_legacy_api_base() + "/", "api/ido/capabilities"), timeout=5)
        checks["ido_caps"] = {"ok": r.ok, "status_code": r.status_code}
    except Exception as exc:
        checks["ido_caps"] = {"ok": False, "error": str(exc)}

    all_ok = bool(checks["legacy_health"].get("ok"))
    status = "ok" if all_ok else "degraded"
    return _envelope(status=status, data=checks, message="v2 health")


@router.get("/omni/health")
def v2_omni_health(_: Dict[str, Any] = Depends(_require_scope("health.read"))):
    return v2_health(_)


@router.get("/actions")
def v2_actions(_: Dict[str, Any] = Depends(_require_scope("actions.read"))):
    return _envelope(
        status="ok",
        data={
            "actions": sorted(_ACTION_HANDLERS.keys()),
            "notes": {
                "mt.*": "Native renderer actions",
                "legacy.proxy": "Whitelisted generic proxy to legacy /api/* endpoint",
                "activity.list/configs.list": "Convenience wrappers for common list endpoints",
            },
        },
    )


@router.get("/omni/actions")
def v2_omni_actions(_: Dict[str, Any] = Depends(_require_scope("actions.read"))):
    return v2_actions(_)


@router.get("/whoami")
def v2_whoami(auth: Dict[str, Any] = Depends(_require_scope("health.read"))):
    return _envelope(status="ok", data={"api_key": auth["api_key"], "scopes": auth["scopes"]})


@router.get("/omni/whoami")
def v2_omni_whoami(auth: Dict[str, Any] = Depends(_require_scope("health.read"))):
    return v2_whoami(auth)


@router.get("/omni/bootstrap")
def v2_omni_bootstrap(auth: Dict[str, Any] = Depends(_require_scope("actions.read"))):
    _ = auth
    return _envelope(
        status="ok",
        data={
            "api_version": "v2",
            "service": "noc-configmaker",
            "base_url_hint": "/api/v2",
            "methods_supported": ["GET", "POST", "PUT", "PATCH"],
            "resources": {
                "health": {"method": "GET", "path": "/api/v2/health"},
                "identity": {"method": "GET", "path": "/api/v2/whoami"},
                "actions": {"method": "GET", "path": "/api/v2/actions"},
                "job_submit": {"method": "POST", "path": "/api/v2/jobs"},
                "job_list": {"method": "GET", "path": "/api/v2/jobs"},
                "job_get": {"method": "GET", "path": "/api/v2/jobs/{job_id}"},
                "job_events": {"method": "GET", "path": "/api/v2/jobs/{job_id}/events"},
                "job_cancel_patch": {"method": "PATCH", "path": "/api/v2/jobs/{job_id}"},
                "job_cancel_put": {"method": "PUT", "path": "/api/v2/jobs/{job_id}/cancel"},
            },
            "notes": {
                "read_method": "READ maps to GET in HTTP semantics",
                "auth": "X-API-Key + HMAC signature headers",
                "idempotency": "Mutating endpoints require Idempotency-Key",
            },
        },
        message="OMNI bootstrap contract",
    )


@router.get("/omni/workflows")
def v2_omni_workflows(_: Dict[str, Any] = Depends(_require_scope("actions.read"))):
    return _envelope(
        status="ok",
        data={
            "workflows": _OMNI_WORKFLOWS,
            "parity_doc": "/docs/UI_API_PARITY.md",
            "actions_count": len(_ACTION_HANDLERS),
        },
        message="OMNI workflow/action mappings",
    )


@router.post("/jobs")
def v2_submit_job(
    request: Request,
    payload: Dict[str, Any] = Body(default_factory=dict),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.submit")),
):
    idem_key = _normalize_idempotency_key(idempotency_key)
    if _IDEMPOTENCY_REQUIRED and not idem_key:
        raise HTTPException(status_code=400, detail="Missing Idempotency-Key")

    req_hash = _body_hash(_request_body_bytes(request))
    if idem_key:
        existing = _load_idempotency(
            idem_key=idem_key,
            api_key=auth["api_key"],
            method=request.method.upper(),
            path=request.url.path,
            request_hash=req_hash,
        )
        if existing:
            status_code, body = existing
            return JSONResponse(status_code=status_code, content=body)

    action = (payload.get("action") or "").strip()
    if not action:
        raise HTTPException(status_code=422, detail="Missing 'action'")
    job_payload = payload.get("payload")
    if not isinstance(job_payload, dict):
        job_payload = {k: v for k, v in payload.items() if k != "action"}
    rid = request.headers.get("X-Request-ID") or _request_id()
    job = _JOBS.submit(action=action, payload=job_payload, submitted_by=auth["api_key"], request_id=rid)
    # Stamp tenant_id for audit trail (additive; no filtering change)
    try:
        _tj_conn = _db_conn()
        job.tenant_id = _get_tenant_id_for_api_key(auth["api_key"], _tj_conn)
        _tj_conn.close()
        if job.tenant_id is not None:
            _JOBS._persist_job(job)
    except Exception:
        pass
    response_body = _envelope(
        status="accepted",
        data={
            "job_id": job.job_id,
            "request_id": job.request_id,
            "action": action,
            "status": job.status,
        },
        message="Job accepted",
        request_id=rid,
    )
    if idem_key:
        _save_idempotency(
            idem_key=idem_key,
            api_key=auth["api_key"],
            method=request.method.upper(),
            path=request.url.path,
            request_hash=req_hash,
            status_code=202,
            response_json=response_body,
        )
    return JSONResponse(status_code=202, content=response_body)


@router.post("/omni/jobs")
def v2_omni_submit_job(
    request: Request,
    payload: Dict[str, Any] = Body(default_factory=dict),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.submit")),
):
    return v2_submit_job(
        request=request,
        payload=payload,
        idempotency_key=idempotency_key,
        auth=auth,
    )


@router.get("/jobs")
def v2_list_jobs(
    limit: int = 100,
    auth: Dict[str, Any] = Depends(_require_scope("job.read")),
):
    _ = auth
    rows = [_job_to_dict(j, include_payload=False, include_events=False) for j in _JOBS.list(limit=limit)]
    return _envelope(status="ok", data={"jobs": rows, "count": len(rows)})


@router.get("/omni/jobs")
def v2_omni_list_jobs(
    limit: int = 100,
    auth: Dict[str, Any] = Depends(_require_scope("job.read")),
):
    return v2_list_jobs(limit=limit, auth=auth)


@router.get("/jobs/{job_id}")
def v2_get_job(job_id: str, auth: Dict[str, Any] = Depends(_require_scope("job.read"))):
    _ = auth
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return _envelope(status="ok", data=_job_to_dict(job, include_payload=True, include_events=False))


@router.get("/omni/jobs/{job_id}")
def v2_omni_get_job(job_id: str, auth: Dict[str, Any] = Depends(_require_scope("job.read"))):
    return v2_get_job(job_id=job_id, auth=auth)


@router.get("/jobs/{job_id}/events")
def v2_get_job_events(job_id: str, auth: Dict[str, Any] = Depends(_require_scope("job.read"))):
    _ = auth
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return _envelope(
        status="ok",
        data={
            "job_id": job.job_id,
            "status": job.status,
            "events": [{"ts": e.ts, "level": e.level, "message": e.message} for e in job.events],
        },
    )


@router.get("/omni/jobs/{job_id}/events")
def v2_omni_get_job_events(job_id: str, auth: Dict[str, Any] = Depends(_require_scope("job.read"))):
    return v2_get_job_events(job_id=job_id, auth=auth)


@router.post("/jobs/{job_id}/cancel")
def v2_cancel_job(
    request: Request,
    job_id: str,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.cancel")),
):
    idem_key = _normalize_idempotency_key(idempotency_key)
    if _IDEMPOTENCY_REQUIRED and not idem_key:
        raise HTTPException(status_code=400, detail="Missing Idempotency-Key")
    req_hash = _body_hash(_request_body_bytes(request))
    if idem_key:
        existing = _load_idempotency(
            idem_key=idem_key,
            api_key=auth["api_key"],
            method=request.method.upper(),
            path=request.url.path,
            request_hash=req_hash,
        )
        if existing:
            status_code, body = existing
            return JSONResponse(status_code=status_code, content=body)

    _ = auth
    job = _JOBS.cancel(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    response_body = _envelope(
        status="ok",
        data={"job_id": job.job_id, "status": job.status, "cancel_requested": job.cancel_requested},
        message="Cancel request accepted",
    )
    if idem_key:
        _save_idempotency(
            idem_key=idem_key,
            api_key=auth["api_key"],
            method=request.method.upper(),
            path=request.url.path,
            request_hash=req_hash,
            status_code=200,
            response_json=response_body,
        )
    return response_body


@router.post("/omni/jobs/{job_id}/cancel")
def v2_omni_cancel_job(
    request: Request,
    job_id: str,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.cancel")),
):
    return v2_cancel_job(
        request=request,
        job_id=job_id,
        idempotency_key=idempotency_key,
        auth=auth,
    )


@router.put("/jobs/{job_id}/cancel")
def v2_cancel_job_put(
    request: Request,
    job_id: str,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.cancel")),
):
    return v2_cancel_job(
        request=request,
        job_id=job_id,
        idempotency_key=idempotency_key,
        auth=auth,
    )


@router.put("/omni/jobs/{job_id}/cancel")
def v2_omni_cancel_job_put(
    request: Request,
    job_id: str,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.cancel")),
):
    return v2_cancel_job_put(
        request=request,
        job_id=job_id,
        idempotency_key=idempotency_key,
        auth=auth,
    )


@router.patch("/jobs/{job_id}")
def v2_patch_job(
    request: Request,
    job_id: str,
    payload: Dict[str, Any] = Body(default_factory=dict),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.cancel")),
):
    op = str(payload.get("op") or payload.get("action") or "").strip().lower()
    if op not in {"cancel", "stop"}:
        raise HTTPException(status_code=422, detail="Supported PATCH ops: cancel")
    return v2_cancel_job(
        request=request,
        job_id=job_id,
        idempotency_key=idempotency_key,
        auth=auth,
    )


@router.patch("/omni/jobs/{job_id}")
def v2_omni_patch_job(
    request: Request,
    job_id: str,
    payload: Dict[str, Any] = Body(default_factory=dict),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.cancel")),
):
    return v2_patch_job(
        request=request,
        job_id=job_id,
        payload=payload,
        idempotency_key=idempotency_key,
        auth=auth,
    )
