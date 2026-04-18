import asyncio
import base64
import os
import fnmatch
import io
import re
import tarfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from api_server import verify_token


router = APIRouter(prefix="/api/unimus-backup-configs", tags=["unimus-backup-configs"])

_ZONE_CACHE: dict[str, Any] = {
    "expires_at": 0.0,
    "zone_numbers": [],
    "zone_map": {},
}
_NETONIX_BASE_CONFIG_PATH = Path(__file__).resolve().parent / "assets" / "NETONIX_BASE_CONFIG.ncfg"
_DOWNLOAD_EXTENSION_RULES = {
    "default_extension": ".cfg",
    "rules": [
        {"vendor": "MikroTik", "type": "*", "model": "*", "extension": ".rsc"},
        {"vendor": "Netonix", "type": "*", "model": "*", "extension": ".ncfg"},
        {"vendor": "Cambium", "type": "ePMP", "model": "*", "extension": ".json"},
        {"vendor": "Ubiquiti", "type": "Wave AP", "model": "*", "extension": ".cfg"},
        {"vendor": "Aviat", "type": "WTM Radio", "model": "*", "extension": ".config"},
        {"vendor": "Siklu", "type": "*", "model": "*", "extension": ".txt"},
    ],
}


def _env_flag(name: str, default: bool = False) -> bool:
    raw = os.getenv(name, "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on", "y"}


def _zabbix_runtime() -> dict[str, Any]:
    base_url = (os.getenv("ZABBIX_BASE_URL") or "").strip().rstrip("/")
    api_url = (os.getenv("ZABBIX_API_URL") or "").strip()
    api_token = (os.getenv("ZABBIX_API_TOKEN") or "").strip()
    timeout = float((os.getenv("ZABBIX_TIMEOUT") or "30").strip() or 30)
    configured = bool(api_url and api_token)
    return {
        "active": configured,
        "configured": configured,
        "base_url": base_url,
        "api_url": api_url,
        "api_token": api_token,
        "timeout": timeout,
    }


def _unimus_runtime() -> dict[str, Any]:
    base_url = (os.getenv("UNIMUS_BASE_URL") or "").strip().rstrip("/")
    api_token = (os.getenv("UNIMUS_API_TOKEN") or "").strip()
    timeout = float((os.getenv("UNIMUS_TIMEOUT") or "30").strip() or 30)
    verify_ssl = _env_flag("UNIMUS_VERIFY_SSL", True)
    configured = bool(base_url and api_token)
    return {
        "active": configured,
        "configured": configured,
        "base_url": base_url,
        "api_token": api_token,
        "timeout": timeout,
        "verify_ssl": verify_ssl,
    }


def _require_auth(request: Request) -> dict[str, Any]:
    auth_header = request.headers.get("Authorization", "")
    token = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else auth_header.strip()
    user = verify_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return user


def _require_unimus_runtime() -> dict[str, Any]:
    runtime = _unimus_runtime()
    if not runtime.get("configured"):
        raise HTTPException(status_code=500, detail="Unimus integration is not configured")
    return runtime


def _headers(config: dict[str, Any]) -> dict[str, str]:
    token = str(config.get("api_token") or "").strip()
    if not token:
        raise ValueError("Unimus API token is missing")
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    }


def _request(method: str, path: str, *, params: dict[str, Any] | None = None, config: dict[str, Any]) -> Any:
    base_url = str(config.get("base_url") or "").rstrip("/")
    if not base_url:
        raise ValueError("Unimus base URL is missing")
    response = requests.request(
        method,
        f"{base_url}{path}",
        headers=_headers(config),
        params=params,
        timeout=float(config.get("timeout") or 30),
        verify=bool(config.get("verify_ssl", True)),
    )
    if response.status_code == 404:
        return None
    response.raise_for_status()
    if response.status_code == 204 or not response.content:
        return None
    payload = response.json()
    if isinstance(payload, dict) and "data" in payload:
        return payload.get("data")
    return payload


def _list_zone_numbers(config: dict[str, Any]) -> list[str]:
    now = time.time()
    if _ZONE_CACHE["expires_at"] > now:
        return list(_ZONE_CACHE["zone_numbers"])

    payload = _request("GET", "/api/v3/zones", config=config) or {}
    zones = list(payload.get("zones") or [])
    zone_numbers: list[str] = []
    zone_map: dict[str, dict[str, str]] = {}
    seen: set[str] = set()
    for zone in zones:
        number = str(zone.get("number") or "").strip()
        if not number or number in seen:
            continue
        seen.add(number)
        zone_numbers.append(number)
        zone_map[number] = {
            "name": str(zone.get("name") or "").strip(),
            "proxy_type": str(zone.get("proxyTypeString") or zone.get("proxyTypeEnum") or "").strip(),
        }
    zone_numbers.sort(key=lambda value: (value == "0", int(value) if value.isdigit() else value))
    _ZONE_CACHE["zone_numbers"] = zone_numbers
    _ZONE_CACHE["zone_map"] = zone_map
    _ZONE_CACHE["expires_at"] = now + 300
    return list(zone_numbers)


def _get_zone_map(config: dict[str, Any]) -> dict[str, dict[str, str]]:
    _list_zone_numbers(config)
    return dict(_ZONE_CACHE["zone_map"])


def _list_devices_by_addresses(addresses: list[str], config: dict[str, Any]) -> list[dict[str, Any]]:
    cleaned: list[str] = []
    seen: set[str] = set()
    for address in addresses:
        text = str(address or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        cleaned.append(text)

    devices: list[dict[str, Any]] = []
    for address in cleaned:
        device = _request(
            "GET",
            f"/api/v2/devices/findByAddress/{quote(address, safe='')}",
            params={"attr": "c"},
            config=config,
        )
        if not device:
            zone_numbers = [zone for zone in _list_zone_numbers(config) if zone != "0"]
            if zone_numbers:
                max_workers = min(12, max(1, len(zone_numbers)))
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {
                        executor.submit(
                            _request,
                            "GET",
                            f"/api/v2/devices/findByAddress/{quote(address, safe='')}",
                            params={"attr": "c", "zoneId": zone_number},
                            config=config,
                        ): zone_number
                        for zone_number in zone_numbers
                    }
                    for future in as_completed(futures):
                        try:
                            candidate = future.result()
                        except Exception:
                            continue
                        if candidate:
                            device = candidate
                            for pending in futures:
                                if pending is not future:
                                    pending.cancel()
                            break
        if device:
            devices.append(device)
    return devices


def _get_device(device_id: str, config: dict[str, Any]) -> dict[str, Any]:
    payload = _request(
        "GET",
        f"/api/v2/devices/{quote(str(device_id), safe='')}",
        params={"attr": "c"},
        config=config,
    )
    if not payload:
        raise LookupError(f"Unimus device {device_id} not found")
    return payload


def _get_device_connections(device_id: str, config: dict[str, Any]) -> list[dict[str, Any]]:
    return list((_get_device(device_id, config)).get("connections") or [])


def _list_device_backups(device_id: str, *, latest: bool = False, size: int = 100, page: int = 0, config: dict[str, Any]) -> list[dict[str, Any]]:
    if latest:
        payload = _request("GET", f"/api/v2/devices/{quote(str(device_id), safe='')}/backups/latest", config=config)
        return [payload] if payload else []
    payload = _request(
        "GET",
        f"/api/v2/devices/{quote(str(device_id), safe='')}/backups",
        params={"page": max(0, int(page)), "size": max(1, int(size))},
        config=config,
    )
    if isinstance(payload, list):
        return payload
    return []


def _get_backup(device_id: str, backup_id: str, config: dict[str, Any]) -> dict[str, Any]:
    for backup in _list_device_backups(device_id, size=250, config=config):
        if str(backup.get("id") or "").strip() == str(backup_id or "").strip():
            return backup
    raise LookupError(f"Unimus backup {backup_id} not found for device {device_id}")


def _trigger_device_backup(device_id: str, config: dict[str, Any]) -> dict[str, Any]:
    payload = _request("PATCH", "/api/v2/jobs/backup", params={"id": str(device_id)}, config=config)
    return payload or {}


def _decode_backup_text(backup: dict[str, Any]) -> str:
    raw_bytes = backup.get("bytes")
    if not raw_bytes:
        return ""
    if isinstance(raw_bytes, list):
        decoded = bytearray()
        for chunk in raw_bytes:
            if not chunk:
                continue
            try:
                decoded.extend(base64.b64decode(chunk))
            except Exception:
                continue
        return decoded.decode("utf-8", errors="replace") if decoded else ""
    if isinstance(raw_bytes, str):
        try:
            return base64.b64decode(raw_bytes).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return ""


def _format_epoch_millis(value: Any) -> str:
    try:
        epoch = int(value)
    except Exception:
        return ""
    if epoch <= 0:
        return ""
    if epoch > 10_000_000_000:
        dt = datetime.fromtimestamp(epoch / 1000, tz=timezone.utc)
    else:
        dt = datetime.fromtimestamp(epoch, tz=timezone.utc)
    return dt.isoformat()


def _serialize_backups(backups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    backups_sorted = sorted(backups or [], key=lambda row: int(row.get("validSince") or 0), reverse=True)
    rows: list[dict[str, Any]] = []
    for backup in backups_sorted:
        backup_id = str(backup.get("id") or "").strip()
        if not backup_id:
            continue
        rows.append(
            {
                "id": backup_id,
                "type": str(backup.get("type") or "").strip() or "UNKNOWN",
                "validSince": backup.get("validSince"),
                "validSinceIso": _format_epoch_millis(backup.get("validSince")),
                "validUntil": backup.get("validUntil"),
                "validUntilIso": _format_epoch_millis(backup.get("validUntil")),
            }
        )
    return rows


def _latest_backup_signature(backups: list[dict[str, Any]]) -> tuple[str, int, int]:
    records = _serialize_backups(backups)
    if not records:
        return ("", 0, 0)
    latest = records[0]
    return (str(latest.get("id") or ""), int(latest.get("validSince") or 0), int(latest.get("validUntil") or 0))


def _safe_label(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(value or ""))
    return cleaned.strip("._") or "unimus-device"


def _resolve_download_extension(vendor: str, device_type: str, model: str) -> str:
    vendor_text = str(vendor or "").strip().lower()
    type_text = str(device_type or "").strip().lower()
    model_text = str(model or "").strip().lower()
    for rule in _DOWNLOAD_EXTENSION_RULES["rules"]:
        vendor_rule = str(rule.get("vendor") or "*").strip().lower()
        type_rule = str(rule.get("type") or "*").strip().lower()
        model_rule = str(rule.get("model") or "*").strip().lower()
        if (
            (vendor_rule == "*" or fnmatch.fnmatch(vendor_text, vendor_rule))
            and (type_rule == "*" or fnmatch.fnmatch(type_text, type_rule))
            and (model_rule == "*" or fnmatch.fnmatch(model_text, model_rule))
        ):
            return str(rule.get("extension") or _DOWNLOAD_EXTENSION_RULES["default_extension"])
    return str(_DOWNLOAD_EXTENSION_RULES["default_extension"])


def _build_netonix_ncfg_bytes(cfg_bytes: bytes) -> bytes:
    if not _NETONIX_BASE_CONFIG_PATH.exists():
        raise FileNotFoundError(f"Netonix base config not found at {_NETONIX_BASE_CONFIG_PATH}")
    first_two_lines = cfg_bytes.decode("utf-8", errors="ignore").splitlines()[:2]
    if not any("Config_Version" in line for line in first_two_lines):
        raise ValueError("Downloaded Netonix backup does not appear to be a valid Netonix config")
    output = io.BytesIO()
    with tarfile.open(_NETONIX_BASE_CONFIG_PATH, "r") as base_tar, tarfile.open(fileobj=output, mode="w") as new_tar:
        for member in base_tar.getmembers():
            if member.name == "www/config.json":
                member.size = len(cfg_bytes)
                member.mtime = int(time.time())
                new_tar.addfile(member, io.BytesIO(cfg_bytes))
            else:
                fileobj = base_tar.extractfile(member)
                new_tar.addfile(member, fileobj)
    output.seek(0)
    return output.getvalue()


def _strip_unimus_command_wrappers(text: str) -> str:
    lines = str(text or "").splitlines()
    cleaned: list[str] = []
    idx = 0
    while idx < len(lines):
        current = lines[idx]
        if current.strip() == "#" and idx + 2 < len(lines) and lines[idx + 2].strip() == "#":
            middle = lines[idx + 1].strip()
            if middle.startswith("#") and middle[1:].strip():
                idx += 3
                continue
        cleaned.append(current)
        idx += 1
    while cleaned and not str(cleaned[0]).strip():
        cleaned.pop(0)
    return "\n".join(cleaned)


def _build_download_payload(text: str, vendor: str, device_type: str, model: str) -> tuple[bytes, str, str]:
    extension = _resolve_download_extension(vendor, device_type, model)
    text_value = str(text or "")
    text_bytes = text_value.encode("utf-8")
    if str(vendor or "").strip().lower() == "netonix":
        return _build_netonix_ncfg_bytes(text_bytes), extension, "application/x-netonix-config"
    sanitized_text = _strip_unimus_command_wrappers(text_value)
    return sanitized_text.encode("utf-8"), extension, "application/octet-stream"


def _zabbix_request(payload: dict[str, Any]) -> Any:
    config = _zabbix_runtime()
    if not config.get("configured"):
        raise ValueError("Zabbix integration is not configured")
    response = requests.post(
        str(config.get("api_url")),
        json=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config.get('api_token', '')}",
        },
        timeout=float(config.get("timeout") or 30),
    )
    response.raise_for_status()
    data = response.json()
    if data.get("error"):
        raise RuntimeError(str(data["error"]))
    return data.get("result") or []


def _build_zabbix_search_wildcard(term: str) -> str:
    cleaned = str(term or "").strip()
    if not cleaned:
        return ""
    if "*" in cleaned or "?" in cleaned:
        return cleaned
    parts = [part for part in cleaned.split() if part]
    if len(parts) > 1:
        return "*" + "*".join(parts) + "*"
    return f"*{cleaned}*"


def _looks_like_ip_query(query: str) -> bool:
    """Check if a query looks like an IP address or IP fragment."""
    cleaned = str(query or "").strip()
    if not cleaned:
        return False
    # Match: starts with digits + dot (e.g., "192.168") or full IP (e.g., "192.168.1.1")
    if re.match(r"^\d+\.", cleaned):
        return True
    # Match full IPv4 pattern
    if re.match(r"^\d{1,3}(\.\d{1,3}){1,3}$", cleaned):
        return True
    return False


def _collect_zabbix_hosts(result: list[dict[str, Any]]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for host in result or []:
        interfaces = host.get("interfaces") or []
        main_interface = next((item for item in interfaces if str(item.get("main")) == "1"), None)
        selected_interface = main_interface or (interfaces[0] if interfaces else {})
        ip_address = str(selected_interface.get("ip") or "").strip()
        if not ip_address:
            continue
        dedupe_key = (str(host.get("hostid") or "").strip(), ip_address)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        items.append(
            {
                "hostid": str(host.get("hostid") or "").strip(),
                "host": str(host.get("host") or "").strip(),
                "name": str(host.get("name") or host.get("host") or "").strip(),
                "status": str(host.get("status") or "").strip(),
                "disabled": str(host.get("status") or "").strip() != "0",
                "ip": ip_address,
                "label": str(host.get("name") or host.get("host") or "").strip(),
                "description": ip_address,
            }
        )
    return items


def _zabbix_host_by_ip(address: str) -> dict[str, str]:
    cleaned = str(address or "").strip()
    if not cleaned:
        return {}
    config = _zabbix_runtime()
    if not config.get("configured"):
        return {}
    interfaces_payload = {
        "jsonrpc": "2.0",
        "method": "hostinterface.get",
        "params": {"output": ["hostid", "ip", "main"], "filter": {"ip": [cleaned]}},
        "auth": config.get("api_token"),
        "id": 1,
    }
    interfaces = _zabbix_request(interfaces_payload)
    host_ids = sorted({str(item.get("hostid") or "").strip() for item in interfaces if str(item.get("hostid") or "").strip()})
    if not host_ids:
        return {}
    hosts_payload = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {"output": ["hostid", "host", "name", "status"], "hostids": host_ids},
        "auth": config.get("api_token"),
        "id": 2,
    }
    hosts = _zabbix_request(hosts_payload)
    if not hosts:
        return {}
    enabled_hosts = [host for host in hosts if str(host.get("status") or "").strip() == "0"]
    disabled_hosts = [host for host in hosts if str(host.get("status") or "").strip() != "0"]
    chosen = (enabled_hosts or disabled_hosts)[0]
    return {
        "hostid": str(chosen.get("hostid") or "").strip(),
        "name": str(chosen.get("name") or chosen.get("host") or "").strip(),
        "status": str(chosen.get("status") or "").strip(),
    }


def _build_zabbix_status(zabbix_host: dict[str, str]) -> dict[str, str]:
    host_status = str((zabbix_host or {}).get("status") or "").strip()
    host_id = str((zabbix_host or {}).get("hostid") or "").strip()
    if host_status == "1":
        return {"label": "Host Disabled", "state": "down"}
    if not host_id:
        return {"label": "ICMP Down", "state": "down"}
    config = _zabbix_runtime()
    payload = {
        "jsonrpc": "2.0",
        "method": "item.get",
        "params": {
            "hostids": [host_id],
            "output": ["key_", "lastvalue", "lastclock"],
            "search": {"key_": "icmpping"},
        },
        "auth": config.get("api_token"),
        "id": 3,
    }
    items = _zabbix_request(payload)
    latest_ping_value = None
    latest_ping_clock = -1
    for item in items:
        key = str(item.get("key_") or "")
        if not key.startswith("icmpping") or key.startswith("icmppingloss") or key.startswith("icmppingsec"):
            continue
        try:
            clock = int(item.get("lastclock") or 0)
        except Exception:
            clock = 0
        if clock >= latest_ping_clock:
            latest_ping_clock = clock
            latest_ping_value = item.get("lastvalue")
    try:
        ping_numeric = float(latest_ping_value) if latest_ping_value is not None else None
    except Exception:
        ping_numeric = None
    if ping_numeric is not None and ping_numeric > 0:
        return {"label": "ICMP Up", "state": "up"}
    return {"label": "ICMP Down", "state": "down"}


def _resolve_device_by_request(config: dict[str, Any], device_id: str, address: str) -> tuple[dict[str, Any], str]:
    cleaned_id = str(device_id or "").strip()
    cleaned_address = str(address or "").strip()
    if cleaned_id:
        return _get_device(cleaned_id, config), cleaned_id
    if not cleaned_address:
        raise ValueError("Missing required parameter: device_id or address")
    devices = _list_devices_by_addresses([cleaned_address], config)
    for device in devices:
        if str(device.get("address") or "").strip() == cleaned_address:
            resolved_id = str(device.get("id") or "").strip()
            if resolved_id:
                return device, resolved_id
    raise LookupError(f"No Unimus device found for address {cleaned_address}")


def _resolve_device_connections(config: dict[str, Any], device: dict[str, Any], device_id: str, address: str) -> list[dict[str, Any]]:
    inline_connections = list(device.get("connections") or [])
    if inline_connections:
        return inline_connections
    direct_connections = _get_device_connections(device_id, config) or []
    if direct_connections:
        return direct_connections
    cleaned_address = str(address or device.get("address") or "").strip()
    if cleaned_address:
        for matched_device in _list_devices_by_addresses([cleaned_address], config):
            matched_connections = list(matched_device.get("connections") or [])
            if matched_connections:
                return matched_connections
    return []


def _build_unimus_status(device: dict[str, Any], remote_core_name: str) -> dict[str, str]:
    normalized_job_status = str(device.get("lastJobStatus") or "").strip().upper()
    is_successful = normalized_job_status == "SUCCESSFUL"
    if is_successful:
        return {"label": "Managed", "state": "up", "detail": ""}
    if normalized_job_status:
        return {
            "label": "Not Managed",
            "state": "down",
            "detail": (
                "The host is present in Unimus but cannot establish a login session with the device.\n"
                f"Please verify that SSH is enabled and that the device is reachable from {remote_core_name or 'a configured remote core.'}"
            ),
        }
    return {
        "label": "Not Managed",
        "state": "down",
        "detail": "The host is not currently returning a successful Unimus backup state.",
    }


@router.get("/summary")
def get_summary(request: Request):
    _require_auth(request)
    runtime = _unimus_runtime()
    if not runtime.get("configured"):
        return {"configured": False, "remote_core_count": 0, "remote_core_label": "Remote Cores"}
    try:
        zone_map = _get_zone_map(runtime)
        remote_core_count = len([zone for zone in zone_map.keys() if str(zone) != "0"])
        return {
            "configured": True,
            "remote_core_count": remote_core_count,
            "remote_core_label": "Remote Core" if remote_core_count == 1 else "Remote Cores",
        }
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to load Unimus summary: {exc}")


@router.get("/host-search")
def search_hosts(request: Request, q: str = "", limit: int = 10):
    _require_auth(request)
    query = str(q or "").strip()
    limit = max(1, min(int(limit or 10), 35))
    if len(query) < 2:
        return {"results": []}
    config = _zabbix_runtime()
    if not config.get("configured"):
        raise HTTPException(status_code=500, detail="Zabbix integration is not configured")
    try:
        matches: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()

        # If query looks like an IP, search via hostinterface.get first (highest relevance)
        if _looks_like_ip_query(query):
            for idx, status_value in enumerate(("0", "1"), start=77):
                # Search interfaces by IP
                interface_payload = {
                    "jsonrpc": "2.0",
                    "method": "hostinterface.get",
                    "params": {
                        "output": ["hostid", "ip"],
                        "filter": {"status": [status_value]},
                        "search": {"ip": query},
                        "searchWildcardsEnabled": True,
                        "limit": 75,
                    },
                    "auth": config.get("api_token"),
                    "id": idx,
                }
                interfaces = _zabbix_request(interface_payload)
                host_ids = sorted({str(item.get("hostid") or "").strip() for item in interfaces if str(item.get("hostid") or "").strip()})

                if host_ids:
                    # Fetch hosts by their IDs
                    hosts_payload = {
                        "jsonrpc": "2.0",
                        "method": "host.get",
                        "params": {
                            "output": ["hostid", "host", "name", "status"],
                            "selectInterfaces": ["ip", "main"],
                            "hostids": host_ids,
                            "sortfield": ["name"],
                            "sortorder": "ASC",
                        },
                        "auth": config.get("api_token"),
                        "id": idx + 100,
                    }
                    for host in _collect_zabbix_hosts(_zabbix_request(hosts_payload)):
                        dedupe_key = (str(host.get("hostid") or "").strip(), str(host.get("ip") or "").strip())
                        if dedupe_key in seen:
                            continue
                        seen.add(dedupe_key)
                        matches.append(host)
                        if len(matches) >= limit:
                            break
                if len(matches) >= limit:
                    break

        # Always search by name/host for completeness (append results not already found)
        for idx, status_value in enumerate(("0", "1"), start=77):
            payload = {
                "jsonrpc": "2.0",
                "method": "host.get",
                "params": {
                    "output": ["hostid", "host", "name", "status"],
                    "selectInterfaces": ["ip", "main"],
                    "filter": {"status": [status_value]},
                    "search": {
                        "host": _build_zabbix_search_wildcard(query),
                        "name": _build_zabbix_search_wildcard(query),
                    },
                    "searchByAny": True,
                    "searchWildcardsEnabled": True,
                    "sortfield": ["name"],
                    "sortorder": "ASC",
                    "limit": 75,
                },
                "auth": config.get("api_token"),
                "id": idx,
            }
            for host in _collect_zabbix_hosts(_zabbix_request(payload)):
                dedupe_key = (str(host.get("hostid") or "").strip(), str(host.get("ip") or "").strip())
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                matches.append(host)
                if len(matches) >= limit:
                    break
            if len(matches) >= limit:
                break
        return {"results": matches}
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to search Zabbix hosts: {exc}")


@router.get("/host-details")
def get_host_details(request: Request, device_id: str = "", address: str = ""):
    _require_auth(request)
    device_id = str(device_id or "").strip()
    address = str(address or "").strip()
    if not device_id and not address:
        raise HTTPException(status_code=400, detail="Missing required parameter: device_id or address")
    config = _require_unimus_runtime()
    try:
        device, device_id = _resolve_device_by_request(config, device_id, address)
        resolved_address = str(device.get("address") or address or "").strip()
        zabbix_host = _zabbix_host_by_ip(resolved_address)
        zabbix_status = _build_zabbix_status(zabbix_host)
        connections = _resolve_device_connections(config, device, device_id, address)
        zone_info = _get_zone_map(config).get(str(device.get("zoneId") or "").strip(), {})
        remote_core_name = str(zone_info.get("name") or "").strip()
        backups = _list_device_backups(device_id, size=10, page=0, config=config)
        next_page_rows = _list_device_backups(device_id, size=10, page=1, config=config)
        unimus_status = _build_unimus_status(device, remote_core_name)
        return {
            "device": device,
            "device_id": device_id,
            "address": resolved_address,
            "connections": connections,
            "backups": _serialize_backups(backups),
            "backups_page": 0,
            "backups_page_size": 10,
            "backups_has_more": bool(next_page_rows),
            "download_extension": _resolve_download_extension(
                str(device.get("vendor") or "").strip(),
                str(device.get("type") or "").strip(),
                str(device.get("model") or "").strip(),
            ),
            "remote_core_name": remote_core_name,
            "remote_core_type": str(zone_info.get("proxy_type") or "").strip(),
            "zabbix_host": zabbix_host,
            "zabbix_status": zabbix_status,
            "unimus_status": unimus_status,
        }
    except LookupError as exc:
        return JSONResponse(
            status_code=404,
            content={
                "error": "This device is not currently present in Unimus",
                "code": "device_not_found",
                "details": str(exc),
            },
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to fetch Unimus host details: {exc}")


@router.get("/host-backups")
def get_host_backups(request: Request, device_id: str = "", address: str = "", page: int = 0, size: int = 10):
    _require_auth(request)
    device_id = str(device_id or "").strip()
    address = str(address or "").strip()
    page = max(0, int(page or 0))
    size = max(1, min(int(size or 10), 50))
    if not device_id and not address:
        raise HTTPException(status_code=400, detail="Missing required parameter: device_id or address")
    config = _require_unimus_runtime()
    try:
        _, resolved_device_id = _resolve_device_by_request(config, device_id, address)
        backups = _list_device_backups(resolved_device_id, size=size, page=page, config=config)
        next_page_rows = _list_device_backups(resolved_device_id, size=size, page=page + 1, config=config)
        return {
            "device_id": resolved_device_id,
            "page": page,
            "page_size": size,
            "has_more": bool(next_page_rows),
            "backups": _serialize_backups(backups),
        }
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to fetch Unimus backups: {exc}")


@router.get("/host-backup")
def get_host_backup(request: Request, device_id: str = "", address: str = "", backup_id: str = "", download: int = 0):
    _require_auth(request)
    device_id = str(device_id or "").strip()
    address = str(address or "").strip()
    backup_id = str(backup_id or "").strip()
    if (not device_id and not address) or not backup_id:
        raise HTTPException(status_code=400, detail="Missing required device_id/address or backup_id")
    config = _require_unimus_runtime()
    try:
        device, resolved_device_id = _resolve_device_by_request(config, device_id, address)
        backup = _get_backup(resolved_device_id, backup_id, config)
        backup_text = _decode_backup_text(backup)
        if int(download or 0) == 1:
            payload_bytes, extension, mimetype = _build_download_payload(
                backup_text,
                str(device.get("vendor") or "").strip(),
                str(device.get("type") or "").strip(),
                str(device.get("model") or "").strip(),
            )
            host_name = str(device.get("description") or device.get("address") or "unimus-device").strip()
            address_label = str(device.get("address") or address or "unimus-device").strip()
            model_label = str(device.get("model") or "unknown-model").strip()
            timestamp_label = str(_format_epoch_millis(backup.get("validSince")) or backup.get("validSince") or backup_id)
            download_name = (
                f"{_safe_label(host_name)}_{_safe_label(address_label)}_{_safe_label(model_label)}_{_safe_label(timestamp_label)}{extension}"
            )
            return Response(
                content=payload_bytes,
                media_type=mimetype,
                headers={
                    "Content-Disposition": f'attachment; filename="{download_name}"',
                    "X-Content-Type-Options": "nosniff",
                },
            )
        return {
            "id": backup_id,
            "device_id": resolved_device_id,
            "type": backup.get("type") or "",
            "validSince": backup.get("validSince"),
            "validSinceIso": _format_epoch_millis(backup.get("validSince")),
            "validUntil": backup.get("validUntil"),
            "validUntilIso": _format_epoch_millis(backup.get("validUntil")),
            "text": backup_text,
        }
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to fetch Unimus backup: {exc}")


def _poll_backup_completion(
    device_id: str,
    before_status: str,
    before_signature: tuple[str, int, int],
    before_backups: list[dict[str, Any]],
    config: dict[str, Any],
    address: str,
) -> tuple[list[dict[str, Any]], dict[str, Any], bool]:
    """Poll for backup completion synchronously. Returns (completed_backups, refreshed_device, completed)."""
    completed_backups = before_backups
    completed = False
    refreshed_device = _get_device(device_id, config)
    deadline = time.time() + 45
    while time.time() < deadline:
        time.sleep(2)
        refreshed_device = _get_device(device_id, config)
        current_status = str(refreshed_device.get("lastJobStatus") or "").strip()
        current_backups = _list_device_backups(device_id, size=100, config=config)
        if (current_status and current_status != before_status) or (_latest_backup_signature(current_backups) != before_signature):
            completed_backups = current_backups
            completed = True
            break
    if not completed:
        completed_backups = _list_device_backups(device_id, size=100, config=config)
        refreshed_device = _get_device(device_id, config)
    return completed_backups, refreshed_device, completed


@router.post("/host-backup-now")
async def run_host_backup_now(request: Request, device_id: str = "", address: str = ""):
    _require_auth(request)
    device_id = str(device_id or "").strip()
    address = str(address or "").strip()
    if not device_id and not address:
        raise HTTPException(status_code=400, detail="Missing required parameter: device_id or address")
    config = _require_unimus_runtime()
    try:
        device, resolved_device_id = _resolve_device_by_request(config, device_id, address)
        before_status = str(device.get("lastJobStatus") or "").strip()
        before_backups = _list_device_backups(resolved_device_id, size=10, config=config)
        before_signature = _latest_backup_signature(before_backups)

        trigger_result = _trigger_device_backup(resolved_device_id, config) or {}
        accepted = int(trigger_result.get("accepted") or 0)
        refused = int(trigger_result.get("refused") or 0)
        undiscovered = int(trigger_result.get("undiscovered") or 0)
        if accepted < 1:
            status_code = 409 if refused or undiscovered else 502
            return JSONResponse(
                status_code=status_code,
                content={
                    "error": "Unimus did not accept the backup request",
                    "accepted": accepted,
                    "refused": refused,
                    "undiscovered": undiscovered,
                },
            )

        # Run polling asynchronously without blocking thread pool
        completed_backups, refreshed_device, completed = await asyncio.to_thread(
            _poll_backup_completion,
            resolved_device_id,
            before_status,
            before_signature,
            before_backups,
            config,
            address,
        )

        connections = _resolve_device_connections(
            config,
            refreshed_device,
            resolved_device_id,
            str(refreshed_device.get("address") or address or "").strip(),
        )
        zone_info = _get_zone_map(config).get(str(refreshed_device.get("zoneId") or "").strip(), {})
        remote_core_name = str(zone_info.get("name") or "").strip()
        resolved_address = str(refreshed_device.get("address") or address or "").strip()
        zabbix_host = _zabbix_host_by_ip(resolved_address)
        payload = {
            "device_id": resolved_device_id,
            "device": refreshed_device,
            "connections": connections,
            "backups": _serialize_backups(completed_backups),
            "remote_core_name": remote_core_name,
            "remote_core_type": str(zone_info.get("proxy_type") or "").strip(),
            "download_extension": _resolve_download_extension(
                str(refreshed_device.get("vendor") or "").strip(),
                str(refreshed_device.get("type") or "").strip(),
                str(refreshed_device.get("model") or "").strip(),
            ),
            "zabbix_host": zabbix_host,
            "zabbix_status": _build_zabbix_status(zabbix_host),
            "unimus_status": _build_unimus_status(refreshed_device, remote_core_name),
            "accepted": accepted,
            "refused": refused,
            "undiscovered": undiscovered,
            "completed": completed,
        }
        if completed:
            return payload
        return JSONResponse(
            status_code=202,
            content={**payload, "message": "Backup request was accepted, but completion was not confirmed before timeout."},
        )
    except LookupError:
        return JSONResponse(
            status_code=404,
            content={"error": "This device is not currently present in Unimus", "code": "device_not_found"},
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to start Unimus backup: {exc}")
