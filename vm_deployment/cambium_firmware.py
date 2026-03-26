from __future__ import annotations

import os
import re
import time
from pathlib import Path
from typing import Any

import requests


requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]


DEVICE_WAIT_TIMEOUT = int(os.getenv("CAMBIUM_DEVICE_WAIT_TIMEOUT", "5"))
UPLOAD_STATUS_TIMEOUT = int(os.getenv("CAMBIUM_UPLOAD_STATUS_TIMEOUT", "900"))
REBOOT_WAIT_TIMEOUT = int(os.getenv("CAMBIUM_REBOOT_WAIT_TIMEOUT", "600"))
REQUEST_TIMEOUT = int(os.getenv("CAMBIUM_REQUEST_TIMEOUT", "15"))

DEFAULT_USERNAME = os.getenv("CAMBIUM_DEFAULT_USERNAME", "admin")
DEFAULT_PASSWORD = (
    os.getenv("AP_STANDARD_PW")
    or os.getenv("SM_STANDARD_PW")
    or os.getenv("NEXTLINK_SSH_PASSWORD")
    or "admin"
)

DEVICE_TYPE_ALIASES = {}

# Only AP types deployed at Nextlink towers.
# CNEP3KL shares the same firmware images as CNEP3K (both use the EP3K folder).
DEVICE_FIRMWARE_FAMILIES = {
    "CNEP3K": {"family": "EP3K", "label": "Cambium ePMP 3000"},
    "CNEP3KL": {"family": "EP3K", "label": "Cambium ePMP 3000 Lite"},
    "CN4600": {"family": "4600", "label": "Cambium ePMP 4600"},
}


def _default_base_config_path() -> str:
    return str(Path(__file__).resolve().parent / "base_configs")


os.environ.setdefault("BASE_CONFIG_PATH", _default_base_config_path())
os.environ.setdefault("FIRMWARE_PATH", os.getenv("FIRMWARE_PATH") or _default_base_config_path())

from ido_modules.device_io.epmp_config import EPMPConfig  # noqa: E402


def _log(message: str, callback=None) -> None:
    text = str(message)
    if callable(callback):
        callback(text)


def resolve_device_type(device_type: str) -> str:
    raw = str(device_type or "").strip()
    if not raw:
        raise ValueError("device_type is required")
    normalized = DEVICE_TYPE_ALIASES.get(raw, raw)
    if normalized not in DEVICE_FIRMWARE_FAMILIES:
        raise ValueError(
            f"Unsupported Cambium device_type '{device_type}'. "
            f"Supported values: {sorted(DEVICE_FIRMWARE_FAMILIES)}"
        )
    return normalized


def _firmware_root() -> Path:
    candidates = [
        (os.getenv("FIRMWARE_PATH") or "").strip(),
        "/opt/firmware",
        (os.getenv("BASE_CONFIG_PATH") or "").strip(),
        _default_base_config_path(),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        root = Path(candidate)
        if (root / "Cambium").is_dir():
            return root
    return Path(_default_base_config_path())


def _extract_version(filename: str) -> str:
    name = Path(filename).stem
    match = re.search(r"[Vv](\d+(?:\.\d+)+(?:[-A-Za-z0-9.]+)?)", name)
    if match:
        return match.group(1)
    match = re.search(r"(\d+(?:\.\d+){1,}(?:[-A-Za-z0-9.]+)?)", name)
    return match.group(1) if match else name


def _version_sort_key(version: str):
    text = str(version or "")
    parts = re.findall(r"\d+|[A-Za-z]+", text)
    key = []
    for part in parts:
        if part.isdigit():
            key.append((0, int(part)))
        else:
            key.append((1, part.lower()))
    return key


def list_firmware_catalog() -> dict[str, Any]:
    root = _firmware_root()
    catalog: dict[str, Any] = {}

    for device_type, meta in DEVICE_FIRMWARE_FAMILIES.items():
        family = meta["family"]
        firmware_dir = root / "Cambium" / family
        images = []
        if firmware_dir.is_dir():
            for path in sorted(firmware_dir.glob("*.img")):
                images.append(
                    {
                        "version": _extract_version(path.name),
                        "filename": path.name,
                        "stem": path.stem,
                        "path": str(path),
                    }
                )
        images.sort(key=lambda item: _version_sort_key(item["version"]), reverse=True)
        catalog[device_type] = {
            "device_type": device_type,
            "family": family,
            "label": meta["label"],
            "firmware_dir": str(firmware_dir),
            "default_version": images[0]["version"] if images else None,
            "available_versions": [item["version"] for item in images],
            "images": images,
        }

    return {
        "firmware_root": str(root),
        "default_username": DEFAULT_USERNAME,
        "default_password_configured": bool(DEFAULT_PASSWORD),
        "devices": catalog,
    }


def resolve_firmware_image(device_type: str, update_version: str | None = None) -> dict[str, Any]:
    canonical = resolve_device_type(device_type)
    catalog = list_firmware_catalog()["devices"][canonical]
    images = list(catalog["images"])
    if not images:
        raise FileNotFoundError(
            f"No firmware images found for {canonical} under {catalog['firmware_dir']}"
        )

    selected = None
    requested = str(update_version or "").strip()
    if requested:
        request_lower = requested.lower()
        for image in images:
            if (
                image["version"].lower() == request_lower
                or image["stem"].lower() == request_lower
                or request_lower in image["filename"].lower()
            ):
                selected = image
                break
        if selected is None:
            raise FileNotFoundError(
                f"Firmware '{requested}' not found for {canonical}. "
                f"Available: {catalog['available_versions']}"
            )
    else:
        selected = images[0]

    return {
        "device_type": canonical,
        "family": catalog["family"],
        "label": catalog["label"],
        "version": selected["version"],
        "filename": selected["filename"],
        "stem": selected["stem"],
        "path": selected["path"],
        "available_versions": catalog["available_versions"],
    }


def get_device_info(
    ip_address: str,
    device_type: str,
    password: str | None = None,
    run_tests: bool = True,
) -> dict[str, Any]:
    canonical = resolve_device_type(device_type)
    return EPMPConfig.get_device_info(
        ip_address,
        canonical,
        password=password or None,
        run_tests=run_tests,
    )


def _discover_management_url(ip_address: str) -> str:
    try:
        requests.get(f"https://{ip_address}", verify=False, timeout=2)
        return f"https://{ip_address}"
    except requests.RequestException:
        return f"http://{ip_address}"


def update_device(
    ip_address: str,
    device_type: str,
    username: str | None = None,
    password: str | None = None,
    update_version: str | None = None,
    callback=None,
) -> dict[str, Any]:
    image = resolve_firmware_image(device_type, update_version)
    mgmt_url = _discover_management_url(ip_address)
    username = str(username or DEFAULT_USERNAME).strip() or DEFAULT_USERNAME
    password = str(password or DEFAULT_PASSWORD).strip()
    if not password:
        raise ValueError("No Cambium password configured or provided")

    session = requests.Session()
    session.verify = False

    def _try_login(base_url: str, use_basic_auth: bool) -> "requests.Response":
        s = requests.Session()
        s.verify = False
        if use_basic_auth:
            s.auth = (username, password)
        # Prime the session so any CSRF cookie arrives before the POST.
        try:
            s.get(base_url, timeout=REQUEST_TIMEOUT)
        except requests.RequestException:
            pass
        # Use allow_redirects=False so we can read the 302 Location header
        # directly — newer ePMP firmware puts the stok in the redirect URL.
        resp = s.post(
            f"{base_url}/cgi-bin/luci",
            data={"username": username, "password": password},
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
        # If the redirect leads somewhere, follow it manually to populate cookies
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location", "")
            if location and not location.startswith("http"):
                location = base_url.rstrip("/") + "/" + location.lstrip("/")
            if location:
                try:
                    s.get(location, timeout=REQUEST_TIMEOUT)
                except requests.RequestException:
                    pass
        # Re-attach session cookies to resp for unified cookie scanning below
        resp._session = s  # type: ignore[attr-defined]
        return resp

    # Attempt 1: plain form auth (no Basic Auth) — works for most ePMP devices
    login_resp = _try_login(mgmt_url, use_basic_auth=False)

    # Attempt 2: if HTTP-level auth required, retry with Basic Auth
    if login_resp.status_code == 401:
        login_resp = _try_login(mgmt_url, use_basic_auth=True)

    # Attempt 3: fall back from HTTPS to HTTP
    if login_resp.status_code == 401 and mgmt_url.startswith("https://"):
        mgmt_url = "http://" + mgmt_url[len("https://"):]
        login_resp = _try_login(mgmt_url, use_basic_auth=True)

    login_resp.raise_for_status()

    # -----------------------------------------------------------------------
    # Extract stok token — checked in priority order:
    #  1. 302 Location header (newer ePMP: redirect to /;stok=TOKEN/)
    #  2. JSON body {"stok": "..."}  (some older firmwares)
    #  3. Final response URL after redirect
    #  4. Raw response text scan
    # -----------------------------------------------------------------------
    token = None
    location_hdr = login_resp.headers.get("Location", "") or ""
    stok_match = re.search(r";stok=([a-f0-9]+)", location_hdr)
    if stok_match:
        token = stok_match.group(1)

    if not token:
        try:
            login_json = login_resp.json()
            if login_json.get("msg"):
                raise PermissionError(f"Login failed: {login_json['msg']}")
            token = login_json.get("stok") or None
        except PermissionError:
            raise
        except Exception:
            pass

    if not token:
        for src in [login_resp.url or "", login_resp.text or ""]:
            m = re.search(r";stok=([a-f0-9]+)", src)
            if m:
                token = m.group(1)
                break

    # Gather sysauth cookie from both the response and the primed session
    sess_obj = getattr(login_resp, "_session", session)
    all_cookies = list(login_resp.cookies) + list(sess_obj.cookies)
    sysauth = None
    for cookie in all_cookies:
        if "sysauth" in cookie.name:
            sysauth = cookie.value
            break

    if not token:
        _log(
            f"[{ip_address}] Login diagnostic: status={login_resp.status_code} "
            f"url={login_resp.url!r} location={location_hdr!r} "
            f"cookies={[c.name for c in all_cookies]} "
            f"body_preview={login_resp.text[:120]!r}",
            callback,
        )
        raise ConnectionError(
            "Cambium login succeeded (HTTP 200) but no stok token found. "
            "Check the log for diagnostic details."
        )
    if not sysauth:
        raise ConnectionError(
            "Cambium login succeeded but no sysauth cookie returned."
        )

    # Carry forward the authenticated session for subsequent requests
    session = sess_obj

    cookies = {
        f"sysauth_{ip_address}_44443": sysauth,
        f"sysauth_{ip_address}_443": sysauth,
        f"sysauth_{ip_address}_80": sysauth,
        "usernameType_80": username,
        "usernameType_443": username,
        "stok_80": token,
        "stok_443": token,
    }

    _log(f"[{ip_address}] Uploading firmware {image['filename']}...", callback)
    with open(image["path"], "rb") as firmware_file:
        upload_resp = session.post(
            f"{mgmt_url}/cgi-bin/luci/;stok={token}/admin/local_upload_image",
            cookies=cookies,
            files={"image": (Path(image["path"]).name, firmware_file, "application/octet-stream")},
            timeout=max(REQUEST_TIMEOUT, 120),
        )
    if upload_resp.status_code != 200:
        raise ConnectionError(f"Firmware upload request failed with status {upload_resp.status_code}")
    _log(f"[{ip_address}] Firmware uploaded.", callback)

    previous_status = -1
    start = time.monotonic()
    while True:
        if time.monotonic() - start > UPLOAD_STATUS_TIMEOUT:
            raise TimeoutError("Timed out waiting for Cambium upload status to complete")
        time.sleep(0.5)
        status_resp = session.post(
            f"{mgmt_url}/cgi-bin/luci/;stok={token}/admin/get_upload_status",
            cookies=cookies,
            timeout=REQUEST_TIMEOUT,
        )
        try:
            status_json = status_resp.json()
        except Exception as exc:
            raise ConnectionError(f"Upload status returned invalid JSON: {exc}") from exc

        status_value = int(status_json.get("status", 0) or 0)
        if status_value > previous_status:
            _log(f"[{ip_address}] Updating... ({status_value}/7)", callback)
        previous_status = status_value

        error_code = int(status_json.get("error", 0) or 0)
        if error_code > 0:
            if error_code in {2, 8}:
                raise RuntimeError(
                    "Firmware update failed. This device is likely incompatible with the selected firmware image."
                )
            raise RuntimeError(f"Firmware update failed with error code {error_code}")

        if status_value == 7:
            break

    reboot_resp = session.post(
        f"{mgmt_url}/cgi-bin/luci/;stok={token}/admin/reboot",
        cookies=cookies,
        timeout=REQUEST_TIMEOUT,
    )
    if reboot_resp.status_code >= 400:
        raise ConnectionError(f"Reboot request failed with status {reboot_resp.status_code}")

    _log(f"[{ip_address}] Waiting for device to reboot...", callback)
    time.sleep(8)
    deadline = time.monotonic() + REBOOT_WAIT_TIMEOUT
    while time.monotonic() < deadline:
        try:
            ping_resp = requests.get(mgmt_url, timeout=DEVICE_WAIT_TIMEOUT, verify=False)
            if ping_resp.status_code == 200:
                _log(f"[{ip_address}] Device updated.", callback)
                return {
                    "success": True,
                    "ip": ip_address,
                    "device_type": image["device_type"],
                    "target_version": image["version"],
                    "selected_image": image["filename"],
                    "management_url": mgmt_url,
                }
        except OSError:
            pass
        except requests.RequestException:
            pass
        time.sleep(1)

    raise TimeoutError("Timed out waiting for Cambium device to come back online after reboot")
