from fastapi import APIRouter, Body, HTTPException
import sys
from os import path
import io
import json
import asyncio
import functools
import concurrent.futures
import logging
from .device_info import device_info

sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from device_io.epmp_config import EPMPConfig
from device_io.tachyon_config import TachyonConfig
from device_io.wave_config import WaveConfig


DEVICE_TYPE_ALIASES = {
    "CNF300-13": "F300-13",
    "CNF300-16": "F300-16",
    "CNF300-25": "F300-25",
    "CNF300-CSM": "F300-CSM",
}

CONFIG_PARAM_KEYS = {
    "site_name",
    "azimuth",
    "device_number",
    "latitude",
    "longitude",
    "height",
    "antenna",
    "frequency",
    "cnm_url",
    "mac_address",
    "user_number",
}


def _clean_dict(values: dict | None) -> dict:
    cleaned = {}
    for key, value in dict(values or {}).items():
        if value is None:
            continue
        if isinstance(value, str):
            value = value.strip()
            if value == "":
                continue
        cleaned[key] = value
    if cleaned.get("device_type"):
        cleaned["device_type"] = DEVICE_TYPE_ALIASES.get(cleaned["device_type"], cleaned["device_type"])
    return cleaned


def _has_config_params(params: dict) -> bool:
    return any(key in params for key in CONFIG_PARAM_KEYS)


def get_cambium_running_config(ip_address: str, device_type: str, password: str | None = None):
    params = {
        "ip_address": ip_address,
        "device_type": DEVICE_TYPE_ALIASES.get(device_type, device_type),
        "use_default": True,
    }
    if password:
        params["password"] = password
    d = EPMPConfig(**params)
    d.init_session()
    config = d.get_running_config()
    d.logout()
    return config


def get_cambium_standard_config(params: dict):
    params = _clean_dict(params)
    params.setdefault("ip_address", "0.0.0.0")
    params["use_default"] = not _has_config_params(params)
    d = EPMPConfig(**params)
    return d.get_standard_config(stripped=True, json_conf=True)


def get_cambium_device_info(ip_address: str, device_type: str, run_tests: bool = False, password: str | None = None):
    device_type = DEVICE_TYPE_ALIASES.get(device_type, device_type)
    return EPMPConfig.get_device_info(ip_address, device_type, password=password, run_tests=run_tests)


def configure_cambium_device(payload: dict):
    payload = _clean_dict(payload)
    payload["use_default"] = False
    logstream = io.StringIO()
    payload["logstream"] = logstream
    d = EPMPConfig(**payload)
    result = d.init_and_configure() or {}
    response = {
        "success": True,
        "device_type": payload.get("device_type"),
        "device_name": getattr(d, "device_name", None),
        "logs": logstream.getvalue(),
    }
    if isinstance(result, dict):
        response.update(result)
    return response


def get_tachyon_running_config(ip_address: str, device_type: str, password: str | None = None):
    params = {"ip_address": ip_address, "device_type": device_type, "readonly": True}
    if password:
        params["password"] = password
    d = TachyonConfig(**params)
    d.init_session()
    config = d.get_running_config(paths=True)
    d.logout()
    config = sorted([f"{x['path']}: {json.dumps(x['value'])}" for x in config])
    return "\n".join(config)


def get_tachyon_standard_config(params: dict):
    params = _clean_dict(params)
    params.setdefault("ip_address", "0.0.0.0")
    params["readonly"] = not _has_config_params(params)
    d = TachyonConfig(**params)
    config = d.get_standard_config()
    config = sorted([f"{x['path']}: {json.dumps(x['value'])}" for x in config])
    return "\n".join(config)


def get_tachyon_device_info(ip_address: str, device_type: str, run_tests: bool = False, password: str | None = None):
    return TachyonConfig.get_device_info(ip_address, device_type, password=password, run_tests=run_tests)


def configure_tachyon_device(payload: dict):
    payload = _clean_dict(payload)
    payload["readonly"] = False
    logstream = io.StringIO()
    payload["logstream"] = logstream
    d = TachyonConfig(**payload)
    d.init_and_configure()
    return {
        "success": True,
        "device_type": payload.get("device_type"),
        "device_name": getattr(d, "device_name", None),
        "logs": logstream.getvalue(),
    }


def get_wave_running_config(ip_address: str, device_type: str, password: str | None = None):
    config = WaveConfig.get_device_info(ip_address, device_type.split("UB")[1], password=password, run_tests=False)
    return config.get("running_config")


def get_wave_standard_config(device_type: str, ip_address: str = "0.0.0.0", password: str | None = None):
    config = WaveConfig.get_device_info(f"{ip_address}", device_type.split("UB")[1], password=password, run_tests=False)
    return config.get("standard_config")


def get_wave_device_info(ip_address: str, device_type: str, run_tests: bool = False, password: str | None = None):
    return WaveConfig.get_device_info(ip_address, device_type.split("UB")[1], password=password, run_tests=run_tests)


VALID_DEVICE_TYPES = {
    "CNEP3K": "CN",
    "CNEP3KL": "CN",
    "CN4600": "CN",
    "F4600C": "CN",
    "F4525": "CN",
    "F300-13": "CN",
    "F300-16": "CN",
    "F300-25": "CN",
    "F300-CSM": "CN",
    "CNF300-13": "CN",
    "CNF300-16": "CN",
    "CNF300-25": "CN",
    "CNF300-CSM": "CN",
    "TYN301": "TY",
    "TYN302": "TY",
    "UBWAP": "UB",
    "UBWAPM": "UB",
}

app = APIRouter()


@app.get("/api/ap/running_config")
async def get_ap_running_config(ip_address: str, device_type: str, password: str | None = None):
    device_type = DEVICE_TYPE_ALIASES.get(device_type, device_type)
    oem = VALID_DEVICE_TYPES.get(device_type)

    loop = asyncio.get_running_loop()

    try:
        if oem == "CN":
            with concurrent.futures.ProcessPoolExecutor() as pool:
                return await loop.run_in_executor(
                    pool,
                    functools.partial(
                        get_cambium_running_config,
                        ip_address=ip_address,
                        device_type=device_type,
                        password=password,
                    ),
                )
        if oem == "TY":
            with concurrent.futures.ProcessPoolExecutor() as pool:
                return await loop.run_in_executor(
                    pool,
                    functools.partial(
                        get_tachyon_running_config,
                        ip_address=ip_address,
                        device_type=device_type,
                        password=password,
                    ),
                )
        if oem == "UB":
            with concurrent.futures.ProcessPoolExecutor() as pool:
                return await loop.run_in_executor(
                    pool,
                    functools.partial(
                        get_wave_running_config,
                        ip_address=ip_address,
                        device_type=device_type,
                        password=password,
                    ),
                )

        raise ValueError("Invalid device type")

    except ValueError as err:
        raise HTTPException(status_code=400, detail=f"{err}") from err
    except Exception as err:
        msg = str(err)
        if "configuration import is in progress" in msg.lower():
            raise HTTPException(
                status_code=409,
                detail="Device configuration import is already in progress on this AP. Wait for the AP to finish applying/rebooting, then retry.",
            ) from err
        if "invalid response while logging in" in msg.lower() or "login failed" in msg.lower():
            raise HTTPException(
                status_code=400,
                detail="Device login failed while fetching running config. Verify AP credentials/default passwords and that the target is a supported Cambium/Tachyon/Wave AP.",
            ) from err
        raise HTTPException(status_code=500, detail=f"{err}") from err


@app.get("/api/ap/standard_config")
async def get_ap_standard_config(
    ip_address: str,
    device_type: str,
    password: str | None = None,
    site_name: str | None = None,
    azimuth: str | None = None,
    device_number: str | None = None,
    latitude: str | None = None,
    longitude: str | None = None,
    height: str | None = None,
    antenna: str | None = None,
    frequency: str | None = None,
    cnm_url: str | None = None,
    mac_address: str | None = None,
    user_number: str | None = None,
):
    params = _clean_dict(
        {
            "ip_address": ip_address,
            "device_type": device_type,
            "password": password,
            "site_name": site_name,
            "azimuth": azimuth,
            "device_number": device_number,
            "latitude": latitude,
            "longitude": longitude,
            "height": height,
            "antenna": antenna,
            "frequency": frequency,
            "cnm_url": cnm_url,
            "mac_address": mac_address,
            "user_number": user_number,
        }
    )
    oem = VALID_DEVICE_TYPES.get(params.get("device_type"))

    loop = asyncio.get_running_loop()

    try:
        if oem == "CN":
            with concurrent.futures.ProcessPoolExecutor() as pool:
                return await loop.run_in_executor(pool, functools.partial(get_cambium_standard_config, params))
        if oem == "TY":
            with concurrent.futures.ProcessPoolExecutor() as pool:
                return await loop.run_in_executor(pool, functools.partial(get_tachyon_standard_config, params))
        if oem == "UB":
            with concurrent.futures.ProcessPoolExecutor() as pool:
                return await loop.run_in_executor(
                    pool,
                    functools.partial(
                        get_wave_standard_config,
                        ip_address=params["ip_address"],
                        device_type=params["device_type"],
                        password=password,
                    ),
                )

        raise ValueError("Invalid device type")

    except ValueError as err:
        raise HTTPException(status_code=400, detail=f"{err}") from err
    except Exception as err:
        msg = str(err)
        if "configuration import is in progress" in msg.lower():
            raise HTTPException(
                status_code=409,
                detail="Device configuration import is already in progress on this AP. Wait for the AP to finish applying/rebooting, then retry.",
            ) from err
        if "invalid response while logging in" in msg.lower() or "login failed" in msg.lower():
            raise HTTPException(
                status_code=400,
                detail="Device login failed while fetching standard config. Verify AP credentials/default passwords and that the target is a supported Cambium/Tachyon/Wave AP.",
            ) from err
        raise HTTPException(status_code=500, detail=f"{err}") from err


@app.get("/api/ap/device_info")
async def get_ap_device_info(
    ip_address: str, device_type: str, run_tests: bool = False, password: str | None = None
):
    device_type = DEVICE_TYPE_ALIASES.get(device_type, device_type)
    oem = VALID_DEVICE_TYPES.get(device_type)

    loop = asyncio.get_running_loop()

    try:
        result = {}
        if oem == "CN":
            with concurrent.futures.ProcessPoolExecutor() as pool:
                result = await loop.run_in_executor(
                    pool,
                    functools.partial(
                        get_cambium_device_info,
                        ip_address=ip_address,
                        device_type=device_type,
                        password=password,
                        run_tests=run_tests,
                    ),
                )
        elif oem == "TY":
            with concurrent.futures.ProcessPoolExecutor() as pool:
                result = await loop.run_in_executor(
                    pool,
                    functools.partial(
                        get_tachyon_device_info,
                        ip_address=ip_address,
                        device_type=device_type,
                        password=password,
                        run_tests=run_tests,
                    ),
                )
        elif oem == "UB":
            with concurrent.futures.ProcessPoolExecutor() as pool:
                result = await loop.run_in_executor(
                    pool,
                    functools.partial(
                        get_wave_device_info,
                        ip_address=ip_address,
                        device_type=device_type,
                        password=password,
                        run_tests=run_tests,
                    ),
                )
        else:
            raise ValueError("Invalid device type")

        with concurrent.futures.ProcessPoolExecutor() as pool:
            generic_result = await loop.run_in_executor(
                pool, functools.partial(device_info, ip_address, run_tests=run_tests)
            )

            if result.get("test_results"):
                result["test_results"] = list(
                    filter(
                        lambda x: x.get("name") != "Device Name",
                        result.get("test_results"),
                    )
                )

            combined = {}
            for test in result.get("test_results", []) + generic_result.get("test_results", []):
                name = test["name"]
                if name not in combined or (combined[name].get("pass") is False and test.get("pass")):
                    combined[name] = test
            result["test_results"] = list(combined.values())
            generic_result.pop("test_results", None)

            for key, value in generic_result.items():
                if isinstance(value, list) and result.get(key):
                    result[key] += value
                elif not result.get(key):
                    result[key] = value

        return result

    except ValueError as err:
        logging.error(err)
        raise HTTPException(status_code=400, detail=f"{err}") from err
    except Exception as err:
        logging.error(err)
        msg = str(err)
        if "configuration import is in progress" in msg.lower():
            raise HTTPException(
                status_code=409,
                detail="Device configuration import is already in progress on this AP. Wait for the AP to finish applying/rebooting, then retry.",
            ) from err
        if "invalid response while logging in" in msg.lower() or "login failed" in msg.lower():
            raise HTTPException(
                status_code=400,
                detail="Device login failed while fetching device info. Verify AP credentials/default passwords and that the target is a supported Cambium/Tachyon/Wave AP.",
            ) from err
        raise HTTPException(status_code=500, detail=f"{err}") from err


@app.post("/api/ap/configure")
async def configure_ap_device(payload: dict = Body(...)):
    payload = _clean_dict(payload)
    device_type = payload.get("device_type")
    oem = VALID_DEVICE_TYPES.get(device_type)
    if not oem:
        raise HTTPException(status_code=400, detail="Invalid device type")
    if oem == "UB":
        raise HTTPException(status_code=400, detail="Use /api/waveconfig/full_config for Ubiquiti Wave devices.")

    loop = asyncio.get_running_loop()
    try:
        if oem == "CN":
            return await loop.run_in_executor(None, functools.partial(configure_cambium_device, payload))
        if oem == "TY":
            return await loop.run_in_executor(None, functools.partial(configure_tachyon_device, payload))
        raise HTTPException(status_code=400, detail="Device type is not supported for AP configure.")
    except HTTPException:
        raise
    except ValueError as err:
        raise HTTPException(status_code=400, detail=f"{err}") from err
    except Exception as err:
        if "configuration import is in progress" in str(err).lower():
            raise HTTPException(
                status_code=409,
                detail="Device configuration import is already in progress on this AP. Wait for the AP to finish applying/rebooting, then retry.",
            ) from err
        raise HTTPException(status_code=500, detail=f"{err}") from err
