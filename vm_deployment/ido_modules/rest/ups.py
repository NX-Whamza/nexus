from fastapi import APIRouter, Body, HTTPException
import sys
from os import path
import io
import asyncio
import functools
import concurrent.futures
from .device_info import device_info

sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))

from device_io.smart_sys_config import SmartSysConfig
try:
    from device_io.ict_ups_config import ICTUPSConfig
    HAS_ICT_UPS = True
except Exception as ict_ups_import_error:
    ICTUPSConfig = None
    HAS_ICT_UPS = False
    ICT_UPS_IMPORT_ERROR = ict_ups_import_error

VALID_DEVICE_TYPES = {"SS": "SS", "ICT800": "ICT", "ICTMPS": "ICT"}

app = APIRouter()


def configure_ups_device(payload: dict):
    payload = dict(payload or {})
    logstream = io.StringIO()
    payload["logstream"] = logstream
    oem = VALID_DEVICE_TYPES.get(payload.get("device_type"))
    if oem == "SS":
        d = SmartSysConfig(**payload)
    elif oem == "ICT":
        if not HAS_ICT_UPS or ICTUPSConfig is None:
            raise RuntimeError(f"ICT UPS support unavailable on this runtime: {ICT_UPS_IMPORT_ERROR}")
        d = ICTUPSConfig(**payload)
    else:
        raise ValueError("Invalid device type")
    d.init_and_configure()
    return {
        "success": True,
        "device_type": payload.get("device_type"),
        "device_name": getattr(d, "device_name", None),
        "logs": logstream.getvalue(),
    }


@app.get("/api/ups/device_info")
async def get_ups_device_info(
    ip_address: str, device_type: str, run_tests: bool = False, password: str | None = None
):
    try:
        result = {}
        oem = VALID_DEVICE_TYPES.get(device_type)
        loop = asyncio.get_running_loop()
        if oem == "SS":
            with concurrent.futures.ProcessPoolExecutor() as pool:
                result = await loop.run_in_executor(
                    pool,
                    functools.partial(
                        SmartSysConfig.get_device_info,
                        ip_address,
                        device_type,
                        password=password,
                        run_tests=run_tests,
                    ),
                )
        elif oem == "ICT":
            if not HAS_ICT_UPS or ICTUPSConfig is None:
                raise HTTPException(
                    status_code=501,
                    detail=f"ICT UPS support unavailable on this runtime: {ICT_UPS_IMPORT_ERROR}",
                )
            with concurrent.futures.ProcessPoolExecutor() as pool:
                result = await loop.run_in_executor(
                    pool,
                    functools.partial(
                        ICTUPSConfig.get_device_info,
                        ip_address,
                        device_type,
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

            for key, value in generic_result.items():
                if isinstance(value, list) and result.get(key):
                    result[key] += value
                elif not result.get(key):
                    result[key] = value

        return result
    except ValueError as err:
        raise HTTPException(status_code=400, detail=f"{err}") from err
    except HTTPException:
        raise
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"{err}") from err


@app.post("/api/ups/configure")
async def configure_ups(payload: dict = Body(...)):
    payload = dict(payload or {})
    if payload.get("device_type") not in VALID_DEVICE_TYPES:
        raise HTTPException(status_code=400, detail="Invalid device type")
    loop = asyncio.get_running_loop()
    try:
        return await loop.run_in_executor(None, functools.partial(configure_ups_device, payload))
    except RuntimeError as err:
        raise HTTPException(status_code=501, detail=f"{err}") from err
    except ValueError as err:
        raise HTTPException(status_code=400, detail=f"{err}") from err
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"{err}") from err
