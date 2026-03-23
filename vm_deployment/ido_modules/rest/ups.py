from fastapi import APIRouter, HTTPException
import sys
from os import path
import json
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

VALID_DEVICE_TYPES = {"SS": "SS", "ICT800": "ICT"}

app = APIRouter()


@app.get("/api/ups/device_info")
async def get_ups_device_info(
    ip_address: str, device_type: str, run_tests: bool = False
):
    try:
        result = {}
        oem = VALID_DEVICE_TYPES.get(device_type)
        if oem == "SS":
            loop = asyncio.get_running_loop()
            with concurrent.futures.ProcessPoolExecutor() as pool:
                result = await loop.run_in_executor(
                    pool,
                    functools.partial(
                        SmartSysConfig.get_device_info,
                        ip_address,
                        device_type,
                        run_tests=run_tests,
                    ),
                )
        if oem == "ICT":
            if not HAS_ICT_UPS or ICTUPSConfig is None:
                raise HTTPException(
                    status_code=501,
                    detail=f"ICT UPS support unavailable on this runtime: {ICT_UPS_IMPORT_ERROR}",
                )
            loop = asyncio.get_running_loop()
            with concurrent.futures.ProcessPoolExecutor() as pool:
                result = await loop.run_in_executor(
                    pool,
                    functools.partial(
                        ICTUPSConfig.get_device_info,
                        ip_address,
                        device_type,
                        run_tests=run_tests,
                    ),
                )

        else:
            raise ValueError("Invalid device type")

        # Add ping and SNMP to test results
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
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"{err}") from err
